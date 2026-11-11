//! Files streamed from Dooray straight to disk, under an overall deadline and
//! a stall limit instead of the per-request timeout and the JSON body cap.

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

use super::{Client, MAX_BODY, Policy, check_header, failure, shape_error};
use crate::{
    error::AppError,
    http::{self, Follow, Method, Response},
};

const CHUNK: usize = 64 * 1024;

/// The time budget shared by every transfer of one command.
#[derive(Clone, Copy)]
pub struct Limits {
    deadline: Instant,
    stall: Duration,
}

impl Limits {
    pub fn new(max_seconds: u64, stall_seconds: u64) -> Self {
        Self {
            deadline: Instant::now() + Duration::from_secs(max_seconds),
            stall: Duration::from_secs(stall_seconds),
        }
    }

    fn remaining(&self) -> Result<Duration, AppError> {
        match self.deadline.saturating_duration_since(Instant::now()) {
            Duration::ZERO => Err(overdue()),
            left => Ok(left),
        }
    }
}

fn overdue() -> AppError {
    AppError::network("the download did not finish within --max-seconds")
}

/// How many bytes the file must have.
#[derive(Clone, Copy)]
pub enum Size {
    Exact(u64),
    AtMost(u64),
}

impl Client {
    /// GETs `target`, a site-root path such as an attachment's `downloadUrl`,
    /// and streams the body into `file`, returning its length. Errors call it
    /// `shown`, since the target can carry Dooray's file name.
    pub fn download(
        &self,
        target: &str,
        shown: &str,
        size: Size,
        limits: Limits,
        file: &mut File,
    ) -> Result<u64, AppError> {
        let url = self
            .base
            .join(target)
            .ok()
            .filter(|url| url.origin() == self.base.origin())
            .ok_or_else(|| AppError::shape("Dooray gave a download link outside Dooray"))?;
        let agent = http::streaming_agent(limits.remaining()?, limits.stall);
        let mut policy = Policy {
            base: &self.base,
            cookie: &self.cookie,
            shown,
        };
        let request = Follow {
            method: Method::GET,
            url,
            payload: None,
            max_redirects: 3,
            strict: true,
        };
        let response = http::follow(&agent, request, &mut policy).map_err(failure)?;
        let declared = response.content_length();
        let (exact, max) = match size {
            Size::Exact(bytes) => (Some(bytes), bytes),
            Size::AtMost(bytes) => (None, bytes),
        };
        // Dooray reports a failed file request as a wapi envelope, whose
        // size need not match; a JSON file of the listed size is the file.
        let json = response
            .header("content-type")
            .is_some_and(|kind| kind.to_ascii_lowercase().contains("json"));
        let limit = if json { max.max(MAX_BODY) } else { max };
        match (exact, declared) {
            (Some(expected), Some(declared)) if declared != expected && !json => {
                return Err(shape_error(
                    shown,
                    &format!("{declared} bytes for a file Dooray lists as {expected} bytes"),
                ));
            }
            (_, Some(declared)) if declared > limit => {
                return Err(AppError::limit(format!(
                    "Dooray {shown} is larger than {limit} bytes"
                )));
            }
            _ => {}
        }
        let written = copy(response, file, limit, limits)?;
        let ended_early =
            || AppError::network(format!("Dooray {shown} ended after {written} bytes"));
        if declared.is_some_and(|declared| declared != written) {
            return Err(ended_early());
        }
        match exact {
            Some(expected) if written == expected => Ok(written),
            _ if json => Err(envelope_error(shown, file)),
            Some(_) => Err(ended_early()),
            None => Ok(written),
        }
    }
}

/// The error the wapi envelope just written to `file` reports.
fn envelope_error(shown: &str, file: &mut File) -> AppError {
    let mut bytes = Vec::new();
    let read = file
        .seek(SeekFrom::Start(0))
        .and_then(|_| file.take(MAX_BODY).read_to_end(&mut bytes));
    if let Err(error) = read {
        return AppError::config(format!("could not read the download back: {error}"));
    }
    match check_header(shown, &bytes) {
        Err(error) => error,
        Ok(()) => shape_error(shown, "JSON instead of the file"),
    }
}

fn copy(response: Response, file: &mut File, max: u64, limits: Limits) -> Result<u64, AppError> {
    let chunks = read_in_background(response);
    let mut written = 0u64;
    loop {
        let wait = limits.remaining()?.min(limits.stall);
        let chunk = match chunks.recv_timeout(wait) {
            Ok(Ok(chunk)) if chunk.is_empty() => return Ok(written),
            Ok(Ok(chunk)) => chunk,
            Ok(Err(_)) | Err(RecvTimeoutError::Timeout) if Instant::now() >= limits.deadline => {
                return Err(overdue());
            }
            Ok(Err(error)) => {
                return Err(AppError::network(format!(
                    "the download broke off: {error}"
                )));
            }
            Err(RecvTimeoutError::Timeout) => {
                return Err(AppError::network(format!(
                    "no data arrived for {} s (--stall-seconds)",
                    limits.stall.as_secs()
                )));
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(AppError::internal("the download reader stopped"));
            }
        };
        written += chunk.len() as u64;
        if written > max {
            return Err(AppError::limit(format!(
                "the download exceeded {max} bytes"
            )));
        }
        file.write_all(&chunk)
            .map_err(|error| AppError::config(format!("could not write the download: {error}")))?;
    }
}

/// Reads on a thread so a silent connection is noticed after the stall
/// limit. An empty chunk marks the end of the body.
fn read_in_background(mut response: Response) -> Receiver<std::io::Result<Vec<u8>>> {
    let (sender, receiver) = mpsc::sync_channel(4);
    thread::spawn(move || {
        loop {
            let mut chunk = vec![0; CHUNK];
            let result = response.read(&mut chunk).map(|read| {
                chunk.truncate(read);
                chunk
            });
            let done = !matches!(&result, Ok(chunk) if !chunk.is_empty());
            if sender.send(result).is_err() || done {
                return;
            }
        }
    });
    receiver
}
