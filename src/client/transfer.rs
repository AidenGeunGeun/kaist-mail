//! Files streamed from Dooray straight to disk, under an overall deadline and
//! a stall limit instead of the per-request timeout and the JSON body cap.

use std::{
    fs::File,
    io::{Read, Write},
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

use super::{Client, Policy, check_header, failure, read_body, shape_error};
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
    /// and streams the body into `file`, returning its length.
    pub fn download(
        &self,
        target: &str,
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
        let path = url.path().to_owned();
        let agent = http::streaming_agent(limits.remaining()?, limits.stall);
        let mut policy = Policy {
            base: &self.base,
            cookie: &self.cookie,
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
        let json = response
            .header("content-type")
            .is_some_and(|kind| kind.to_ascii_lowercase().contains("json"));
        // Dooray reports a failed file request as a wapi envelope; a JSON
        // attachment of exactly the listed size is the file itself.
        if json && (exact.is_none() || declared != exact) {
            check_header(&path, &read_body(response)?)?;
            return Err(shape_error(&path, "JSON instead of the file"));
        }
        match (exact, declared) {
            (Some(expected), Some(declared)) if declared != expected => {
                return Err(shape_error(
                    &path,
                    &format!("{declared} bytes for a file Dooray lists as {expected} bytes"),
                ));
            }
            (_, Some(declared)) if declared > max => {
                return Err(AppError::limit(format!(
                    "Dooray {path} is larger than {max} bytes"
                )));
            }
            _ => {}
        }
        let written = copy(response, file, max, limits)?;
        if declared
            .or(exact)
            .is_some_and(|expected| expected != written)
        {
            return Err(AppError::network(format!(
                "Dooray {path} ended after {written} bytes"
            )));
        }
        Ok(written)
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
