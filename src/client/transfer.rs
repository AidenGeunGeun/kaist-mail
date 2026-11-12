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
    url::Url,
};

const CHUNK: usize = 64 * 1024;

/// The time budget shared by every transfer of one command.
#[derive(Clone, Copy)]
pub struct Limits {
    pub deadline: Instant,
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

/// Dooray ends many transfers of a few MB early, at random, and ignores
/// `Range`; a whole new attempt often completes.
const ATTEMPTS: usize = 5;

/// Why one attempt failed: Dooray cutting the body short, described for the
/// user, is worth a new attempt; anything else is final.
enum Failed {
    Cut(String),
    Final(AppError),
}

impl From<AppError> for Failed {
    fn from(error: AppError) -> Self {
        Self::Final(error)
    }
}

impl Client {
    /// GETs `target`, a site-root path such as an attachment's `downloadUrl`,
    /// and streams the body into `file`, starting over when Dooray cuts it
    /// short. Returns its length and a warning for each cut attempt. Errors
    /// call it `shown`, since the target can carry Dooray's file name.
    pub fn download(
        &self,
        target: &str,
        shown: &str,
        size: Size,
        limits: Limits,
        file: &mut File,
    ) -> Result<(u64, Vec<String>), AppError> {
        let url = self
            .base
            .join(target)
            .ok()
            .filter(|url| url.origin() == self.base.origin())
            .ok_or_else(|| AppError::shape("Dooray gave a download link outside Dooray"))?;
        let mut cuts: Vec<String> = Vec::new();
        loop {
            match self.attempt(&url, shown, size, limits, file) {
                Ok(bytes) => {
                    let warnings = cuts
                        .iter()
                        .enumerate()
                        .map(|(n, cut)| format!("attempt {} at {shown} {cut}; started over", n + 1))
                        .collect();
                    return Ok((bytes, warnings));
                }
                Err(Failed::Cut(cut)) => {
                    cuts.push(cut);
                    if cuts.len() == ATTEMPTS {
                        return Err(AppError::network(format!(
                            "Dooray cut {shown} short on all {ATTEMPTS} attempts: {}",
                            cuts.join("; ")
                        ))
                        .with_hint("Dooray often ends large transfers early; try again later"));
                    }
                    file.set_len(0)
                        .and_then(|()| file.seek(SeekFrom::Start(0)))
                        .map_err(|error| {
                            AppError::config(format!("could not restart the download: {error}"))
                        })?;
                }
                Err(Failed::Final(mut error)) => {
                    if Instant::now() >= limits.deadline {
                        error = error.with_hint(
                            "Dooray can be slow and cut transfers short; allow more time with a larger --max-seconds",
                        );
                    }
                    if !cuts.is_empty() {
                        error.message = format!(
                            "{} on attempt {}, after: {}",
                            error.message,
                            cuts.len() + 1,
                            cuts.join("; ")
                        );
                    }
                    return Err(error);
                }
            }
        }
    }

    fn attempt(
        &self,
        url: &Url,
        shown: &str,
        size: Size,
        limits: Limits,
        file: &mut File,
    ) -> Result<u64, Failed> {
        let response = self.signed(Some(limits.deadline), |cookie| {
            let agent = http::streaming_agent(limits.remaining()?, limits.stall);
            let mut policy = Policy {
                base: &self.base,
                cookie,
                shown,
            };
            let request = Follow {
                method: Method::GET,
                url: url.clone(),
                payload: None,
                max_redirects: 3,
                strict: true,
            };
            http::follow(&agent, request, &mut policy).map_err(failure)
        })?;
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
                )
                .into());
            }
            (_, Some(declared)) if declared > limit => {
                return Err(AppError::limit(format!(
                    "Dooray {shown} is larger than {limit} bytes"
                ))
                .into());
            }
            _ => {}
        }
        let written = copy(response, file, limit, limits)?;
        match exact {
            Some(expected) if written == expected => Ok(written),
            _ if json => Err(envelope_error(shown, file).into()),
            Some(expected) => Err(Failed::Cut(format!(
                "ended after {written} of {expected} bytes"
            ))),
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

/// Streams the body into `file` and returns its length, which matches the
/// declared `Content-Length` if there is one.
fn copy(response: Response, file: &mut File, max: u64, limits: Limits) -> Result<u64, Failed> {
    let declared = response.content_length();
    let progress = |written: u64| match declared {
        Some(declared) => format!("{written} of {declared} bytes"),
        None => format!("{written} bytes"),
    };
    let chunks = read_in_background(response);
    let mut written = 0u64;
    loop {
        let wait = limits.remaining()?.min(limits.stall);
        let chunk = match chunks.recv_timeout(wait) {
            Ok(Ok(chunk)) if chunk.is_empty() => {
                return match declared {
                    Some(declared) if declared != written => {
                        Err(Failed::Cut(format!("ended after {}", progress(written))))
                    }
                    _ => Ok(written),
                };
            }
            Ok(Ok(chunk)) => chunk,
            Ok(Err(_)) | Err(RecvTimeoutError::Timeout) if Instant::now() >= limits.deadline => {
                return Err(overdue().into());
            }
            Ok(Err(error)) => {
                return Err(Failed::Cut(format!(
                    "broke off after {}: {error}",
                    progress(written)
                )));
            }
            Err(RecvTimeoutError::Timeout) => {
                return Err(Failed::Cut(format!(
                    "sent nothing for {} s (--stall-seconds) after {}",
                    limits.stall.as_secs(),
                    progress(written)
                )));
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(AppError::internal("the download reader stopped").into());
            }
        };
        written += chunk.len() as u64;
        if written > max {
            return Err(AppError::limit(format!("the download exceeded {max} bytes")).into());
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
