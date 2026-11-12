//! Optional password storage in the macOS login keychain through
//! `/usr/bin/security`, under this CLI's own service name. Secrets reach the
//! helper on standard input only, never in argv or the environment.

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use zeroize::Zeroizing;

use crate::error::AppError;

const SERVICE: &str = "kaist-mail";
const HELPER_TIMEOUT: Duration = Duration::from_secs(30);
/// `security` has no switch to refuse user interaction: on a locked keychain
/// it waits for the unlock dialog. Nobody may be there to answer it.
const UNATTENDED_TIMEOUT: Duration = Duration::from_secs(5);
/// Keeps a `security -i` command line far below its 4096-byte limit.
const MAX_SECRET: usize = 1024;
const NOT_FOUND: i32 = 44; // errSecItemNotFound

/// The keychain behind one `security` program. Tests point it at a fake.
pub struct Keychain {
    pub program: PathBuf,
    timeout: Duration,
}

impl Keychain {
    pub fn system() -> Self {
        Self::new("/usr/bin/security".into())
    }

    fn new(program: PathBuf) -> Self {
        Self {
            program,
            timeout: HELPER_TIMEOUT,
        }
    }

    /// For use without a user: give up on a keychain dialog quickly.
    pub fn unattended(self) -> Self {
        Self {
            timeout: UNATTENDED_TIMEOUT,
            ..self
        }
    }

    /// Run `security`, giving up at its timeout or at the command's
    /// `deadline` (`--max-seconds`), whichever comes first.
    fn run(
        &self,
        args: &[&str],
        stdin: Option<&[u8]>,
        deadline: Option<Instant>,
    ) -> Result<Finished, AppError> {
        let limit = Instant::now() + self.timeout;
        let cut = deadline.filter(|deadline| *deadline < limit);
        let name = self
            .program
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        run_helper(&self.program, args, stdin, cut.unwrap_or(limit))?.ok_or_else(|| {
            AppError::config(match cut {
                Some(_) => format!("`{name}` did not finish before the command's --max-seconds ran out"),
                None => format!(
                    "`{name}` did not finish within {} seconds; a locked keychain waits for its unlock dialog",
                    self.timeout.as_secs()
                ),
            })
        })
    }

    pub fn available(&self) -> bool {
        self.program.is_file()
    }

    pub fn store(
        &self,
        account: &str,
        secret: &str,
        deadline: Option<Instant>,
    ) -> Result<(), AppError> {
        if !self.available() {
            return Err(AppError::config(
                "cannot remember the password: the macOS keychain is not available here",
            )
            .with_hint("Omit `--remember-password` and enter the password each time."));
        }
        if secret.is_empty() || secret.len() > MAX_SECRET {
            return Err(AppError::usage(format!(
                "a remembered password must be 1 to {MAX_SECRET} bytes long"
            )));
        }
        // `security -w` prints a password with any byte outside printable
        // ASCII as hex, so it could never be read back.
        if !secret.bytes().all(|byte| (b' '..=b'~').contains(&byte)) {
            return Err(AppError::usage(
                "the macOS keychain can only remember passwords of printable ASCII characters",
            )
            .with_hint("Omit `--remember-password` and enter the password each time."));
        }
        if account.is_empty() || account.len() > MAX_SECRET || account.chars().any(char::is_control)
        {
            return Err(AppError::usage("invalid account name for password storage"));
        }
        let mut command = Zeroizing::new(String::with_capacity(
            64 + 2 * (account.len() + secret.len()),
        ));
        command.push_str("add-generic-password -U -s ");
        command.push_str(SERVICE);
        command.push_str(" -a ");
        push_quoted(&mut command, account);
        command.push_str(" -w ");
        push_quoted(&mut command, secret);
        command.push('\n');
        let finished = self.run(&["-i"], Some(command.as_bytes()), deadline)?;
        // `security -i` can report command failures only on stderr, so prove
        // the write by reading it back.
        let stored = self.lookup(account, deadline);
        let stored = stored.as_ref().ok().and_then(Option::as_deref);
        if finished.code != Some(0) || stored.map(String::as_str) != Some(secret) {
            let mut error = AppError::config("the macOS keychain did not accept the password")
                .with_hint("Unlock the login keychain and retry, or omit `--remember-password`.");
            if let Err(cleanup) = self.clear(account, deadline) {
                error
                    .message
                    .push_str(&format!("; rollback failed: {}", cleanup.message));
            }
            return Err(error);
        }
        Ok(())
    }

    pub fn lookup(
        &self,
        account: &str,
        deadline: Option<Instant>,
    ) -> Result<Option<Zeroizing<String>>, AppError> {
        let args = ["find-generic-password", "-s", SERVICE, "-a", account, "-w"];
        let finished = self.run(&args, None, deadline)?;
        match finished.code {
            Some(0) => finished.secret().map(Some),
            Some(NOT_FOUND) => Ok(None),
            _ => Err(finished.failure("macOS keychain lookup")),
        }
    }

    /// Delete the secret; deleting an absent one succeeds.
    pub fn clear(&self, account: &str, deadline: Option<Instant>) -> Result<(), AppError> {
        let args = ["delete-generic-password", "-s", SERVICE, "-a", account];
        let finished = self.run(&args, None, deadline)?;
        match finished.code {
            Some(0 | NOT_FOUND) => Ok(()),
            _ => Err(finished.failure("macOS keychain delete")),
        }
    }

    /// Delete every account under this CLI's service name; `true` when at
    /// least one item was removed.
    pub fn clear_all(&self) -> Result<bool, AppError> {
        let mut removed = false;
        for _ in 0..256 {
            let finished = self.run(&["delete-generic-password", "-s", SERVICE], None, None)?;
            match finished.code {
                Some(0) => removed = true,
                Some(NOT_FOUND) => return Ok(removed),
                _ => return Err(finished.failure("macOS keychain delete")),
            }
        }
        Err(AppError::config(
            "macOS keychain purge reached the limit of 256 deletions; passwords may remain",
        ))
    }
}

struct Finished {
    code: Option<i32>,
    stdout: Zeroizing<Vec<u8>>,
    stderr: String,
}

/// Run a helper with `stdin` (never argv or env) and capped output; `None`
/// when it was still running at `until` and had to be killed.
fn run_helper(
    program: &Path,
    args: &[&str],
    stdin: Option<&[u8]>,
    until: Instant,
) -> Result<Option<Finished>, AppError> {
    let name = program.file_name().unwrap_or_default().to_string_lossy();
    let mut child = Command::new(program)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| AppError::config(format!("cannot run `{name}`: {error}")))?;
    if let (Some(bytes), Some(mut pipe)) = (stdin, child.stdin.take()) {
        // A helper that exits early closes the pipe; its status reports why.
        let _ = pipe.write_all(bytes);
    }
    let drain = |pipe: Option<Box<dyn Read + Send>>, cap: u64| {
        thread::spawn(move || {
            let mut buffer = Zeroizing::new(Vec::new());
            if let Some(pipe) = pipe {
                let _ = pipe.take(cap).read_to_end(&mut buffer);
            }
            buffer
        })
    };
    let out = drain(child.stdout.take().map(|p| Box::new(p) as _), 1 << 20);
    let err = drain(child.stderr.take().map(|p| Box::new(p) as _), 1 << 16);
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| AppError::config(format!("cannot wait for `{name}`: {error}")))?
        {
            break status;
        }
        if Instant::now() >= until {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(5));
    };
    let stderr = err.join().unwrap_or_default();
    Ok(Some(Finished {
        code: status.code(),
        stdout: out.join().unwrap_or_default(),
        stderr: String::from_utf8_lossy(&stderr).trim().to_owned(),
    }))
}

impl Finished {
    fn secret(&self) -> Result<Zeroizing<String>, AppError> {
        let text = std::str::from_utf8(&self.stdout)
            .map_err(|_| AppError::config("the stored password is not valid UTF-8"))?;
        Ok(Zeroizing::new(
            text.trim_end_matches(['\n', '\r']).to_owned(),
        ))
    }

    fn failure(&self, what: &str) -> AppError {
        AppError::config(format!("{what} failed: {}", self.stderr))
    }
}

/// Append one word quoted for the `security -i` command parser.
fn push_quoted(out: &mut String, word: &str) {
    out.push('"');
    for c in word.chars() {
        if matches!(c, '\\' | '"') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::*;

    pub(crate) fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    /// A fake `security` that keeps one item in `store`: `-i` stores the
    /// quoted `-w` word it reads from stdin.
    pub(crate) fn fake_security(bin: &Path, store: &Path) -> Keychain {
        let program = script(
            bin,
            "security",
            &format!(
                r#"echo "$@" >> "{s}/argv.log"
case "$1" in
  -i) IFS= read -r line; printf '%s\n' "$line" > "{s}/stdin.log"
      printf '%s' "$line" | sed 's/.* -w "\(.*\)"$/\1/' | sed 's/\\\(.\)/\1/g' > "{s}/secret" ;;
  find-generic-password) if [ -f "{s}/secret" ]; then cat "{s}/secret"; echo; else echo "not found" >&2; exit 44; fi ;;
  delete-generic-password) if [ -f "{s}/fail-delete" ]; then echo "denied" >&2; exit 1; fi
      if [ -f "{s}/secret" ]; then rm "{s}/secret"; else exit 44; fi ;;
esac"#,
                s = store.display()
            ),
        );
        Keychain::new(program)
    }

    #[test]
    fn passwords_reach_the_keychain_on_stdin_only_and_round_trip() {
        let (bin, store) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let keychain = fake_security(bin.path(), store.path());
        let secret = "pa\"ss\\word";
        assert!(keychain.lookup("student", None).unwrap().is_none());
        keychain.store("student", secret, None).unwrap();
        assert_eq!(
            keychain.lookup("student", None).unwrap().unwrap().as_str(),
            secret
        );
        assert!(keychain.clear_all().unwrap());
        assert!(keychain.lookup("student", None).unwrap().is_none());

        let stdin = fs::read_to_string(store.path().join("stdin.log")).unwrap();
        assert!(stdin.starts_with("add-generic-password -U -s kaist-mail -a \"student\" -w "));
        let argv = fs::read_to_string(store.path().join("argv.log")).unwrap();
        assert!(!argv.contains("pa\"ss"), "{argv}");
    }

    #[test]
    fn a_write_that_reads_back_differently_is_refused_and_removed() {
        let (bin, store) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        // `security` prints non-ASCII passwords as hex, so a bad readback is real.
        let program = script(
            bin.path(),
            "security",
            &format!(
                r#"case "$1" in
  -i) cat >/dev/null; touch "{s}/item" ;;
  find-generic-password) echo 70c3a4; exit 0 ;;
  delete-generic-password) rm "{s}/item" ;;
esac"#,
                s = store.path().display()
            ),
        );
        let error = Keychain::new(program)
            .store("student", "pw", None)
            .unwrap_err();
        assert_eq!(
            error.message,
            "the macOS keychain did not accept the password"
        );
        assert!(!store.path().join("item").exists());
    }
}
