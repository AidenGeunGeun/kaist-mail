//! Owner-only files and XDG base directories.
use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
};

pub(crate) fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

pub(crate) fn xdg_home(name: &str, home: Option<&Path>, fallback: &str) -> Option<PathBuf> {
    env_path(name).or_else(|| home.map(|home| home.join(fallback)))
}

/// Write-only options that create files with mode 0600 on Unix.
pub(crate) fn private_file_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
}
