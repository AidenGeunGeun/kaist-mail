#!/usr/bin/env bash
# Install a kaist-mail release binary, verified by its SHA-256, without sudo.
#
#   KAIST_MAIL_VERSION      release tag to install (default: the latest release)
#   KAIST_MAIL_INSTALL_DIR  destination directory (default: ~/.local/bin)
#   KAIST_MAIL_RELEASES     releases URL; tests point it at a loopback or file:// copy
#
# Everything runs from `main` on the last line, so a truncated download does nothing.
set -euo pipefail

die() {
  echo "kaist-mail installer: $*" >&2
  exit 1
}

main() {
  local tool
  for tool in curl mkdir mktemp shasum tar uname; do
    command -v "$tool" >/dev/null 2>&1 || die "required command not found: $tool"
  done

  local target
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) target="aarch64-apple-darwin" ;;
    *) die "no prebuilt release for $(uname -s) $(uname -m); build from source (see README.md)" ;;
  esac

  local releases="${KAIST_MAIL_RELEASES:-https://github.com/AidenGeunGeun/kaist-mail/releases}"
  local loopback='^http://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]+)?(/|$)'
  if [[ "$releases" == https://* ]]; then
    proto="=https"
  elif [[ "$releases" =~ $loopback || "$releases" == file://* ]]; then
    proto="=http,https,file"
  else
    die "KAIST_MAIL_RELEASES must be https://, file://, or http:// on a loopback host"
  fi

  local version latest
  if [[ -n "${KAIST_MAIL_VERSION:-}" ]]; then
    version="v${KAIST_MAIL_VERSION#v}"
  else
    latest="$(fetch -I -o /dev/null -w '%{url_effective}' "$releases/latest")" || die "could not reach $releases"
    version="${latest%/}"
    version="${version##*/}"
  fi
  if [[ ! "$version" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    [[ -n "${KAIST_MAIL_VERSION:-}" ]] && die "KAIST_MAIL_VERSION must be a release tag such as v0.1.0"
    die "no release published at $releases"
  fi

  local package="kaist-mail-${version}-${target}"
  local archive="$package.tar.gz"
  work_dir=""
  trap '[[ -z "$work_dir" ]] || rm -rf "$work_dir"' EXIT
  work_dir="$(mktemp -d)"

  echo "Downloading kaist-mail $version for $target"
  fetch -o "$work_dir/$archive" "$releases/download/$version/$archive" || die "could not download $archive"
  fetch -o "$work_dir/$archive.sha256" "$releases/download/$version/$archive.sha256" ||
    die "could not download $archive.sha256"

  # Compare the digest ourselves: a checksum file cannot select other paths.
  local expected checksum_name extra actual
  read -r expected checksum_name extra < "$work_dir/$archive.sha256" || die "invalid checksum file"
  [[ "$expected" =~ ^[0-9a-f]{64}$ && "${checksum_name#\*}" == "$archive" && -z "${extra:-}" ]] ||
    die "invalid checksum file"
  actual="$(shasum -a 256 "$work_dir/$archive")"
  [[ "${actual%% *}" == "$expected" ]] || die "checksum verification failed for $archive"

  # Extract only the fixed executable, never archive-controlled paths.
  tar -xzOf "$work_dir/$archive" "$package/kaist-mail" > "$work_dir/kaist-mail" ||
    die "archive has no kaist-mail executable"
  chmod 0755 "$work_dir/kaist-mail"
  [[ "$("$work_dir/kaist-mail" --version)" == "kaist-mail ${version#v}" ]] ||
    die "downloaded binary does not report version $version"

  local install_dir="${KAIST_MAIL_INSTALL_DIR:-$HOME/.local/bin}"
  mkdir -p "$install_dir"
  install_dir="$(cd "$install_dir" && pwd)"
  local destination="$install_dir/kaist-mail"
  if [[ -L "$destination" || (-e "$destination" && ! -f "$destination") ]]; then
    die "$destination exists and is not a regular file; remove it and run the installer again"
  fi
  # BSD install writes a private temporary file beside the target and renames it over the target, so a
  # symlink planted at that name is replaced, never followed. GNU install on PATH does not. The directory
  # operand matters: a file operand that became a symlink to a directory would be resolved into it.
  /usr/bin/install -m 0755 "$work_dir/kaist-mail" "$install_dir/"
  if [[ -L "$destination" || ! -f "$destination" ]]; then
    die "$destination was replaced by something else during the install"
  fi

  echo "Installed kaist-mail $version to $destination"
  case ":$PATH:" in
    *":$install_dir:"*) echo "Next: kaist-mail auth login" ;;
    *)
      echo
      echo "$install_dir is not on your PATH. Add it, then open a new terminal:"
      echo "  echo 'export PATH=\"$install_dir:\$PATH\"' >> ~/.zshrc"
      echo "Then sign in: kaist-mail auth login"
      ;;
  esac
}

fetch() {
  curl --proto "$proto" --tlsv1.2 --max-time 300 --max-redirs 5 --max-filesize 67108864 -fsSL "$@"
}

main "$@"
