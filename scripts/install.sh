#!/usr/bin/env bash
# Install a kaist-mail release binary, verified by its SHA-256, without sudo.
#
#   KAIST_MAIL_VERSION      release tag to install (default: the latest release)
#   KAIST_MAIL_INSTALL_DIR  destination directory (default: ~/.local/bin)
#   KAIST_MAIL_RELEASES     releases URL; tests point it at a loopback or file:// copy
set -euo pipefail

die() {
  echo "kaist-mail installer: $*" >&2
  exit 1
}

for tool in chmod curl mkdir mktemp mv shasum tar uname; do
  command -v "$tool" >/dev/null 2>&1 || die "required command not found: $tool"
done

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) readonly target="aarch64-apple-darwin" ;;
  *) die "no prebuilt release for $(uname -s) $(uname -m); build from source (see README.md)" ;;
esac

readonly releases="${KAIST_MAIL_RELEASES:-https://github.com/AidenGeunGeun/kaist-mail/releases}"
if [[ "$releases" == https://* ]]; then
  readonly proto="=https"
else
  readonly proto="=http,https,file"
fi
fetch() {
  curl --proto "$proto" --tlsv1.2 --max-time 300 --max-redirs 5 --max-filesize 67108864 -fsSL "$@"
}

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

readonly package="kaist-mail-${version}-${target}"
readonly archive="$package.tar.gz"
work_dir="$(mktemp -d)"
readonly work_dir
trap 'rm -rf "$work_dir"' EXIT

echo "Downloading kaist-mail $version for $target"
fetch -o "$work_dir/$archive" "$releases/download/$version/$archive" || die "could not download $archive"
fetch -o "$work_dir/$archive.sha256" "$releases/download/$version/$archive.sha256" || die "could not download $archive.sha256"

# Compare the digest ourselves: a checksum file cannot select other paths.
read -r expected checksum_name extra < "$work_dir/$archive.sha256" || die "invalid checksum file"
[[ "$expected" =~ ^[0-9a-f]{64}$ && "${checksum_name#\*}" == "$archive" && -z "${extra:-}" ]] || die "invalid checksum file"
actual="$(shasum -a 256 "$work_dir/$archive")"
[[ "${actual%% *}" == "$expected" ]] || die "checksum verification failed for $archive"

# Extract only the fixed executable, never archive-controlled paths.
tar -xzOf "$work_dir/$archive" "$package/kaist-mail" > "$work_dir/kaist-mail" || die "archive has no kaist-mail executable"
chmod 0755 "$work_dir/kaist-mail"
[[ "$("$work_dir/kaist-mail" --version)" == "kaist-mail ${version#v}" ]] || die "downloaded binary does not report version $version"

install_dir="${KAIST_MAIL_INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$install_dir"
install_dir="$(cd "$install_dir" && pwd)"
# Stage beside the destination so the final rename is atomic.
staged="$(mktemp "$install_dir/.kaist-mail.XXXXXX")"
trap 'rm -rf "$work_dir"; rm -f "$staged"' EXIT
cat "$work_dir/kaist-mail" > "$staged"
chmod 0755 "$staged"
mv -f "$staged" "$install_dir/kaist-mail"

echo "Installed kaist-mail $version to $install_dir/kaist-mail"
case ":$PATH:" in
  *":$install_dir:"*) echo "Next: kaist-mail auth login" ;;
  *)
    echo
    echo "$install_dir is not on your PATH. Add it, then open a new terminal:"
    echo "  echo 'export PATH=\"$install_dir:\$PATH\"' >> ~/.zshrc"
    echo "Then sign in: kaist-mail auth login"
    ;;
esac
