#!/usr/bin/env bash
set -euo pipefail

usage() { echo "Usage: bash scripts/prepare-ui.sh [--download | --archive PATH]"; }
fail() { echo "UI preparation failed: $*" >&2; exit 1; }
ui_mode=offline
ui_archive=""
case "$#" in
  0) ;;
  1) case "$1" in --download) ui_mode=download ;; --help|-h) usage; exit 0 ;; *) usage >&2; exit 2 ;; esac ;;
  2) [[ "$1" == --archive && -n "$2" ]] || { usage >&2; exit 2; }
     ui_mode=archive
     ui_archive="$(cd -- "$(dirname -- "$2")" && pwd)/$(basename -- "$2")" ;;
  *) usage >&2; exit 2 ;;
esac

ui_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ui_patch="$ui_root/scripts/patch-ui.mjs"
ui_version=$(node "$ui_patch" --version "$ui_root")
ui_destination="$ui_root/static/web-vault"
mkdir -p "$ui_root/static"
ui_stage=$(mktemp -d "$ui_root/static/.web-vault.XXXXXX")
cleanup() {
  ui_status=$?
  trap - EXIT
  if [[ -d "$ui_stage/previous" && ! -e "$ui_destination" ]]; then
    if ! mv -- "$ui_stage/previous" "$ui_destination"; then
      echo "Could not restore Web Vault; previous files remain at $ui_stage/previous" >&2
      exit 1
    fi
  fi
  rm -rf -- "$ui_stage"
  exit "$ui_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "$ui_mode" == download ]]; then
  ui_archive="$ui_stage/web-vault.tar.gz"
  curl --fail --location --silent --show-error --max-time 120 \
    "https://github.com/dani-garcia/bw_web_builds/releases/download/v$ui_version/bw_web_v$ui_version.tar.gz" \
    --output "$ui_archive"
fi
if [[ "$ui_mode" == offline ]]; then
  [[ -d "$ui_destination" && ! -L "$ui_destination" ]] || fail "Missing existing Web Vault; use --download or --archive PATH"
  cp -R -- "$ui_destination" "$ui_stage/web-vault"
else
  # Official releases contain only ordinary files/directories under web-vault/.
  tar -tzf "$ui_archive" > "$ui_stage/paths"
  [[ -s "$ui_stage/paths" ]] || fail "Archive is empty"
  while IFS= read -r ui_entry; do
    ui_entry=${ui_entry#./}
    case "$ui_entry" in web-vault|web-vault/*) ;; *) fail "Archive must contain only paths inside web-vault/" ;; esac
    case "/$ui_entry/" in */../*|*\\*) fail "Archive must contain only paths inside web-vault/" ;; esac
  done < "$ui_stage/paths"
  tar -tvzf "$ui_archive" | awk 'substr($0,1,1) != "d" && substr($0,1,1) != "-" { exit 1 }' \
    || fail "Archive must contain only regular files and directories, without links"
  tar -xzf "$ui_archive" -C "$ui_stage"
fi

ui_prepared="$ui_stage/web-vault"
[[ -z "$(find "$ui_prepared" ! -type f ! -type d -print -quit)" ]] || fail "Web Vault must contain only regular files and directories"
node "$ui_patch" "$ui_root" "$ui_prepared"
find "$ui_prepared" -type f -name '*.map' -delete
# The opt-in demo is served by Rust, never by the unguarded assets binding.
rm -f -- "$ui_prepared/demo.html"
mkdir -p "$ui_prepared/css" "$ui_prepared/js"
cp -- "$ui_root/static/overrides/vaultwarden.css" "$ui_prepared/css/vaultwarden.css"
cp -- "$ui_root/static/overrides/raywarden.js" "$ui_prepared/js/raywarden.js"

# Validate and prepare everything before replacing the complete previous tree.
if [[ -e "$ui_destination" || -L "$ui_destination" ]]; then mv -- "$ui_destination" "$ui_stage/previous"; fi
mv -- "$ui_prepared" "$ui_destination"
echo "Prepared Web Vault $ui_version in static/web-vault"
