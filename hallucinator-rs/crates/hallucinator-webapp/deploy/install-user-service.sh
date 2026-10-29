#!/usr/bin/env bash
# Run hallucinator-webapp in the background as a systemd *user* service:
# no root needed, restarts if it crashes, starts at boot (via linger) and
# keeps running after you log out.
#
#   deploy/install-user-service.sh [BIND] [E2E_KEY_FILE]   # default 127.0.0.1:5001, no key
#
# Re-run it to change BIND or the key file. Build first: `cargo build --release`.
# With E2E_KEY_FILE (mode 600, made by `hallucinator-webapp e2e-key new PATH`)
# every API call must come through the end-to-end tunnel.
# Manage it with `systemctl --user {status,restart,stop} hallucinator-webapp`
# and read logs with `journalctl --user -u hallucinator-webapp -f`.
set -euo pipefail

bind="${1:-127.0.0.1:5001}"
key_file="${2:-}"
crate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin="$crate_dir/target/release/hallucinator-webapp"
unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
unit="$unit_dir/hallucinator-webapp.service"

if [[ ! -x "$bin" ]]; then
    echo "error: $bin not found — run \`cargo build --release\` in $crate_dir first" >&2
    exit 1
fi
key_env=""
if [[ -n "$key_file" ]]; then
    key_file="$(cd "$(dirname "$key_file")" && pwd)/$(basename "$key_file")"
    if [[ ! -f "$key_file" ]]; then
        echo "error: $key_file not found — make it with \`$bin e2e-key new $key_file\`" >&2
        exit 1
    fi
    key_env="Environment=HALLUCINATOR_E2E_KEY_FILE=$key_file"
fi
# systemctl --user needs the user bus; tmux/ssh shells sometimes lack it.
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"

mkdir -p "$unit_dir"
# WorkingDirectory matches a manual `./target/release/hallucinator-webapp`
# run from the crate, so a ./.hallucinator.toml or ./.env there still applies.
cat >"$unit" <<EOF
[Unit]
Description=Hallucinated reference detector web interface
Documentation=file://$crate_dir/README.md

[Service]
WorkingDirectory=$crate_dir
ExecStart=$bin
Environment=HALLUCINATOR_WEB_BIND=$bind
$key_env
Environment=NO_COLOR=1
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF
echo "wrote $unit"

# Without linger, user services stop at logout and don't start at boot.
if [[ "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null)" != "yes" ]]; then
    loginctl enable-linger "$USER" ||
        echo "warning: could not enable linger; run \`sudo loginctl enable-linger $USER\`" >&2
fi

systemctl --user daemon-reload
systemctl --user enable hallucinator-webapp
systemctl --user restart hallucinator-webapp
systemctl --user --no-pager status hallucinator-webapp | head -n 5
