#!/usr/bin/env bash
# Install OWASP ZAP and the Python runtime dependencies on Debian/Ubuntu.
set -Eeuo pipefail

ZAP_VERSION="${ZAP_VERSION:-2.16.1}"
ZAP_DIR="${ZAP_DIR:-$HOME/vapt_automation/tools/ZAP}"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${VENV_DIR:-$PROJECT_DIR/.venv}"
INSTALLER="ZAP_${ZAP_VERSION//./_}_unix.sh"
DOWNLOAD_URL="https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/${INSTALLER}"

echo "== OWASP ZAP VAPT Automation setup =="
echo "ZAP version : ${ZAP_VERSION}"
echo "ZAP location: ${ZAP_DIR}"
echo "Project     : ${PROJECT_DIR}"

if ! command -v apt-get >/dev/null 2>&1; then
  echo "This setup script currently supports Debian/Ubuntu systems using apt." >&2
  exit 1
fi

sudo apt-get update
sudo apt-get install -y \
  ca-certificates curl wget unzip \
  python3 python3-pip python3-venv \
  openjdk-17-jre-headless \
  firefox xvfb

JAVA_VERSION="$(java -version 2>&1 | sed -n '1s/.*version "\([^"]*\)".*/\1/p')"
JAVA_MAJOR="${JAVA_VERSION%%.*}"
if [[ ! "$JAVA_MAJOR" =~ ^[0-9]+$ ]] || (( JAVA_MAJOR < 17 )); then
  echo "Java 17 or newer is required. Detected: ${JAVA_VERSION:-unknown}" >&2
  exit 1
fi

mkdir -p "$ZAP_DIR"
if [[ ! -x "$ZAP_DIR/zap.sh" ]]; then
  tmp_installer="$(mktemp)"
  trap 'rm -f "$tmp_installer"' EXIT
  echo "[+] Downloading OWASP ZAP ${ZAP_VERSION}"
  curl --fail --location --silent --show-error "$DOWNLOAD_URL" -o "$tmp_installer"
  chmod +x "$tmp_installer"
  echo "[+] Installing OWASP ZAP"
  "$tmp_installer" -q -dir "$ZAP_DIR"
else
  echo "[+] ZAP launcher already exists; skipping ZAP installation."
fi

if [[ ! -x "$ZAP_DIR/zap.sh" ]]; then
  echo "ZAP installation did not produce $ZAP_DIR/zap.sh" >&2
  exit 1
fi

echo "[+] Creating Python virtual environment"
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install --upgrade pip
"$VENV_DIR/bin/python" -m pip install -r "$PROJECT_DIR/requirements.txt"

cat <<EOF

Setup completed.

Next steps:
  1. cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
  2. Edit .env and set ZAP_API_KEY, VAPT_API_TOKEN and VAPT_ALLOWED_HOSTS.
  3. Activate the environment:
       source "$VENV_DIR/bin/activate"
  4. Start one scanner:
       python "$PROJECT_DIR/blackbox_scanner.py"
     or:
       python "$PROJECT_DIR/graybox_scanner.py"

ZAP launcher: $ZAP_DIR/zap.sh
Never expose the Flask development server directly to the public internet.
EOF
