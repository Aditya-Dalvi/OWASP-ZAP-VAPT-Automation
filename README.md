# OWASP ZAP VAPT Automation

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![OWASP ZAP](https://img.shields.io/badge/OWASP%20ZAP-2.16.1-00549E)
![Platform](https://img.shields.io/badge/Platform-Debian%20%7C%20Ubuntu-lightgrey)

Automate **authorized** web-application security assessments with OWASP ZAP, Python and Flask. This project keeps separate Black-Box and Gray-Box API entry points while sharing the scan engine, report generation and notification code.

> **Authorization required:** Only scan applications you own or have explicit written permission to test. Active scanning sends attack-like requests and can affect availability or data. Obtain approval, use dedicated test accounts, and agree on scan windows before running it.

## Features

- Black-Box scanning without supplied application credentials.
- Gray-Box scanning using ZAP form-based authentication and a dedicated ZAP user.
- Traditional Spider, AJAX Spider, passive scanning and active scanning.
- HTML, CSV, XML and JSON reports.
- Local report storage with restrictive file permissions.
- Optional SMTP email delivery to two configurable recipient groups:
  - `EMAIL_HTML_CSV`: HTML and CSV.
  - `EMAIL_ALL_FILES`: HTML, CSV, XML and JSON.
- Optional Google Chat webhook notifications at scan start and completion.
- Bearer-token protected Flask API.
- Explicit hostname allowlisting, HTTPS-by-default, private-address protection and one-scan-at-a-time locking.
- Scan/job status endpoint.

## Repository layout

```text
OWASP-ZAP-VAPT-Automation/
├── blackbox_scanner.py       # Black-Box API entry point
├── graybox_scanner.py        # Gray-Box API entry point
├── zap-setup.sh              # Debian/Ubuntu setup helper
├── requirements.txt
├── .env.example              # Safe template; no real secrets
├── .gitignore
├── LICENSE
├── README.md
└── src/
    ├── __init__.py
    ├── api.py                # Flask routes, auth and job tracking
    ├── config.py             # Environment-backed settings
    ├── notifications.py      # Email, Google Chat and report helpers
    └── scanner.py            # ZAP lifecycle and scan orchestration
```

## Requirements

- Debian or Ubuntu Linux (the included setup script uses `apt`).
- Python 3.10 or newer.
- Java 17 or newer.
- OWASP ZAP 2.16.1 (installed by the setup script).
- Firefox and Xvfb for browser-driven AJAX Spider operation.
- Network reachability to the authorized target.
- Optional: SMTP account and Google Chat incoming webhook.

The setup script installs Java 17, Firefox, Xvfb, Python tooling and OWASP ZAP 2.16.1. The ZAP version can be overridden with `ZAP_VERSION`, and its install location with `ZAP_DIR`.

## Installation

```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/OWASP-ZAP-VAPT-Automation.git
cd OWASP-ZAP-VAPT-Automation

chmod +x zap-setup.sh
./zap-setup.sh

cp .env.example .env
```

Edit `.env` before starting the service. Generate unique random values for `ZAP_API_KEY` and `VAPT_API_TOKEN`. For example, generate each value with:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Do not reuse the same secret for both settings.

### Important configuration

| Variable | Purpose |
|---|---|
| `ZAP_PATH` | Absolute path to the ZAP `zap.sh` launcher |
| `ZAP_HOST`, `ZAP_PORT` | Local ZAP daemon listener |
| `ZAP_API_KEY` | Secret required to access the ZAP API |
| `VAPT_API_TOKEN` | Bearer token required by this Flask API |
| `VAPT_ALLOWED_HOSTS` | Comma-separated list of authorized target hostnames |
| `VAPT_ALLOW_PRIVATE_TARGETS` | Set `true` only when approved internal/private targets must be scanned |
| `VAPT_ALLOW_HTTP` | Set `true` only if an approved target requires HTTP |
| `SMTP_USER`, `SMTP_PASS` | SMTP sender and app password |
| `EMAIL_HTML_CSV` | Comma-separated recipients for HTML and CSV |
| `EMAIL_ALL_FILES` | Comma-separated recipients for all four formats |
| `GCHAT_WEBHOOK` | Optional Google Chat incoming webhook URL |
| `REPORTS_DIR` | Local directory for generated reports |

**Target allowlisting is mandatory.** `VAPT_ALLOWED_HOSTS` accepts exact hostnames and wildcard subdomains such as `*.staging.example.test`. Wildcards do not include the apex domain. Do not put URL paths or schemes in this variable.

By default, the service rejects targets resolving to non-public IP addresses. For an approved internal assessment only, set `VAPT_ALLOW_PRIVATE_TARGETS=true` and maintain a strict hostname allowlist. Be aware that DNS changes and DNS rebinding are additional reasons to run this service only in a controlled network.

### Gmail SMTP

For Gmail SMTP, use a dedicated Google App Password where your account and organization policy permit it. Do not use your normal account password. An organization may disable App Passwords; use an approved mail relay if so.

### Google Chat

Set `GCHAT_WEBHOOK` to the incoming webhook URL for the destination space. Treat the entire webhook URL as a secret. Leave it empty to disable Chat notifications.

## Run the API

Activate the virtual environment:

```bash
source .venv/bin/activate
```

Start **one** scanner process at a time. Both entry points use the configured API host and port (default `127.0.0.1:6969`).

### Black-Box API

```bash
python blackbox_scanner.py
```

Submit a scan:

```bash
curl --fail-with-body -X POST http://127.0.0.1:6969/scan \
  -H "Authorization: Bearer YOUR_VAPT_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://app.example.test"
  }'
```

The request returns a `job_id`. Check progress using that ID:

```bash
curl --fail-with-body \
  -H "Authorization: Bearer YOUR_VAPT_API_TOKEN" \
  http://127.0.0.1:6969/scan/YOUR_JOB_ID
```

### Gray-Box API

Stop the Black-Box process and start the Gray-Box entry point:

```bash
python graybox_scanner.py
```

Submit a scan using a dedicated, approved test account:

```bash
curl --fail-with-body -X POST http://127.0.0.1:6969/scan \
  -H "Authorization: Bearer YOUR_VAPT_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://app.example.test",
    "auth": {
      "login_url": "https://app.example.test/login",
      "username": "approved-test-user",
      "password": "REPLACE_WITH_TEST_PASSWORD",
      "username_field": "username",
      "password_field": "password",
      "logged_in_regex": "dashboard",
      "logged_out_regex": "login"
    }
  }'
```

Optional Gray-Box fields:

- `extra_post_data`: additional URL-encoded login form parameters, for example `rememberMe=true`.
- `logged_in_regex`: text or regex identifying an authenticated response.
- `logged_out_regex`: text or regex identifying a logged-out response.

The login URL must use the same scheme and hostname as the target. Gray-Box authentication setup failure stops the scan; it does **not** silently downgrade to Black-Box.

### Health check

```bash
curl http://127.0.0.1:6969/health
```

The health endpoint is intentionally unauthenticated and returns only basic service status.

## Reports

Reports are written to `REPORTS_DIR` (default `./reports`) and may also be emailed if SMTP and recipient settings are configured.

| Format | Intended use |
|---|---|
| HTML | Human-readable assessment report |
| CSV | Spreadsheet review and filtering |
| XML | Structured report interchange |
| JSON | Automation and downstream processing |

Reports can contain sensitive URLs, request evidence, parameters and application details. Protect the report directory, limit retention and share reports only with approved recipients. The directory is ignored by Git.

Email delivery is optional. A scan can complete even if an email group is not configured or email delivery fails; inspect the `email_delivery` fields in the job result.

## Security notes and limitations

- The Flask development server is intended for local testing only. It binds to `127.0.0.1` by default.
- Do not set `VAPT_API_HOST=0.0.0.0` on an internet-facing host. For remote access, deploy behind a properly configured TLS reverse proxy or production WSGI server, restrict network access, and protect secrets.
- Use a high-entropy `VAPT_API_TOKEN`; send it only over TLS if requests leave localhost.
- Keep ZAP bound to loopback. Do not expose the ZAP API port to untrusted networks.
- The hostname allowlist is a guardrail, not a substitute for authorization, network segmentation, egress filtering or DNS controls.
- Gray-Box credentials are accepted in the request body and held in process memory while the job runs. Use a dedicated low-privilege test account, protect transport, and never put real credentials in shell history or shared logs.
- The service runs one scan at a time in a single process. Job state is held in memory and is lost when the process restarts.
- Scan timeouts are configurable. Tune them for application size and approved test windows.
- This project is an automation wrapper around ZAP, not a replacement for manual testing, business-logic assessment, source review or professional VAPT validation.
- Review ZAP findings for false positives and validate each issue before reporting it as confirmed.

## Development

Install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest
```

Run syntax checks:

```bash
python -m compileall blackbox_scanner.py graybox_scanner.py src
bash -n zap-setup.sh
```

## License

No license is currently included. Before adding an open-source license, confirm that you own the rights to publish and license every part of this project, including code created as part of employment or using employer resources. Without a license, normal copyright restrictions apply.

## Author

**Aditya Dalvi**  
Cybersecurity | Information Security | VAPT Automation  
GitHub: [Aditya-Dalvi](https://github.com/Aditya-Dalvi)
