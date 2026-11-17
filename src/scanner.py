"""OWASP ZAP scan orchestration for black-box and authenticated gray-box scans."""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import subprocess
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests
from zapv2 import ZAPv2

from .config import settings
from .notifications import (
    build_alert_stats, build_csv_bytes, notify_email, safe_hostname,
    scan_completed, scan_started,
)

log = logging.getLogger("vapt")


class ScanError(RuntimeError):
    """Raised when ZAP setup or scan execution fails."""


def validate_target(target_url: str) -> str:
    """Require an explicitly allowlisted HTTP(S) host before any scan starts."""
    if not isinstance(target_url, str) or not target_url.strip():
        raise ValueError("A target URL is required.")
    parsed = urlparse(target_url.strip())
    if parsed.scheme not in ({"https", "http"} if settings.allow_http else {"https"}):
        raise ValueError("Target must use HTTPS (HTTP can be enabled explicitly in configuration).")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Target URL is malformed or contains embedded credentials.")
    if parsed.fragment:
        raise ValueError("Target URL must not contain a URL fragment.")
    host = parsed.hostname.rstrip(".").lower()
    allowed = [item.lower().strip() for item in settings.allowed_hosts]
    if not allowed:
        raise ValueError("VAPT_ALLOWED_HOSTS is empty. Configure authorized target hosts before scanning.")
    host_allowed = any(
        host == entry or (entry.startswith("*.") and host.endswith(entry[1:]) and host != entry[2:])
        for entry in allowed
    )
    if not host_allowed:
        raise ValueError(f"Target host '{host}' is not in VAPT_ALLOWED_HOSTS.")

    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))}
    except socket.gaierror as exc:
        raise ValueError(f"Target host could not be resolved: {host}") from exc
    if not settings.allow_private_targets:
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if not ip.is_global:
                raise ValueError(
                    f"Target resolves to a non-public address ({address}). "
                    "Set VAPT_ALLOW_PRIVATE_TARGETS=true only for approved internal assessments."
                )
    return target_url.strip()


def _start_zap() -> subprocess.Popen:
    zap_path = Path(settings.zap_path).expanduser()
    if settings.zap_host not in {"127.0.0.1", "localhost", "::1"}:
        raise ScanError("ZAP_HOST must be loopback-only; do not expose the ZAP API.")
    if not zap_path.is_file():
        raise ScanError(f"OWASP ZAP launcher not found: {zap_path}. Run zap-setup.sh or set ZAP_PATH.")
    if not settings.zap_api_key:
        raise ScanError("ZAP_API_KEY is not configured.")
    command = [
        str(zap_path), "-daemon", "-host", settings.zap_host,
        "-port", str(settings.zap_port),
        "-config", f"api.key={settings.zap_api_key}",
        "-config", "api.disablekey=false",
        "-config", "api.addrs.addr.name=127.0.0.1",
        "-config", "api.addrs.addr.regex=false",
    ]
    log.info("Starting OWASP ZAP daemon on %s:%s", settings.zap_host, settings.zap_port)
    return subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _wait_for_zap(timeout: int, process: subprocess.Popen) -> None:
    endpoint = f"http://{settings.zap_host}:{settings.zap_port}/JSON/core/view/version/"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ScanError(f"ZAP exited unexpectedly with code {process.returncode}.")
        try:
            response = requests.get(endpoint, params={"apikey": settings.zap_api_key}, timeout=3)
            if response.ok:
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    raise ScanError(f"OWASP ZAP did not become ready within {timeout} seconds.")


def _wait_for_progress(label: str, status_fn, timeout: int, interval: int) -> None:
    deadline = time.monotonic() + timeout
    last_status = None
    while time.monotonic() < deadline:
        try:
            status = int(status_fn())
        except (TypeError, ValueError) as exc:
            raise ScanError(f"Could not read {label} status from ZAP.") from exc
        if status != last_status:
            log.info("%s progress: %s%%", label, status)
            last_status = status
        if status >= 100:
            return
        time.sleep(interval)
    raise ScanError(f"{label} timed out after {timeout} seconds.")


def _wait_for_ajax(zap: ZAPv2, timeout: int, interval: int) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = str(zap.ajaxSpider.status).lower()
        if status != "running":
            log.info("AJAX Spider status: %s", status)
            return
        time.sleep(interval)
    try:
        zap.ajaxSpider.stop()
    except Exception:
        log.exception("Unable to stop timed-out AJAX Spider.")
    log.warning("AJAX Spider reached its timeout; continuing with passive scan results.")


def _setup_authenticated_context(zap: ZAPv2, target_url: str, auth: dict) -> tuple[str, str]:
    required = ("username", "password")
    if any(not isinstance(auth.get(key), str) or not auth[key] for key in required):
        raise ValueError("Gray-Box auth requires non-empty username and password.")
    login_url = auth.get("login_url", target_url)
    login_parsed = urlparse(login_url)
    target_parsed = urlparse(target_url)
    if (
        login_parsed.scheme != target_parsed.scheme
        or login_parsed.hostname != target_parsed.hostname
        or login_parsed.username is not None
        or login_parsed.password is not None
        or login_parsed.fragment
    ):
        raise ValueError("login_url must use the same scheme and host as the authorized target and must not contain embedded credentials or fragments.")
    context_name = "vapt_auth_context"
    context_id = zap.context.new_context(context_name)
    zap.context.include_in_context(context_name, f"{target_url.rstrip('/')}.*")

    username_field = auth.get("username_field", "username")
    password_field = auth.get("password_field", "password")
    post_data = (
        f"{username_field}={{%25username%25}}&"
        f"{password_field}={{%25password%25}}"
    )
    extra_post_data = auth.get("extra_post_data", "")
    if extra_post_data:
        post_data += f"&{extra_post_data}"
    auth_config = (
        f"loginUrl={requests.utils.quote(login_url, safe='')}"
        f"&loginRequestData={requests.utils.quote(post_data, safe='')}"
    )
    zap.authentication.set_authentication_method(
        context_id, "formBasedAuthentication", auth_config
    )
    zap.authentication.set_logged_in_indicator(
        context_id, auth.get("logged_in_regex", r"\Qdashboard\E")
    )
    zap.authentication.set_logged_out_indicator(
        context_id, auth.get("logged_out_regex", r"\Qlogin\E")
    )
    user_id = zap.users.new_user(context_id, "vapt_user")
    credentials = (
        f"username={requests.utils.quote(auth['username'], safe='')}"
        f"&password={requests.utils.quote(auth['password'], safe='')}"
    )
    zap.users.set_authentication_credentials(context_id, user_id, credentials)
    zap.users.set_user_enabled(context_id, user_id, True)
    zap.sessionManagement.set_session_management_method(
        context_id, "cookieBasedSessionManagement", ""
    )
    return str(context_id), str(user_id)


def _write_reports(target_url: str, timestamp: str, reports: dict[str, bytes]) -> None:
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    try:
        settings.reports_dir.chmod(0o700)
    except OSError:
        log.warning("Could not restrict report directory permissions.")
    host = safe_hostname(target_url)
    for extension, content in reports.items():
        path = settings.reports_dir / f"{host}_{timestamp}.{extension}"
        path.write_bytes(content)
        try:
            path.chmod(0o600)
        except OSError:
            pass
    log.info("Reports saved under %s", settings.reports_dir)


def run_scan(target_url: str, auth: dict | None = None) -> dict:
    target_url = validate_target(target_url)
    if auth is not None and not isinstance(auth, dict):
        raise ValueError("auth must be a JSON object.")
    is_gray_box = auth is not None
    scan_type = "Gray-Box (Authenticated)" if is_gray_box else "Black-Box"
    started = datetime.now()
    scan_started(target_url, scan_type, started)
    zap_process = None
    zap = None
    try:
        zap_process = _start_zap()
        _wait_for_zap(settings.zap_start_timeout, zap_process)
        proxy = f"http://{settings.zap_host}:{settings.zap_port}"
        zap = ZAPv2(
            apikey=settings.zap_api_key,
            proxies={"http": proxy, "https": proxy},
        )

        context_id = user_id = None
        if is_gray_box:
            # Authentication setup failures are fatal; never silently downgrade
            # an authenticated assessment to an unauthenticated scan.
            context_id, user_id = _setup_authenticated_context(zap, target_url, auth)

        log.info("Opening target host %s", safe_hostname(target_url))
        zap.urlopen(target_url)
        time.sleep(2)

        if context_id and user_id:
            spider_id = zap.spider.scan_as_user(
                contextid=context_id, userid=user_id, url=target_url,
                maxchildren=None, recurse=True,
            )
        else:
            spider_id = zap.spider.scan(target_url)
        _wait_for_progress(
            "Spider", lambda: zap.spider.status(spider_id),
            settings.spider_timeout, settings.poll_interval,
        )

        if context_id and user_id:
            zap.ajaxSpider.scan_as_user(
                contextname="vapt_auth_context", username="vapt_user",
                url=target_url, subtreeonly=False,
            )
        else:
            zap.ajaxSpider.scan(target_url)
        _wait_for_ajax(zap, settings.ajax_spider_timeout, settings.poll_interval)

        passive_deadline = time.monotonic() + settings.scan_timeout
        while time.monotonic() < passive_deadline:
            try:
                remaining = int(zap.pscan.records_to_scan)
            except Exception:
                remaining = 0
            log.info("Passive scan records remaining: %s", remaining)
            if remaining <= 0:
                break
            time.sleep(settings.poll_interval)
        else:
            raise ScanError("Passive scan timed out.")

        if context_id and user_id:
            active_id = zap.ascan.scan_as_user(
                url=target_url, contextid=context_id, userid=user_id, recurse=True,
            )
        else:
            active_id = zap.ascan.scan(target_url)
        _wait_for_progress(
            "Active Scan", lambda: zap.ascan.status(active_id),
            settings.scan_timeout, settings.poll_interval,
        )

        alerts = zap.core.alerts()
        stats = build_alert_stats(alerts)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        date_str = datetime.now().strftime("%d-%m-%Y")
        reports = {
            "html": zap.core.htmlreport().encode("utf-8"),
            "xml": zap.core.xmlreport().encode("utf-8"),
            "json": json.dumps(alerts, indent=2, ensure_ascii=False).encode("utf-8"),
            "csv": build_csv_bytes(alerts),
        }
        _write_reports(target_url, timestamp, reports)
        ended = datetime.now()

        email_results = notify_email(
            target_url, scan_type, timestamp, date_str, reports, stats["total_instances"]
        )
        report_time = datetime.now()
        scan_completed(target_url, scan_type, started, ended, stats, report_time)
        return {
            "success": True,
            "target": target_url,
            "scan_type": scan_type,
            "timestamp": timestamp,
            "total_vulnerabilities": stats["total_vulns"],
            "total_instances": stats["total_instances"],
            "vulnerabilities_by_risk": stats["vuln_by_risk"],
            "email_delivery": email_results,
        }
    except Exception as exc:
        log.exception("VAPT scan failed for %s", target_url)
        raise ScanError(str(exc)) from exc
    finally:
        if zap is not None:
            try:
                zap.core.shutdown()
            except Exception:
                log.warning("ZAP API shutdown request failed.", exc_info=True)
        if zap_process is not None:
            try:
                zap_process.terminate()
                zap_process.wait(timeout=15)
            except Exception:
                try:
                    zap_process.kill()
                except Exception:
                    log.warning("Could not terminate ZAP process.", exc_info=True)
