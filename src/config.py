"""Environment-backed configuration for the VAPT automation service."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(PROJECT_ROOT / ".env")


def _csv_env(name: str) -> list[str]:
    return [item.strip() for item in os.getenv(name, "").split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    zap_path: str = os.getenv("ZAP_PATH", str(Path.home() / "vapt_automation/tools/ZAP/zap.sh"))
    zap_host: str = os.getenv("ZAP_HOST", "127.0.0.1")
    zap_port: int = int(os.getenv("ZAP_PORT", "8090"))
    zap_api_key: str = os.getenv("ZAP_API_KEY", "")
    zap_start_timeout: int = int(os.getenv("ZAP_START_TIMEOUT", "180"))
    scan_timeout: int = int(os.getenv("SCAN_TIMEOUT_SECONDS", "3600"))
    spider_timeout: int = int(os.getenv("SPIDER_TIMEOUT_SECONDS", "900"))
    ajax_spider_timeout: int = int(os.getenv("AJAX_SPIDER_TIMEOUT_SECONDS", "300"))
    poll_interval: int = int(os.getenv("POLL_INTERVAL_SECONDS", "5"))
    api_token: str = os.getenv("VAPT_API_TOKEN", "")
    api_host: str = os.getenv("VAPT_API_HOST", "127.0.0.1")
    api_port: int = int(os.getenv("VAPT_API_PORT", "6969"))
    allowed_hosts: tuple[str, ...] = tuple(_csv_env("VAPT_ALLOWED_HOSTS"))
    allow_private_targets: bool = os.getenv("VAPT_ALLOW_PRIVATE_TARGETS", "false").lower() == "true"
    allow_http: bool = os.getenv("VAPT_ALLOW_HTTP", "false").lower() == "true"
    smtp_host: str = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
    smtp_user: str = os.getenv("SMTP_USER", "")
    smtp_pass: str = os.getenv("SMTP_PASS", "")
    email_html_csv: tuple[str, ...] = tuple(_csv_env("EMAIL_HTML_CSV"))
    email_all_files: tuple[str, ...] = tuple(_csv_env("EMAIL_ALL_FILES"))
    gchat_webhook: str = os.getenv("GCHAT_WEBHOOK", "")
    reports_dir: Path = Path(os.getenv("REPORTS_DIR", str(PROJECT_ROOT / "reports"))).expanduser()


settings = Settings()
