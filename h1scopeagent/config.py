"""Application configuration, settings, and profile system."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    hackerone_username: str = Field(default="", alias="HACKERONE_USERNAME")
    hackerone_token: str = Field(default="", alias="HACKERONE_TOKEN")
    hackerone_graphql_url: str = "https://api.hackerone.com/graphql"
    hackerone_rest_base_url: str = "https://api.hackerone.com/v1"

    h1_profile: str = Field(default="default", alias="H1_PROFILE")
    h1_risk_level: str = Field(default="verified", alias="H1_RISK_LEVEL")
    h1_concurrency: int = Field(default=3, alias="H1_CONCURRENCY")
    h1_delay: float = Field(default=3.0, alias="H1_DELAY")
    h1_timeout: int = Field(default=30, alias="H1_TIMEOUT")
    h1_browser_headless: bool = Field(default=True, alias="H1_BROWSER_HEADLESS")
    h1_finding_limit: int = Field(default=10, alias="H1_FINDING_LIMIT")
    h1_asset_limit: int = Field(default=50, alias="H1_ASSET_LIMIT")
    h1_daemon_interval: int = Field(default=3600, alias="H1_DAEMON_INTERVAL")
    h1_auto_install_tools: bool = Field(default=True, alias="H1_AUTO_INSTALL_TOOLS")
    h1_log_level: str = Field(default="info", alias="H1_LOG_LEVEL")
    h1_data_dir: str = Field(default="./data", alias="H1_DATA_DIR")
    h1_db_path: str = Field(default="./data/h1scopeagent.db", alias="H1_DB_PATH")

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "populate_by_name": True,
        "extra": "ignore",
    }

    @property
    def has_credentials(self) -> bool:
        return bool(self.hackerone_username and self.hackerone_token)


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


class ConfigProfile(BaseModel):
    name: str = "default"
    concurrency: int = 3
    delay: float = 3.0
    request_timeout: int = 30
    browser_headless: bool = True
    browser_slowmo: int = 0
    full_page_screenshots: bool = False
    finding_limit: int = 10
    asset_limit: int = 50
    crawl_depth: int = 3
    js_collection: bool = True
    attack_enabled: bool = False
    submit_enabled: bool = False
    risk_level: str = "verified"
    attack_score_threshold: float = 0.6
    attack_max_concurrency: int = 2
    subdomain_enum: bool = True
    dns_resolution: bool = True
    http_probing: bool = True
    tls_inspection: bool = True
    port_scanning: bool = False
    url_crawling: bool = True
    wayback_import: bool = True
    github_search: bool = False
    leak_scanning: bool = False
    cloud_bucket_check: bool = False
    recon_modules: list[str] = Field(default_factory=lambda: [
        "subdomains", "dns", "http", "tls", "crawler", "javascript", "history"
    ])
    attack_tools: list[str] = Field(default_factory=lambda: [
        "nuclei", "gobuster", "ffuf", "nmap"
    ])
    attack_tool_timeouts: dict[str, int] = Field(default_factory=lambda: {
        "nuclei": 300, "gobuster": 180, "ffuf": 180, "nmap": 120
    })
    excluded_detectors: list[str] = Field(default_factory=list)


PROFILES_DIR = Path(__file__).resolve().parent.parent / "profiles"

_profile_cache: dict[str, ConfigProfile] = {}


def load_profile(name: str | None = None) -> ConfigProfile:
    name = name or get_settings().h1_profile
    if name in _profile_cache:
        return _profile_cache[name]

    profile_path = PROFILES_DIR / f"{name}.toml"
    if profile_path.exists():
        with open(profile_path, "rb") as f:
            data = tomllib.load(f)
        data.pop("name", None)
        profile = ConfigProfile(name=name, **data)
    else:
        profile = _get_builtin_profile(name)

    _profile_cache[name] = profile
    return profile


def _get_builtin_profile(name: str) -> ConfigProfile:
    builtins = {
        "default": ConfigProfile(name="default"),
        "fast": ConfigProfile(
            name="fast", concurrency=10, delay=0.5, crawl_depth=1,
            js_collection=False, wayback_import=False,
            recon_modules=["subdomains", "dns", "http", "tls", "crawler"],
            attack_tools=["nuclei"],
        ),
        "deep": ConfigProfile(
            name="deep", concurrency=2, delay=5.0, crawl_depth=5,
            port_scanning=True, github_search=True, leak_scanning=True,
            cloud_bucket_check=True,
            recon_modules=["subdomains", "dns", "http", "tls", "crawler",
                          "javascript", "history", "github", "leaks", "cloud",
                          "api_routes", "admin_panels"],
            attack_tools=["nuclei", "gobuster", "ffuf", "nmap"],
            attack_score_threshold=0.4, attack_max_concurrency=3,
        ),
        "passive-only": ConfigProfile(
            name="passive-only", browser_headless=True,
            subdomain_enum=True, dns_resolution=True, http_probing=False,
            tls_inspection=True, port_scanning=False, url_crawling=False,
            wayback_import=True, github_search=False,
            attack_enabled=False, submit_enabled=False,
            recon_modules=["subdomains", "dns", "history"],
            attack_tools=[],
        ),
    }
    return builtins.get(name, ConfigProfile(name=name))


def list_profiles() -> list[str]:
    profiles = []
    if PROFILES_DIR.exists():
        for f in PROFILES_DIR.glob("*.toml"):
            profiles.append(f.stem)
    for name in ["default", "fast", "deep", "passive-only"]:
        if name not in profiles:
            profiles.append(name)
    return sorted(set(profiles))


# Paths
DATA_DIR: Path = Path(get_settings().h1_data_dir)
SCREENSHOTS_DIR: Path = DATA_DIR / "screenshots"
METADATA_DIR: Path = DATA_DIR / "scouts"
REPORTS_DIR: Path = DATA_DIR / "reports"
LOGS_DIR: Path = DATA_DIR / "logs"
DB_PATH: Path = Path(get_settings().h1_db_path)

DEFAULT_FINDING_LIMIT: int = 10
DEFAULT_ASSET_LIMIT: int = 50
DEFAULT_DELAY: float = 3.0
DEFAULT_REQUEST_TIMEOUT: int = 30
MAX_BATCH_SIZE: int = 100
DAEMON_LOOP_INTERVAL: int = 3600
DAEMON_AUTO_SUBMIT: bool = True
DAEMON_MAX_ITERATIONS: int = 0
RISK_LEVEL: str = "verified"
HACKERONE_SUBMIT_URL: str = "https://api.hackerone.com/v1/hackers/reports"
AUTO_ATTACK_TOOLS: list[str] = ["nuclei", "gobuster", "ffuf", "nmap"]
AUTO_ATTACK_TOOL_TIMEOUTS: dict[str, int] = {"nuclei": 300, "gobuster": 180, "ffuf": 180, "nmap": 120}
AUTO_ATTACK_MAX_CONCURRENCY: int = 2
ATTACK_SCORE_THRESHOLD: float = 0.6

RISK_LEVELS: dict = {
    "safe": {"attack_enabled": False, "submit_enabled": False},
    "verified": {"attack_enabled": True, "submit_enabled": False},
    "aggressive": {"attack_enabled": True, "submit_enabled": True},
}

EXPOSED_FILE_CHECK_LIST: list[str] = [
    ".git/config", ".env", ".env.bak", ".env.example",
    "backup.sql", "dump.sql", "wp-config.php.bak", "config.php.bak",
    "database.yml", "credentials.json", ".htaccess", ".htpasswd", "web.config",
]

SECURITY_HEADERS: list[str] = [
    "content-security-policy", "strict-transport-security",
    "x-frame-options", "x-content-type-options", "x-xss-protection",
    "referrer-policy", "permissions-policy",
    "access-control-allow-origin", "access-control-allow-credentials",
    "access-control-allow-methods", "access-control-allow-headers",
    "cross-origin-resource-policy", "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
]

SECRET_DETECTION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE)),
    ("AWS Secret Key", re.compile(r"(?i)(aws.?secret|secret.?key).*['\"]([A-Za-z0-9/+=]{40})['\"]")),
    ("GitHub Token", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("GitHub OAuth", re.compile(r"gho_[A-Za-z0-9]{36}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Generic API Key", re.compile(r"(?i)(api[_-]?key|api[_-]?secret|apikey).*['\"]([A-Za-z0-9\-_]{20,})['\"]")),
    ("JWT Token", re.compile(r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+")),
    ("Private Key Header", re.compile(r"-----BEGIN\s+(RSA|OPENSSH|EC|DSA)\s+PRIVATE\s+KEY-----")),
    ("Generic Token", re.compile(r"(?i)(token|secret|password|passwd).*['\"]([A-Za-z0-9\-_]{16,})['\"]")),
]

SUBJECT_ALT_NAMES_PATTERN = re.compile(r"DNS:(?P<dns>[^\s,]+)", re.IGNORECASE)


def redact_secret(value: str) -> str:
    if len(value) <= 8:
        return value[0] + "*" * (len(value) - 1)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def redact_token_from_text(text: str, token: str) -> str:
    if not token or token not in text:
        return text
    return text.replace(token, "[REDACTED_TOKEN]")
