"""Application configuration, settings, and safety constants."""

import re
from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings loaded from environment and .env file."""

    hackerone_username: str = Field(default="", alias="HACKERONE_USERNAME")
    hackerone_token: str = Field(default="", alias="HACKERONE_TOKEN")

    hackerone_graphql_url: str = "https://api.hackerone.com/graphql"
    hackerone_rest_base_url: str = "https://api.hackerone.com/v1"

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


DATA_DIR: Path = Path.cwd() / "data"
SCREENSHOTS_DIR: Path = DATA_DIR / "screenshots"
METADATA_DIR: Path = DATA_DIR / "scouts"
REPORTS_DIR: Path = DATA_DIR / "reports"
LOGS_DIR: Path = DATA_DIR / "logs"
DB_PATH: Path = DATA_DIR / "h1scopeagent.db"

DEFAULT_FINDING_LIMIT: int = 5
DEFAULT_ASSET_LIMIT: int = 20
DEFAULT_DELAY: float = 3.0
DEFAULT_REQUEST_TIMEOUT: int = 30
MAX_BATCH_SIZE: int = 50
DAEMON_LOOP_INTERVAL: int = 3600
DAEMON_AUTO_SUBMIT: bool = True
DAEMON_MAX_ITERATIONS: int = 0
RISK_LEVEL: str = "verified"
RISK_LEVELS: dict = {
    "safe": {"auto_attack": False, "auto_submit": False, "max_severity_attack": "low"},
    "verified": {"auto_attack": True, "auto_submit": False, "max_severity_attack": "medium"},
    "aggressive": {"auto_attack": True, "auto_submit": True, "max_severity_attack": "high"},
}
ATTACK_SCORE_THRESHOLD: float = 0.6
AUTO_ATTACK_TOOLS: list[str] = ["nuclei", "gobuster", "ffuf", "nmap"]
AUTO_ATTACK_TOOL_TIMEOUTS: dict = {"nuclei": 300, "gobuster": 180, "ffuf": 180, "nmap": 120}
AUTO_ATTACK_MAX_CONCURRENCY: int = 2
HACKERONE_SUBMIT_URL: str = "https://api.hackerone.com/v1/hackers/reports"

DANGEROUS_BUTTON_KEYWORDS: list[str] = [
    "delete", "remove", "destroy", "purchase", "buy",
    "submit payment", "transfer", "send", "invite", "reset",
    "revoke", "logout", "sign out", "deactivate", "suspend",
    "terminate", "close account",
]

BLOCKED_PATTERNS: list[re.Pattern] = [
    re.compile(r"hydra", re.IGNORECASE),
    re.compile(r"medusa", re.IGNORECASE),
    re.compile(r"patator", re.IGNORECASE),
    re.compile(r"sqlmap\s.*--dump", re.IGNORECASE),
    re.compile(r"sqlmap\s.*--os-shell", re.IGNORECASE),
    re.compile(r"sqlmap\s.*--file-read", re.IGNORECASE),
    re.compile(r"sqlmap\s.*--file-write", re.IGNORECASE),
    re.compile(r"masscan", re.IGNORECASE),
    re.compile(r"hping3", re.IGNORECASE),
    re.compile(r"slowloris", re.IGNORECASE),
    re.compile(r"metasploit", re.IGNORECASE),
    re.compile(r"msfconsole", re.IGNORECASE),
    re.compile(r"\bexploit\b", re.IGNORECASE),
    re.compile(r"reverse.?shell", re.IGNORECASE),
    re.compile(r"nc\s.*-e", re.IGNORECASE),
    re.compile(r"bash\s.*-i", re.IGNORECASE),
    re.compile(r"/dev/tcp", re.IGNORECASE),
    re.compile(r"rm\s+-rf\s+", re.IGNORECASE),
    re.compile(r"\bexfiltrat", re.IGNORECASE),
    re.compile(r"\bpersist", re.IGNORECASE),
    re.compile(r"lateral.?movement", re.IGNORECASE),
    re.compile(r"credential.?stuff", re.IGNORECASE),
    re.compile(r"phish", re.IGNORECASE),
    re.compile(r"malware", re.IGNORECASE),
    re.compile(r"captcha.?bypass", re.IGNORECASE),
    re.compile(r"ddos", re.IGNORECASE),
    re.compile(r"denial.?of.?service", re.IGNORECASE),
    re.compile(r"bruteforce", re.IGNORECASE),
    re.compile(r"brute.?force", re.IGNORECASE),
]

APPROVAL_REQUIRED_PATTERNS: list[re.Pattern] = [
    re.compile(r"nmap\s.*-sV", re.IGNORECASE),
    re.compile(r"nmap\s.*-[sS]C", re.IGNORECASE),
    re.compile(r"nmap\s.*-A\b", re.IGNORECASE),
    re.compile(r"nmap\s.*--script", re.IGNORECASE),
    re.compile(r"nikto", re.IGNORECASE),
    re.compile(r"gobuster", re.IGNORECASE),
    re.compile(r"dirsearch", re.IGNORECASE),
    re.compile(r"ffuf", re.IGNORECASE),
    re.compile(r"wfuzz", re.IGNORECASE),
    re.compile(r"nuclei", re.IGNORECASE),
    re.compile(r"curl\s.*-X\s*POST", re.IGNORECASE),
    re.compile(r"curl\s.*-X\s*PUT", re.IGNORECASE),
    re.compile(r"curl\s.*-X\s*PATCH", re.IGNORECASE),
    re.compile(r"curl\s.*-X\s*DELETE", re.IGNORECASE),
    re.compile(r"curl\s.*--data", re.IGNORECASE),
    re.compile(r"curl\s.*--data-binary", re.IGNORECASE),
    re.compile(r"wget\s.*--post-data", re.IGNORECASE),
    re.compile(r"-t\s*\d{2,}", re.IGNORECASE),
    re.compile(r"--threads?\s*\d{2,}", re.IGNORECASE),
    re.compile(r"rate\s*\d{3,}", re.IGNORECASE),
]

SAFE_COMMAND_PATTERNS: list[re.Pattern] = [
    re.compile(r"^dig\s+", re.IGNORECASE),
    re.compile(r"^nslookup\s+", re.IGNORECASE),
    re.compile(r"^host\s+", re.IGNORECASE),
    re.compile(r"^whois\s+", re.IGNORECASE),
    re.compile(r"^curl\s+-I\s+https?://", re.IGNORECASE),
    re.compile(r"^curl\s+--head\s+https?://", re.IGNORECASE),
    re.compile(r"^curl\s+https?://[^/\s]+/robots\.txt", re.IGNORECASE),
    re.compile(r"^curl\s+https?://[^/\s]+/\.well-known/security\.txt", re.IGNORECASE),
    re.compile(r"^curl\s+https?://[^/\s]+/security\.txt", re.IGNORECASE),
    re.compile(r"^curl\s+https?://[^/\s]+/sitemap\.xml", re.IGNORECASE),
    re.compile(r"^openssl\s+s_client\s+-connect", re.IGNORECASE),
]

EXPOSED_FILE_CHECK_LIST: list[str] = [
    ".git/config",
    ".env",
    ".env.bak",
    ".env.example",
    "backup.sql",
    "dump.sql",
    "wp-config.php.bak",
    "config.php.bak",
    "database.yml",
    "credentials.json",
    ".htaccess",
    ".htpasswd",
    "web.config",
]

SECURITY_HEADERS: list[str] = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "cross-origin-resource-policy",
    "cross-origin-opener-policy",
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
