"""Shannon entropy-based secret detection."""

import math
import re
import string

# Character sets for entropy calculation
B64_CHARS = string.ascii_letters + string.digits + "+/="
HEX_CHARS = string.hexdigits
URL_SAFE_CHARS = string.ascii_letters + string.digits + "-_"

MIN_SECRET_LENGTH = 16
HIGH_ENTROPY_THRESHOLD = 4.5

# Patterns that strongly suggest a secret
SECRET_PATTERNS = [
    # Cloud credentials
    (r"AKIA[0-9A-Z]{16}", "aws_access_key", "critical"),
    (r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", "aws_secret_key", "critical"),
    (r"AIza[0-9A-Za-z\-_]{35}", "google_api_key", "high"),
    (r"ya29\.[0-9A-Za-z\-_]+", "google_oauth_token", "high"),
    # GitHub
    (r"ghp_[A-Za-z0-9]{36}", "github_pat", "high"),
    (r"ghs_[A-Za-z0-9]{36}", "github_actions_token", "high"),
    (r"github[_\-\s]?(?:api[_\-\s]?)?token\s*[=:]\s*['\"]?([A-Za-z0-9_]{40})['\"]?", "github_token", "high"),
    # Slack
    (r"xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}", "slack_bot_token", "high"),
    (r"xoxp-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]+", "slack_user_token", "high"),
    (r"T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}", "slack_webhook", "high"),
    # OpenAI
    (r"sk-[A-Za-z0-9]{48}", "openai_api_key", "high"),
    # Stripe
    (r"sk_live_[0-9a-zA-Z]{24}", "stripe_live_key", "critical"),
    (r"sk_test_[0-9a-zA-Z]{24}", "stripe_test_key", "medium"),
    # Twilio
    (r"AC[a-z0-9]{32}", "twilio_account_sid", "medium"),
    (r"SK[a-z0-9]{32}", "twilio_api_key", "high"),
    # Private keys
    (r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", "private_key", "critical"),
    # Connection strings
    (r"(?i)(?:postgresql|mysql|mongodb|redis|amqp)://[^:]+:[^@]+@[^\s'\"]+", "db_connection_string", "critical"),
    # Generic secret assignments
    (r"(?i)(?:password|passwd|pwd|secret|api_key|apikey|auth_token|access_token|private_key|client_secret)\s*[=:]\s*['\"]([^'\"\s]{8,})['\"]", "generic_secret", "high"),
    # JWT secrets
    (r"(?i)jwt[_\-\s]?secret\s*[=:]\s*['\"]([^'\"\s]{8,})['\"]", "jwt_secret", "critical"),
    # Mailchimp
    (r"[0-9a-f]{32}-us[0-9]{1,2}", "mailchimp_api_key", "high"),
    # SendGrid
    (r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}", "sendgrid_api_key", "high"),
    # Azure
    (r"(?i)(?:account.?key|storage.?key)\s*[=:]\s*['\"]?([A-Za-z0-9+/]{86}==)", "azure_storage_key", "critical"),
    (r"(?i)(?:client.?secret|app.?secret)\s*[=:]\s*['\"]?([A-Za-z0-9~._\-]{34,40})['\"]?", "azure_client_secret", "high"),
    # GCP
    (r'"type"\s*:\s*"service_account"', "gcp_service_account", "critical"),
    (r"AIza[0-9A-Za-z\-_]{35}", "gcp_api_key", "high"),
    # Twilio
    (r"AC[a-f0-9]{32}", "twilio_account_sid", "high"),
    (r"(?i)twilio.*auth.*token\s*[=:]\s*['\"]?([a-f0-9]{32})['\"]?", "twilio_auth_token", "high"),
    # Heroku
    (r"(?i)heroku.*[=:]\s*['\"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['\"]?", "heroku_api_key", "high"),
    # npm
    (r"npm_[A-Za-z0-9]{36}", "npm_token", "high"),
    (r"//registry\.npmjs\.org/:_authToken\s*=\s*([^\s]+)", "npmrc_token", "high"),
    # Docker Hub
    (r"dckr_pat_[A-Za-z0-9_\-]{27}", "dockerhub_token", "high"),
    # HashiCorp Vault
    (r"s\.[A-Za-z0-9]{24}", "vault_token", "critical"),
    (r"b\.[A-Za-z0-9+/]{90,}", "vault_batch_token", "critical"),
    # Databricks
    (r"dapi[a-f0-9]{32}", "databricks_token", "high"),
    # Vercel
    (r"(?i)vercel.*token\s*[=:]\s*['\"]?([A-Za-z0-9]{24})['\"]?", "vercel_token", "high"),
    # SendGrid (additional full pattern — already have prefix match above)
    # PagerDuty
    (r"(?i)pagerduty.*key\s*[=:]\s*['\"]?([A-Za-z0-9+/]{20})['\"]?", "pagerduty_key", "high"),
    # Additional private key types
    (r"-----BEGIN OPENSSH PRIVATE KEY-----", "openssh_private_key", "critical"),
    (r"-----BEGIN EC PRIVATE KEY-----", "ec_private_key", "critical"),
    # JWT tokens (actual tokens, not patterns)
    (r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "jwt_token", "medium"),
    # Generic password in config
    (r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']', "generic_password", "medium"),
]

# Strings that look like secrets but are not
FALSE_POSITIVE_INDICATORS = [
    r"your[-_\s]?(?:api[-_\s]?)?key",
    r"<YOUR",
    r"example",
    r"placeholder",
    r"changeme",
    r"replace[-_\s]?me",
    r"todo",
    r"\$\{",       # environment variable references like ${SECRET}
    r"\$\(",       # shell command substitution
    r"process\.env\.",
    r"os\.environ",
    r"os\.getenv",
    r"ENV\[",
    r"secrets\.",  # k8s secrets reference
]

_FP_REGEX = re.compile("|".join(FALSE_POSITIVE_INDICATORS), re.IGNORECASE)


def shannon_entropy(data: str, charset: str) -> float:
    """Calculate Shannon entropy of a string given its character set."""
    if not data:
        return 0.0
    data = "".join(c for c in data if c in charset)
    if len(data) < MIN_SECRET_LENGTH:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy


def is_high_entropy_secret(token: str) -> tuple:
    """Return (is_secret, entropy_score, charset_name)."""
    b64_ent = shannon_entropy(token, B64_CHARS)
    hex_ent = shannon_entropy(token, HEX_CHARS)
    url_ent = shannon_entropy(token, URL_SAFE_CHARS)

    best = max(b64_ent, hex_ent, url_ent)
    charset = {b64_ent: "base64", hex_ent: "hex", url_ent: "url_safe"}[best]

    return best >= HIGH_ENTROPY_THRESHOLD, best, charset


def is_false_positive(value: str) -> bool:
    return bool(_FP_REGEX.search(value))


def scan_line_for_secrets(line: str, line_num: int, file_path: str) -> list:
    """Scan a single line for secret patterns and high-entropy strings."""
    findings = []
    stripped = line.strip()

    # Skip comments in most languages
    if stripped.startswith(("#", "//", "*", "<!--", "--")):
        return []

    # Check named patterns first
    for pattern, secret_type, severity in SECRET_PATTERNS:
        m = re.search(pattern, line)
        if m:
            value = m.group(0)
            if not is_false_positive(value):
                findings.append({
                    "file_path": file_path,
                    "line_start": line_num,
                    "secret_type": secret_type,
                    "evidence": _mask_secret(value),
                    "raw_match": value,
                    "entropy": shannon_entropy(value, B64_CHARS),
                    "severity": severity,
                    "detection_method": "pattern",
                })

    # High-entropy string detection for quoted strings
    for m in re.finditer(r'["\']([A-Za-z0-9+/=_\-]{20,})["\']', line):
        token = m.group(1)
        if is_false_positive(token):
            continue
        is_secret, entropy, charset = is_high_entropy_secret(token)
        if is_secret:
            findings.append({
                "file_path": file_path,
                "line_start": line_num,
                "secret_type": "high_entropy_string",
                "evidence": _mask_secret(token),
                "raw_match": token,
                "entropy": round(entropy, 2),
                "severity": "medium",
                "detection_method": "entropy",
                "charset": charset,
            })

    return findings


def _mask_secret(value: str) -> str:
    """Mask most of a secret value for safe display in reports."""
    if len(value) <= 8:
        return "****"
    visible = min(4, len(value) // 4)
    return value[:visible] + "****" + value[-2:]
