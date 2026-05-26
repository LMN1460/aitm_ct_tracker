"""SMTP email sending for CT Watcher."""

from dataclasses import dataclass
from email.message import EmailMessage
import smtplib
from typing import List, Dict, Optional

from .config import (
    EMAIL_ENABLED,
    SMTP_ENABLED,
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USERNAME,
    SMTP_PASSWORD,
    SMTP_FROM_EMAIL,
    SMTP_REPLY_TO,
    SMTP_USE_STARTTLS,
    SMTP_USE_SSL,
    SMTP_TIMEOUT_SECONDS,
    AUTOMATED_EMAIL_DISCLAIMER,
)
from .state import state
from .utils import defang_domain


@dataclass
class EmailSendStatus:
    """Result of an SMTP send attempt."""
    state: str
    details: str


def _build_iocs_list(all_domains: List[str], non_cdn_ips: Optional[List[str]]) -> str:
    """Build IOC text for template substitution."""
    iocs_list = "\n".join(defang_domain(d) for d in all_domains[:50])
    if len(all_domains) > 50:
        iocs_list += f"\n... and {len(all_domains) - 50} more domains"

    if non_cdn_ips:
        iocs_list += "\n\nIP Addresses:\n"
        iocs_list += "\n".join(non_cdn_ips[:20])
        if len(non_cdn_ips) > 20:
            iocs_list += f"\n... and {len(non_cdn_ips) - 20} more IPs"

    return iocs_list


def _build_email_body(all_domains: List[str], non_cdn_ips: Optional[List[str]]) -> str:
    """Render email template and append automation disclaimer."""
    iocs_list = _build_iocs_list(all_domains, non_cdn_ips)
    body = state.email_template.replace("{IOCS_LIST}", iocs_list).rstrip()
    return f"{body}\n\n{AUTOMATED_EMAIL_DISCLAIMER}\n"


def _smtp_ready() -> bool:
    """Check whether required SMTP settings are present."""
    return bool(SMTP_HOST and SMTP_PORT and SMTP_FROM_EMAIL)


def send_automated_target_email(
    target_info: Optional[Dict[str, str]],
    domain: str,
    all_domains: List[str],
    non_cdn_ips: Optional[List[str]],
    ) -> EmailSendStatus:
    """Send automated SMTP email when policy requirements are met."""
    if not EMAIL_ENABLED:
        return EmailSendStatus("skipped", "Skipped: email feature disabled")

    if not SMTP_ENABLED:
        return EmailSendStatus("skipped", "Skipped: SMTP disabled")

    if not _smtp_ready():
        return EmailSendStatus("failed", "Failed: SMTP config incomplete")

    if not target_info:
        return EmailSendStatus("skipped", "Skipped: unknown target organization")

    target_email = target_info.get("email", "").strip()
    target_name = target_info.get("name", "target")
    if not target_email:
        return EmailSendStatus("skipped", "Skipped: target email missing")

    if SMTP_ONLY_WATCHED and api_id not in state.watched_org_ids:
        return EmailSendStatus("skipped", "Skipped: only emailing watched orgs")

    subject = f"[Threat Intel] Phishing infrastructure detected targeting {target_name}"
    body = _build_email_body(all_domains, non_cdn_ips)

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = SMTP_FROM_EMAIL
    message["To"] = target_email
    if SMTP_REPLY_TO:
        message["Reply-To"] = SMTP_REPLY_TO
    message.set_content(body)

    try:
        if SMTP_USE_SSL:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT_SECONDS) as smtp:
                if SMTP_USERNAME and SMTP_PASSWORD:
                    smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
                smtp.send_message(message)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT_SECONDS) as smtp:
                smtp.ehlo()
                if SMTP_USE_STARTTLS:
                    smtp.starttls()
                    smtp.ehlo()
                if SMTP_USERNAME and SMTP_PASSWORD:
                    smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
                smtp.send_message(message)
        return EmailSendStatus("sent", f"Sent automated email to {target_email}")
    except Exception as exc:
        print(f"[!] SMTP send failed for {domain}: {exc}")
        return EmailSendStatus("failed", f"Failed: {str(exc)[:180]}")
