from __future__ import annotations

import re
from typing import Any
from src.config.logging_config import setup_logger

logger = setup_logger()

# Incident domain requirements for CERT-SG IRMs in the knowledge base
PLAYBOOK_DOMAIN_REQUIREMENTS: dict[str, list[str]] = {
    "business_email_compromise": [
        "email", "mailbox", "inbox", "exchange", "o365", "office 365", "phish", "bec", "mail", "wire fraud"
    ],
    "customer_phishing": [
        "phish", "credential harvest", "fake site", "fake domain", "spoofed domain", "typosquat", "phishing website"
    ],
    "social_engineering": [
        "social engineering", "phone call", "vishing", "pretext", "impersonat", "red phone"
    ],
    "ransomware": [
        "ransomware", "encrypt", "ransom note", "decryptor", "extortion", "shaming site"
    ],
    "insider_abuse": [
        "insider", "employee abuse", "disgruntled", "privilege abuse", "unauthorized copy"
    ],
    "worm_infection": [
        "worm", "propagation vector", "mass infection", "self-replicating"
    ],
    "information_leakage": [
        "leak", "data disclosure", "confidential document", "dlp", "unintentional disclosure"
    ],
    "scam": [
        "scam", "fraudulent transfer", "advance fee", "banking scam"
    ],
    "ddos": [
        "denial of service", "ddos", "syn flood", "volumetric attack"
    ],
}


def normalize_playbook_name(name: str) -> str:
    """Normalize playbook filename/ID to a domain key."""
    clean = re.sub(r"^IRM-\d+-", "", name, flags=re.IGNORECASE)
    clean = clean.replace("-", "_").lower()
    return clean


def is_playbook_applicable(
    playbook_name: str,
    playbook_content: str,
    alert_text: str,
    alert_mitre_techniques: list[str] | None = None,
    rerank_score: float | None = None,
    min_score_threshold: float = 0.15,
) -> tuple[bool, str]:
    """
    Strict applicability guard to prevent mismatched playbooks (e.g. Business Email Compromise)
    from being attached to unrelated alerts (e.g. Host TCP/memory anomaly) purely by weak semantic score.
    """
    alert_text_lower = (alert_text or "").lower()
    domain_key = normalize_playbook_name(playbook_name)

    # 1. Check if playbook domain has explicit keyword requirements
    required_keywords = PLAYBOOK_DOMAIN_REQUIREMENTS.get(domain_key)
    if not required_keywords:
        for k, v in PLAYBOOK_DOMAIN_REQUIREMENTS.items():
            if k in domain_key:
                required_keywords = v
                break

    if required_keywords:
        domain_matched = any(kw in alert_text_lower for kw in required_keywords)
        if not domain_matched:
            # Check MITRE technique overlap
            has_technique_overlap = False
            if alert_mitre_techniques:
                pb_text_lower = playbook_content.lower()
                for tech in alert_mitre_techniques:
                    m = re.search(r"\bT\d{4}(?:\.\d{3})?\b", tech)
                    tech_id = m.group(0).lower() if m else tech.lower()
                    if tech_id in pb_text_lower:
                        has_technique_overlap = True
                        break

            if not has_technique_overlap:
                return False, (
                    f"Incident mismatch: Playbook '{playbook_name}' requires specific evidence "
                    f"({', '.join(required_keywords[:3])}...) or explicit MITRE overlap, none found in alert."
                )

    # 2. Score threshold check
    if rerank_score is not None and rerank_score < min_score_threshold:
        return False, f"Playbook score ({rerank_score:.4f}) below relevance threshold ({min_score_threshold})."

    return True, f"Playbook '{playbook_name}' is applicable to incident."
