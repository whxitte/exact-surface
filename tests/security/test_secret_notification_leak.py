"""A leaked secret's plaintext must never reach a notification channel (§9c, §8).

Vantari stores masked value + hash + locator; alerts are built only from the
masked field. These tests prove that: (1) ``mask`` never returns the full value
for a realistic secret, and (2) the alert an operator receives — the text that
goes to Discord/Slack/Telegram/email/webhook — contains the masked hint and
*never* the plaintext, even if a stored doc were to erroneously still carry it.
"""

from __future__ import annotations

from core.secrets_policy import mask
from modules.notification.router import alert_from_leak, alert_from_secret

PLAINTEXT = "AKIAIOSFODNN7EXAMPLE"  # canonical fake AWS access key id


def test_mask_never_reveals_full_value():
    masked = mask(PLAINTEXT)
    assert PLAINTEXT not in masked
    assert "•" in masked
    assert masked.startswith("AKIA")  # a hint, not the secret


def _all_strings(alert) -> str:
    return " ".join(
        str(v) for v in (alert.title, alert.detail, alert.location, alert.reference, alert.text())
    )


def test_secret_alert_carries_masked_not_plaintext():
    doc = {
        "kind": "aws_access_key",
        "masked": mask(PLAINTEXT),
        "secret_hash": "deadbeef",
        "source_locator": "https://acme.com/app.js#L42",
        "severity": "critical",
    }
    alert = alert_from_secret(doc, program="acme.com")
    blob = _all_strings(alert)
    assert PLAINTEXT not in blob
    assert mask(PLAINTEXT) in blob
    assert "rotate" in blob.lower()


def test_secret_alert_ignores_stray_plaintext_field():
    """Defense in depth: even if a doc wrongly still held the plaintext under
    'value', the alert builder reads only 'masked' — so it cannot leak."""
    doc = {
        "kind": "aws_access_key",
        "masked": mask(PLAINTEXT),
        "value": PLAINTEXT,  # must be ignored
        "source_locator": "https://acme.com/app.js",
    }
    alert = alert_from_secret(doc, program="acme.com")
    assert PLAINTEXT not in _all_strings(alert)


def test_leak_alert_carries_masked_not_plaintext():
    doc = {
        "kind": "github_pat",
        "source": "github",
        "masked": mask("ghp_" + "A" * 36),
        "url": "https://github.com/acme/repo/blob/main/.env",
        "severity": "high",
    }
    alert = alert_from_leak(doc, program="acme.com")
    blob = _all_strings(alert)
    assert "ghp_" + "A" * 36 not in blob
    assert alert.location.startswith("https://github.com/")
