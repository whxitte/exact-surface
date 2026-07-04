"""Nuclei template watch (module 25) — state-aware new-template → asset matcher.

When the nuclei-templates repo publishes new templates, Vantari should re-scan
*only* the assets those templates could match, not everything (§3.1 state-awareness).
These pure functions compute the new templates since last check and which of them
are relevant to the tenant's fingerprinted tech; the scheduler turns the result
into targeted rescans.
"""

from __future__ import annotations


def new_template_ids(known_ids: set[str], current_ids: set[str]) -> set[str]:
    """Template ids present now but not at the last check."""
    return current_ids - known_ids


def relevant_templates(templates: list[dict], tech_products: set[str]) -> list[dict]:
    """Filter *templates* to those matching the fingerprinted tech.

    A template matches if its product or any of its tags overlaps the tech set.
    ``templates``: ``[{id, product?, tags?}, ...]``.
    """
    tech = {t.lower() for t in tech_products}
    matches: list[dict] = []
    for template in templates:
        product = (template.get("product") or "").lower()
        tags = {t.lower() for t in (template.get("tags") or [])}
        if (product and product in tech) or (tags & tech):
            matches.append(template)
    return matches
