"""Lookalike / typosquat domain generation — phishing infrastructure aimed *at* them.

Every other module in this product asks "what does the operator own that they forgot
about?". This one inverts it: what has *somebody else* registered that looks like the
operator, and is therefore positioned to phish their staff and operators?

The generator is a set of the mutations real phishing operators use — character swaps,
adjacent-key typos, homoglyphs, hyphenation, and lookalike TLDs. Generation is pure and
bounded; the pipeline then resolves each candidate and only reports the ones that exist.
An unregistered lookalike is not news. A registered one with a mail server is.

Detection-only, and notably *not* about the operator's own infrastructure: we resolve
third-party names, which is the same public DNS anyone can query.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.severity import Severity

#: Physically adjacent keys on a QWERTY keyboard — the source of real typos.
_ADJACENT: dict[str, str] = {
    "a": "qwsz",
    "b": "vghn",
    "c": "xdfv",
    "d": "serfcx",
    "e": "wsdr",
    "f": "drtgvc",
    "g": "ftyhbv",
    "h": "gyujnb",
    "i": "ujko",
    "j": "huikmn",
    "k": "jiolm",
    "l": "kop",
    "m": "njk",
    "n": "bhjm",
    "o": "iklp",
    "p": "ol",
    "q": "wa",
    "r": "edft",
    "s": "awedxz",
    "t": "rfgy",
    "u": "yhji",
    "v": "cfgb",
    "w": "qase",
    "x": "zsdc",
    "y": "tghu",
    "z": "asx",
    "0": "o9",
    "1": "l2",
    "2": "13",
    "3": "24",
    "5": "s46",
    "9": "0o",
}

#: Characters that look alike in a browser address bar.
_HOMOGLYPHS: dict[str, tuple[str, ...]] = {
    "o": ("0",),
    "0": ("o",),
    "l": ("1", "i"),
    "1": ("l", "i"),
    "i": ("1", "l"),
    "e": ("3",),
    "a": ("4",),
    "s": ("5",),
    "g": ("9", "q"),
    "b": ("6",),
    "rn": ("m",),
    "m": ("rn",),
    "vv": ("w",),
    "w": ("vv",),
    "cl": ("d",),
}

#: TLDs phishers reach for: cheap, or one keystroke from the real one.
_LOOKALIKE_TLDS: tuple[str, ...] = (
    "com",
    "net",
    "org",
    "co",
    "cm",
    "om",
    "io",
    "info",
    "biz",
    "online",
    "site",
    "xyz",
    "top",
    "shop",
    "app",
    "cloud",
    "live",
    "click",
    "link",
    "help",
    "support",
    "security",
    "login",
    "email",
)

#: Words prepended/appended to build a credible-looking brand domain.
_BRAND_WORDS: tuple[str, ...] = (
    "secure",
    "login",
    "account",
    "verify",
    "support",
    "mail",
    "portal",
    "auth",
    "billing",
    "update",
    "my",
    "app",
    "web",
    "help",
    "signin",
)

#: Hard cap. Permutation space is combinatorial; this bounds DNS work per run.
MAX_CANDIDATES = 600


@dataclass(frozen=True)
class Lookalike:
    """A registered domain that impersonates the operator's."""

    domain: str
    technique: str  # how it was derived — shown to the user so the result is checkable
    resolved_ips: tuple[str, ...] = ()
    has_mx: bool = False

    @property
    def severity(self) -> Severity:
        # A lookalike that can *receive mail* is a phishing campaign with the plumbing
        # already installed; one that merely resolves may just be a squatter parking it.
        return Severity.HIGH if self.has_mx else Severity.MEDIUM

    @property
    def evidence(self) -> str:
        where = ", ".join(self.resolved_ips[:4]) or "no A record"
        mail = (
            "It also has MX records, so it can send and receive email that appears to "
            "come from a domain your staff and operators will read as yours."
            if self.has_mx
            else "No MX records were found, so it is not currently set up for email."
        )
        return (
            f"{self.domain} is registered and resolving ({where}). It was derived from "
            f"your domain by {self.technique}. {mail}"
        )


def _split(domain: str) -> tuple[str, str]:
    """``(name, tld)`` — TLD is everything after the first dot, so co.uk survives."""
    domain = domain.strip().lower().strip(".")
    if "." not in domain:
        return domain, "com"
    name, _, tld = domain.partition(".")
    return name, tld


def generate(domain: str, *, limit: int = MAX_CANDIDATES) -> list[tuple[str, str]]:
    """``(candidate_domain, technique)`` pairs for *domain*, deduped and bounded.

    The technique string travels with the candidate all the way to the UI — a user
    seeing "exarnple.com" should be told it came from a homoglyph substitution, not
    left to work out why we're showing it to them.
    """
    name, tld = _split(domain)
    if not name:
        return []

    out: dict[str, str] = {}

    def add(candidate: str, technique: str) -> None:
        candidate = candidate.strip(".").lower()
        if candidate and candidate != f"{name}.{tld}" and candidate not in out:
            out[candidate] = technique

    # 1. Omission — a dropped character.
    for i in range(len(name)):
        add(f"{name[:i]}{name[i + 1 :]}.{tld}", "omitting a character")

    # 2. Repetition — a doubled character.
    for i, ch in enumerate(name):
        add(f"{name[:i]}{ch}{ch}{name[i:]}.{tld}", "doubling a character")

    # 3. Transposition — two adjacent characters swapped.
    for i in range(len(name) - 1):
        add(f"{name[:i]}{name[i + 1]}{name[i]}{name[i + 2 :]}.{tld}", "swapping two letters")

    # 4. Adjacent-key typo.
    for i, ch in enumerate(name):
        for near in _ADJACENT.get(ch, ""):
            add(f"{name[:i]}{near}{name[i + 1 :]}.{tld}", "a neighbouring-key typo")

    # 5. Homoglyph — looks identical at a glance.
    for src, repls in _HOMOGLYPHS.items():
        start = 0
        while (idx := name.find(src, start)) != -1:
            for repl in repls:
                add(f"{name[:idx]}{repl}{name[idx + len(src) :]}.{tld}", "a homoglyph substitution")
            start = idx + 1

    # 6. Hyphenation.
    for i in range(1, len(name)):
        add(f"{name[:i]}-{name[i:]}.{tld}", "inserting a hyphen")

    # 7. Different TLD, same name.
    for alt in _LOOKALIKE_TLDS:
        if alt != tld:
            add(f"{name}.{alt}", "the same name on a different TLD")

    # 8. Brand-word prefix/suffix — the "secure-acme.com" pattern.
    for word in _BRAND_WORDS:
        add(f"{word}-{name}.{tld}", f"prefixing '{word}'")
        add(f"{name}-{word}.{tld}", f"appending '{word}'")

    return list(out.items())[:limit]
