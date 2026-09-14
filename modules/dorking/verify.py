"""Verify a search-engine hit against the page it points at.

A dork is a *lead*, not a finding. Search engines stem words, drop punctuation and
match OR-groups loosely, so ``site:x "password="`` happily returns a terms-of-service
page that says "we protect your password" — and rating that at the query's category
severity produced two "critical" findings on a public ToS. Every other module in this
product fetches the thing and shows the request; this makes dorking do the same.

Pure: query parsing and matching only. The fetch is injected by the pipeline.
"""

from __future__ import annotations

import html
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from urllib.parse import urlparse

Fetch = Callable[[str], Awaitable[str]]

_TOKEN = re.compile(r'(\w+):"([^"]+)"|(\w+):(\S+)|"([^"]+)"|(\S+)')
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


@dataclass(frozen=True)
class Constraints:
    """What a dork actually asserts about a page. Each tuple is an OR-group: one match
    from each non-empty group is required, which is how a query like
    ``ext:pem OR ext:key`` reads."""

    ext: tuple[str, ...] = ()
    inurl: tuple[str, ...] = ()
    intitle: tuple[str, ...] = ()
    phrases: tuple[str, ...] = ()

    @property
    def needs_page(self) -> bool:
        return bool(self.intitle or self.phrases)

    @property
    def is_empty(self) -> bool:
        return not (self.ext or self.inurl or self.intitle or self.phrases)


@dataclass(frozen=True)
class Verification:
    #: True: the page bears out the dork. False: it does not — the engine fuzzed.
    #: None: it could not be checked (fetch failed), so nothing is known either way.
    verified: bool | None
    evidence: str = ""
    #: the token that matched, for a reproduction the user can run themselves
    matched: str = ""


def parse_query(query: str) -> Constraints:
    """Read the operators out of a dork. ``site:`` is scoping, not an assertion, and
    is dropped; ``OR`` is the separator inside a group and is dropped too."""
    ext: list[str] = []
    inurl: list[str] = []
    intitle: list[str] = []
    phrases: list[str] = []
    for m in _TOKEN.finditer(query):
        op_q, val_q, op, val, phrase, bare = m.groups()
        if op_q:
            op, val = op_q, val_q
        if op:
            op = op.lower()
            if op == "site":
                continue
            if op == "ext" or op == "filetype":
                ext.append(val.lower().lstrip("."))
            elif op == "inurl":
                inurl.append(val.lower())
            elif op == "intitle":
                intitle.append(val.lower())
            continue
        if phrase:
            phrases.append(phrase.lower())
            continue
        if bare and bare.upper() != "OR":
            # An unquoted bare word: treat as a body phrase too.
            phrases.append(bare.lower())
    return Constraints(tuple(ext), tuple(inurl), tuple(intitle), tuple(phrases))


def check_url(c: Constraints, url: str) -> bool | None:
    """The structural constraints, decidable from the URL alone. ``None`` when the
    dork has none."""
    if not (c.ext or c.inurl):
        return None
    u = urlparse(url)
    path = (u.path or "").lower()
    whole = url.lower()
    if c.ext and not any(path.endswith("." + e) for e in c.ext):
        return False
    if c.inurl and not any(s in whole for s in c.inurl):
        return False
    return True


def _context(text: str, needle: str, width: int = 60) -> str:
    i = text.lower().find(needle.lower())
    if i < 0:
        return ""
    start, end = max(0, i - width), min(len(text), i + len(needle) + width)
    return re.sub(r"\s+", " ", text[start:end]).strip()


def check_page(c: Constraints, body: str) -> Verification:
    """The content constraints, against a fetched page. Literal, case-insensitive
    substring match — the thing the search engine did not do."""
    text = html.unescape(body)
    lowered = text.lower()
    if c.intitle:
        m = _TITLE.search(text)
        title = html.unescape(m.group(1)).lower() if m else ""
        hit = next((t for t in c.intitle if t in title), None)
        if hit is None:
            return Verification(False, evidence=f"title is {title[:80]!r}")
        if not c.phrases:
            return Verification(True, evidence=f"title: {title[:120]}", matched=hit)
    if c.phrases:
        hit = next((p for p in c.phrases if p in lowered), None)
        if hit is None:
            return Verification(
                False, evidence="page does not contain any of: " + ", ".join(c.phrases)
            )
        return Verification(True, evidence=_context(text, hit), matched=hit)
    return Verification(True)


async def verify_hit(query: str, url: str, fetch: Fetch) -> Verification:
    """Decide whether *url* really bears out *query*.

    Structural operators are checked on the URL with no request. Content operators
    need the page; a fetch that fails or returns nothing is ``None`` — unknown, not
    false — so a rate-limited or blocked page is not mistaken for a clean one.
    """
    c = parse_query(query)
    if c.is_empty:
        return Verification(None, evidence="dork has no verifiable operator")
    structural = check_url(c, url)
    if structural is False:
        return Verification(False, evidence="URL does not match the dork's ext:/inurl: constraint")
    if not c.needs_page:
        return Verification(
            True, evidence="URL matches the dork's structural constraint", matched=url
        )
    try:
        body = await fetch(url)
    except Exception as exc:  # noqa: BLE001 - unknown, and say why
        return Verification(None, evidence=f"could not fetch page: {type(exc).__name__}")
    if not body:
        return Verification(None, evidence="page returned no content")
    return check_page(c, body)
