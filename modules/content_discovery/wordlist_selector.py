"""Tech-aware wordlist selection (module 17, §7 Phase D).

The spec calls this out specifically: content discovery must pick its wordlist from
the fingerprinted tech (WordPress → wp lists, nginx → nginx list, generic → raft).
A focused wordlist finds real paths faster and generates far less noise/traffic than
blasting a giant generic list at every target.
"""

from __future__ import annotations

import os

from core.cpe import parse_tech

DEFAULT_WORDLIST = "raft-medium-directories.txt"

_BY_PRODUCT = {
    "wordpress": "wp-common.txt",
    "drupal": "drupal.txt",
    "joomla": "joomla.txt",
    "nginx": "nginx.txt",
    "apache": "apache.txt",
    "tomcat": "tomcat.txt",
    "iis": "iis.txt",
}


def select_wordlist(tech: list[str]) -> str:
    """Return the best wordlist *name* for the given tech list, else the generic
    default. Names are logical; :func:`wordlist_path` resolves them to real files."""
    for item in tech or []:
        product, _ = parse_tech(item)
        if product in _BY_PRODUCT:
            return _BY_PRODUCT[product]
    return DEFAULT_WORDLIST


def wordlist_base() -> str:
    from core.config import get_settings

    return get_settings().wordlist_dir


def wordlist_path(name: str) -> str:
    """Resolve a logical wordlist name to an absolute file path under the wordlist
    dir. Falls back to the default list if the tech-specific one isn't installed;
    returns the default's path even if that too is missing (the caller warns)."""
    base = wordlist_base()
    specific = os.path.join(base, name)
    if os.path.exists(specific):
        return specific
    return os.path.join(base, DEFAULT_WORDLIST)


def wordlists_installed() -> bool:
    """True if the default wordlist exists (content discovery can run)."""
    return os.path.exists(os.path.join(wordlist_base(), DEFAULT_WORDLIST))
