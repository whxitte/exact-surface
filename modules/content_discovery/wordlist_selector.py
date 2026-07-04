"""Tech-aware wordlist selection (module 17, §7 Phase D).

The spec calls this out specifically: content discovery must pick its wordlist from
the fingerprinted tech (WordPress → wp lists, nginx → nginx list, generic → raft).
A focused wordlist finds real paths faster and generates far less noise/traffic than
blasting a giant generic list at every target.
"""

from __future__ import annotations

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
    """Return the best wordlist for the given tech list, else the generic default."""
    for item in tech or []:
        product, _ = parse_tech(item)
        if product in _BY_PRODUCT:
            return _BY_PRODUCT[product]
    return DEFAULT_WORDLIST
