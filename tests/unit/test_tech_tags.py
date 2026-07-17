"""Detected-tech → Nuclei tag selection (§7, engine quality).

The value is targeted coverage on the safe (HTTP-only) scan: a WordPress or Jenkins
host gets its relevant templates without widening to the full library. The two
non-obvious properties pinned here are (1) it only ever ADDS tags — it can never
remove the safe baseline or the harmful-tag exclusion — and (2) domain-name inference
catches a product hidden behind a reverse proxy, which is exactly how exposed panels
dodge fingerprinting.
"""

from __future__ import annotations

from core.tech_tags import nuclei_tags_for


def test_detected_tech_maps_to_product_tags():
    tags = nuclei_tags_for(["WordPress 6.1", "PHP", "nginx"])
    assert "wordpress" in tags
    assert "php" in tags
    assert "nginx" in tags


def test_unknown_tech_yields_nothing():
    """A tech with no mapping must contribute no tags — the caller then runs its
    baseline unchanged, never a widened set."""
    assert nuclei_tags_for(["SomeBespokeInHouseThing"]) == set()
    assert nuclei_tags_for([], []) == set()


def test_hostname_infers_tech_behind_a_reverse_proxy():
    """httpx sees only nginx in front of kibana.example.com; the name gives it away.
    This is the highest-value case — an exposed panel that fingerprinting misses."""
    tags = nuclei_tags_for(technologies=["nginx"], hosts=["kibana.internal.example.com"])
    assert "kibana" in tags


def test_hint_and_detected_tech_combine():
    tags = nuclei_tags_for(["WordPress"], ["grafana.example.com"])
    assert {"wordpress", "grafana"} <= tags


def test_matching_is_case_insensitive_and_substring():
    assert "jenkins" in nuclei_tags_for(["Jenkins"])
    assert "gitlab" in nuclei_tags_for(["GitLab Enterprise Edition"])


def test_a_short_or_empty_tech_does_not_false_match():
    """Guards against a 1-char tech token matching a map key as a substring."""
    assert nuclei_tags_for([""], []) == set()
    assert nuclei_tags_for(["a"], []) == set()
