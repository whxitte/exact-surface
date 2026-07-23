"""Vendor control-plane (§ commercial / self-hosted).

The ONLY thing the vendor hosts. Customer instances run everything else in their own
infra and phone home to these two tiny, stateless endpoints:

* ``/v1/license/refresh`` — renews a subscription token (recurring enforcement).
* ``/v1/updates/manifest`` — the license-gated update feed (freshness enforcement).

Both are gated on the license: a lapsed/suspended customer gets neither a renewal nor
new detections, which is what makes a self-hosted subscription actually enforceable.
The heavy data-plane (scanning, DB, findings) never touches the vendor.
"""
