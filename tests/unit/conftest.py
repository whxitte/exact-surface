"""Unit tests must not touch the network.

Why this exists
---------------
Three consecutive CI-only failures came from unit tests quietly reaching the internet:
they passed on a developer laptop with open egress and failed, hung, or went
non-deterministic on a runner without it. The worst of them was
``test_data_found_before_the_stop_is_kept``, where an un-injected crt.sh call took 45
seconds, which changed how many times a *polling* cancel check fired, which changed
what the test observed. Nothing in the failure pointed at the network.

A unit test that reaches the network is wrong regardless of whether it passes: it is
slow, it depends on a third party's uptime, and -- as above -- its timing can silently
alter the behaviour under test. So make it fail immediately and say why, instead of
leaving the next person to decode a 45-second hang.

Loopback is still allowed: local fakes and any test binding an ephemeral port are
legitimate and involve no third party. Integration and e2e tests are unaffected -- this
conftest applies to ``tests/unit`` only.
"""

from __future__ import annotations

import socket

import pytest

_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", ""}


def _is_loopback(address) -> bool:
    if not isinstance(address, tuple) or not address:
        return False
    host = address[0]
    if host in _ALLOWED_HOSTS:
        return True
    import ipaddress

    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@pytest.fixture(autouse=True)
def _no_outbound_network(monkeypatch):
    """Fail any unit test that opens a non-loopback connection."""
    real_connect = socket.socket.connect
    real_getaddrinfo = socket.getaddrinfo

    def guarded_connect(self, address, *args, **kwargs):
        if not _is_loopback(address):
            raise RuntimeError(
                f"unit test attempted a network connection to {address!r}. Inject a fake "
                "for whatever makes this call -- unit tests must not depend on the "
                "internet. See tests/unit/conftest.py."
            )
        return real_connect(self, address, *args, **kwargs)

    def guarded_getaddrinfo(host, port, *args, **kwargs):
        if host not in _ALLOWED_HOSTS and not _is_loopback((host, port)):
            raise RuntimeError(
                f"unit test attempted to resolve {host!r}. Inject a fake for whatever "
                "makes this call -- unit tests must not depend on DNS. "
                "See tests/unit/conftest.py."
            )
        return real_getaddrinfo(host, port, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)
    yield
