"""PDF report (module 31) — renders the HTML report to PDF.

The renderer is injected (tests pass a fake; production uses WeasyPrint, which is
installed in the pipeline image). Kept behind an interface so the heavy native
dependency is never required just to import the reporting package.
"""

from __future__ import annotations

from collections.abc import Callable

Renderer = Callable[[str], bytes]


def _default_renderer(html: str) -> bytes:  # pragma: no cover - needs weasyprint + native libs
    from weasyprint import HTML

    return HTML(string=html).write_pdf()


def render_pdf(html: str, *, renderer: Renderer | None = None) -> bytes:
    return (renderer or _default_renderer)(html)
