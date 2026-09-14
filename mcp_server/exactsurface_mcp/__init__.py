"""ExactSurface MCP server: an agent's window onto attack-surface data.

A thin process over the REST API, authenticating with one scoped API key. Every
control the API enforces — scopes, human-only actions, the scope engine, tenant
isolation — applies unchanged; this package adds nothing and can remove nothing.
"""

__version__ = "0.1.0"
