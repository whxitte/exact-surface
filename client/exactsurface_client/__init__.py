"""ExactSurface from outside: the CLI and the MCP server.

Both are thin clients over the REST API, authenticating with one scoped API key.
Every control the API enforces — scopes, human-only actions, the scope engine,
tenant isolation — applies unchanged; this package adds nothing and can remove
nothing. `exactsurface` is for people and CI; `exactsurface-mcp` is for agents.
"""

__version__ = "1.4.0"
