# RenderCV MCP Server

MCP server that renders CVs from YAML via claude.ai. Built on [mcp-oauth-template](https://github.com/5queezer/mcp-oauth-template).

## MCP Tools

- **render_cv** — YAML in, PDF + PNG preview out
- **validate_cv** — Check YAML without rendering
- **list_themes** — Available themes (classic, ember, harvard, ...)
- **get_example** — Full example YAML for any theme

## Run locally

```bash
pip install -r requirements.txt
uvicorn server:app --reload --port 8080
```

## Deploy (Coolify)

Push to GitHub, add as Docker Compose resource in Coolify with domain `cv.vasudev.xyz`.

## Connect in claude.ai

Settings → Integrations → Add MCP Server → URL: `https://cv.vasudev.xyz/mcp`
