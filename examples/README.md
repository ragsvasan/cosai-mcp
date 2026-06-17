# cosai-mcp examples

Two minimal, runnable MCP servers you can scan with `cosai scan` to see real
findings in under a minute.

> **WARNING — these servers are intentionally insecure.**
> They deliberately violate CoSAI threat controls (raw shell command execution,
> prompt-injection-laden tool descriptions) so the scanner has something to find.
> They are for **local testing only** — never deploy them or expose them to a
> network.

## What's baked in

Each server ships two deliberately vulnerable tools:

| Tool | CoSAI threat | Why it's vulnerable |
|------|--------------|---------------------|
| `run_command` | **T3** Input Validation | Passes a raw `cmd` string to the shell (`shell=True`) — command injection. |
| `read_notes` | **T4** Data/Control Boundary | Tool description embeds adversarial "ignore previous instructions" text — tool poisoning / indirect prompt injection. |

## FastMCP server

```bash
pip install fastmcp
python examples/fastmcp/server.py
```

Listens on **http://127.0.0.1:8000** (Streamable HTTP, path `/mcp`). Scan it:

```bash
cosai scan http://127.0.0.1:8000
```

## FastAPI server

```bash
pip install fastapi uvicorn
python examples/fastapi-mcp/server.py
```

Listens on **http://127.0.0.1:8001** (Streamable HTTP, path `/mcp`). Scan it:

```bash
cosai scan http://127.0.0.1:8001
```

## Notes

- FastMCP / FastAPI / uvicorn are **not** declared as cosai-mcp dependencies —
  install them only if you want to run these demo servers (see `pip install`
  lines above).
- The scanner talks **to** these servers over JSON-RPC; it does not import them.
- Expect findings under **T3** and **T4** from the black-box prober. Run with
  `--fail-on critical` to see the CI gate behavior.
