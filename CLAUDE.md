# NetFlow MCP Server

NetFlow v9 collector + MCP server for Meraki MX traffic analysis, exposed to Claude.ai as a connector via OAuth 2.0.

## Architecture

Everything runs in Docker containers on the same LAN as the Meraki MX devices. Cloudflare Tunnel provides external HTTPS access (no local SSL certs needed).

```
Meraki MX --UDP 2055--> [ingestor] --SQLite WAL--> /mnt/netflow-data/flows.db <--reads-- [mcp-netflow]
                                                                                    |
                                                                              [cloudflared]
                                                                                    |
                                                                           Claude.ai connector
```

### Containers

| Service | Container Name | Build Context | Port | Purpose |
|---------|---------------|---------------|------|---------|
| `ingestor` | `netflow-ingestor` | `./ingestor` | 2055/udp (host) | goflow2 subprocess, GeoIP enrichment, writes to SQLite |
| `mcp-netflow` | `netflow-mcp` | `./mcp-server` | 3000 (internal) | MCP server with OAuth 2.0, reads from SQLite |
| `geoipupdate` | `netflow-geoipupdate` | `ghcr.io/maxmind/geoipupdate` | none | Weekly GeoIP database updates from MaxMind |
| `cloudflared` | `netflow-cloudflared` | `cloudflare/cloudflared` | none | Cloudflare Tunnel, points at `http://mcp-netflow:3000` |

**Important:** The Docker Compose service name is `mcp-netflow` but the build directory is `./mcp-server`. These intentionally differ — the service name is what other containers use for DNS, the build path is just the directory on disk.

### Shared Volume

`/mnt/netflow-data` is a dedicated 100G ext4 volume (Proxmox secondary disk `/dev/sdb1`, mounted via fstab with `nofail`). It is bind-mounted to `/data` in both ingestor and mcp-netflow, and to `/usr/share/GeoIP` in geoipupdate. Contains:
- `flows.db` — SQLite database (WAL mode, both services need read-write)
- `token_store.json` — OAuth token persistence
- `GeoLite2-ASN.mmdb` — MaxMind ASN database (auto-updated by geoipupdate container)
- `GeoLite2-Country.mmdb` — MaxMind Country database (auto-updated by geoipupdate container)

## Key Files

```
docker-compose.yml          — 4 services, no nginx
.env                        — TZ only (secrets are inline in compose)
ingestor/
  Dockerfile                — python:3.12-slim + goflow2 v2.2.6 binary
  requirements.txt          — geoip2, maxminddb
  ingestor.py               — goflow2 subprocess, GeoIP cache, batch SQLite writes
mcp-server/
  Dockerfile                — python:3.12-slim + aiohttp
  requirements.txt          — aiohttp only
  server.py                 — MCP server (~600 lines): 8 tools + OAuth 2.0 + JSON-RPC
```

## MCP Server (server.py)

### Auth Pattern
Uses raw aiohttp + JSON-RPC (NOT FastMCP) to match the OAuth 2.0 Authorization Code + PKCE pattern required by Claude.ai connectors. Copied from the Meraki MCP server pattern (`meraki_mcp_server_enhanced_SAMPLE.py`).

OAuth endpoints:
- `GET /.well-known/oauth-protected-resource`
- `GET /.well-known/oauth-authorization-server`
- `GET /authorize`
- `POST /oauth/token`

MCP endpoint: `POST /mcp` (Bearer token required)

`get_server_url()` constructs OAuth URLs from `X-Forwarded-Proto` (defaults to `https`) and `X-Forwarded-Host` headers. Cloudflare sets these.

### Environment Variables
- `OAUTH_CLIENT_ID` — must match what's configured in Claude.ai connector
- `OAUTH_CLIENT_SECRET` — validated during token exchange
- `TOKEN_STORE_PATH` — defaults to `/data/token_store.json`

### Tools (10 total)
All tools are plain functions returning JSON strings. Defined as dicts in `TOOLS` list with `name`/`description`/`inputSchema`. Dispatched via `TOOL_MAP` dict in `execute_tool()`.

1. `get_network_deep_dive` — broad analysis: top talkers, destinations, countries, anomalies, rare ports, new destinations (max 14 days)
2. `get_sample_flows` — raw flow drill-down with filters (max 500 rows)
3. `get_host_profile` — behavioral profile for a single IP
4. `detect_beaconing` — C2 beaconing detection via interval regularity analysis
5. `get_geoip_context` — everything known about an external IP
6. `get_time_window` — traffic summary for an exact timestamp range
7. `get_baseline_delta` — compare current vs prior period, spot changes (simple pct-based)
8. `get_baseline` — return stored statistical baseline profile (avg, stddev, p95 per day) for 7d/14d/30d across network total, per-host, per-port, per-country
9. `check_baseline_deviation` — compare last 24h against stored baseline using z-scores; returns severity ratings (normal/notable/anomalous), new items, and disappearances
10. `get_collector_health` — collector status, flow counts, DB size

### Adding a New Tool
1. Add a dict to `TOOLS` list with `name`, `description`, `inputSchema`
2. Write a plain function that returns `json.dumps(result)`
3. Add the function to `TOOL_MAP` dict

## Ingestor (ingestor.py)

- Launches `goflow2` as a subprocess listening on UDP 2055
- Reads JSON lines from goflow2's stdout
- Enriches with GeoIP (ASN + Country) using a 50k-entry cache
- Batch-writes to SQLite every 100 flows
- Background thread runs hourly: rebuilds `hourly_summary` table, purges flows older than 30 days
- GeoIP databases are optional — if missing, country/org fields will be null
- GeoIP mmdb files are loaded once at startup. After geoipupdate refreshes the files, restart the ingestor to pick up the new databases (`docker compose restart ingestor`)

### SQLite Schema
- `flows` — raw flow records with GeoIP enrichment, indexed on ts/src_addr/dst_addr/dst_port/dst_country/dst_is_private
- `hourly_summary` — pre-aggregated hourly rollups (rebuilt hourly from raw flows)
- `baselines` — statistical baseline profiles (avg, stddev, p95) per dimension (network_total, host, port, country) for 7d/14d/30d periods, rebuilt hourly from hourly_summary
- `known_destinations` — tracks first/last seen per destination (used for "newly seen" detection)

## Common Operations

```bash
# Build
docker compose build

# Start all
docker compose up -d

# View logs
docker compose logs -f
docker compose logs -f ingestor    # just ingestor
docker compose logs -f mcp-netflow # just MCP server

# Restart after code changes
docker compose build mcp-netflow && docker compose up -d mcp-netflow

# Check health
curl http://localhost:3000/health   # from host (only if port is exposed)

# Stop
docker compose down
```

## GeoIP Updates

The `geoipupdate` container (MaxMind's official image) automatically downloads fresh GeoLite2-ASN and GeoLite2-Country databases every 168 hours (weekly). It writes to `/mnt/netflow-data/` which is mapped to `/usr/share/GeoIP` in the container. MaxMind account credentials are configured inline in `docker-compose.yml`.

The ingestor loads mmdb files at startup and caches lookups in memory. After a geoipupdate refresh, restart the ingestor to use the new databases. Existing flows in the DB are not retroactively re-enriched.

## Gotchas

- SQLite WAL mode requires **both** services to have read-write access to `/mnt/netflow-data`. Don't mount as read-only for mcp-netflow.
- goflow2 binary is pinned to v2.2.6. The release asset name format is `goflow2-{version}-linux-amd64` (not `goflow2_linux_amd64`).
- Token store is in-memory + file-backed. If the container restarts, existing tokens are reloaded from `token_store.json`. Authorization codes are in-memory only (ephemeral, 10-minute TTL).
- The `X-Forwarded-Proto` default is `https` (assumes Cloudflare Tunnel). If testing locally without the tunnel, OAuth URL construction will use `https://localhost` which won't work. For local testing, hit `http://localhost:3000` directly.
