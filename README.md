# NetFlow MCP Server for Meraki MX

A self-hosted NetFlow v9 collector that exposes network traffic analysis to [Claude.ai](https://claude.ai) via the [Model Context Protocol (MCP)](https://modelcontextprotocol.io). Ask Claude questions about your network in plain English.

## Architecture

```
Meraki MX --UDP 2055--> [ingestor] --SQLite WAL--> flows.db <-- [mcp-netflow]
                                                                      |
                                                                [cloudflared]
                                                                      |
                                                               Claude.ai connector
```

| Container | Purpose |
|-----------|---------|
| `ingestor` | goflow2 subprocess + GeoIP enrichment, writes to SQLite |
| `mcp-netflow` | MCP server with OAuth 2.0, reads from SQLite |
| `geoipupdate` | Weekly MaxMind GeoLite2 database updates |
| `cloudflared` | Cloudflare Tunnel for HTTPS access |

## Prerequisites

- Linux server on the same LAN as your Meraki MX
- [Docker](https://docs.docker.com/engine/install/) and Docker Compose
- [Meraki Dashboard](https://dashboard.meraki.com) access (to enable NetFlow export)
- [MaxMind](https://www.maxmind.com/en/geolite2/signup) account (free GeoLite2 license)
- [Cloudflare](https://dash.cloudflare.com) account (for Tunnel)
- [Claude.ai](https://claude.ai) Pro or Team account (for MCP connectors)

## Quick Start

### 1. Clone and configure

```bash
git clone https://github.com/crwickha/netflow-mcp-server.git
cd netflow-mcp-server
cp .env.example .env
```

Edit `.env` with your credentials. Generate OAuth secrets:

```bash
# Generate OAuth client ID and secret
openssl rand -hex 32   # use as OAUTH_CLIENT_ID
openssl rand -hex 32   # use as OAUTH_CLIENT_SECRET
```

### 2. Configure Meraki NetFlow export

In Meraki Dashboard:
1. Navigate to **Network-wide > Configure > General > Reporting**
2. Enable **NetFlow**
3. Set **Collector IP** to your Docker host's LAN IP
4. Set **Port** to `2055`

### 3. Set up Cloudflare Tunnel

1. Go to [Cloudflare Zero Trust](https://one.dash.cloudflare.com) > Networks > Tunnels
2. Create a tunnel pointing to `http://mcp-netflow:3000`
3. Copy the tunnel token into your `.env`

### 4. Prepare storage

```bash
sudo mkdir -p /mnt/netflow-data
```

For production, use a dedicated disk:

```bash
sudo mkfs.ext4 /dev/sdb1
echo '/dev/sdb1 /mnt/netflow-data ext4 defaults,nofail 0 2' | sudo tee -a /etc/fstab
sudo mount -a
```

### 5. Launch

```bash
docker compose build
docker compose up -d
```

Verify:

```bash
docker compose ps                    # all 4 containers running
docker compose logs -f ingestor      # flow ingestion
docker compose logs -f mcp-netflow   # MCP server ready
```

### 6. Connect to Claude.ai

1. Go to Claude.ai > Settings > Connectors
2. Add a new MCP connector
3. Enter your Cloudflare Tunnel URL
4. Enter the OAuth client ID and secret from your `.env`
5. Complete the OAuth authorization flow

## MCP Tools

Once connected, Claude has access to 10 analysis tools:

| Tool | What it does |
|------|-------------|
| `get_network_deep_dive` | Broad analysis: top talkers, destinations, countries, anomalies, rare ports |
| `get_sample_flows` | Raw flow drill-down with filters (IP, port, protocol) |
| `get_host_profile` | Behavioral profile for a single IP |
| `detect_beaconing` | C2 beaconing detection via interval regularity analysis |
| `get_geoip_context` | Everything known about an external IP |
| `get_time_window` | Traffic summary for an exact timestamp range |
| `get_baseline_delta` | Compare current vs prior period, spot changes |
| `get_baseline` | Statistical baseline profile (avg, stddev, p95) |
| `check_baseline_deviation` | Compare last 24h against baseline using z-scores |
| `get_collector_health` | Collector status, flow counts, DB size |

### Example prompts

- *"Give me an overview of my network traffic for the last 7 days"*
- *"Check for any C2 beaconing patterns in the last 24 hours"*
- *"Is anything abnormal right now compared to baseline?"*
- *"Profile the behavior of 192.168.1.100 over the last week"*
- *"What do we know about IP 185.220.101.1?"*

## Common Operations

```bash
# Rebuild after code changes
docker compose build mcp-netflow && docker compose up -d mcp-netflow

# View logs
docker compose logs -f

# Restart ingestor (after GeoIP database update)
docker compose restart ingestor

# Stop everything
docker compose down
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| No flows arriving | Check Meraki config, firewall allows UDP 2055 to Docker host |
| GeoIP fields are null | Verify mmdb files exist in `/mnt/netflow-data`, restart ingestor |
| OAuth errors | Ensure client ID/secret match between `.env` and Claude.ai connector |
| SQLite locked | Both containers need read-write access to `/mnt/netflow-data` |
| Baselines empty | Needs 2+ days of data before baselines populate |

## Blog Post

See [docs/blog-post.md](docs/blog-post.md) for the full writeup on building and deploying this system.

## License

MIT
