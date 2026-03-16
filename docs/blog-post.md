# Give Claude Eyes on Your Network: A NetFlow MCP Server for Meraki MX

What if you could ask an AI to analyze your network traffic in plain English?

Network telemetry — NetFlow, IPFIX, sFlow — is one of the richest data sources in any environment. It captures every conversation between every host: who talked to whom, on which port, how much data moved, and when. But extracting insights from it typically requires specialized tools, query languages, and deep domain expertise.

This post walks through building a self-hosted NetFlow v9 collector that exposes traffic data to [Claude.ai](https://claude.ai) via the [Model Context Protocol (MCP)](https://modelcontextprotocol.io). The result: you can ask Claude questions like "is anything abnormal on my network right now?" or "check for C2 beaconing in the last 24 hours" and get real answers backed by actual flow data.

By the end, you'll have a four-container Docker stack running on your LAN, ingesting flows from Meraki MX appliances, enriching them with GeoIP data, and serving them to Claude through a secure OAuth 2.0 tunnel.

---

## Architecture Overview

The system is four Docker containers on a single host, connected to the same LAN as the Meraki MX devices. Cloudflare Tunnel handles external HTTPS — no SSL certificates, no port forwarding.

```
┌──────────┐         ┌────────────────────────────────────────────────┐
│ Meraki   │  UDP    │  Docker Host                                   │
│ MX       │──2055──▶│  ┌───────────┐    SQLite    ┌──────────────┐   │
│          │         │  │ ingestor  │───(WAL)────▶ │ mcp-netflow  │   │
└──────────┘         │  │           │    flows.db  │              │   │
                     │  │ goflow2 + │              │ MCP Server   │   │
                     │  │ GeoIP     │              │ OAuth 2.0    │   │
                     │  └───────────┘              │ JSON-RPC     │   │
                     │                             └───────┬──────┘   │
                     │  ┌─────────────┐                    │          │
                     │  │ geoipupdate │  weekly mmdb       │          │
                     │  └─────────────┘  updates           │          │
                     │                              ┌──────┴───────┐  │
                     │                              │ cloudflared  │  │
                     │                              └──────┬───────┘  │
                     └─────────────────────────────────────┼──────────┘
                                                           │
                                                    Cloudflare Tunnel
                                                           │
                                                    ┌──────┴───────┐
                                                    │  Claude.ai   │
                                                    │  Connector   │
                                                    └──────────────┘
```

### Why these technologies?

| Component | Choice | Why |
|-----------|--------|-----|
| NetFlow decoder | [goflow2](https://github.com/netsampler/goflow2) | Lightweight single-binary, outputs JSON lines to stdout — easy to pipe into Python |
| Database | SQLite (WAL mode) | No separate server, built-in concurrent read/write, good enough for single-site deployments |
| MCP Server | aiohttp + raw JSON-RPC | Claude.ai connectors require OAuth 2.0 Authorization Code + PKCE — FastMCP doesn't support this pattern |
| Tunnel | Cloudflare Tunnel | Zero-config HTTPS with no certs to manage and no firewall ports to open |
| GeoIP | MaxMind GeoLite2 | Free tier, auto-updated weekly, adds country and ASN context to every flow |

### Container Summary

| Service | Container | Port | Role |
|---------|-----------|------|------|
| `ingestor` | `netflow-ingestor` | 2055/udp (host) | goflow2 subprocess, GeoIP enrichment, batch SQLite writes |
| `mcp-netflow` | `netflow-mcp` | 3000 (internal) | MCP server with OAuth 2.0, reads from SQLite |
| `geoipupdate` | `netflow-geoipupdate` | — | Weekly GeoLite2 database downloads |
| `cloudflared` | `netflow-cloudflared` | — | Cloudflare Tunnel to expose MCP server |

All four containers share a bind-mounted volume at `/mnt/netflow-data` (mapped to `/data` in the application containers). This holds the SQLite database, GeoIP databases, and OAuth token store.

<!-- Screenshot: docker compose ps showing all 4 containers -->

---

## Prerequisites

Before you start, you'll need:

- **A Linux server** on the same LAN as your Meraki MX (a VM works fine — this runs on a Proxmox VM with 2 cores and 4GB RAM)
- **Docker and Docker Compose** installed
- **Meraki Dashboard access** to enable NetFlow export on your MX
- **A MaxMind account** (free) — [sign up here](https://www.maxmind.com/en/geolite2/signup) for a GeoLite2 license key
- **A Cloudflare account** (free tier is sufficient) to create a Tunnel
- **A Claude.ai Pro or Team account** with access to MCP connectors
- **UDP 2055** open from the Meraki MX to the Docker host (usually just a LAN path, no firewall changes needed)

---

## Step-by-Step Deployment

### Step 1: Clone the repository

```bash
git clone https://github.com/crwickha/netflow-mcp-server.git
cd netflow-mcp-server
```

### Step 2: Configure Meraki NetFlow export

In the [Meraki Dashboard](https://dashboard.meraki.com):

1. Navigate to **Network-wide > Configure > General**
2. Scroll to **Reporting**
3. Enable **NetFlow**
4. Set the **Collector IP** to your Docker host's LAN IP address
5. Set the **Port** to `2055`

The Meraki MX will begin exporting NetFlow v9 templates and data packets to your collector. Template packets describe the field layout; data packets carry the actual flow records. goflow2 handles both automatically.

<!-- Screenshot: Meraki Dashboard NetFlow configuration page -->

### Step 3: Create a MaxMind account and get a license key

1. Sign up at [maxmind.com](https://www.maxmind.com/en/geolite2/signup) (free GeoLite2 tier)
2. Navigate to **Account > Manage License Keys**
3. Generate a new license key
4. Note your **Account ID** and **License Key** — you'll need these for the Docker Compose configuration

<!-- Screenshot: MaxMind license key page -->

### Step 4: Set up Cloudflare Tunnel

The Cloudflare Tunnel gives Claude.ai secure HTTPS access to the MCP server without exposing any ports on your firewall.

1. Log in to [Cloudflare Zero Trust](https://one.dash.cloudflare.com)
2. Go to **Networks > Tunnels**
3. Create a new tunnel
4. Set the service to `http://mcp-netflow:3000` (this is the Docker DNS name)
5. Assign a public hostname (e.g., `netflow.yourdomain.com`)
6. Copy the **tunnel token** — it's the long JWT string

<!-- Screenshot: Cloudflare Tunnel configuration -->

### Step 5: Prepare host storage

Create the shared data directory:

```bash
sudo mkdir -p /mnt/netflow-data
```

For production deployments, use a dedicated disk to isolate the database from the OS:

```bash
sudo mkfs.ext4 /dev/sdb1
echo '/dev/sdb1 /mnt/netflow-data ext4 defaults,nofail 0 2' | sudo tee -a /etc/fstab
sudo mount -a
```

Both the ingestor and MCP server need **read-write** access to this directory — SQLite WAL mode requires it on both ends.

### Step 6: Configure environment variables

Copy the example environment file and fill in your credentials:

```bash
cp .env.example .env
```

Generate your own OAuth client ID and secret:

```bash
openssl rand -hex 32   # → use as OAUTH_CLIENT_ID
openssl rand -hex 32   # → use as OAUTH_CLIENT_SECRET
```

Edit `.env`:

```ini
TZ=America/Vancouver

OAUTH_CLIENT_ID=<your-generated-client-id>
OAUTH_CLIENT_SECRET=<your-generated-client-secret>

TUNNEL_TOKEN=<your-cloudflare-tunnel-token>

GEOIPUPDATE_ACCOUNT_ID=<your-maxmind-account-id>
GEOIPUPDATE_LICENSE_KEY=<your-maxmind-license-key>
```

> **Security note:** Never use the example values in production. The OAuth client ID and secret are what prevent unauthorized access to your network data through Claude.ai.

### Step 7: Build and launch

```bash
docker compose build
docker compose up -d
```

Watch the startup:

```bash
docker compose logs -f
```

You should see:
- **ingestor**: `goflow2 started, listening on UDP 2055` followed by flow parsing output
- **mcp-netflow**: `MCP NetFlow server started on port 3000`
- **cloudflared**: tunnel connection established
- **geoipupdate**: initial database download (first run only)

Verify all containers are running:

```bash
docker compose ps
```

<!-- Screenshot: docker compose ps output -->
<!-- Screenshot: ingestor logs showing flow ingestion -->

### Step 8: Register as a Claude.ai MCP connector

1. Go to [Claude.ai](https://claude.ai) > **Settings** > **Connectors**
2. Click **Add Connector**
3. Enter your Cloudflare Tunnel URL (e.g., `https://netflow.yourdomain.com`)
4. Enter the OAuth client ID and secret from your `.env`
5. Complete the OAuth authorization flow in the browser popup

Once connected, Claude will have access to all 10 network analysis tools.

<!-- Screenshot: Claude.ai connector configuration -->
<!-- Screenshot: OAuth authorization flow -->
<!-- Screenshot: Successful connection -->

---

## The 10 MCP Tools

Each tool is designed for a specific analysis pattern. Claude chains them together automatically during investigations.

### 1. Network Deep Dive (`get_network_deep_dive`)

The starting point for most analyses. Returns a comprehensive overview including top talkers, external destinations with GeoIP, protocol breakdown, anomaly candidates, rare ports, newly seen destinations, and off-hours activity.

**Try asking Claude:**
> "Give me an overview of my network traffic for the last 7 days"

### 2. Sample Flows (`get_sample_flows`)

Raw flow drill-down. Filter by source IP, destination IP, destination port, or protocol. Returns up to 500 individual flow records with timestamps, bytes, packets, and GeoIP data.

**Try asking Claude:**
> "Show me the raw flows from 192.168.1.50 to port 443 in the last 24 hours"

### 3. Host Profile (`get_host_profile`)

Complete behavioral profile for a single IP: all destinations contacted, ports used, countries reached, inbound connections, and hourly activity patterns.

**Try asking Claude:**
> "Profile the behavior of 192.168.1.100 over the last week"

### 4. Beaconing Detection (`detect_beaconing`)

Identifies potential C2 (command-and-control) beaconing by analyzing connection interval regularity. A host connecting to the same external destination at suspiciously regular intervals (low coefficient of variation) gets flagged.

The algorithm:
1. Find all src→dst pairs with 6+ connections in the time window
2. Calculate the intervals between consecutive connections
3. Compute the coefficient of variation (stddev / mean)
4. Score: CV < 0.15 = HIGH suspicion, < 0.35 = MEDIUM, else LOW

**Try asking Claude:**
> "Check for any C2 beaconing patterns in the last 24 hours"

### 5. GeoIP Context (`get_geoip_context`)

Everything known about an external IP from flow data: country, ASN organization, all internal hosts that communicated with it, total bytes transferred, ports used, and first/last seen timestamps.

**Try asking Claude:**
> "What do we know about IP 185.220.101.1?"

### 6. Time Window Analysis (`get_time_window`)

Traffic summary for an exact Unix timestamp range. Useful for isolating a specific incident window — for example, the hour around a suspicious spike.

**Try asking Claude:**
> "Show me all traffic between 2am and 3am last Tuesday"

### 7. Baseline Delta (`get_baseline_delta`)

Compares the most recent N days against the equivalent prior period. Highlights hosts with significant traffic increases or decreases and identifies new hosts that appeared.

**Try asking Claude:**
> "Compare this week's traffic to last week"

### 8. Baseline Profile (`get_baseline`)

Returns the stored statistical baseline: daily average bytes, standard deviation, and 95th percentile for each dimension (network total, per-host, per-port, per-country) over 7, 14, or 30-day windows.

**Try asking Claude:**
> "What's the normal traffic baseline for the last 30 days?"

### 9. Baseline Deviation Check (`check_baseline_deviation`)

The "is anything weird right now?" tool. Compares the last 24 hours against the stored baseline using z-scores. Returns severity ratings (normal / notable / anomalous) for each dimension, plus newly appeared and disappeared items.

**Try asking Claude:**
> "Is anything abnormal right now compared to baseline?"

### 10. Collector Health (`get_collector_health`)

Operational check: total flows in the database, data retention range, flows received in the last 5 minutes, unique exporters, and database file size.

**Try asking Claude:**
> "Is the collector running and healthy?"

<!-- Screenshot: Claude answering a network deep dive question -->
<!-- Screenshot: Claude detecting beaconing patterns -->
<!-- Screenshot: Claude analyzing baseline deviations -->

---

## Real-World Use Cases

The real power shows when Claude chains multiple tools together in a single conversation.

### Security Investigation

> **You:** "I noticed unusual traffic overnight. Can you investigate?"

Claude will typically:
1. Call `get_network_deep_dive` to get the broad picture
2. Spot off-hours activity in the `off_hours_activity_0000_0500` section
3. Call `get_host_profile` on the suspicious host
4. Call `detect_beaconing` to check for C2 patterns
5. Call `get_geoip_context` on any suspicious external IPs
6. Provide a narrative summary with findings and recommendations

### Capacity Planning

> **You:** "How has our traffic changed compared to last month?"

Claude uses `get_baseline_delta` to identify growth trends, `get_baseline` to show what "normal" looks like, and highlights new services or hosts that have appeared.

### Incident Response

> **You:** "We got an alert about IP 203.0.113.50. What's our exposure?"

Claude calls `get_geoip_context` to understand the external IP, then `get_sample_flows` to see exactly which internal hosts communicated with it, when, and how much data moved.

### Daily Health Check

> **You:** "Give me a daily network health summary"

Claude checks `get_collector_health` to confirm the system is operational, runs `check_baseline_deviation` to surface anything abnormal, and summarizes the highlights from `get_network_deep_dive`.

<!-- Screenshot: Full multi-tool investigation conversation -->

---

## How It Works Under the Hood

### The Ingestor Pipeline

The ingestor container runs [goflow2](https://github.com/netsampler/goflow2) as a subprocess. goflow2 listens on UDP 2055, decodes NetFlow v9 packets, and writes JSON lines to stdout. The Python wrapper reads these lines, enriches each flow with GeoIP data, and batch-writes to SQLite.

```python
# Flow parsing — extract fields from goflow2 JSON output
def parse_flow(raw, geo):
    ts = int(raw.get("time_flow_start_ns", 0) / 1e9) or int(time.time())
    ts_end = int(raw.get("time_flow_end_ns", 0) / 1e9) or None
    src = raw.get("src_addr", "")
    dst = raw.get("dst_addr", "")
    dst_info = geo.lookup(dst)
    return (
        ts, ts_end, src, dst,
        raw.get("src_port"), raw.get("dst_port"),
        proto_name(raw.get("proto", 0)),
        raw.get("bytes", 0), raw.get("packets", 0),
        round((ts_end - ts), 2) if ts_end else None,
        str(raw.get("tcp_flags", "")),
        raw.get("sampler_address", ""),
        dst_info["country"], dst_info["org"],
        1 if is_private(dst) else 0,
        1 if is_private(src) else 0,
    )
```

GeoIP lookups use a 50,000-entry LRU cache to avoid repeated database reads:

```python
class GeoCache:
    def lookup(self, ip_str):
        if ip_str in self._cache:
            return self._cache[ip_str]
        # ... MaxMind lookup ...
        if len(self._cache) > 50000:
            self._cache.clear()
        self._cache[ip_str] = result
        return result
```

A background thread runs hourly to:
- Rebuild the `hourly_summary` aggregation table
- Recompute statistical baselines (avg, stddev, p95 per dimension)
- Purge raw flows older than 45 days

### Beaconing Detection Algorithm

C2 beaconing detection works by analyzing the regularity of connection intervals. The key insight: human-generated traffic has irregular timing, while automated beacons (malware check-ins, C2 heartbeats) tend to have consistent intervals.

```python
# For each src→dst pair with enough connections:
intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
avg_interval = sum(intervals) / len(intervals)
variance = sum((x - avg_interval)**2 for x in intervals) / len(intervals)
stddev = variance ** 0.5
cv = stddev / avg_interval  # coefficient of variation

# Lower CV = more regular = more suspicious
suspicion = "HIGH" if cv < 0.15 else "MEDIUM" if cv < 0.35 else "LOW"
```

A coefficient of variation below 0.15 means the intervals are very consistent — almost certainly automated. Between 0.15 and 0.35 is worth investigating. Above 0.35 looks like normal human traffic.

### Baseline Z-Score Calculation

The deviation check compares the last 24 hours against stored baselines using z-scores:

```
z = (current_value - baseline_avg) / baseline_stddev
```

Severity ratings:
- **Normal**: |z| < 2
- **Notable**: 2 ≤ |z| < 3
- **Anomalous**: |z| ≥ 3

The system also flags items that appear in the current window but not in the baseline (new hosts, new ports, new countries) and items that have disappeared.

### MCP + OAuth 2.0

Claude.ai connectors require the OAuth 2.0 Authorization Code flow with PKCE. The server implements this with raw aiohttp and JSON-RPC rather than using FastMCP, which doesn't support this auth pattern.

The flow:
1. Claude.ai discovers auth requirements via `/.well-known/oauth-protected-resource`
2. Redirects the user to `/authorize` with a PKCE code challenge
3. User approves, gets an authorization code
4. Claude.ai exchanges the code for a Bearer token at `/oauth/token`
5. All subsequent MCP requests to `/mcp` include the Bearer token

---

## Customization & Extension

### Adding a new MCP tool

It's a three-step process:

1. **Define the tool** — add a dict to the `TOOLS` list in `server.py` with `name`, `description`, and `inputSchema`
2. **Implement the function** — write a plain Python function that queries SQLite and returns `json.dumps(result)`
3. **Register it** — add the function to the `TOOL_MAP` dict

### Adjusting retention

The ingestor purges raw flows older than 45 days by default. Change the `days` parameter in the `purge_old_flows()` call in `summary_worker()`.

### Supporting other NetFlow exporters

goflow2 supports NetFlow v5, v9, IPFIX, and sFlow. Any device that can export NetFlow v9 to UDP 2055 will work — not just Meraki. Palo Alto, Fortinet, Cisco IOS, and many others are compatible.

### Scaling beyond SQLite

For high-volume environments (thousands of flows per second), consider:
- Moving to PostgreSQL with TimescaleDB for time-series optimization
- Adding a message queue (Redis) between goflow2 and the database
- Sharding by time period

For most single-site deployments with Meraki MX, SQLite handles the load without issues.

---

## Troubleshooting

### No flows arriving

- Verify the Meraki MX NetFlow configuration points to the correct IP and port 2055
- Check that UDP 2055 is open between the MX and the Docker host (`sudo tcpdump -i any udp port 2055`)
- Confirm the ingestor container is running: `docker compose logs ingestor`

### GeoIP fields are null

- Check that the mmdb files exist: `ls /mnt/netflow-data/*.mmdb`
- If `geoipupdate` hasn't run yet, wait for the initial download or restart it: `docker compose restart geoipupdate`
- After new mmdb files appear, restart the ingestor: `docker compose restart ingestor`

### OAuth errors

- Ensure the `OAUTH_CLIENT_ID` and `OAUTH_CLIENT_SECRET` in your Docker Compose environment match what you entered in the Claude.ai connector settings
- Check the MCP server logs: `docker compose logs mcp-netflow`

### SQLite "database is locked"

- Both containers must have **read-write** access to `/mnt/netflow-data` — don't mount it as read-only for the MCP server
- WAL mode requires write access even for readers

### Baselines are empty

- Baselines need at least 2 days of data before they populate
- The ingestor recomputes baselines hourly — check `docker compose logs ingestor` for "Rebuilding baselines" messages

### Cloudflare Tunnel issues

- Check cloudflared logs: `docker compose logs cloudflared`
- Verify the tunnel token is correct
- Ensure the tunnel points to `http://mcp-netflow:3000` (the Docker service name, not localhost)

---

## Security Considerations

- **Generate unique OAuth secrets** — use `openssl rand -hex 32`, never reuse example values
- **No exposed ports** — Cloudflare Tunnel means no inbound firewall rules needed for Claude.ai access
- **Isolated storage** — use a dedicated volume for the SQLite database to isolate it from the OS disk
- **Token persistence** — OAuth tokens survive container restarts via `token_store.json`; authorization codes are ephemeral (10-minute TTL, in-memory only)
- **No PII stored** — flow data contains IP addresses and traffic metadata, not packet payloads
- **Network segmentation** — place the collector on a management VLAN where it can receive NetFlow exports without being in the data path

---

## Conclusion

This project bridges two worlds: network telemetry and conversational AI. Instead of writing SQL queries or navigating dashboards, you ask Claude a question in plain English and it pulls from real flow data to give you an answer.

The system is intentionally simple — four containers, one SQLite database, no external dependencies beyond Cloudflare and MaxMind. It runs on modest hardware and handles single-site Meraki MX deployments without breaking a sweat.

Some directions for future work:
- **Alert integration**: pipe baseline deviations into Slack or PagerDuty
- **Automated responses**: have Claude suggest or execute firewall rules when it detects threats
- **Multi-site correlation**: aggregate flows from multiple Meraki networks into a single collector
- **Historical trend analysis**: longer retention with compressed time-series storage

The full source code is available on [GitHub](https://github.com/crwickha/netflow-mcp-server). Contributions and feedback are welcome.

---

*Built with [goflow2](https://github.com/netsampler/goflow2), [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data), [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/), and the [Model Context Protocol](https://modelcontextprotocol.io).*
