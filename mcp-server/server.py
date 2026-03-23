import os
import json
import time
import sqlite3
import secrets
import hashlib
import base64
import logging
from datetime import datetime, timezone
from urllib.parse import urlencode
from aiohttp import web

DB_PATH = "/data/flows.db"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("netflow-mcp")


# ============================================================================
# DATABASE HELPERS
# ============================================================================

def db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def ts_range(days):
    end = int(time.time())
    start = end - (days * 86400)
    return start, end


def rows_to_list(rows):
    return [dict(r) for r in rows]


# ============================================================================
# TOOL DEFINITIONS
# ============================================================================

TOOLS = [
    {
        "name": "get_traffic_overview",
        "description": (
            "Return a high-level traffic summary for the last N days: total bytes, "
            "packets, flows, unique hosts, hourly volume timeline, top 20 talkers "
            "by bytes, and protocol/port breakdown. This is the fastest broad view "
            "of network activity. Start here for any network analysis. Max 14 days."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "days": {"type": "integer", "description": "Number of days to analyze (max 14)", "default": 7}
            },
            "required": []
        }
    },
    {
        "name": "get_top_destinations",
        "description": (
            "Return top external destinations with GeoIP context, traffic by country, "
            "internal east-west traffic pairs, and newly seen destinations vs baseline. "
            "Use after get_traffic_overview to understand WHERE traffic is going. Max 14 days."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "days": {"type": "integer", "description": "Number of days to analyze (max 14)", "default": 7}
            },
            "required": []
        }
    },
    {
        "name": "get_anomaly_scan",
        "description": (
            "Scan for anomalies: hosts with unusually high destination counts, "
            "rare external ports (non-standard), off-hours activity (midnight-5am UTC), "
            "and suspicious flow patterns (high flow count with low bytes per flow, "
            "which indicates port scanning or reconnaissance). Use after "
            "get_traffic_overview for security investigations. Max 14 days."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "days": {"type": "integer", "description": "Number of days to analyze (max 14)", "default": 7}
            },
            "required": []
        }
    },
    {
        "name": "get_sample_flows",
        "description": (
            "Return raw individual flow records for drill-down investigation. "
            "Filter by any combination of: source host IP, destination IP, "
            "destination port, protocol. Returns up to 500 flows ordered by "
            "bytes, packets, or ts (timestamp). Use after get_network_deep_dive "
            "to investigate specific hosts, ports, or connections."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Source or destination IP to filter by"},
                "dst_ip": {"type": "string", "description": "Destination IP to filter by"},
                "dst_port": {"type": "integer", "description": "Destination port to filter by"},
                "proto": {"type": "string", "description": "Protocol to filter by (TCP, UDP, etc.)"},
                "hours_back": {"type": "integer", "description": "How many hours back to search (max 48)", "default": 24},
                "limit": {"type": "integer", "description": "Max flows to return (max 500)", "default": 200},
                "order_by": {"type": "string", "description": "Order by: bytes, packets, or ts", "default": "bytes"}
            },
            "required": []
        }
    },
    {
        "name": "get_host_profile",
        "description": (
            "Return a complete behavioral profile for a single IP address. "
            "Includes: total traffic sent/received, all destination IPs contacted, "
            "ports used, countries reached, time-of-day patterns, and any hosts "
            "that contacted this IP internally. Useful for investigating a "
            "specific device after get_network_deep_dive flags it as suspicious."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to profile"},
                "days": {"type": "integer", "description": "Number of days to analyze (max 7)", "default": 7}
            },
            "required": ["ip"]
        }
    },
    {
        "name": "detect_beaconing",
        "description": (
            "Detect potential C2 beaconing behavior: hosts that contact the same "
            "external destination repeatedly at regular intervals. Returns pairs "
            "with their connection regularity score (lower stddev = more regular = "
            "more suspicious). Flags sessions that look like automated check-ins "
            "rather than human-generated traffic."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "hours_back": {"type": "integer", "description": "Hours to analyze (max 48)", "default": 24},
                "min_occurrences": {"type": "integer", "description": "Minimum connection count to flag", "default": 6}
            },
            "required": []
        }
    },
    {
        "name": "get_geoip_context",
        "description": (
            "Return everything known about an external IP address from flow data: "
            "GeoIP country and org, all internal hosts that talked to it, "
            "total bytes transferred, ports used, and first/last seen timestamps. "
            "Use to investigate a suspicious external destination."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "External IP address to look up"}
            },
            "required": ["ip"]
        }
    },
    {
        "name": "get_time_window",
        "description": (
            "Return a traffic summary for an exact Unix timestamp range. "
            "Use this to isolate and analyze a specific incident window -- "
            "for example, 2 hours around a suspicious off-hours spike. "
            "Returns top talkers, top destinations, and rare ports for that window."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "start_ts": {"type": "integer", "description": "Start Unix timestamp"},
                "end_ts": {"type": "integer", "description": "End Unix timestamp"}
            },
            "required": ["start_ts", "end_ts"]
        }
    },
    {
        "name": "get_baseline_delta",
        "description": (
            "Compare the most recent N days of traffic against the equivalent "
            "prior period. Highlights hosts or destinations with significant "
            "increases in activity. Useful for spotting gradual changes that "
            "wouldn't trigger threshold-based alerts."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "days": {"type": "integer", "description": "Number of days for each comparison period (max 7)", "default": 7}
            },
            "required": []
        }
    },
    {
        "name": "get_baseline",
        "description": (
            "Return the stored statistical baseline profile for the network. "
            "Shows what 'normal' looks like across multiple dimensions: overall "
            "network volume, per-host, per-port, and per-country. Each entry "
            "includes daily average bytes, standard deviation, and 95th percentile. "
            "Use this to understand typical traffic patterns before investigating "
            "deviations. Baselines are recomputed hourly from historical data."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "period": {
                    "type": "string",
                    "description": "Baseline period: '7d', '14d', or '30d'",
                    "default": "7d",
                    "enum": ["7d", "14d", "30d"]
                },
                "dimension": {
                    "type": "string",
                    "description": "Filter to a specific dimension, or omit for all",
                    "enum": ["network_total", "host", "port", "country"]
                }
            },
            "required": []
        }
    },
    {
        "name": "check_baseline_deviation",
        "description": (
            "Compare the last 24 hours of traffic against the stored baseline "
            "for a given period. Returns z-scores and severity ratings (normal, "
            "notable, anomalous) for each host, port, and country. Also identifies "
            "new hosts, ports, or countries not seen in the baseline, and things "
            "that have disappeared. Use this to answer 'is anything abnormal right now?'"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "period": {
                    "type": "string",
                    "description": "Baseline period to compare against: '7d', '14d', or '30d'",
                    "default": "7d",
                    "enum": ["7d", "14d", "30d"]
                }
            },
            "required": []
        }
    },
    {
        "name": "get_collector_health",
        "description": (
            "Return status of the NetFlow collector: total flows in DB, "
            "data retention range, flows in last 5 minutes (confirms live data), "
            "unique exporters seen, and DB file size. "
            "Use to confirm the collector is running before starting an analysis."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
]


# ============================================================================
# TOOL IMPLEMENTATIONS
# ============================================================================

def get_traffic_overview(days=7):
    days = min(days, 14)
    start, end = ts_range(days)
    start_day = (start // 86400) * 86400
    conn = db()

    # Totals from daily_summary (~70k rows, near-instant)
    totals = dict(conn.execute("""
        SELECT SUM(flow_count) as total_flows,
               COUNT(DISTINCT src_addr) as unique_internal_hosts,
               SUM(total_bytes) as total_bytes,
               SUM(total_packets) as total_packets
        FROM daily_summary WHERE day_ts >= ?
    """, (start_day,)).fetchone())

    # Top talkers from daily_summary
    top_talkers = rows_to_list(conn.execute("""
        SELECT src_addr,
               SUM(total_bytes) as bytes_out,
               SUM(total_packets) as packets_out,
               SUM(flow_count) as flow_count,
               SUM(unique_dsts) as unique_destinations,
               SUM(unique_ports) as unique_ports_used
        FROM daily_summary WHERE day_ts >= ?
        GROUP BY src_addr ORDER BY bytes_out DESC LIMIT 20
    """, (start_day,)).fetchall())

    # Port/protocol breakdown from daily_port_summary
    protocols = rows_to_list(conn.execute("""
        SELECT dst_port, proto,
               SUM(total_bytes) as bytes, SUM(flow_count) as flows,
               SUM(unique_sources) as host_count
        FROM daily_port_summary WHERE day_ts >= ?
        GROUP BY dst_port, proto ORDER BY bytes DESC LIMIT 25
    """, (start_day,)).fetchall())

    # Hourly volume still needs hourly_summary (but it's a simple GROUP BY on indexed hour_ts)
    start_hour = (start // 3600) * 3600
    hourly = rows_to_list(conn.execute("""
        SELECT hour_ts,
               SUM(total_bytes) as bytes, SUM(total_packets) as packets,
               SUM(flow_count) as flows
        FROM hourly_summary WHERE hour_ts >= ?
        GROUP BY hour_ts ORDER BY hour_ts
    """, (start_hour,)).fetchall())

    conn.close()

    return json.dumps({
        "analysis_period_days": days,
        "period_start_utc": datetime.fromtimestamp(start, timezone.utc).isoformat(),
        "period_end_utc": datetime.fromtimestamp(end, timezone.utc).isoformat(),
        "totals": totals,
        "hourly_volume": hourly,
        "top_talkers": top_talkers,
        "port_protocol_breakdown": protocols,
    }, default=str)


def get_top_destinations(days=7):
    days = min(days, 14)
    start, end = ts_range(days)
    start_day = (start // 86400) * 86400
    conn = db()

    # Top external destinations from daily_dst_summary
    top_external = rows_to_list(conn.execute("""
        SELECT dst_addr, dst_country, dst_org,
               SUM(total_bytes) as bytes,
               SUM(flow_count) as flows,
               SUM(unique_sources) as internal_hosts_count
        FROM daily_dst_summary WHERE day_ts >= ? AND dst_is_private = 0
        GROUP BY dst_addr ORDER BY bytes DESC LIMIT 30
    """, (start_day,)).fetchall())

    # Countries from daily_country_summary (~1k rows total)
    countries = rows_to_list(conn.execute("""
        SELECT dst_country, SUM(total_bytes) as bytes, SUM(flow_count) as flows
        FROM daily_country_summary WHERE day_ts >= ?
        GROUP BY dst_country ORDER BY bytes DESC LIMIT 20
    """, (start_day,)).fetchall())

    # East-west from daily_dst_summary
    east_west = rows_to_list(conn.execute("""
        SELECT dst_addr,
               SUM(total_bytes) as bytes, SUM(flow_count) as flows,
               SUM(unique_sources) as source_count
        FROM daily_dst_summary WHERE day_ts >= ? AND dst_is_private = 1
        GROUP BY dst_addr ORDER BY bytes DESC LIMIT 20
    """, (start_day,)).fetchall())

    # Newly seen destinations (needs known_destinations table)
    new_dsts = rows_to_list(conn.execute("""
        SELECT d.dst_addr, d.dst_country, d.dst_org,
               SUM(d.total_bytes) as bytes, SUM(d.flow_count) as flows
        FROM daily_dst_summary d
        LEFT JOIN known_destinations kd ON d.dst_addr = kd.dst_addr
        WHERE d.day_ts >= ?
          AND d.dst_is_private = 0
          AND (kd.first_seen IS NULL OR kd.first_seen >= ?)
        GROUP BY d.dst_addr ORDER BY bytes DESC LIMIT 20
    """, (start_day, start)).fetchall())

    conn.close()

    return json.dumps({
        "analysis_period_days": days,
        "period_start_utc": datetime.fromtimestamp(start, timezone.utc).isoformat(),
        "period_end_utc": datetime.fromtimestamp(end, timezone.utc).isoformat(),
        "top_external_destinations": top_external,
        "traffic_by_country": countries,
        "internal_east_west_traffic": east_west,
        "newly_seen_destinations": new_dsts,
    }, default=str)


def get_anomaly_scan(days=7):
    days = min(days, 14)
    start, end = ts_range(days)
    start_day = (start // 86400) * 86400
    conn = db()

    # Average unique destinations per host from daily_summary
    avg_row = conn.execute("""
        SELECT AVG(total_dsts) as avg_dsts FROM (
            SELECT src_addr, SUM(unique_dsts) as total_dsts
            FROM daily_summary WHERE day_ts >= ?
            GROUP BY src_addr
        )
    """, (start_day,)).fetchone()
    avg_dsts = avg_row["avg_dsts"] or 1

    # Hosts with unusually high destination counts
    anomaly_high_dsts = rows_to_list(conn.execute("""
        SELECT src_addr,
               SUM(unique_dsts) as unique_dsts,
               SUM(unique_ports) as unique_ports,
               SUM(total_bytes) as total_bytes
        FROM daily_summary WHERE day_ts >= ?
        GROUP BY src_addr
        HAVING unique_dsts > ? ORDER BY unique_dsts DESC LIMIT 10
    """, (start_day, avg_dsts * 3)).fetchall())

    # Rare ports from daily_port_summary
    COMMON_PORTS = (80, 443, 53, 123, 67, 68, 22, 25, 587, 993, 995, 143, 110,
                    3389, 5222, 8080, 8443, 2055, 6343)
    placeholders = ",".join("?" * len(COMMON_PORTS))
    rare_ports = rows_to_list(conn.execute(f"""
        SELECT dst_port, proto,
               SUM(flow_count) as flows,
               SUM(unique_sources) as host_count,
               SUM(total_bytes) as bytes
        FROM daily_port_summary WHERE day_ts >= ?
          AND dst_port NOT IN ({placeholders})
          AND dst_is_private = 0
          AND dst_port > 0
        GROUP BY dst_port, proto ORDER BY flows DESC LIMIT 15
    """, (start_day, *COMMON_PORTS)).fetchall())

    # Off-hours activity (midnight-5am UTC) from hourly_summary
    start_hour = (start // 3600) * 3600
    off_hours = rows_to_list(conn.execute("""
        SELECT src_addr,
               SUM(total_bytes) as bytes, SUM(flow_count) as flows,
               COUNT(DISTINCT dst_addr) as unique_dsts
        FROM hourly_summary WHERE hour_ts >= ?
          AND (hour_ts % 86400) / 3600 BETWEEN 0 AND 5
        GROUP BY src_addr ORDER BY bytes DESC LIMIT 10
    """, (start_hour,)).fetchall())

    # Suspicious flow patterns: internal hosts with high flow count but very low
    # bytes-per-flow, plus high port diversity relative to destinations.
    # Catches port scanning, SYN sweeps, and slow-and-low reconnaissance.
    suspicious_flow_ratio = rows_to_list(conn.execute("""
        SELECT src_addr,
               SUM(flow_count) as total_flows,
               SUM(total_bytes) as total_bytes,
               ROUND(CAST(SUM(total_bytes) AS REAL) / MAX(SUM(flow_count), 1), 0) as avg_bytes_per_flow,
               SUM(unique_dsts) as unique_dsts,
               SUM(unique_ports) as unique_ports,
               ROUND(CAST(SUM(unique_ports) AS REAL) / MAX(SUM(unique_dsts), 1), 1) as ports_per_dst
        FROM daily_summary WHERE day_ts >= ? AND dst_is_private = 0
        GROUP BY src_addr
        HAVING total_flows > 1000 AND avg_bytes_per_flow < 500
        ORDER BY total_flows DESC LIMIT 10
    """, (start_day,)).fetchall())

    conn.close()

    return json.dumps({
        "analysis_period_days": days,
        "period_start_utc": datetime.fromtimestamp(start, timezone.utc).isoformat(),
        "period_end_utc": datetime.fromtimestamp(end, timezone.utc).isoformat(),
        "anomaly_candidates": {
            "high_unique_destinations": anomaly_high_dsts,
            "network_avg_unique_destinations_per_host": round(avg_dsts, 1),
        },
        "rare_external_ports": rare_ports,
        "off_hours_activity_0000_0500": off_hours,
        "suspicious_flow_patterns": {
            "description": "Hosts with high flow count but very low bytes per flow — indicates port scanning, SYN sweeps, or slow reconnaissance",
            "threshold": "over 1000 flows with under 500 bytes per flow average",
            "hosts": suspicious_flow_ratio,
        },
    }, default=str)


def get_sample_flows(host=None, dst_ip=None, dst_port=None, proto=None,
                     hours_back=24, limit=200, order_by="bytes"):
    limit = min(limit, 500)
    hours_back = min(hours_back, 48)
    start = int(time.time()) - (hours_back * 3600)
    conditions = ["ts >= ?"]
    params = [start]

    if host:
        conditions.append("(src_addr = ? OR dst_addr = ?)")
        params += [host, host]
    if dst_ip:
        conditions.append("dst_addr = ?")
        params.append(dst_ip)
    if dst_port:
        conditions.append("dst_port = ?")
        params.append(dst_port)
    if proto:
        conditions.append("proto = ?")
        params.append(proto.upper())

    order_col = {"bytes": "bytes", "packets": "packets", "ts": "ts"}.get(order_by, "bytes")
    where = " AND ".join(conditions)

    conn = db()
    rows = rows_to_list(conn.execute(f"""
        SELECT ts, src_addr, src_port, dst_addr, dst_port,
               proto, bytes, packets, duration_s,
               dst_country, dst_org, tcp_flags
        FROM flows WHERE {where}
        ORDER BY {order_col} DESC LIMIT ?
    """, params + [limit]).fetchall())
    conn.close()

    for r in rows:
        r["ts_utc"] = datetime.fromtimestamp(r["ts"], timezone.utc).isoformat()

    return json.dumps({
        "filter_applied": {"host": host, "dst_ip": dst_ip,
                           "dst_port": dst_port, "proto": proto,
                           "hours_back": hours_back},
        "returned_flows": len(rows),
        "flows": rows
    }, default=str)


def get_host_profile(ip, days=7):
    days = min(days, 7)
    start, end = ts_range(days)
    start_day = (start // 86400) * 86400
    start_hour = (start // 3600) * 3600
    conn = db()

    # Outbound connections from daily_dst_summary via hourly_summary (filtered by src_addr + indexed)
    outbound = rows_to_list(conn.execute("""
        SELECT dst_addr, dst_port, proto, dst_country, dst_org,
               SUM(total_bytes) as bytes, SUM(flow_count) as flows,
               MIN(hour_ts) as first_seen, MAX(hour_ts) as last_seen
        FROM hourly_summary WHERE src_addr = ? AND hour_ts >= ?
        GROUP BY dst_addr, dst_port, proto ORDER BY bytes DESC LIMIT 50
    """, (ip, start_hour)).fetchall())

    # Inbound — use daily_dst_summary (the target IP is the dst_addr there)
    inbound = rows_to_list(conn.execute("""
        SELECT src_addr, dst_port, proto,
               SUM(total_bytes) as bytes, SUM(flow_count) as flows
        FROM hourly_summary WHERE dst_addr = ? AND hour_ts >= ?
        GROUP BY src_addr, dst_port, proto ORDER BY bytes DESC LIMIT 20
    """, (ip, start_hour)).fetchall())

    # Hourly activity from hourly_summary (indexed on src_addr, hour_ts)
    hourly = rows_to_list(conn.execute("""
        SELECT hour_ts,
               SUM(total_bytes) as bytes, SUM(flow_count) as flows
        FROM hourly_summary WHERE src_addr = ? AND hour_ts >= ?
        GROUP BY hour_ts ORDER BY hour_ts
    """, (ip, start_hour)).fetchall())

    # Totals from daily_summary
    totals = dict(conn.execute("""
        SELECT SUM(total_bytes) as total_bytes_out,
               SUM(flow_count) as total_flows_out,
               SUM(unique_dsts) as unique_destinations,
               SUM(unique_ports) as unique_ports
        FROM daily_summary WHERE src_addr = ? AND day_ts >= ?
    """, (ip, start_day)).fetchone())

    conn.close()

    return json.dumps({
        "host": ip, "period_days": days,
        "outbound_summary": totals,
        "outbound_connections": outbound,
        "inbound_connections": inbound,
        "hourly_activity": hourly,
    }, default=str)


def detect_beaconing(hours_back=24, min_occurrences=6):
    hours_back = min(hours_back, 48)
    start = int(time.time()) - (hours_back * 3600)
    start_hour = (start // 3600) * 3600
    conn = db()

    # Use hourly_summary to find candidates with high flow counts to same dest
    # Then only hit raw flows for the top candidates to get actual timestamps
    candidates = rows_to_list(conn.execute("""
        SELECT src_addr, dst_addr, dst_port, dst_country, dst_org,
               SUM(flow_count) as occurrence_count,
               MIN(hour_ts) as first_seen, MAX(hour_ts) as last_seen
        FROM hourly_summary
        WHERE hour_ts >= ? AND dst_is_private = 0
        GROUP BY src_addr, dst_addr, dst_port
        HAVING occurrence_count >= ?
        ORDER BY occurrence_count DESC LIMIT 30
    """, (start_hour, min_occurrences)).fetchall())

    # For the top 30 candidates, get timestamps from raw flows
    results = []
    for c in candidates:
        timestamps = [r[0] for r in conn.execute("""
            SELECT ts FROM flows
            WHERE src_addr=? AND dst_addr=? AND dst_port=? AND ts>=?
            ORDER BY ts
        """, (c["src_addr"], c["dst_addr"], c["dst_port"], start)).fetchall()]

        if len(timestamps) < 3:
            continue

        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        avg_interval = sum(intervals) / len(intervals)
        variance = sum((x - avg_interval)**2 for x in intervals) / len(intervals)
        stddev = variance ** 0.5
        cv = (stddev / avg_interval) if avg_interval > 0 else 999

        results.append({
            **{k: v for k, v in c.items()},
            "occurrence_count": len(timestamps),
            "avg_interval_seconds": round(avg_interval, 1),
            "interval_stddev_seconds": round(stddev, 1),
            "regularity_coefficient": round(cv, 3),
            "suspicion": "HIGH" if cv < 0.15 else "MEDIUM" if cv < 0.35 else "LOW"
        })

    conn.close()
    results.sort(key=lambda x: x["regularity_coefficient"])
    return json.dumps({"hours_analyzed": hours_back,
                        "beaconing_candidates": results[:20]}, default=str)


def get_geoip_context(ip):
    conn = db()

    # Use hourly_summary instead of raw flows — dst_addr is indexed
    meta = dict(conn.execute("""
        SELECT dst_country, dst_org,
               SUM(total_bytes) as total_bytes,
               SUM(flow_count) as total_flows,
               COUNT(DISTINCT src_addr) as internal_hosts,
               MIN(hour_ts) as first_seen, MAX(hour_ts) as last_seen
        FROM hourly_summary WHERE dst_addr = ?
    """, (ip,)).fetchone())

    hosts = rows_to_list(conn.execute("""
        SELECT src_addr, dst_port, SUM(total_bytes) as bytes, SUM(flow_count) as flows
        FROM hourly_summary WHERE dst_addr = ?
        GROUP BY src_addr, dst_port ORDER BY bytes DESC LIMIT 20
    """, (ip,)).fetchall())

    conn.close()

    meta["first_seen_utc"] = datetime.fromtimestamp(meta["first_seen"] or 0, timezone.utc).isoformat()
    meta["last_seen_utc"] = datetime.fromtimestamp(meta["last_seen"] or 0, timezone.utc).isoformat()

    return json.dumps({"ip": ip, "geo_and_traffic": meta,
                        "internal_hosts_communicating": hosts}, default=str)


def get_time_window(start_ts, end_ts):
    # Cap window to 48 hours max
    max_window = 48 * 3600
    if end_ts - start_ts > max_window:
        start_ts = end_ts - max_window
    start_hour = (start_ts // 3600) * 3600
    conn = db()

    # Summary from hourly_summary
    summary = dict(conn.execute("""
        SELECT SUM(flow_count) as flows, SUM(total_bytes) as bytes,
               COUNT(DISTINCT src_addr) as src_hosts,
               COUNT(DISTINCT dst_addr) as dst_hosts
        FROM hourly_summary WHERE hour_ts BETWEEN ? AND ?
    """, (start_hour, end_ts)).fetchone())

    # Top flows — still need raw flows for individual flow detail, but time-bounded
    top = rows_to_list(conn.execute("""
        SELECT src_addr, dst_addr, dst_port, proto, dst_country,
               bytes, packets, ts
        FROM flows WHERE ts BETWEEN ? AND ?
        ORDER BY bytes DESC LIMIT 100
    """, (start_ts, end_ts)).fetchall())

    conn.close()

    return json.dumps({
        "window_start_utc": datetime.fromtimestamp(start_ts, timezone.utc).isoformat(),
        "window_end_utc": datetime.fromtimestamp(end_ts, timezone.utc).isoformat(),
        "summary": summary,
        "top_flows_by_bytes": top,
    }, default=str)


def get_baseline_delta(days=7):
    days = min(days, 7)
    now = int(time.time())
    current_start = now - (days * 86400)
    prior_start = current_start - (days * 86400)
    current_start_day = (current_start // 86400) * 86400
    prior_start_day = (prior_start // 86400) * 86400
    conn = db()

    current = {r["src_addr"]: r for r in rows_to_list(conn.execute("""
        SELECT src_addr, SUM(total_bytes) as bytes, SUM(flow_count) as flows,
               SUM(unique_dsts) as unique_dsts
        FROM daily_summary WHERE day_ts >= ?
        GROUP BY src_addr
    """, (current_start_day,)).fetchall())}

    prior = {r["src_addr"]: r for r in rows_to_list(conn.execute("""
        SELECT src_addr, SUM(total_bytes) as bytes, SUM(flow_count) as flows,
               SUM(unique_dsts) as unique_dsts
        FROM daily_summary WHERE day_ts BETWEEN ? AND ?
        GROUP BY src_addr
    """, (prior_start_day, current_start_day)).fetchall())}

    conn.close()

    deltas = []
    for ip, curr in current.items():
        prev = prior.get(ip, {"bytes": 0, "flows": 0, "unique_dsts": 0})
        prev_bytes = prev["bytes"] or 1
        change_pct = round(((curr["bytes"] - prev_bytes) / prev_bytes) * 100, 1)
        deltas.append({
            "src_addr": ip,
            "current_bytes": curr["bytes"],
            "prior_bytes": prev["bytes"],
            "change_percent": change_pct,
            "current_flows": curr["flows"],
            "prior_flows": prev["flows"],
        })

    deltas.sort(key=lambda x: abs(x["change_percent"]), reverse=True)
    new_hosts = [ip for ip in current if ip not in prior]

    return json.dumps({
        "current_period_days": days,
        "prior_period_days": days,
        "host_deltas": deltas[:30],
        "new_hosts_this_period": new_hosts,
    }, default=str)


def get_baseline(period="7d", dimension=None):
    conn = db()
    if dimension:
        rows = rows_to_list(conn.execute(
            "SELECT * FROM baselines WHERE period = ? AND dimension = ? ORDER BY avg_bytes DESC",
            (period, dimension)
        ).fetchall())
    else:
        rows = rows_to_list(conn.execute(
            "SELECT * FROM baselines WHERE period = ? ORDER BY dimension, avg_bytes DESC",
            (period,)
        ).fetchall())
    conn.close()

    if not rows:
        return json.dumps({
            "period": period,
            "error": "No baseline data found. Baselines are computed hourly by the ingestor. "
                     "Ensure the ingestor has run at least one summary cycle."
        })

    grouped = {}
    for r in rows:
        dim = r["dimension"]
        if dim not in grouped:
            grouped[dim] = []
        entry = {
            "key": r["key"],
            "avg_bytes_per_day": round(r["avg_bytes"], 0),
            "stddev_bytes": round(r["stddev_bytes"], 0),
            "p95_bytes_per_day": round(r["p95_bytes"], 0),
            "avg_flows_per_day": round(r["avg_flows"], 0),
            "stddev_flows": round(r["stddev_flows"], 0),
            "sample_days": r["sample_days"],
        }
        grouped[dim].append(entry)

    # Limit per-dimension results for readability
    for dim in grouped:
        if dim != "network_total":
            grouped[dim] = grouped[dim][:30]

    computed_at = rows[0].get("computed_at")

    return json.dumps({
        "period": period,
        "computed_at_utc": datetime.fromtimestamp(computed_at or 0, timezone.utc).isoformat(),
        "baselines": grouped,
    }, default=str)


def check_baseline_deviation(period="7d"):
    import math
    conn = db()

    # Load baselines for this period
    baseline_rows = conn.execute(
        "SELECT * FROM baselines WHERE period = ?", (period,)
    ).fetchall()

    if not baseline_rows:
        conn.close()
        return json.dumps({
            "error": "No baseline data found for period " + period,
            "hint": "Baselines are computed hourly by the ingestor."
        })

    baselines = {}
    for r in baseline_rows:
        baselines[(r["dimension"], r["key"])] = dict(r)

    # Get last 24h actuals from daily_summary tables (fast, ~70k rows)
    now = int(time.time())
    start_24h = now - 86400
    start_24h_day = (start_24h // 86400) * 86400

    # Network total
    net_actual = conn.execute("""
        SELECT SUM(total_bytes) as bytes, SUM(flow_count) as flows
        FROM daily_summary WHERE day_ts >= ?
    """, (start_24h_day,)).fetchone()

    # Per host
    host_actual = {r["src_addr"]: dict(r) for r in rows_to_list(conn.execute("""
        SELECT src_addr, SUM(total_bytes) as bytes, SUM(flow_count) as flows,
               SUM(unique_dsts) as unique_dsts
        FROM daily_summary WHERE day_ts >= ?
        GROUP BY src_addr
    """, (start_24h_day,)).fetchall())}

    # Per port
    port_actual = {str(r["dst_port"]): dict(r) for r in rows_to_list(conn.execute("""
        SELECT dst_port, SUM(total_bytes) as bytes, SUM(flow_count) as flows
        FROM daily_port_summary WHERE day_ts >= ? AND dst_port IS NOT NULL
        GROUP BY dst_port
    """, (start_24h_day,)).fetchall())}

    # Per country
    country_actual = {r["dst_country"]: dict(r) for r in rows_to_list(conn.execute("""
        SELECT dst_country, SUM(total_bytes) as bytes, SUM(flow_count) as flows
        FROM daily_country_summary WHERE day_ts >= ?
          AND dst_country IS NOT NULL
        GROUP BY dst_country
    """, (start_24h_day,)).fetchall())}

    conn.close()

    def zscore(actual, avg, stddev):
        if stddev == 0:
            return 0.0 if actual == avg else 99.0
        return (actual - avg) / stddev

    def severity(z):
        az = abs(z)
        if az < 1:
            return "normal"
        elif az < 2:
            return "notable"
        else:
            return "anomalous"

    result = {
        "period": period,
        "comparison_window": "last_24h",
        "comparison_start_utc": datetime.fromtimestamp(start_24h, timezone.utc).isoformat(),
    }

    # Network total deviation
    net_bl = baselines.get(("network_total", "*"))
    if net_bl and net_actual:
        z = zscore(net_actual["bytes"] or 0, net_bl["avg_bytes"], net_bl["stddev_bytes"])
        result["network_total"] = {
            "actual_bytes": net_actual["bytes"],
            "baseline_avg_bytes": round(net_bl["avg_bytes"]),
            "baseline_stddev": round(net_bl["stddev_bytes"]),
            "z_score": round(z, 2),
            "severity": severity(z),
            "actual_flows": net_actual["flows"],
            "baseline_avg_flows": round(net_bl["avg_flows"]),
        }

    # Per-dimension deviations
    def compute_deviations(actual_map, dimension):
        baseline_keys = {k for (d, k) in baselines if d == dimension}
        actual_keys = set(actual_map.keys())

        deviations = []
        for key in actual_keys & baseline_keys:
            bl = baselines[(dimension, key)]
            act = actual_map[key]
            z = zscore(act["bytes"] or 0, bl["avg_bytes"], bl["stddev_bytes"])
            sev = severity(z)
            if sev == "normal":
                continue
            deviations.append({
                "key": key,
                "actual_bytes": act["bytes"],
                "baseline_avg_bytes": round(bl["avg_bytes"]),
                "z_score": round(z, 2),
                "severity": sev,
                "multiplier": round(act["bytes"] / bl["avg_bytes"], 1) if bl["avg_bytes"] > 0 else None,
            })

        deviations.sort(key=lambda x: abs(x["z_score"]), reverse=True)

        new_keys = actual_keys - baseline_keys
        new_entries = []
        for key in new_keys:
            act = actual_map[key]
            if act["bytes"] and act["bytes"] > 0:
                new_entries.append({"key": key, "bytes": act["bytes"], "flows": act["flows"]})
        new_entries.sort(key=lambda x: x["bytes"], reverse=True)

        disappeared = baseline_keys - actual_keys
        disappeared_entries = []
        for key in disappeared:
            bl = baselines[(dimension, key)]
            if bl["avg_bytes"] > 0:
                disappeared_entries.append({
                    "key": key,
                    "baseline_avg_bytes": round(bl["avg_bytes"]),
                })
        disappeared_entries.sort(key=lambda x: x["baseline_avg_bytes"], reverse=True)

        return {
            "deviations": deviations[:20],
            "new_in_last_24h": new_entries[:15],
            "disappeared_vs_baseline": disappeared_entries[:15],
        }

    result["host_deviations"] = compute_deviations(host_actual, "host")
    result["port_deviations"] = compute_deviations(port_actual, "port")
    result["country_deviations"] = compute_deviations(country_actual, "country")

    # Summary counts for quick triage
    total_anomalous = sum(
        1 for dim in ["host_deviations", "port_deviations", "country_deviations"]
        for d in result[dim]["deviations"] if d["severity"] == "anomalous"
    )
    total_new = sum(
        len(result[dim]["new_in_last_24h"])
        for dim in ["host_deviations", "port_deviations", "country_deviations"]
    )
    result["summary"] = {
        "anomalous_count": total_anomalous,
        "new_items_count": total_new,
        "verdict": "anomalies detected" if total_anomalous > 0
                   else "new activity detected" if total_new > 0
                   else "within normal range",
    }

    return json.dumps(result, default=str)


def get_collector_health():
    conn = db()
    # Use max(rowid) as a fast approximation of total rows instead of COUNT(*)
    max_id = conn.execute("SELECT MAX(rowid) FROM flows").fetchone()[0] or 0
    oldest = conn.execute("SELECT MIN(ts) FROM flows").fetchone()[0]
    newest = conn.execute("SELECT MAX(ts) FROM flows").fetchone()[0]
    recent = conn.execute(
        "SELECT COUNT(*) as c FROM flows WHERE ts >= ?",
        (int(time.time()) - 300,)
    ).fetchone()["c"]
    exporters = rows_to_list(conn.execute(
        "SELECT DISTINCT sampler_addr FROM flows WHERE sampler_addr != '' LIMIT 20"
    ).fetchall())
    conn.close()

    db_size = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0

    return json.dumps({
        "status": "ok" if recent > 0 else "warning: no flows in last 5 minutes",
        "total_flows_in_db_approx": max_id,
        "oldest_flow_utc": datetime.fromtimestamp(oldest or 0, timezone.utc).isoformat(),
        "newest_flow_utc": datetime.fromtimestamp(newest or 0, timezone.utc).isoformat(),
        "flows_last_5_minutes": recent,
        "flow_exporters": [e["sampler_addr"] for e in exporters],
        "db_size_mb": round(db_size / 1024 / 1024, 2),
    }, default=str)


# ============================================================================
# TOOL DISPATCHER
# ============================================================================

TOOL_MAP = {
    "get_traffic_overview": get_traffic_overview,
    "get_top_destinations": get_top_destinations,
    "get_anomaly_scan": get_anomaly_scan,
    "get_sample_flows": get_sample_flows,
    "get_host_profile": get_host_profile,
    "detect_beaconing": detect_beaconing,
    "get_geoip_context": get_geoip_context,
    "get_time_window": get_time_window,
    "get_baseline_delta": get_baseline_delta,
    "get_baseline": get_baseline,
    "check_baseline_deviation": check_baseline_deviation,
    "get_collector_health": get_collector_health,
}


def execute_tool(name, args):
    func = TOOL_MAP.get(name)
    if not func:
        return json.dumps({"error": f"Unknown tool: {name}"})
    try:
        filtered_args = {
            k: v for k, v in args.items()
            if k not in ("sessionId", "action", "chatInput", "toolCallId")
        }
        return func(**filtered_args)
    except Exception as e:
        logger.error(f"Error executing tool {name}: {e}")
        return json.dumps({"error": str(e)})


# ============================================================================
# OAUTH 2.0 AUTHENTICATION (Authorization Code + PKCE)
# ============================================================================

TOKEN_STORE_PATH = os.environ.get("TOKEN_STORE_PATH", "/app/token_store.json")

valid_tokens = {}
refresh_tokens = {}
authorization_codes = {}


def load_tokens():
    global valid_tokens, refresh_tokens
    try:
        if os.path.exists(TOKEN_STORE_PATH):
            with open(TOKEN_STORE_PATH, "r") as f:
                data = json.load(f)
            now = time.time()
            valid_tokens = {
                t: meta for t, meta in data.get("access_tokens", {}).items()
                if meta.get("expires", 0) > now
            }
            refresh_tokens = {
                t: meta for t, meta in data.get("refresh_tokens", {}).items()
                if meta.get("expires", 0) > now
            }
            logger.info(f"Loaded {len(valid_tokens)} access tokens, {len(refresh_tokens)} refresh tokens")
    except Exception as e:
        logger.warning(f"Could not load token store: {e}")


def save_tokens():
    try:
        os.makedirs(os.path.dirname(TOKEN_STORE_PATH) or ".", exist_ok=True)
        data = {
            "access_tokens": valid_tokens,
            "refresh_tokens": refresh_tokens,
        }
        with open(TOKEN_STORE_PATH, "w") as f:
            json.dump(data, f)
    except Exception as e:
        logger.warning(f"Could not save token store: {e}")


def generate_access_token():
    return secrets.token_hex(32)


def generate_refresh_token():
    return secrets.token_hex(48)


def generate_authorization_code():
    return secrets.token_urlsafe(32)


def validate_client_id(client_id):
    expected_id = os.environ.get("OAUTH_CLIENT_ID", "")
    if not expected_id:
        return False
    return secrets.compare_digest(client_id, expected_id)


def validate_client_secret(client_secret):
    expected_secret = os.environ.get("OAUTH_CLIENT_SECRET", "")
    if not expected_secret:
        return True  # no secret configured, skip validation
    return secrets.compare_digest(client_secret, expected_secret)


def is_oauth_enabled():
    return bool(os.environ.get("OAUTH_CLIENT_ID"))


def verify_pkce(code_verifier, code_challenge, method):
    if method == "S256":
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return secrets.compare_digest(computed, code_challenge)
    elif method == "plain":
        return secrets.compare_digest(code_verifier, code_challenge)
    return False


def get_server_url(request):
    forwarded_proto = request.headers.get("X-Forwarded-Proto", "https")
    forwarded_host = request.headers.get("X-Forwarded-Host", request.host)
    return f"{forwarded_proto}://{forwarded_host}"


# ============================================================================
# HTTP HANDLERS
# ============================================================================

async def handle_protected_resource_metadata(request):
    server_url = get_server_url(request)
    metadata = {
        "resource": f"{server_url}/mcp",
        "authorization_servers": [server_url],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["claudeai"],
    }
    return web.json_response(metadata)


async def handle_oauth_metadata(request):
    server_url = get_server_url(request)
    metadata = {
        "issuer": server_url,
        "authorization_endpoint": f"{server_url}/authorize",
        "token_endpoint": f"{server_url}/oauth/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "scopes_supported": ["claudeai"],
    }
    return web.json_response(metadata)


async def handle_authorize(request):
    try:
        response_type = request.query.get("response_type", "")
        client_id = request.query.get("client_id", "")
        redirect_uri = request.query.get("redirect_uri", "")
        code_challenge = request.query.get("code_challenge", "")
        code_challenge_method = request.query.get("code_challenge_method", "S256")
        state = request.query.get("state", "")

        if response_type != "code":
            return web.json_response(
                {"error": "unsupported_response_type",
                 "error_description": "Only 'code' response type is supported"},
                status=400
            )

        if not validate_client_id(client_id):
            logger.warning("Authorization failed - invalid client_id")
            return web.json_response(
                {"error": "invalid_client", "error_description": "Invalid client_id"},
                status=401
            )

        if not redirect_uri:
            return web.json_response(
                {"error": "invalid_request", "error_description": "redirect_uri is required"},
                status=400
            )

        if not code_challenge:
            return web.json_response(
                {"error": "invalid_request",
                 "error_description": "code_challenge is required for PKCE"},
                status=400
            )

        code = generate_authorization_code()

        authorization_codes[code] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "expires": time.time() + 600
        }

        logger.info(f"Authorization code issued for client {client_id[:8]}...")

        redirect_params = {"code": code}
        if state:
            redirect_params["state"] = state

        separator = "&" if "?" in redirect_uri else "?"
        final_redirect = f"{redirect_uri}{separator}{urlencode(redirect_params)}"

        raise web.HTTPFound(location=final_redirect)

    except web.HTTPFound:
        raise
    except Exception as e:
        logger.error(f"Authorization error: {e}")
        return web.json_response(
            {"error": "server_error", "error_description": str(e)},
            status=500
        )


async def handle_oauth_token(request):
    try:
        content_type = request.headers.get("Content-Type", "")

        if "application/x-www-form-urlencoded" in content_type:
            data = await request.post()
        elif "application/json" in content_type:
            data = await request.json()
        else:
            return web.json_response(
                {"error": "invalid_request",
                 "error_description": "Unsupported content type"},
                status=400
            )

        grant_type = data.get("grant_type", "")
        client_id = data.get("client_id", "")
        client_secret = data.get("client_secret", "")

        if not validate_client_secret(client_secret):
            return web.json_response(
                {"error": "invalid_client",
                 "error_description": "Invalid client_secret"},
                status=401
            )

        if grant_type not in ("authorization_code", "refresh_token"):
            return web.json_response(
                {"error": "unsupported_grant_type",
                 "error_description": "Supported: authorization_code, refresh_token"},
                status=400
            )

        if grant_type == "authorization_code":
            code = data.get("code", "")
            redirect_uri = data.get("redirect_uri", "")
            code_verifier = data.get("code_verifier", "")

            if code not in authorization_codes:
                logger.warning("Token request failed - invalid or expired code")
                return web.json_response(
                    {"error": "invalid_grant",
                     "error_description": "Invalid or expired authorization code"},
                    status=400
                )

            code_data = authorization_codes[code]

            if time.time() > code_data["expires"]:
                del authorization_codes[code]
                return web.json_response(
                    {"error": "invalid_grant",
                     "error_description": "Authorization code expired"},
                    status=400
                )

            if not secrets.compare_digest(client_id, code_data["client_id"]):
                return web.json_response(
                    {"error": "invalid_grant",
                     "error_description": "client_id mismatch"},
                    status=400
                )

            if not secrets.compare_digest(redirect_uri, code_data["redirect_uri"]):
                return web.json_response(
                    {"error": "invalid_grant",
                     "error_description": "redirect_uri mismatch"},
                    status=400
                )

            if not verify_pkce(code_verifier, code_data["code_challenge"],
                               code_data["code_challenge_method"]):
                logger.warning("Token request failed - PKCE verification failed")
                return web.json_response(
                    {"error": "invalid_grant",
                     "error_description": "PKCE verification failed"},
                    status=400
                )

            del authorization_codes[code]

        elif grant_type == "refresh_token":
            incoming_refresh = data.get("refresh_token", "")
            if not incoming_refresh or incoming_refresh not in refresh_tokens:
                logger.warning("Token request failed - invalid refresh token")
                return web.json_response(
                    {"error": "invalid_grant",
                     "error_description": "Invalid refresh token"},
                    status=400
                )
            refresh_data = refresh_tokens[incoming_refresh]
            if time.time() > refresh_data["expires"]:
                del refresh_tokens[incoming_refresh]
                save_tokens()
                logger.warning("Token request failed - refresh token expired")
                return web.json_response(
                    {"error": "invalid_grant",
                     "error_description": "Refresh token expired"},
                    status=400
                )
            del refresh_tokens[incoming_refresh]

        access_token = generate_access_token()
        new_refresh_token = generate_refresh_token()
        token_expires = time.time() + 86400       # 24 hours
        refresh_expires = time.time() + 7776000   # 90 days

        valid_tokens[access_token] = {"expires": token_expires}
        refresh_tokens[new_refresh_token] = {"client_id": client_id, "expires": refresh_expires}
        save_tokens()

        logger.info(f"OAuth access token issued via {grant_type} grant")

        return web.json_response({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 86400,
            "refresh_token": new_refresh_token
        })

    except Exception as e:
        logger.error(f"OAuth token error: {e}")
        return web.json_response(
            {"error": "server_error", "error_description": str(e)},
            status=500
        )


async def handle_mcp_request(request):
    if is_oauth_enabled():
        server_url = get_server_url(request)
        resource_metadata_url = f"{server_url}/.well-known/oauth-protected-resource"
        www_authenticate = f'Bearer resource_metadata="{resource_metadata_url}"'

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            logger.warning("Unauthorized request - missing Bearer token")
            return web.json_response(
                {"jsonrpc": "2.0", "id": None,
                 "error": {"code": -32001, "message": "Unauthorized - Bearer token required"}},
                status=401,
                headers={"WWW-Authenticate": www_authenticate}
            )

        token = auth_header[7:]

        token_meta = valid_tokens.get(token)
        if not token_meta or token_meta["expires"] < time.time():
            if token_meta:
                del valid_tokens[token]
                save_tokens()
            logger.warning("Unauthorized request - invalid or expired Bearer token")
            return web.json_response(
                {"jsonrpc": "2.0", "id": None,
                 "error": {"code": -32001, "message": "Unauthorized - invalid or expired token"}},
                status=401,
                headers={"WWW-Authenticate": www_authenticate}
            )

    try:
        body = await request.json()
        logger.info(f"Received: {body.get('method', 'unknown')}")

        method = body.get("method", "")
        params = body.get("params", {})
        request_id = body.get("id")

        if method == "initialize":
            response_data = {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {"listChanged": False}
                },
                "serverInfo": {
                    "name": "netflow-mcp-server",
                    "version": "1.0.0"
                }
            }
        elif method == "tools/list":
            response_data = {"tools": TOOLS}
        elif method == "tools/call":
            tool_name = params.get("name", "")
            tool_args = params.get("arguments", {})
            result_text = execute_tool(tool_name, tool_args)
            response_data = {
                "content": [{"type": "text", "text": result_text}]
            }
        elif method == "notifications/initialized":
            return web.Response(status=204)
        else:
            response_data = {"error": f"Unknown method: {method}"}

        response = {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": response_data
        }

        return web.json_response(response)

    except Exception as e:
        logger.error(f"MCP request error: {e}")
        return web.json_response({
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32603, "message": str(e)}
        }, status=500)


async def health_check(request):
    return web.json_response({
        "status": "healthy",
        "service": "netflow-mcp-server",
        "version": "1.0.0",
        "tool_count": len(TOOLS)
    })


async def list_tools(request):
    return web.json_response({
        "total_tools": len(TOOLS),
        "tools": [{"name": t["name"], "description": t["description"]} for t in TOOLS]
    })


def create_app():
    app = web.Application()
    app.router.add_get("/health", health_check)
    app.router.add_get("/tools", list_tools)
    app.router.add_post("/mcp", handle_mcp_request)
    app.router.add_get("/.well-known/oauth-protected-resource", handle_protected_resource_metadata)
    app.router.add_get("/.well-known/oauth-authorization-server", handle_oauth_metadata)
    app.router.add_get("/authorize", handle_authorize)
    app.router.add_post("/oauth/token", handle_oauth_token)
    return app


if __name__ == "__main__":
    load_tokens()
    app = create_app()
    logger.info(f"Starting NetFlow MCP Server on port 3000 ({len(TOOLS)} tools)")
    web.run_app(app, host="0.0.0.0", port=3000)
