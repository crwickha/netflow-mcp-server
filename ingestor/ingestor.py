import subprocess, json, sqlite3, time, ipaddress, logging, threading, math
from collections import defaultdict
from pathlib import Path
import geoip2.database

DB_PATH = "/data/flows.db"
MMDB_ASN_PATH = "/data/GeoLite2-ASN.mmdb"
MMDB_COUNTRY_PATH = "/data/GeoLite2-Country.mmdb"
BATCH_SIZE = 100
SUMMARY_INTERVAL = 3600

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("ingestor")

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def is_private(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in PRIVATE_RANGES)
    except ValueError:
        return False


def proto_name(num):
    return {6: "TCP", 17: "UDP", 1: "ICMP", 47: "GRE", 50: "ESP"}.get(num, str(num))


class GeoCache:
    def __init__(self):
        self._cache = {}
        self.asn_reader = None
        self.country_reader = None
        self._load_readers()

    def _load_readers(self):
        try:
            self.asn_reader = geoip2.database.Reader(MMDB_ASN_PATH)
            self.country_reader = geoip2.database.Reader(MMDB_COUNTRY_PATH)
            log.info("GeoIP databases loaded")
        except Exception as e:
            log.warning(f"GeoIP not available: {e} — country/org will be null")

    def lookup(self, ip_str):
        if ip_str in self._cache:
            return self._cache[ip_str]
        result = {"country": None, "org": None}
        if is_private(ip_str):
            result = {"country": "RFC1918", "org": "Internal"}
        elif self.asn_reader and self.country_reader:
            try:
                asn = self.asn_reader.asn(ip_str)
                country = self.country_reader.country(ip_str)
                result = {
                    "country": country.country.iso_code,
                    "org": asn.autonomous_system_organization,
                }
            except Exception:
                pass
        if len(self._cache) > 50000:
            self._cache.clear()
        self._cache[ip_str] = result
        return result


def init_db(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS flows (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ts              INTEGER NOT NULL,
            ts_end          INTEGER,
            src_addr        TEXT NOT NULL,
            dst_addr        TEXT NOT NULL,
            src_port        INTEGER,
            dst_port        INTEGER,
            proto           TEXT,
            bytes           INTEGER DEFAULT 0,
            packets         INTEGER DEFAULT 0,
            duration_s      REAL,
            tcp_flags       TEXT,
            sampler_addr    TEXT,
            dst_country     TEXT,
            dst_org         TEXT,
            dst_is_private  INTEGER DEFAULT 0,
            src_is_private  INTEGER DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_ts          ON flows (ts);
        CREATE INDEX IF NOT EXISTS idx_src_addr    ON flows (src_addr);
        CREATE INDEX IF NOT EXISTS idx_dst_addr    ON flows (dst_addr);
        CREATE INDEX IF NOT EXISTS idx_dst_port    ON flows (dst_port);
        CREATE INDEX IF NOT EXISTS idx_dst_country ON flows (dst_country);
        CREATE INDEX IF NOT EXISTS idx_private     ON flows (dst_is_private);
        CREATE INDEX IF NOT EXISTS idx_ts_src_private ON flows (ts, src_is_private);
        CREATE INDEX IF NOT EXISTS idx_ts_dst_private ON flows (ts, dst_is_private);
        CREATE INDEX IF NOT EXISTS idx_src_addr_ts    ON flows (src_addr, ts);
        CREATE INDEX IF NOT EXISTS idx_dst_addr_ts    ON flows (dst_addr, ts);
        CREATE INDEX IF NOT EXISTS idx_ts_dst_port    ON flows (ts, dst_port);

        CREATE TABLE IF NOT EXISTS hourly_summary (
            hour_ts         INTEGER NOT NULL,
            src_addr        TEXT NOT NULL,
            dst_addr        TEXT,
            dst_port        INTEGER,
            proto           TEXT,
            dst_country     TEXT,
            dst_org         TEXT,
            dst_is_private  INTEGER,
            total_bytes     INTEGER,
            total_packets   INTEGER,
            flow_count      INTEGER,
            PRIMARY KEY (hour_ts, src_addr, dst_addr, dst_port, proto)
        );
        CREATE INDEX IF NOT EXISTS idx_hsummary_hour ON hourly_summary (hour_ts);
        CREATE INDEX IF NOT EXISTS idx_hsummary_src  ON hourly_summary (src_addr);
        CREATE INDEX IF NOT EXISTS idx_hsummary_hour_src ON hourly_summary (hour_ts, src_addr);
        CREATE INDEX IF NOT EXISTS idx_hsummary_hour_dst ON hourly_summary (hour_ts, dst_addr);
        CREATE INDEX IF NOT EXISTS idx_hsummary_hour_private ON hourly_summary (hour_ts, dst_is_private);

        CREATE TABLE IF NOT EXISTS baselines (
            period          TEXT NOT NULL,
            dimension       TEXT NOT NULL,
            key             TEXT NOT NULL,
            avg_bytes       REAL,
            stddev_bytes    REAL,
            p95_bytes       REAL,
            avg_flows       REAL,
            stddev_flows    REAL,
            sample_days     INTEGER,
            computed_at     INTEGER,
            PRIMARY KEY (period, dimension, key)
        );

        CREATE TABLE IF NOT EXISTS daily_summary (
            day_ts          INTEGER NOT NULL,
            src_addr        TEXT NOT NULL,
            dst_is_private  INTEGER,
            total_bytes     INTEGER,
            total_packets   INTEGER,
            flow_count      INTEGER,
            unique_dsts     INTEGER,
            unique_ports    INTEGER,
            PRIMARY KEY (day_ts, src_addr, dst_is_private)
        );
        CREATE INDEX IF NOT EXISTS idx_dsummary_day ON daily_summary (day_ts);

        CREATE TABLE IF NOT EXISTS daily_dst_summary (
            day_ts          INTEGER NOT NULL,
            dst_addr        TEXT NOT NULL,
            dst_country     TEXT,
            dst_org         TEXT,
            dst_is_private  INTEGER,
            total_bytes     INTEGER,
            flow_count      INTEGER,
            unique_sources  INTEGER,
            PRIMARY KEY (day_ts, dst_addr)
        );
        CREATE INDEX IF NOT EXISTS idx_ddsummary_day ON daily_dst_summary (day_ts);

        CREATE TABLE IF NOT EXISTS daily_port_summary (
            day_ts          INTEGER NOT NULL,
            dst_port        INTEGER NOT NULL,
            proto           TEXT,
            dst_is_private  INTEGER,
            total_bytes     INTEGER,
            flow_count      INTEGER,
            unique_sources  INTEGER,
            PRIMARY KEY (day_ts, dst_port, proto)
        );
        CREATE INDEX IF NOT EXISTS idx_dpsummary_day ON daily_port_summary (day_ts);

        CREATE TABLE IF NOT EXISTS daily_country_summary (
            day_ts          INTEGER NOT NULL,
            dst_country     TEXT NOT NULL,
            total_bytes     INTEGER,
            flow_count      INTEGER,
            PRIMARY KEY (day_ts, dst_country)
        );
        CREATE INDEX IF NOT EXISTS idx_dcsummary_day ON daily_country_summary (day_ts);

        CREATE TABLE IF NOT EXISTS known_destinations (
            dst_addr    TEXT PRIMARY KEY,
            first_seen  INTEGER,
            last_seen   INTEGER,
            total_flows INTEGER
        );
    """)
    conn.commit()


def rebuild_hourly_summary(conn):
    log.info("Rebuilding hourly summary...")
    cutoff = int(time.time()) - (35 * 86400)
    conn.execute("DELETE FROM hourly_summary WHERE hour_ts < ?", (cutoff,))
    conn.execute("""
        INSERT OR REPLACE INTO hourly_summary
        SELECT
            (ts / 3600) * 3600  AS hour_ts,
            src_addr, dst_addr, dst_port, proto,
            dst_country, dst_org, dst_is_private,
            SUM(bytes), SUM(packets), COUNT(*)
        FROM flows
        WHERE ts >= ?
        GROUP BY hour_ts, src_addr, dst_addr, dst_port, proto
    """, (cutoff,))
    conn.execute("""
        INSERT OR REPLACE INTO known_destinations
        SELECT dst_addr, MIN(ts), MAX(ts), COUNT(*)
        FROM flows GROUP BY dst_addr
    """)
    conn.commit()
    log.info("Hourly summary rebuilt")


def _stats(vals):
    n = len(vals)
    if n == 0:
        return 0, 0, 0
    avg = sum(vals) / n
    variance = sum((x - avg) ** 2 for x in vals) / n
    stddev = math.sqrt(variance)
    sorted_vals = sorted(vals)
    p95_idx = min(int(n * 0.95), n - 1)
    return avg, stddev, sorted_vals[p95_idx]


def _insert_baseline(conn, period, dimension, key, bytes_vals, flows_vals):
    avg_b, std_b, p95_b = _stats(bytes_vals)
    avg_f, std_f, _ = _stats(flows_vals)
    conn.execute("""
        INSERT OR REPLACE INTO baselines
        (period, dimension, key, avg_bytes, stddev_bytes, p95_bytes,
         avg_flows, stddev_flows, sample_days, computed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (period, dimension, key, avg_b, std_b, p95_b, avg_f, std_f,
          len(bytes_vals), int(time.time())))


def rebuild_daily_summaries(conn):
    log.info("Rebuilding daily summaries...")
    cutoff = int(time.time()) - (35 * 86400)

    conn.execute("DELETE FROM daily_summary WHERE day_ts < ?", (cutoff,))
    conn.execute("""
        INSERT OR REPLACE INTO daily_summary
        SELECT (hour_ts / 86400) * 86400 AS day_ts,
               src_addr, dst_is_private,
               SUM(total_bytes), SUM(total_packets), SUM(flow_count),
               COUNT(DISTINCT dst_addr), COUNT(DISTINCT dst_port)
        FROM hourly_summary WHERE hour_ts >= ?
        GROUP BY day_ts, src_addr, dst_is_private
    """, (cutoff,))

    conn.execute("DELETE FROM daily_dst_summary WHERE day_ts < ?", (cutoff,))
    conn.execute("""
        INSERT OR REPLACE INTO daily_dst_summary
        SELECT (hour_ts / 86400) * 86400 AS day_ts,
               dst_addr, dst_country, dst_org, dst_is_private,
               SUM(total_bytes), SUM(flow_count),
               COUNT(DISTINCT src_addr)
        FROM hourly_summary WHERE hour_ts >= ?
        GROUP BY day_ts, dst_addr
    """, (cutoff,))

    conn.execute("DELETE FROM daily_port_summary WHERE day_ts < ?", (cutoff,))
    conn.execute("""
        INSERT OR REPLACE INTO daily_port_summary
        SELECT (hour_ts / 86400) * 86400 AS day_ts,
               dst_port, proto, dst_is_private,
               SUM(total_bytes), SUM(flow_count),
               COUNT(DISTINCT src_addr)
        FROM hourly_summary WHERE hour_ts >= ? AND dst_port IS NOT NULL
        GROUP BY day_ts, dst_port, proto
    """, (cutoff,))

    conn.execute("DELETE FROM daily_country_summary WHERE day_ts < ?", (cutoff,))
    conn.execute("""
        INSERT OR REPLACE INTO daily_country_summary
        SELECT (hour_ts / 86400) * 86400 AS day_ts,
               dst_country,
               SUM(total_bytes), SUM(flow_count)
        FROM hourly_summary WHERE hour_ts >= ? AND dst_country IS NOT NULL AND dst_is_private = 0
        GROUP BY day_ts, dst_country
    """, (cutoff,))

    conn.commit()
    log.info("Daily summaries rebuilt")


def rebuild_baselines(conn):
    log.info("Rebuilding baselines...")
    now = int(time.time())
    periods = {'7d': 7, '14d': 14, '30d': 30}

    conn.execute("DELETE FROM baselines")

    for period_name, days in periods.items():
        start = now - (days * 86400)
        min_days = max(days // 2, 2)

        # Network-wide daily totals
        daily_totals = conn.execute("""
            SELECT (hour_ts / 86400) as day,
                   SUM(total_bytes) as bytes,
                   SUM(flow_count) as flows
            FROM hourly_summary WHERE hour_ts >= ?
            GROUP BY day
        """, (start,)).fetchall()

        if daily_totals:
            _insert_baseline(conn, period_name, 'network_total', '*',
                             [r[1] or 0 for r in daily_totals],
                             [r[2] or 0 for r in daily_totals])

        # Per host
        daily_host = conn.execute("""
            SELECT (hour_ts / 86400) as day, src_addr,
                   SUM(total_bytes) as bytes, SUM(flow_count) as flows
            FROM hourly_summary WHERE hour_ts >= ?
            GROUP BY day, src_addr
        """, (start,)).fetchall()

        host_days = defaultdict(lambda: {'bytes': [], 'flows': []})
        for r in daily_host:
            host_days[r[1]]['bytes'].append(r[2] or 0)
            host_days[r[1]]['flows'].append(r[3] or 0)

        for host, data in host_days.items():
            if len(data['bytes']) >= min_days:
                _insert_baseline(conn, period_name, 'host', host,
                                 data['bytes'], data['flows'])

        # Per port (top 50 by volume)
        daily_port = conn.execute("""
            SELECT (hour_ts / 86400) as day, dst_port,
                   SUM(total_bytes) as bytes, SUM(flow_count) as flows
            FROM hourly_summary
            WHERE hour_ts >= ? AND dst_port IS NOT NULL
            GROUP BY day, dst_port
        """, (start,)).fetchall()

        port_days = defaultdict(lambda: {'bytes': [], 'flows': []})
        for r in daily_port:
            port_days[str(r[1])]['bytes'].append(r[2] or 0)
            port_days[str(r[1])]['flows'].append(r[3] or 0)

        port_totals = {p: sum(d['bytes']) for p, d in port_days.items()}
        top_ports = sorted(port_totals, key=port_totals.get, reverse=True)[:50]
        for port in top_ports:
            if len(port_days[port]['bytes']) >= min_days:
                _insert_baseline(conn, period_name, 'port', port,
                                 port_days[port]['bytes'], port_days[port]['flows'])

        # Per country
        daily_country = conn.execute("""
            SELECT (hour_ts / 86400) as day, dst_country,
                   SUM(total_bytes) as bytes, SUM(flow_count) as flows
            FROM hourly_summary
            WHERE hour_ts >= ? AND dst_country IS NOT NULL AND dst_is_private = 0
            GROUP BY day, dst_country
        """, (start,)).fetchall()

        country_days = defaultdict(lambda: {'bytes': [], 'flows': []})
        for r in daily_country:
            country_days[r[1]]['bytes'].append(r[2] or 0)
            country_days[r[1]]['flows'].append(r[3] or 0)

        for country, data in country_days.items():
            if len(data['bytes']) >= min_days:
                _insert_baseline(conn, period_name, 'country', country,
                                 data['bytes'], data['flows'])

    conn.commit()
    log.info("Baselines rebuilt")


def purge_old_flows(conn, days=45):
    cutoff = int(time.time()) - (days * 86400)
    conn.execute("DELETE FROM flows WHERE ts < ?", (cutoff,))
    conn.commit()
    log.info(f"Purged flows older than {days} days")


def summary_worker(db_path):
    while True:
        time.sleep(SUMMARY_INTERVAL)
        try:
            conn = sqlite3.connect(db_path, timeout=30)
            rebuild_hourly_summary(conn)
            rebuild_daily_summaries(conn)
            rebuild_baselines(conn)
            purge_old_flows(conn)
            conn.close()
        except Exception as e:
            log.error(f"Summary rebuild error: {e}")


def parse_flow(raw, geo):
    ts = int(raw.get("time_flow_start_ns", 0) / 1e9) or int(time.time())
    ts_end = int(raw.get("time_flow_end_ns", 0) / 1e9) or None
    src = raw.get("src_addr", "")
    dst = raw.get("dst_addr", "")
    proto_num = raw.get("proto", 0)
    dst_info = geo.lookup(dst)
    return (
        ts, ts_end,
        src, dst,
        raw.get("src_port"), raw.get("dst_port"),
        proto_name(proto_num),
        raw.get("bytes", 0), raw.get("packets", 0),
        round((ts_end - ts), 2) if ts_end else None,
        str(raw.get("tcp_flags", "")),
        raw.get("sampler_address", ""),
        dst_info["country"], dst_info["org"],
        1 if is_private(dst) else 0,
        1 if is_private(src) else 0,
    )


def main():
    Path("/data").mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    init_db(conn)

    geo = GeoCache()

    t = threading.Thread(target=summary_worker, args=(DB_PATH,), daemon=True)
    t.start()

    proc = subprocess.Popen(
        ["goflow2", "-listen", "netflow://:2055"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        bufsize=1, universal_newlines=True
    )
    log.info("goflow2 started, listening on UDP 2055")

    batch = []
    INSERT = """INSERT INTO flows
        (ts, ts_end, src_addr, dst_addr, src_port, dst_port, proto,
         bytes, packets, duration_s, tcp_flags, sampler_addr,
         dst_country, dst_org, dst_is_private, src_is_private)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""

    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
            row = parse_flow(raw, geo)
            batch.append(row)
            if len(batch) >= BATCH_SIZE:
                conn.executemany(INSERT, batch)
                conn.commit()
                batch.clear()
        except (json.JSONDecodeError, Exception) as e:
            log.debug(f"Parse error: {e}")


if __name__ == "__main__":
    main()
