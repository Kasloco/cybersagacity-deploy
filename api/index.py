"""
CyberSagacity Rule Intelligence Platform — Vercel Serverless Function
Serves the dashboard and rule search API from a bundled SQLite database.
"""

import csv
import io
import json
import os
import sqlite3

from flask import Flask, Response, render_template_string, request, jsonify
from flask_cors import CORS

from api.tool_config import (
    TOOL_CONFIGS, get_tool, get_tool_summary, get_csv_headers, map_severity,
    get_active_tools,
)

app = Flask(__name__)
CORS(app)

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "rules.db")


def get_db():
    # Use immutable mode so SQLite doesn't try to create journal files
    # (Vercel's filesystem is read-only)
    uri = f"file:{DB_PATH}?mode=ro&immutable=1"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def commafy(value):
    try:
        return f"{int(value):,}"
    except (ValueError, TypeError):
        return str(value)


app.jinja_env.filters["commafy"] = commafy


@app.route("/")
def dashboard():
    stats = get_dashboard_stats()
    return render_template_string(DASHBOARD_HTML, stats=stats)


@app.route("/api/stats")
def api_stats():
    return jsonify(get_dashboard_stats())


@app.route("/api/rules")
def api_rules():
    return jsonify(search_rules(
        query=request.args.get("q", ""),
        vendor=request.args.get("vendor"),
        severity=request.args.get("severity"),
        language=request.args.get("language"),
        category=request.args.get("category"),
        page=int(request.args.get("page", 1)),
        per_page=int(request.args.get("per_page", 50)),
    ))


@app.route("/api/rules/<path:rule_id>")
def api_rule_detail(rule_id):
    conn = get_db()
    row = conn.execute("""
        SELECT r.*, v.name as vendor_name, v.display_name as vendor_display_name
        FROM rules r JOIN vendors v ON r.vendor_id=v.id
        WHERE r.rule_id=?
    """, (rule_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Rule not found"}), 404
    return jsonify(dict(row))


@app.route("/api/vendors")
def api_vendors():
    conn = get_db()
    rows = conn.execute("""
        SELECT v.*,
            (SELECT COUNT(*) FROM rules r WHERE r.vendor_id=v.id AND r.is_active=1) as active_rules
        FROM vendors v ORDER BY v.display_name
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/languages")
def api_languages():
    conn = get_db()
    rows = conn.execute("""
        SELECT language, COUNT(*) as count FROM rules
        WHERE is_active=1 AND language != '' GROUP BY language ORDER BY count DESC
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/categories")
def api_categories():
    conn = get_db()
    rows = conn.execute("""
        SELECT category, COUNT(*) as count FROM rules
        WHERE is_active=1 AND category != '' GROUP BY category ORDER BY count DESC
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ---------------------------------------------------------------------------
# Tool Config & CSV Export Endpoints
# ---------------------------------------------------------------------------

@app.route("/api/tool-configs")
def api_tool_configs():
    """Return all 40 tool configurations from Chris's spec."""
    return jsonify(get_tool_summary())


@app.route("/api/tool-configs/<tool_key>")
def api_tool_config_detail(tool_key):
    """Return a single tool's full configuration."""
    cfg = get_tool(tool_key)
    if not cfg:
        return jsonify({"error": f"Tool '{tool_key}' not found"}), 404
    return jsonify(cfg)


@app.route("/api/export/csv")
def api_export_csv():
    """
    Export rules as CSV for a specific vendor and optionally language.
    Uses the tool_config field definitions to produce Chris's exact CSV format.

    Query params:
      vendor  — vendor name (required)
      language — filter by language (optional)
      tool_key — use a specific tool_config key for field mapping (optional)
    """
    vendor = request.args.get("vendor")
    language = request.args.get("language")
    tool_key = request.args.get("tool_key")

    if not vendor:
        return jsonify({"error": "vendor parameter is required"}), 400

    conn = get_db()

    # Find the vendor in DB (case-insensitive, partial match)
    vendor_row = conn.execute(
        "SELECT * FROM vendors WHERE name=? OR display_name=?", (vendor, vendor)
    ).fetchone()
    if not vendor_row:
        # Try case-insensitive partial match
        vendor_row = conn.execute(
            "SELECT * FROM vendors WHERE LOWER(name)=LOWER(?) OR LOWER(display_name) LIKE LOWER(?)",
            (vendor, f"%{vendor}%"),
        ).fetchone()
    if not vendor_row:
        conn.close()
        return jsonify({"error": f"Vendor '{vendor}' not found in database"}), 404

    # Build query
    conditions = ["r.vendor_id=?", "r.is_active=1"]
    params = [vendor_row["id"]]
    if language:
        conditions.append("r.language=?")
        params.append(language)

    where = " AND ".join(conditions)
    rows = conn.execute(
        f"""SELECT r.*, v.name as vendor_name, v.display_name as vendor_display_name
            FROM rules r JOIN vendors v ON r.vendor_id=v.id
            WHERE {where} ORDER BY r.rule_id""",
        params,
    ).fetchall()
    conn.close()

    # Determine tool config for field mapping
    cfg = None
    if tool_key:
        cfg = get_tool(tool_key)
    if not cfg:
        # Try to auto-match vendor name to a tool config
        vendor_lower = vendor_row["name"].lower().replace(" ", "_").replace("-", "_")
        for key, tc in TOOL_CONFIGS.items():
            if (key == vendor_lower or
                tc["display_name"].lower() == vendor_row["display_name"].lower() or
                vendor_lower in key):
                cfg = tc
                tool_key = key
                break

    # Build CSV
    output = io.StringIO()
    if cfg:
        headers = get_csv_headers(tool_key)
        writer = csv.writer(output)
        writer.writerow(headers)

        for row in rows:
            row_dict = dict(row)
            csv_row = []
            for field_def in cfg["fields"]:
                db_field = field_def["db_field"]
                if "." in db_field:
                    # Handle nested metadata fields
                    parts = db_field.split(".", 1)
                    if parts[0] == "metadata":
                        try:
                            meta = json.loads(row_dict.get("metadata") or "{}")
                            val = meta.get(parts[1], "")
                        except (json.JSONDecodeError, TypeError):
                            val = ""
                    else:
                        val = row_dict.get(db_field, "")
                else:
                    val = row_dict.get(db_field, "")

                # Apply severity mapping
                if "severity" in field_def["csv_header"].lower() and tool_key:
                    val = map_severity(tool_key, val)

                # Apply classification mapping for SonarQube
                if field_def["csv_header"] == "Classification" and cfg.get("classification_map"):
                    val = cfg["classification_map"].get(
                        str(val).lower(), val
                    ) if val else ""

                csv_row.append(val or "")
            writer.writerow(csv_row)
    else:
        # Fallback: generic CSV with all standard fields
        headers = ["Rule ID", "Title", "Severity", "Category", "Language",
                   "CWE IDs", "OWASP IDs", "Tags", "Last Updated"]
        writer = csv.writer(output)
        writer.writerow(headers)
        for row in rows:
            row_dict = dict(row)
            writer.writerow([
                row_dict.get("rule_id", ""),
                row_dict.get("title", ""),
                row_dict.get("severity", ""),
                row_dict.get("category", ""),
                row_dict.get("language", ""),
                row_dict.get("cwe_ids", ""),
                row_dict.get("owasp_ids", ""),
                row_dict.get("tags", ""),
                row_dict.get("last_updated_at", ""),
            ])

    # Build filename
    filename_parts = [vendor_row["name"].replace(" ", "_")]
    if language:
        filename_parts.append(language)
    filename_parts.append("rules.csv")
    filename = "_".join(filename_parts)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def search_rules(query="", vendor=None, severity=None, language=None,
                 category=None, page=1, per_page=50):
    conn = get_db()
    conditions = ["r.is_active=1"]
    params = []

    if query:
        conditions.append(
            "r.id IN (SELECT rowid FROM rules_fts WHERE rules_fts MATCH ?)"
        )
        params.append(query)
    if vendor:
        conditions.append("v.name=?")
        params.append(vendor)
    if severity:
        conditions.append("r.severity=?")
        params.append(severity)
    if language:
        conditions.append("r.language=?")
        params.append(language)
    if category:
        conditions.append("r.category=?")
        params.append(category)

    where = " AND ".join(conditions)
    offset = (page - 1) * per_page

    count = conn.execute(
        f"SELECT COUNT(*) as c FROM rules r JOIN vendors v ON r.vendor_id=v.id WHERE {where}",
        params,
    ).fetchone()["c"]

    rows = conn.execute(
        f"""SELECT r.id, r.rule_id, r.title, r.severity, r.category, r.language,
                   r.cwe_ids, r.owasp_ids, r.tags, r.source_file, r.metadata,
                   r.last_updated_at, v.name as vendor_name, v.display_name as vendor_display_name
            FROM rules r JOIN vendors v ON r.vendor_id=v.id
            WHERE {where} ORDER BY r.last_updated_at DESC LIMIT ? OFFSET ?""",
        params + [per_page, offset],
    ).fetchall()
    conn.close()

    return {
        "rules": [dict(r) for r in rows],
        "total": count,
        "page": page,
        "per_page": per_page,
        "pages": (count + per_page - 1) // per_page,
    }


def get_dashboard_stats():
    conn = get_db()

    vendors = [
        dict(r)
        for r in conn.execute("""
        SELECT v.*,
            (SELECT COUNT(*) FROM rules r WHERE r.vendor_id=v.id AND r.is_active=1) as active_rules,
            (SELECT MAX(completed_at) FROM sync_history sh
             WHERE sh.vendor_id=v.id AND sh.status='success') as last_successful_sync
        FROM vendors v ORDER BY v.display_name
    """).fetchall()
    ]

    total_rules = conn.execute(
        "SELECT COUNT(*) as c FROM rules WHERE is_active=1"
    ).fetchone()["c"]

    severity_dist = [
        dict(r)
        for r in conn.execute("""
        SELECT severity, COUNT(*) as count FROM rules
        WHERE is_active=1 GROUP BY severity ORDER BY count DESC
    """).fetchall()
    ]

    language_dist = [
        dict(r)
        for r in conn.execute("""
        SELECT language, COUNT(*) as count FROM rules
        WHERE is_active=1 AND language != '' GROUP BY language ORDER BY count DESC LIMIT 30
    """).fetchall()
    ]

    category_dist = [
        dict(r)
        for r in conn.execute("""
        SELECT category, COUNT(*) as count FROM rules
        WHERE is_active=1 AND category != '' GROUP BY category ORDER BY count DESC LIMIT 50
    """).fetchall()
    ]

    recent_syncs = [
        dict(r)
        for r in conn.execute("""
        SELECT sh.*, v.display_name as vendor_name
        FROM sync_history sh JOIN vendors v ON sh.vendor_id=v.id
        ORDER BY sh.started_at DESC LIMIT 20
    """).fetchall()
    ]

    conn.close()

    return {
        "vendors": vendors,
        "total_rules": total_rules,
        "total_vendors": len(vendors),
        "severity_distribution": severity_dist,
        "language_distribution": language_dist,
        "category_distribution": category_dist,
        "recent_syncs": recent_syncs,
        "recent_changes": [],
        "tool_configs": get_tool_summary(),
    }


# ---------------------------------------------------------------------------
# Inline dashboard template (self-contained, no external template files)
# ---------------------------------------------------------------------------

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberSagacity — Rule Intelligence Platform</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
    <style>
        :root {
            --bg-primary: #0a0e17;
            --bg-secondary: #111827;
            --bg-card: #1a2332;
            --bg-card-hover: #1f2b3d;
            --border: #2a3a4e;
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --accent-purple: #8b5cf6;
            --accent-green: #10b981;
            --accent-amber: #f59e0b;
            --accent-red: #ef4444;
            --accent-rose: #f43f5e;
            --gradient-hero: linear-gradient(135deg, #06b6d4 0%, #3b82f6 50%, #8b5cf6 100%);
            --shadow-lg: 0 10px 25px -3px rgba(0,0,0,0.5);
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            background: var(--bg-primary); color: var(--text-primary); min-height: 100vh;
        }
        .header {
            background: var(--bg-secondary); border-bottom: 1px solid var(--border);
            padding: 1rem 2rem; display: flex; align-items: center; justify-content: space-between;
            position: sticky; top: 0; z-index: 100; backdrop-filter: blur(10px);
        }
        .logo { display: flex; align-items: center; gap: 0.75rem; }
        .logo-icon {
            width: 40px; height: 40px; background: var(--gradient-hero); border-radius: 10px;
            display: flex; align-items: center; justify-content: center;
            font-size: 1.2rem; font-weight: bold; color: white;
        }
        .logo-text {
            font-size: 1.25rem; font-weight: 700;
            background: var(--gradient-hero); -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }
        .logo-sub { font-size: 0.7rem; color: var(--text-muted); letter-spacing: 0.15em; text-transform: uppercase; }
        .header-right { display: flex; align-items: center; gap: 1rem; }
        .header-badge {
            padding: 0.35rem 0.75rem; border-radius: 20px; font-size: 0.75rem; font-weight: 600;
            background: rgba(6,182,212,0.15); color: var(--accent-cyan); border: 1px solid rgba(6,182,212,0.3);
        }
        .user-badge {
            padding: 0.35rem 0.75rem; border-radius: 20px; font-size: 0.75rem; font-weight: 600;
            background: rgba(139,92,246,0.15); color: var(--accent-purple); border: 1px solid rgba(139,92,246,0.3);
        }
        .main { max-width: 1400px; margin: 0 auto; padding: 2rem; }
        .hero-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1.25rem; margin-bottom: 2rem; }
        .stat-card {
            background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px;
            padding: 1.5rem; position: relative; overflow: hidden; transition: transform 0.2s, border-color 0.2s;
        }
        .stat-card:hover { transform: translateY(-2px); border-color: var(--accent-cyan); }
        .stat-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; border-radius: 12px 12px 0 0; }
        .stat-card:nth-child(1)::before { background: var(--gradient-hero); }
        .stat-card:nth-child(2)::before { background: var(--accent-green); }
        .stat-card:nth-child(3)::before { background: var(--accent-amber); }
        .stat-card:nth-child(4)::before { background: var(--accent-purple); }
        .stat-label { font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 0.5rem; }
        .stat-value { font-size: 2.25rem; font-weight: 800; line-height: 1; margin-bottom: 0.25rem; }
        .stat-card:nth-child(1) .stat-value { color: var(--accent-cyan); }
        .stat-card:nth-child(2) .stat-value { color: var(--accent-green); }
        .stat-card:nth-child(3) .stat-value { color: var(--accent-amber); }
        .stat-card:nth-child(4) .stat-value { color: var(--accent-purple); }
        .stat-detail { font-size: 0.75rem; color: var(--text-secondary); }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 2rem; }
        .card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; }
        .card-title {
            font-size: 0.9rem; font-weight: 600; color: var(--text-secondary);
            text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 1.25rem;
            display: flex; align-items: center; gap: 0.5rem;
        }
        .card-title-icon { font-size: 1rem; }
        .vendor-table { width: 100%; border-collapse: collapse; }
        .vendor-table th {
            text-align: left; padding: 0.6rem 0.75rem; font-size: 0.7rem;
            text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-muted);
            border-bottom: 1px solid var(--border);
        }
        .vendor-table td { padding: 0.75rem; border-bottom: 1px solid rgba(42,58,78,0.5); font-size: 0.85rem; }
        .vendor-table tr:hover td { background: var(--bg-card-hover); }
        .vendor-name { font-weight: 600; color: var(--accent-cyan); }
        .vendor-rules { font-weight: 700; color: var(--accent-green); font-variant-numeric: tabular-nums; }
        .status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 0.4rem; }
        .status-active { background: var(--accent-green); box-shadow: 0 0 6px var(--accent-green); }
        .sev-badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }
        .sev-critical { background: rgba(239,68,68,0.2); color: #f87171; }
        .sev-high { background: rgba(244,63,94,0.2); color: #fb7185; }
        .sev-medium { background: rgba(245,158,11,0.2); color: #fbbf24; }
        .sev-low { background: rgba(59,130,246,0.2); color: #60a5fa; }
        .sev-info { background: rgba(100,116,139,0.2); color: #94a3b8; }
        .chart-container { position: relative; height: 280px; }
        .search-section { margin-bottom: 2rem; }
        .search-bar { display: flex; gap: 0.75rem; align-items: center; flex-wrap: wrap; }
        .search-input {
            flex: 1; min-width: 200px; background: var(--bg-card); border: 1px solid var(--border);
            border-radius: 10px; padding: 0.85rem 1.25rem; font-size: 0.95rem;
            color: var(--text-primary); outline: none; transition: border-color 0.2s;
        }
        .search-input:focus { border-color: var(--accent-cyan); box-shadow: 0 0 0 3px rgba(6,182,212,0.1); }
        .search-input::placeholder { color: var(--text-muted); }
        .filter-select {
            background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px;
            padding: 0.85rem 1rem; font-size: 0.85rem; color: var(--text-primary);
            outline: none; min-width: 140px; cursor: pointer;
        }
        .search-btn {
            background: var(--gradient-hero); border: none; border-radius: 10px;
            padding: 0.85rem 1.75rem; font-size: 0.9rem; font-weight: 600; color: white;
            cursor: pointer; transition: opacity 0.2s; white-space: nowrap;
        }
        .search-btn:hover { opacity: 0.9; }
        .results-list { margin-top: 1rem; }
        .result-item {
            background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px;
            padding: 1rem 1.25rem; margin-bottom: 0.75rem; transition: border-color 0.2s; cursor: pointer;
        }
        .result-item:hover { border-color: var(--accent-cyan); }
        .result-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.4rem; flex-wrap: wrap; }
        .result-vendor { font-size: 0.7rem; padding: 0.15rem 0.5rem; border-radius: 4px; background: rgba(6,182,212,0.15); color: var(--accent-cyan); font-weight: 600; }
        .result-id { font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.8rem; color: var(--text-secondary); word-break: break-all; }
        .result-title { font-weight: 600; font-size: 0.95rem; color: var(--text-primary); }
        .result-meta { display: flex; gap: 1rem; margin-top: 0.4rem; font-size: 0.75rem; color: var(--text-muted); flex-wrap: wrap; }
        .result-count { font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 1rem; }
        .lang-pill {
            display: inline-flex; align-items: center; gap: 0.4rem;
            padding: 0.3rem 0.65rem; background: rgba(59,130,246,0.1);
            border: 1px solid rgba(59,130,246,0.2); border-radius: 6px;
            font-size: 0.75rem; color: var(--accent-blue); margin: 0.2rem;
        }
        .lang-count { font-weight: 700; color: var(--text-primary); }
        .sync-item { display: flex; align-items: center; gap: 0.75rem; padding: 0.6rem 0; border-bottom: 1px solid rgba(42,58,78,0.3); font-size: 0.8rem; }
        .sync-status { padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.7rem; font-weight: 600; }
        .sync-success { background: rgba(16,185,129,0.2); color: var(--accent-green); }
        .sync-failed { background: rgba(239,68,68,0.2); color: var(--accent-red); }
        .footer { text-align: center; padding: 2rem; color: var(--text-muted); font-size: 0.75rem; border-top: 1px solid var(--border); margin-top: 2rem; }
        .footer a { color: var(--accent-cyan); text-decoration: none; }
        .spinner { display: inline-block; width: 16px; height: 16px; border: 2px solid var(--border); border-top-color: var(--accent-cyan); border-radius: 50%; animation: spin 0.8s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        .pulse { animation: pulse 2s ease-in-out infinite; }
        .tool-spec-card:hover { border-color: var(--accent-cyan); }
        @media (max-width: 1024px) { .hero-stats { grid-template-columns: repeat(2, 1fr); } .grid-2 { grid-template-columns: 1fr; } }
        @media (max-width: 640px) { .hero-stats { grid-template-columns: 1fr; } .header { padding: 0.75rem 1rem; } .main { padding: 1rem; } .search-bar { flex-direction: column; } .filter-select { width: 100%; } }
    </style>
</head>
<body>
    <header class="header">
        <div class="logo">
            <div class="logo-icon">CS</div>
            <div>
                <div class="logo-text">CyberSagacity</div>
                <div class="logo-sub">Rule Intelligence Platform</div>
            </div>
        </div>
        <div class="header-right">
            <span class="header-badge pulse">{{ stats.total_rules|default(0)|commafy }} Rules Indexed</span>
            <span class="user-badge">Chris Near &bull; Founder</span>
        </div>
    </header>

    <main class="main">
        <section class="hero-stats">
            <div class="stat-card">
                <div class="stat-label">Total Security Rules</div>
                <div class="stat-value">{{ stats.total_rules|default(0)|commafy }}</div>
                <div class="stat-detail">Across all vendors</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Active Vendors</div>
                <div class="stat-value">{{ stats.total_vendors|default(0) }}</div>
                <div class="stat-detail">Scanning tool sources</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Languages Covered</div>
                <div class="stat-value">{{ stats.language_distribution|default([])|length }}</div>
                <div class="stat-detail">Programming languages</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Tool Specifications</div>
                <div class="stat-value">{{ stats.tool_configs|default([])|length }}</div>
                <div class="stat-detail">From Chris Near's spec</div>
            </div>
        </section>

        <section class="search-section">
            <div class="search-bar">
                <input type="text" class="search-input" id="searchInput"
                       placeholder="Search 30,000+ rules — try 'SQL injection', 'XSS', 'deserialization', 'crypto'...">
                <select class="filter-select" id="vendorFilter">
                    <option value="">All Vendors</option>
                    {% for v in stats.vendors|default([]) %}
                    <option value="{{ v.name }}">{{ v.display_name }}</option>
                    {% endfor %}
                </select>
                <select class="filter-select" id="severityFilter">
                    <option value="">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                </select>
                <select class="filter-select" id="categoryFilter">
                    <option value="">All Categories</option>
                    {% for c in stats.category_distribution|default([]) %}
                    <option value="{{ c.category }}">{{ c.category }} ({{ c.count|commafy }})</option>
                    {% endfor %}
                </select>
                <select class="filter-select" id="languageFilter">
                    <option value="">All Languages</option>
                    {% for l in stats.language_distribution|default([]) %}
                    <option value="{{ l.language }}">{{ l.language }} ({{ l.count|commafy }})</option>
                    {% endfor %}
                </select>
                <button class="search-btn" onclick="searchRules()">Search</button>
            </div>
            <div class="results-list" id="searchResults"></div>
        </section>

        <!-- CSV Export Section -->
        <section class="card" style="margin-bottom: 2rem;">
            <div class="card-title"><span class="card-title-icon">&#x1F4E5;</span> CSV Export</div>
            <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 1rem;">
                Download rules as CSV per vendor and language. Each tool uses its own field definitions from Chris's spec.
            </p>
            <div style="display: flex; gap: 0.75rem; align-items: center; flex-wrap: wrap;">
                <select class="filter-select" id="csvVendor">
                    <option value="">Select Vendor</option>
                    {% for v in stats.vendors|default([]) %}
                    <option value="{{ v.name }}">{{ v.display_name }} ({{ v.active_rules|default(0)|commafy }})</option>
                    {% endfor %}
                </select>
                <select class="filter-select" id="csvLanguage">
                    <option value="">All Languages</option>
                    {% for l in stats.language_distribution|default([]) %}
                    <option value="{{ l.language }}">{{ l.language }}</option>
                    {% endfor %}
                </select>
                <button class="search-btn" onclick="exportCsv()">&#x2B07; Download CSV</button>
                <span id="csvStatus" style="font-size: 0.8rem; color: var(--text-muted);"></span>
            </div>
        </section>

        <section class="grid-2">
            <div class="card">
                <div class="card-title"><span class="card-title-icon">&#x1F4BB;</span> Rules by Vendor</div>
                <div class="chart-container"><canvas id="vendorChart"></canvas></div>
            </div>
            <div class="card">
                <div class="card-title"><span class="card-title-icon">&#x1F310;</span> Rules by Language (Top 15)</div>
                <div class="chart-container"><canvas id="languageChart"></canvas></div>
            </div>
        </section>

        <section class="grid-2">
            <div class="card">
                <div class="card-title"><span class="card-title-icon">&#x1F50D;</span> Vendor Sources</div>
                <table class="vendor-table">
                    <thead><tr><th>Vendor</th><th>Rules</th><th>Last Sync</th><th>Status</th></tr></thead>
                    <tbody>
                        {% for v in stats.vendors|default([]) %}
                        <tr>
                            <td><span class="vendor-name">{{ v.display_name }}</span></td>
                            <td><span class="vendor-rules">{{ v.active_rules|default(0)|commafy }}</span></td>
                            <td style="color: var(--text-muted); font-size: 0.8rem;">{{ (v.last_successful_sync or 'Never')|truncate(10, True, '') }}</td>
                            <td>{% if v.active_rules|default(0) > 0 %}<span class="status-dot status-active"></span>Active{% else %}<span class="status-dot"></span>Pending{% endif %}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            <div class="card">
                <div class="card-title"><span class="card-title-icon">&#x1F310;</span> Language Coverage</div>
                <div style="display: flex; flex-wrap: wrap; gap: 0.25rem; padding: 0.5rem 0;">
                    {% for l in stats.language_distribution|default([]) %}
                    <span class="lang-pill">{{ l.language }} <span class="lang-count">{{ l.count|commafy }}</span></span>
                    {% endfor %}
                </div>
            </div>
        </section>

        <section class="grid-2">
            <div class="card">
                <div class="card-title"><span class="card-title-icon">&#x1F504;</span> Recent Syncs</div>
                {% for s in stats.recent_syncs|default([])|batch(10)|first|default([]) %}
                <div class="sync-item">
                    <span class="sync-status {% if s.status == 'success' %}sync-success{% elif s.status == 'failed' %}sync-failed{% endif %}">{{ s.status }}</span>
                    <span style="color: var(--accent-cyan); font-weight: 600;">{{ s.vendor_name }}</span>
                    <span style="color: var(--text-muted); margin-left: auto; font-size: 0.75rem;">
                        {% if s.status == 'success' %}+{{ s.rules_added }} / ~{{ s.rules_updated }}{% endif %}
                        {{ (s.started_at or '')|truncate(16, True, '') }}
                    </span>
                </div>
                {% endfor %}
            </div>
            <div class="card">
                <div class="card-title"><span class="card-title-icon">&#x1F504;</span> Sync Schedule</div>
                <div style="font-size: 0.85rem; color: var(--text-secondary); line-height: 1.7;">
                    <p>Rules are synced via <code style="color: var(--accent-cyan); background: rgba(6,182,212,0.1); padding: 0.1rem 0.4rem; border-radius: 4px;">python cli.py sync</code></p>
                    <p style="margin-top: 0.5rem;">Each vendor is pulled from its upstream source (GitHub repos, API endpoints) and rules are parsed, normalized, and stored in the database.</p>
                </div>
            </div>
        </section>

        <!-- Tool Specifications (Chris's 40-tool spec) -->
        <section class="card" style="margin-bottom: 2rem;">
            <div class="card-title"><span class="card-title-icon">&#x1F6E1;</span> Tool Specifications ({{ stats.tool_configs|default([])|length }} Tools)</div>
            <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 1rem;">
                Full tool specifications from Chris Near's Rule_Gathering document. Each tool has unique fields, severity mappings, and language support.
            </p>
            <div style="display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap;">
                <input type="text" class="search-input" id="toolSearch" placeholder="Filter tools..." style="max-width: 300px; padding: 0.6rem 1rem; font-size: 0.85rem;">
                <span style="font-size: 0.8rem; color: var(--text-muted); align-self: center;" id="toolCount"></span>
            </div>
            <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 0.75rem;" id="toolGrid">
                {% for tc in stats.tool_configs|default([]) %}
                <div class="tool-spec-card" data-name="{{ tc.display_name|lower }}" style="background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; transition: border-color 0.2s;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                        <span style="font-weight: 600; color: var(--accent-cyan); font-size: 0.85rem;">{{ tc.display_name }}</span>
                        {% if tc.active %}<span style="font-size: 0.65rem; padding: 0.1rem 0.4rem; border-radius: 3px; background: rgba(16,185,129,0.2); color: var(--accent-green);">Active</span>
                        {% else %}<span style="font-size: 0.65rem; padding: 0.1rem 0.4rem; border-radius: 3px; background: rgba(100,116,139,0.2); color: var(--text-muted);">Inactive</span>{% endif %}
                    </div>
                    <div style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 0.3rem;">{{ tc.field_count }} fields &bull; {{ tc.language_count }} languages</div>
                    <div style="font-size: 0.7rem; color: var(--text-secondary);">{{ tc.languages[:3]|join(', ') }}{% if tc.languages|length > 3 %}, +{{ tc.languages|length - 3 }} more{% endif %}</div>
                </div>
                {% endfor %}
            </div>
        </section>
    </main>

    <footer class="footer">
        <p>CyberSagacity Rule Intelligence Platform &bull; Built for Chris Near &bull; Powered by open-source security intelligence</p>
        <p style="margin-top: 0.5rem;">{{ stats.tool_configs|default([])|length }} tool specifications loaded &bull; {{ stats.total_rules|default(0)|commafy }} rules indexed &bull; {{ stats.total_vendors|default(0) }} active vendors</p>
    </footer>

    <script>
        Chart.defaults.color = '#94a3b8';
        Chart.defaults.borderColor = 'rgba(42, 58, 78, 0.5)';
        Chart.defaults.font.family = "'Inter', sans-serif";

        const vendors = {{ stats.vendors|default([])|tojson }};
        const vendorColors = ['#06b6d4','#3b82f6','#8b5cf6','#10b981','#f59e0b','#ef4444','#ec4899','#14b8a6','#f97316','#6366f1'];
        if (vendors.length > 0) {
            new Chart(document.getElementById('vendorChart'), {
                type: 'bar',
                data: {
                    labels: vendors.map(v => v.display_name),
                    datasets: [{ label: 'Rules', data: vendors.map(v => v.active_rules || 0), backgroundColor: vendorColors.slice(0, vendors.length), borderRadius: 6, borderSkipped: false }]
                },
                options: { responsive: true, maintainAspectRatio: false, indexAxis: 'y', plugins: { legend: { display: false } }, scales: { x: { grid: { color: 'rgba(42,58,78,0.3)' } }, y: { grid: { display: false } } } }
            });
        }

        const langData = {{ stats.language_distribution|default([])|tojson }};
        if (langData.length > 0) {
            const top15 = langData.slice(0, 15);
            const langColors = ['#06b6d4','#3b82f6','#8b5cf6','#10b981','#f59e0b','#ef4444','#ec4899','#14b8a6','#f97316','#6366f1','#a855f7','#22d3ee','#84cc16','#fb923c','#64748b'];
            new Chart(document.getElementById('languageChart'), {
                type: 'bar',
                data: {
                    labels: top15.map(l => l.language),
                    datasets: [{ label: 'Rules', data: top15.map(l => l.count), backgroundColor: langColors.slice(0, top15.length), borderRadius: 4, borderSkipped: false }]
                },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { grid: { display: false }, ticks: { maxRotation: 45 } }, y: { grid: { color: 'rgba(42,58,78,0.3)' } } } }
            });
        }

        /* CSV Export */
        function exportCsv() {
            const vendor = document.getElementById('csvVendor').value;
            const language = document.getElementById('csvLanguage').value;
            const status = document.getElementById('csvStatus');
            if (!vendor) { status.textContent = 'Please select a vendor.'; status.style.color = 'var(--accent-amber)'; return; }
            const params = new URLSearchParams({ vendor });
            if (language) params.set('language', language);
            status.textContent = 'Downloading...'; status.style.color = 'var(--accent-cyan)';
            window.location.href = '/api/export/csv?' + params.toString();
            setTimeout(() => { status.textContent = 'Download started.'; status.style.color = 'var(--accent-green)'; }, 500);
        }

        /* Tool spec filter */
        const toolSearchInput = document.getElementById('toolSearch');
        const toolCards = document.querySelectorAll('.tool-spec-card');
        const toolCountEl = document.getElementById('toolCount');
        function filterTools() {
            const q = toolSearchInput.value.toLowerCase();
            let visible = 0;
            toolCards.forEach(card => {
                const match = card.dataset.name.includes(q);
                card.style.display = match ? '' : 'none';
                if (match) visible++;
            });
            toolCountEl.textContent = q ? visible + ' of ' + toolCards.length + ' tools' : toolCards.length + ' tools';
        }
        toolSearchInput.addEventListener('input', filterTools);
        filterTools();

        async function searchRules() {
            const query = document.getElementById('searchInput').value;
            const vendor = document.getElementById('vendorFilter').value;
            const severity = document.getElementById('severityFilter').value;
            const category = document.getElementById('categoryFilter').value;
            const language = document.getElementById('languageFilter').value;
            const container = document.getElementById('searchResults');
            container.innerHTML = '<div style="text-align:center; padding:1rem;"><span class="spinner"></span> Searching...</div>';
            try {
                const params = new URLSearchParams();
                if (query) params.set('q', query);
                if (vendor) params.set('vendor', vendor);
                if (severity) params.set('severity', severity);
                if (category) params.set('category', category);
                if (language) params.set('language', language);
                params.set('per_page', '25');
                const resp = await fetch('/api/rules?' + params.toString());
                const data = await resp.json();
                if (data.rules.length === 0) {
                    container.innerHTML = '<div class="result-count" style="text-align:center; padding:2rem; color:var(--text-muted);">No rules found. Try a different search.</div>';
                    return;
                }
                let html = '<div class="result-count">' + data.total.toLocaleString() + ' rules found</div>';
                for (const r of data.rules) {
                    html += '<div class="result-item"><div class="result-header">' +
                        '<span class="sev-badge sev-' + r.severity + '">' + r.severity + '</span>' +
                        '<span class="result-vendor">' + r.vendor_display_name + '</span>' +
                        '<span class="result-id">' + escapeHtml(r.rule_id) + '</span></div>' +
                        '<div class="result-title">' + escapeHtml(r.title || '') + '</div>' +
                        '<div class="result-meta">' +
                        (r.language ? '<span>Language: ' + r.language + '</span>' : '') +
                        (r.category ? '<span>Category: ' + r.category + '</span>' : '') +
                        '<span>Updated: ' + (r.last_updated_at || '').slice(0, 10) + '</span></div></div>';
                }
                container.innerHTML = html;
            } catch (e) {
                container.innerHTML = '<div style="color:var(--accent-red); padding:1rem;">Search failed: ' + e.message + '</div>';
            }
        }
        function escapeHtml(str) { const d = document.createElement('div'); d.textContent = str; return d.innerHTML; }
        document.getElementById('searchInput').addEventListener('keypress', function(e) { if (e.key === 'Enter') searchRules(); });
    </script>
</body>
</html>"""
