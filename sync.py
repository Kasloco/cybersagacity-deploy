#!/usr/bin/env python3
"""
Sync script for GitHub Actions / local use.

Clones (or updates) the cybersagacity-rule-aggregator repo, runs a full
sync, and produces a deployment-optimized rules.db in the deploy repo's
data/ directory. The deploy DB strips rule_changes and sync_history
(not needed on Vercel) and vacuums to minimize file size.

Usage:
    python sync.py            # normal sync
    python sync.py --force    # force re-sync all vendors
"""

import argparse
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

AGGREGATOR_REPO = "https://github.com/Kasloco/cybersagacity-rule-aggregator.git"
AGGREGATOR_DIR = Path(os.environ.get("AGGREGATOR_DIR", "/tmp/aggregator"))
DEPLOY_DIR = Path(__file__).resolve().parent
DB_PATH = DEPLOY_DIR / "data" / "rules.db"


def run(cmd, cwd=None, check=True, env=None):
    """Run a command, streaming output to stdout/stderr."""
    print(f">>> {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    result = subprocess.run(
        cmd if isinstance(cmd, list) else cmd,
        shell=isinstance(cmd, str),
        cwd=str(cwd) if cwd else None,
        check=check,
        env=env,
    )
    return result.returncode


def slim_for_deploy(src_db: Path, dest_db: Path):
    """Copy the aggregator DB and strip data not needed for deployment.

    Three things get stripped:
    1. rule_changes — accumulates full old/new rule content on every sync
       (390MB+ for a fresh sync of 37k rules). Dashboard never reads it.
    2. sync_history — audit log, not needed on a read-only deploy.
    3. rule_content — raw rule definitions (YAML/JSON/XML/Rego), 56MB+.
       The dashboard's search/listing endpoints don't use it. The detail
       endpoint returns it but it's mostly noise in a browser context.
       Dropping it keeps the DB under GitHub's 100MB file size limit.

    Result: ~63MB instead of 512MB, with all 37k rules + FTS intact.
    """
    print(f"\nBuilding deployment DB (stripping change history + rule content)...")
    dest_db.parent.mkdir(parents=True, exist_ok=True)
    if dest_db.exists():
        dest_db.unlink()
    shutil.copy2(str(src_db), str(dest_db))

    conn = sqlite3.connect(str(dest_db))
    conn.isolation_level = None  # autocommit mode required for VACUUM
    conn.execute("DELETE FROM rule_changes;")
    conn.execute("DELETE FROM sync_history;")
    conn.execute("UPDATE rules SET rule_content = '';")
    conn.execute("VACUUM;")
    conn.close()

    print(f"Deploy DB: {dest_db} ({dest_db.stat().st_size:,} bytes)")


def main():
    parser = argparse.ArgumentParser(description="Sync rules.db for deployment")
    parser.add_argument("--force", action="store_true", help="Force re-sync all vendors")
    parser.add_argument("--aggregator-dir", default=str(AGGREGATOR_DIR),
                        help="Where to clone/update the aggregator repo")
    args = parser.parse_args()

    agg_dir = Path(args.aggregator_dir)
    db_path = agg_dir / "rules.db"

    # Clone or update the aggregator repo
    if (agg_dir / ".git").exists():
        print(f"Updating aggregator repo at {agg_dir}...")
        run(["git", "pull", "--ff-only"], cwd=agg_dir)
    else:
        print(f"Cloning aggregator repo to {agg_dir}...")
        run(["git", "clone", "--depth", "1", AGGREGATOR_REPO, str(agg_dir)])

    # Install dependencies
    print("Installing dependencies...")
    run(["pip", "install", "--no-cache-dir", "-r", str(agg_dir / "requirements.txt")])
    # bs4 is needed by the Fortify collector but not in requirements.txt
    run(["pip", "install", "--no-cache-dir", "beautifulsoup4"])

    # Run the sync
    env = os.environ.copy()
    env["RULE_AGGREGATOR_DB"] = str(db_path)

    print("Running setup (init DB + register vendors)...")
    run(["python", "cli.py", "setup"], cwd=agg_dir, env=env)

    sync_cmd = ["python", "cli.py", "sync"]
    if args.force:
        sync_cmd.append("--force")
    print("Running sync...")
    run(sync_cmd, cwd=agg_dir, env=env)

    # Show status
    print("\n=== Status ===")
    run(["python", "cli.py", "status"], cwd=agg_dir, env=env)

    # Build deployment-optimized DB
    if not db_path.exists():
        print(f"ERROR: rules.db not found at {db_path}", file=sys.stderr)
        sys.exit(1)
    slim_for_deploy(db_path, DB_PATH)


if __name__ == "__main__":
    main()