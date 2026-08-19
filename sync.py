#!/usr/bin/env python3
"""
Sync script for GitHub Actions / local use.

Clones (or updates) the cybersagacity-rule-aggregator repo, syncs ONLY
the vendors Chris Near has approved, and produces a deployment-optimized
rules.db in the deploy repo's data/ directory.

The deploy DB strips rule_changes, sync_history, and rule_content
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

# ---------------------------------------------------------------------------
# Supported vendors — only these collectors are run during sync.
#
# This list maps to Chris Near's tool spec (tool_config.py). Only tools
# marked active=True in the spec are included here. Tools that exist in
# the aggregator but are NOT in Chris's spec (Nuclei, Checkov, Brakeman,
# Falco, etc.) or are marked inactive (FindBugs, Flawfinder, CodeQL,
# ErrorProne, Joern, Grype, OSV-Scanner, TruffleHog, Gitleaks) are
# excluded — their rules will not appear in the deployed DB.
#
# NOTE: Some tools in Chris's spec don't have collectors yet (Adacore
# Codepeer, Checkmarx 9/One, Coverity, JFrog, Klocwork, Parasoft,
# StackHawk, Tenable, Veracode DAST, Wallarm, npm). Those are skipped
# gracefully — the CLI reports "Unknown vendor" and continues.
# Tools like detekt, SwiftLint, ShellCheck, Hadolint, PHPStan, Psalm,
# Checkov, Tfsec, Trivy, Retire.js, Nuclei, Falco, Brakeman, gosec,
# OWASP Dependency-Check exist in the aggregator but are NOT in Chris's
# spec, so they're excluded from this list.
# ---------------------------------------------------------------------------
SUPPORTED_VENDORS = [
    "adacore_codepeer",
    "bandit",
    "checkmarx_cxsast",     # maps to checkmarx_9_sast + checkmarx_one_sast
    "clang",
    "coverity",             # maps to blackduck_coverity
    "cppcheck",
    "deque_axe",
    "dlint",
    "eslint_security",      # maps to eslint in spec
    "findsecbugs",
    "fortify",              # maps to opentext_fortify
    "gitlab_advanced_sast",
    "gitlab_dast",
    "gitlab_sast",          # maps to gitlab in spec
    "infer",                # maps to facebook_infer
    "mend_sast",            # maps to mend
    "mobsf",
    "nodejsscan",           # maps to nodejs_scan
    "njsscan",
    "owasp_zap",
    "php_codesniffer",
    "phpcs_security_audit",
    "phpmd",
    "pmd",
    "pylint",
    "security_code_scan",
    "semgrep",
    "snyk",                 # maps to snyk_code_sast
    "sonarqube",
    "spotbugs",
    "veracode",             # maps to veracode_sast
    # --- New collectors (built below) ---
    "npm_audit",
    "snyk_oss_sca",
    "veracode_dast",
    "wallarm_api",
    "tenable_was",
    "stackhawk",
    "jfrog_xray",
    "parasoft_insure",
    "klocwork",
    "adacore_codepeer",
    "checkmarx_dast",
    "checkmarx_one_sast",
    # --- Activated by Kas (2026-08-17) ---
    "flawfinder",
    "joern",
    "osv_scanner",
    # --- ESLint plugin ecosystem (per Chris Near review 8/19/26) ---
    "typescript-eslint",
    "stylistic-eslint",
    "eslint-react",
    "react-hooks-eslint",
]


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


def slim_for_deploy(src_db: Path, dest_db: Path, supported_vendors: list[str] | None = None):
    """Copy the aggregator DB and strip data not needed for deployment.

    Strips:
    1. rule_changes — accumulates full old/new rule content on every sync
       (390MB+ for a fresh sync of 37k rules). Dashboard never reads it.
    2. sync_history — audit log, not needed on a read-only deploy.
    3. rule_content — raw rule definitions (YAML/JSON/XML/Rego), 56MB+.
       Dropping it keeps the DB under GitHub's 100MB file size limit.
    4. Vendors not in the supported list are DELETED entirely (their rules
       and the vendor row). Only Chris Near's active spec tools appear
       in the deploy DB and on the dashboard.
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

    # Delete vendors not in the supported list entirely
    if supported_vendors:
        placeholders = ",".join("?" * len(supported_vendors))
        # Get vendor IDs to remove
        rows = conn.execute(
            f"SELECT id, display_name FROM vendors WHERE name NOT IN ({placeholders})",
            supported_vendors,
        ).fetchall()
        if rows:
            ids = [r[0] for r in rows]
            id_placeholders = ",".join("?" * len(ids))
            # Delete rules for these vendors
            conn.execute(
                f"DELETE FROM rules WHERE vendor_id IN ({id_placeholders})",
                ids,
            )
            # Delete FTS entries for the removed rules
            conn.execute(
                f"DELETE FROM rules_fts WHERE rowid IN "
                f"(SELECT id FROM rules WHERE vendor_id IN ({id_placeholders}))",
                ids,
            )
            # Delete the vendor rows
            conn.execute(
                f"DELETE FROM vendors WHERE id IN ({id_placeholders})",
                ids,
            )
            names = [r[1] for r in rows]
            print(f"Deleted {len(ids)} non-spec vendors: {', '.join(names)}")

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

    # Run the sync — only supported vendors
    env = os.environ.copy()
    env["RULE_AGGREGATOR_DB"] = str(db_path)

    print("Running setup (init DB + register vendors)...")
    run(["python", "cli.py", "setup"], cwd=agg_dir, env=env)

    # Sync each supported vendor individually
    print(f"\nSyncing {len(SUPPORTED_VENDORS)} supported vendors...")
    for vendor in SUPPORTED_VENDORS:
        sync_cmd = ["python", "cli.py", "sync", "--vendor", vendor]
        if args.force:
            sync_cmd.append("--force")
        # Don't raise on failure — some collectors may fail (e.g. file-based
        # sources without local files). Just log and continue.
        run(sync_cmd, cwd=agg_dir, env=env, check=False)

    # Show status
    print("\n=== Status ===")
    run(["python", "cli.py", "status"], cwd=agg_dir, env=env)

    # Build deployment-optimized DB
    if not db_path.exists():
        print(f"ERROR: rules.db not found at {db_path}", file=sys.stderr)
        sys.exit(1)
    slim_for_deploy(db_path, DB_PATH, SUPPORTED_VENDORS)


if __name__ == "__main__":
    main()