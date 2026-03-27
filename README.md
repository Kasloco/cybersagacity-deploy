# CyberSagacity Rule Intelligence Platform — Vercel Deployment

Production deployment of the CyberSagacity Rule Intelligence Platform, serving **30,843 security rules** from a bundled SQLite database via Vercel serverless functions.

🔗 **Live:** [cybersagacity-deploy.vercel.app](https://cybersagacity-deploy.vercel.app)

📦 **Source project:** [cybersagacity-rule-aggregator](https://github.com/Kasloco/cybersagacity-rule-aggregator)

---

## Architecture

This is a self-contained Vercel deployment that packages:

- A **Flask serverless function** (`api/index.py`) that serves both the HTML dashboard and the REST API
- A **slim SQLite database** (`data/rules.db`, ~20MB) containing all 30,843 rules with metadata — stripped of raw rule content to stay within Vercel's deployment size limits
- **Chart.js** visualizations for severity, vendor, and category breakdowns
- **Full-text search** (SQLite FTS5) across all rules

## Endpoints

| URL | Description |
|-----|-------------|
| `/` | Interactive dashboard with charts, search, and filters |
| `/api/stats` | JSON — totals, severity/language/category distributions |
| `/api/rules?q=&vendor=&severity=&category=&language=&page=&per_page=` | JSON — search rules with filters |
| `/api/rules/<rule_id>` | JSON — single rule detail |
| `/api/vendors` | JSON — all vendors with rule counts |
| `/api/languages` | JSON — language distribution |
| `/api/categories` | JSON — category distribution |

## Vendors Included

| Vendor | Rules |
|--------|------:|
| Nuclei (ProjectDiscovery) | 12,818 |
| Semgrep | 7,856 |
| SonarQube (SonarSource) | 6,711 |
| Checkmarx KICS | 1,811 |
| Trivy (Aqua Security) | 905 |
| PMD | 449 |
| FindSecBugs | 144 |
| Falco (CNCF) | 93 |
| Bandit (PyCQA) | 42 |
| ESLint Security | 14 |

## Updating the Database

The database is a snapshot. To update it with the latest rules:

1. Run a full sync in the [main project](https://github.com/Kasloco/cybersagacity-rule-aggregator):
   ```bash
   cd cybersagacity-rule-aggregator
   python cli.py sync
   ```

2. Generate a slim database (strips raw rule content to reduce size):
   ```bash
   python -c "
   import sqlite3, os, json
   src = sqlite3.connect('rules.db')
   dst = sqlite3.connect('rules_slim.db')
   # ... (see main project for full script)
   "
   ```

3. Copy `rules_slim.db` → `cybersagacity-deploy/data/rules.db`

4. Redeploy:
   ```bash
   cd cybersagacity-deploy
   npx vercel --prod
   ```

## Local Development

```bash
pip install flask flask-cors
python -c "from api.index import app; app.run(debug=True, port=8080)"
# Open http://localhost:8080
```

## Project Structure

```
cybersagacity-deploy/
├── vercel.json          # Vercel routing config
├── requirements.txt     # Python deps (flask, flask-cors)
├── api/
│   └── index.py         # Flask app — dashboard + API + inline HTML template
└── data/
    └── rules.db         # Slim SQLite database (~20MB)
```

---

*Built by Jonathan Kaslow for CyberSagacity*
