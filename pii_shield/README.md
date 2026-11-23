# PII Shield

A Flask web app that finds personal data in text and produces a redacted copy. It targets identifiers common in India (Aadhaar, PAN, UPI IDs, GSTIN, IFSC, passport, voter ID, mobile numbers) plus emails, payment cards, IPv4 addresses and dates that may be birth dates.

## Features

- **Scanner page** with paste or file upload (.txt, .csv, .tsv, .log, .md, .json)
- **Validation, not just patterns**: Verhoeff checksum for Aadhaar, Luhn for cards, real-date checks, IP range checks, PAN holder-type check. Impossible matches are dropped; weak ones are marked low confidence
- **Three redaction styles**: partial mask, type label (`[EMAIL]`), solid block
- **Highlighted and redacted views**, severity and confidence for each hit, line and column positions, copy and download
- **Choose which data types to scan for**
- **JSON API** (`/api/v1/scan`, `/api/v1/detectors`) with docs at `/api`
- **Security**: strict CSP, CSRF token, per-IP rate limiting, size limits, `no-store` on scan responses, output escaping, non-root Docker image
- **Nothing is stored**; logs contain only character and finding counts
- Responsive layout, light and dark themes, keyboard and screen-reader friendly

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. Use **Load sample data** to try it.

## Run the tests

```bash
python -m unittest discover -s tests -v
```

## Deploy

With gunicorn:

```bash
gunicorn --bind 0.0.0.0:8000 --workers 2 wsgi:app
```

With Docker:

```bash
docker build -t pii-shield .
docker run -p 8000:8000 pii-shield
```

Put it behind HTTPS (a reverse proxy, Render, Railway, Fly.io, Cloud Run and similar all work). If a proxy sets `X-Forwarded-*` headers, set `TRUST_PROXY=1` so rate limiting sees real client IPs.

## Configuration

Set through environment variables (see `.env.example`):

| Variable | Default | Purpose |
| --- | --- | --- |
| `MAX_CHARS` | 20000 | Longest text accepted |
| `MAX_UPLOAD_BYTES` | 262144 | Largest uploaded file |
| `RATE_LIMIT_PER_MIN` | 30 | Scans per minute per IP |
| `TRUST_PROXY` | 0 | Set to 1 behind a reverse proxy |
| `LOG_LEVEL` | INFO | Python log level |

The rate limiter is in memory per process. For several instances, enforce limits at the gateway or swap in Redis.

## Project layout

```
app.py            Flask app factory, routes, API, security headers
detectors.py      Detection engine (patterns, validators, masking, redaction)
templates/        Jinja pages (scanner, how it works, API docs, privacy, errors)
static/           CSS, JavaScript, favicon
tests/            Unit and app tests (30 tests)
wsgi.py           gunicorn entry point
Dockerfile        Production image
```

## Adding a detector

Add a `Detector(...)` to the `DETECTORS` tuple in `detectors.py` with a regex, a masking function and an optional validator. Order matters: earlier detectors win when matches overlap. Add a test in `tests/test_detectors.py`.

## Limitations

Detection is rule-based. It can miss data and flag harmless numbers, and it does not find names or street addresses. A valid Aadhaar checksum shows that a number is well-formed, not that it belongs to anyone. Use fake data when testing, and complete a privacy review before processing real personal data in production.
