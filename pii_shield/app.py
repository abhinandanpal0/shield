"""PII Shield: a web app that finds personal data in text and redacts it."""
from __future__ import annotations

import hmac
import logging
import os
import secrets
import threading
import time
from collections import defaultdict, deque

from flask import Flask, g, jsonify, render_template, request

import detectors as engine

CSRF_COOKIE = "pii_csrf"
ALLOWED_EXTENSIONS = (".txt", ".csv", ".tsv", ".log", ".md", ".json")
STYLE_LABELS = {"mask": "Partial mask", "label": "Type label", "block": "Solid block"}


class RateLimiter:
    """Sliding-window limiter kept in memory. Use Redis or a gateway for multi-instance setups."""

    def __init__(self, limit: int, window: int = 60):
        self.limit, self.window = limit, window
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> int:
        """Return 0 if allowed, otherwise seconds until the caller may retry."""
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return max(1, int(self.window - (now - hits[0])) + 1)
            hits.append(now)
            if len(self._hits) > 5000:
                for k in [k for k, v in self._hits.items() if not v]:
                    del self._hits[k]
            return 0


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        MAX_CHARS=int(os.environ.get("MAX_CHARS", 20000)),
        MAX_UPLOAD_BYTES=int(os.environ.get("MAX_UPLOAD_BYTES", 256 * 1024)),
        RATE_LIMIT_PER_MIN=int(os.environ.get("RATE_LIMIT_PER_MIN", 30)),
        MAX_CONTENT_LENGTH=1024 * 1024,
        JSON_SORT_KEYS=False,
    )
    if test_config:
        app.config.update(test_config)
    if os.environ.get("TRUST_PROXY") == "1":
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(message)s")
    limiter = RateLimiter(app.config["RATE_LIMIT_PER_MIN"])

    # ------------------------------------------------------------ helpers
    def wants_json() -> bool:
        return request.path.startswith("/api/")

    def error_response(status: int, title: str, message: str, headers: dict | None = None):
        if wants_json():
            resp = jsonify(error=title, message=message)
            resp.status_code = status
        else:
            resp = app.make_response((render_template("error.html", status=status, title=title,
                                                      message=message), status))
        for k, v in (headers or {}).items():
            resp.headers[k] = v
        return resp

    def throttle():
        wait = limiter.check(request.remote_addr or "unknown")
        if wait:
            return error_response(429, "Too many requests",
                                  f"Please wait about {wait} seconds and try again.",
                                  {"Retry-After": str(wait)})
        return None

    def run_scan(text: str, enabled, style: str) -> dict:
        findings = engine.scan(text, enabled)
        return {
            "findings": findings,
            "summary": engine.summarize(findings),
            "style": style,
            "original_segments": engine.segments(text, findings),
            "redacted_segments": engine.segments(text, findings, style),
            "redacted": engine.redact(text, findings, style),
            "characters": len(text),
            "lines": text.count("\n") + 1 if text else 0,
        }

    # ------------------------------------------------------------- pages
    @app.route("/", methods=["GET", "POST"])
    def index():
        token = request.cookies.get(CSRF_COOKIE)
        if not token:
            token = secrets.token_urlsafe(32)
            g.new_csrf = token

        ctx = {
            "csrf_token": token, "text": "", "results": None, "error": None, "notice": None,
            "style": "mask", "enabled": set(engine.DETECTOR_IDS),
            "detectors": engine.DETECTORS, "style_labels": STYLE_LABELS,
            "max_chars": app.config["MAX_CHARS"], "sample": engine.SAMPLE_TEXT,
        }
        if request.method == "GET":
            return render_template("index.html", **ctx)

        blocked = throttle()
        if blocked:
            return blocked
        sent = request.form.get("csrf_token", "")
        if not request.cookies.get(CSRF_COOKIE) or not hmac.compare_digest(sent, request.cookies[CSRF_COOKIE]):
            ctx["error"] = "Your session expired. Your text is still below. Press Scan text to try again."
            ctx["text"] = request.form.get("text", "")[: ctx["max_chars"]]
            return render_template("index.html", **ctx), 400

        style = request.form.get("style", "mask")
        ctx["style"] = style if style in engine.STYLES else "mask"
        chosen = set(request.form.getlist("detectors")) & set(engine.DETECTOR_IDS)
        ctx["enabled"] = chosen

        text = request.form.get("text", "")
        upload = request.files.get("file")
        if upload and upload.filename:
            if not upload.filename.lower().endswith(ALLOWED_EXTENSIONS):
                ctx["error"] = f"Upload a text file ({', '.join(ALLOWED_EXTENSIONS)})."
                ctx["text"] = text
                return render_template("index.html", **ctx), 400
            raw = upload.read(app.config["MAX_UPLOAD_BYTES"] + 1)
            if len(raw) > app.config["MAX_UPLOAD_BYTES"]:
                ctx["error"] = f"That file is larger than {app.config['MAX_UPLOAD_BYTES'] // 1024} KB."
                ctx["text"] = text
                return render_template("index.html", **ctx), 400
            if b"\x00" in raw:
                ctx["error"] = "That doesn't look like a plain text file."
                ctx["text"] = text
                return render_template("index.html", **ctx), 400
            text = raw.decode("utf-8", errors="replace")
            ctx["notice"] = f"Scanned the uploaded file {upload.filename[:80]}."

        text = text.replace("\r\n", "\n")
        if len(text) > app.config["MAX_CHARS"]:
            text = text[: app.config["MAX_CHARS"]]
            ctx["notice"] = f"Only the first {app.config['MAX_CHARS']:,} characters were scanned."
        ctx["text"] = text

        if not text.strip():
            ctx["error"] = "Paste some text or upload a file to scan."
        elif not chosen:
            ctx["error"] = "Select at least one type of data to look for."
        else:
            ctx["results"] = run_scan(text, chosen, ctx["style"])
            app.logger.info("scan chars=%d findings=%d", len(text), len(ctx["results"]["findings"]))
        return render_template("index.html", **ctx), (400 if ctx["error"] else 200)

    @app.get("/how-it-works")
    def how_it_works():
        return render_template("how.html", detectors=engine.DETECTORS)

    @app.get("/api")
    def api_docs():
        return render_template("api.html", detectors=engine.DETECTORS, max_chars=app.config["MAX_CHARS"],
                               limit=app.config["RATE_LIMIT_PER_MIN"])

    @app.get("/privacy")
    def privacy():
        return render_template("privacy.html", max_chars=app.config["MAX_CHARS"])

    # --------------------------------------------------------------- API
    @app.get("/api/v1/detectors")
    def api_detectors():
        return jsonify(detectors=engine.detector_catalog())

    @app.post("/api/v1/scan")
    def api_scan():
        blocked = throttle()
        if blocked:
            return blocked
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or not isinstance(payload.get("text"), str):
            return error_response(400, "Invalid request", 'Send JSON like {"text": "..."}.')
        text = payload["text"]
        if len(text) > app.config["MAX_CHARS"]:
            return error_response(413, "Text too long",
                                  f"The limit is {app.config['MAX_CHARS']:,} characters.")
        style = payload.get("style", "mask")
        if style not in engine.STYLES:
            return error_response(400, "Invalid style", f"style must be one of: {', '.join(engine.STYLES)}.")
        types = payload.get("detectors")
        if types is not None:
            if not isinstance(types, list) or not all(isinstance(t, str) for t in types):
                return error_response(400, "Invalid detectors", "detectors must be a list of ids.")
            unknown = sorted(set(types) - set(engine.DETECTOR_IDS))
            if unknown:
                return error_response(400, "Unknown detectors", f"Unknown ids: {', '.join(unknown)}.")
        include_values = payload.get("include_values", False) is True
        findings = engine.scan(text, types)
        body = {
            "summary": {k: v for k, v in engine.summarize(findings).items()},
            "findings": [f.as_dict(include_values) for f in findings],
            "redacted_text": engine.redact(text, findings, style),
        }
        resp = jsonify(body)
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok")

    # ------------------------------------------------------------ errors
    @app.errorhandler(404)
    def not_found(_):
        return error_response(404, "Page not found", "That page doesn't exist. Check the address or head back to the scanner.")

    @app.errorhandler(405)
    def not_allowed(_):
        return error_response(405, "Method not allowed", "That address doesn't accept this kind of request.")

    @app.errorhandler(413)
    def too_large(_):
        return error_response(413, "Request too large", "The upload is larger than 1 MB. Try a smaller file.")

    @app.errorhandler(500)
    def server_error(_):
        return error_response(500, "Something went wrong", "The scan didn't finish. Try again in a moment.")

    # ----------------------------------------------------------- hooks
    @app.after_request
    def secure(resp):
        new_token = g.get("new_csrf")
        if new_token:
            resp.set_cookie(CSRF_COOKIE, new_token, httponly=True, samesite="Lax",
                            secure=request.is_secure, max_age=60 * 60 * 8)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; img-src 'self' data:; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'",
        )
        if request.is_secure:
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if request.method == "POST" or request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)),
            debug=os.environ.get("FLASK_DEBUG") == "1")
