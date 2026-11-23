"""PII detection engine.

Pure Python, no web dependencies, so it can be unit-tested and reused.
Each detector is a regular expression plus an optional validator (checksum or
structural rule) and a masking function. Validators raise confidence or, for
detectors marked ``reject_invalid``, discard impossible matches entirely.
"""
from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

MAX_FINDINGS = 500
STYLES = ("mask", "label", "block")
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


# ---------------------------------------------------------------- checksums
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def verhoeff_valid(number: str) -> bool:
    check = 0
    for i, ch in enumerate(reversed(number)):
        check = _VERHOEFF_D[check][_VERHOEFF_P[i % 8][int(ch)]]
    return check == 0


def luhn_valid(number: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(number)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# --------------------------------------------------------------- validators
def _aadhaar_ok(value: str) -> bool:
    d = _digits(value)
    return len(d) == 12 and verhoeff_valid(d)


def _card_ok(value: str) -> bool:
    d = _digits(value)
    if not 13 <= len(d) <= 19 or not luhn_valid(d):
        return False
    return bool(re.match(r"4|5[1-5]|2[2-7]|3[47]|35|30[0-5]|36|38|6", d))


def _pan_ok(value: str) -> bool:
    return value[3].upper() in "PCHFATBLJG"


def _gstin_ok(value: str) -> bool:
    state = int(value[:2])
    return 1 <= state <= 38 or state in (97, 99)


def _date_ok(value: str) -> bool:
    parts = re.split(r"[/.-]", value)
    try:
        day, month, year = (int(p) for p in parts)
        return _dt.date(year, month, day) <= _dt.date.today()
    except ValueError:
        return False


def _ipv4_ok(value: str) -> bool:
    return all(int(octet) <= 255 for octet in value.split("."))


# ------------------------------------------------------------------ masking
def _stars(n: int) -> str:
    return "*" * max(n, 0)


def _mask_email(v: str) -> str:
    local, _, domain = v.partition("@")
    return f"{local[:1]}***@{domain}"


def _mask_phone(v: str) -> str:
    d = _digits(v)
    prefix = "+91 " if v.strip().startswith(("+", "00")) else ""
    return f"{prefix}******{d[-4:]}"


def _mask_aadhaar(v: str) -> str:
    return f"XXXX XXXX {_digits(v)[-4:]}"


def _mask_card(v: str) -> str:
    return f"**** **** **** {_digits(v)[-4:]}"


def _mask_pan(v: str) -> str:
    return v[:2] + _stars(6) + v[-2:]


def _mask_gstin(v: str) -> str:
    return v[:2] + _stars(11) + v[-2:]


def _mask_ifsc(v: str) -> str:
    return v[:4] + _stars(len(v) - 4)


def _mask_ip(v: str) -> str:
    return "***.***.***." + v.rsplit(".", 1)[-1]


def _mask_date(v: str) -> str:
    return "**/**/" + v[-4:]


def _mask_generic(v: str) -> str:
    return v[:1] + _stars(len(v) - 3) + v[-2:]


# --------------------------------------------------------------- detectors
@dataclass(frozen=True)
class Detector:
    id: str
    label: str
    tag: str
    severity: str
    description: str
    pattern: re.Pattern
    mask: Callable[[str], str]
    example: str
    validator: Optional[Callable[[str], bool]] = None
    reject_invalid: bool = False
    validation_note: str = "Pattern match only."
    base_confidence: str = "medium"


_UPI_HANDLES = (
    "okhdfcbank|okicici|okaxis|oksbi|ybl|ibl|axl|paytm|apl|upi|sbi|icici|"
    "hdfcbank|axisbank|freecharge|jio|airtel|postbank|fbl|barodampay|ikwik|"
    "pthdfc|ptyes|waicici|wahdfcbank"
)
_B = r"(?<![A-Za-z0-9])"   # not preceded by a letter or digit
_E = r"(?![A-Za-z0-9])"    # not followed by a letter or digit

# Order matters: earlier detectors win when matches overlap.
DETECTORS: tuple[Detector, ...] = (
    Detector(
        "card", "Payment card number", "CARD", "high",
        "13–19 digit card numbers, with or without spaces or dashes.",
        re.compile(r"(?<!\d)(?<!\d[ -])\d(?:[ -]?\d){12,18}(?![ -]?\d)"),
        _mask_card, "4111 1111 1111 1111",
        validator=_card_ok, reject_invalid=True,
        validation_note="Luhn checksum and issuer prefix are verified; failures are discarded.",
        base_confidence="high",
    ),
    Detector(
        "aadhaar", "Aadhaar number", "AADHAAR", "high",
        "12-digit Aadhaar-style numbers starting with 2–9, grouped consistently.",
        re.compile(r"(?<![\d+])(?<!\d[ -])[2-9]\d{3}([ -]?)\d{4}\1\d{4}(?![ -]?\d)"),
        _mask_aadhaar, "2345 6789 0124",
        validator=_aadhaar_ok,
        validation_note="Verhoeff checksum verified. Numbers that fail are kept as low confidence.",
    ),
    Detector(
        "upi", "UPI ID", "UPI", "medium",
        "Payment addresses such as name@okhdfcbank.",
        re.compile(rf"(?<![\w.%+-])[A-Za-z0-9._-]{{2,64}}@(?:{_UPI_HANDLES})(?![\w-]|\.\w)", re.I),
        _mask_email, "alex@okhdfcbank",
        validation_note="Matched against a list of common UPI handles.",
        base_confidence="high",
    ),
    Detector(
        "email", "Email address", "EMAIL", "medium",
        "Standard email addresses.",
        re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"),
        _mask_email, "alex.rao@example.com",
        base_confidence="high",
    ),
    Detector(
        "gstin", "GSTIN", "GSTIN", "low",
        "15-character GST registration numbers. Usually business data.",
        re.compile(rf"{_B}\d{{2}}[A-Z]{{5}}\d{{4}}[A-Z][1-9A-Z]Z[0-9A-Z]{_E}"),
        _mask_gstin, "27ABCPE1234F1Z5",
        validator=_gstin_ok,
        validation_note="State code (01–38, 97, 99) is verified.",
    ),
    Detector(
        "pan", "PAN", "PAN", "high",
        "10-character Permanent Account Numbers.",
        re.compile(rf"{_B}[A-Za-z]{{5}}\d{{4}}[A-Za-z]{_E}"),
        _mask_pan, "ABCPE1234F",
        validator=_pan_ok,
        validation_note="Fourth character must be a valid holder type. Others are kept as low confidence.",
    ),
    Detector(
        "passport", "Indian passport number", "PASSPORT", "high",
        "One letter followed by seven digits.",
        re.compile(rf"{_B}[A-PR-WY][1-9]\d\s?\d{{4}}[1-9]{_E}"),
        _mask_generic, "K1234567",
    ),
    Detector(
        "voter", "Voter ID (EPIC)", "VOTER_ID", "medium",
        "Three letters followed by seven digits.",
        re.compile(rf"{_B}[A-Z]{{3}}\d{{7}}{_E}"),
        _mask_generic, "ABC1234567",
    ),
    Detector(
        "ifsc", "Bank IFSC code", "IFSC", "low",
        "Bank branch codes. Public, but useful alongside account details.",
        re.compile(rf"{_B}[A-Z]{{4}}0[A-Z0-9]{{6}}{_E}"),
        _mask_ifsc, "HDFC0001234",
    ),
    Detector(
        "phone", "Indian mobile number", "PHONE", "medium",
        "10-digit mobile numbers starting 6–9, with optional +91.",
        re.compile(r"(?<![\w])(?:(?:\+|00)91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)"),
        _mask_phone, "98765 43210",
    ),
    Detector(
        "ip", "IPv4 address", "IP", "low",
        "Dotted IPv4 addresses.",
        re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)"),
        _mask_ip, "192.168.1.24",
        validator=_ipv4_ok, reject_invalid=True,
        validation_note="Each part must be 0–255.",
    ),
    Detector(
        "dob", "Date (possible birth date)", "DATE", "medium",
        "dd/mm/yyyy, dd-mm-yyyy or dd.mm.yyyy dates between 1900 and today.",
        re.compile(r"(?<![\d/.-])(?:0?[1-9]|[12]\d|3[01])([/.-])(?:0?[1-9]|1[0-2])\1(?:19|20)\d{2}(?!\d|[/.-]\d)"),
        _mask_date, "12/08/2004",
        validator=_date_ok, reject_invalid=True,
        validation_note="Must be a real calendar date that is not in the future.",
    ),
)
DETECTOR_IDS = tuple(d.id for d in DETECTORS)
_BY_ID = {d.id: d for d in DETECTORS}


# ------------------------------------------------------------------ results
@dataclass
class Finding:
    detector: str
    label: str
    tag: str
    severity: str
    confidence: str
    value: str
    masked: str
    start: int
    end: int
    line: int
    column: int

    def replacement(self, style: str) -> str:
        if style == "label":
            return f"[{self.tag}]"
        if style == "block":
            return "█" * len(self.value)
        return self.masked

    def as_dict(self, include_value: bool = True) -> dict:
        data = {
            "type": self.detector, "label": self.label, "severity": self.severity,
            "confidence": self.confidence, "masked": self.masked,
            "start": self.start, "end": self.end, "line": self.line, "column": self.column,
        }
        if include_value:
            data["value"] = self.value
        return data


def scan(text: str, enabled: Optional[Iterable[str]] = None) -> list[Finding]:
    """Return non-overlapping findings sorted by position."""
    allowed = set(DETECTOR_IDS if enabled is None else enabled)
    accepted: list[Finding] = []
    spans: list[tuple[int, int]] = []

    for det in DETECTORS:
        if det.id not in allowed:
            continue
        for m in det.pattern.finditer(text):
            start, end = m.span()
            value = m.group()
            if det.validator:
                if det.validator(value):
                    confidence = "high"
                elif det.reject_invalid:
                    continue
                else:
                    confidence = "low"
            else:
                confidence = det.base_confidence
            if any(start < e and end > s for s, e in spans):
                continue
            spans.append((start, end))
            line = text.count("\n", 0, start) + 1
            column = start - (text.rfind("\n", 0, start) + 1) + 1
            accepted.append(Finding(det.id, det.label, det.tag, det.severity, confidence,
                                    value, det.mask(value), start, end, line, column))
            if len(accepted) >= MAX_FINDINGS:
                break
        if len(accepted) >= MAX_FINDINGS:
            break

    accepted.sort(key=lambda f: f.start)
    return accepted


def redact(text: str, findings: list[Finding], style: str = "mask") -> str:
    if style not in STYLES:
        style = "mask"
    out, cursor = [], 0
    for f in findings:
        out.append(text[cursor:f.start])
        out.append(f.replacement(style))
        cursor = f.end
    out.append(text[cursor:])
    return "".join(out)


def segments(text: str, findings: list[Finding], style: Optional[str] = None) -> list[dict]:
    """Split text into plain and flagged parts for rendering.

    With ``style`` set, flagged parts carry the replacement text instead of the
    original, which gives the redacted view the same structure as the original.
    """
    parts, cursor = [], 0
    for i, f in enumerate(findings):
        if f.start > cursor:
            parts.append({"text": text[cursor:f.start], "i": None})
        parts.append({
            "text": f.replacement(style) if style else f.value,
            "i": i, "sev": f.severity, "label": f.label,
        })
        cursor = f.end
    if cursor < len(text):
        parts.append({"text": text[cursor:], "i": None})
    return parts


def summarize(findings: list[Finding]) -> dict:
    by_sev = {"high": 0, "medium": 0, "low": 0}
    by_type: dict[str, dict] = {}
    for f in findings:
        by_sev[f.severity] += 1
        row = by_type.setdefault(f.detector, {"label": f.label, "severity": f.severity, "count": 0})
        row["count"] += 1
    if by_sev["high"]:
        risk = "high"
    elif by_sev["medium"]:
        risk = "medium"
    elif by_sev["low"]:
        risk = "low"
    else:
        risk = "none"
    types = sorted(by_type.values(), key=lambda r: (SEVERITY_ORDER[r["severity"]], -r["count"]))
    return {"total": len(findings), "by_severity": by_sev, "by_type": types, "risk": risk}


def detector_catalog() -> list[dict]:
    return [{
        "id": d.id, "label": d.label, "severity": d.severity, "description": d.description,
        "example": d.example, "validation": d.validation_note,
    } for d in DETECTORS]


SAMPLE_TEXT = (
    "Support ticket #4821\n"
    "Customer: Meera Nair, meera.nair@example.com, mobile +91 98765 43210.\n"
    "DOB on file: 12/08/1994. PAN ABCPE1234F, Aadhaar 2345 6789 0124.\n"
    "Refund to UPI meera@okhdfcbank or card 4111 1111 1111 1111.\n"
    "Bank: HDFC0001234. Logged in from 192.168.1.24.\n"
)
