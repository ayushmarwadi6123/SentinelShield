import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote_plus


@dataclass(frozen=True)
class Finding:
    category: str
    severity: str
    technique: str
    evidence: str


class ThreatDetector:
    """
    Explainable teaching-grade signature detector.

    The purpose is to demonstrate how a WAF can normalize
    input and compare it against security rules.
    """

    RULES = (
        {
            "category": "SQL Injection",
            "severity": "Critical",
            "technique": "T1190 / SQLi pattern detection",
            "patterns": [
                re.compile(
                    r"\bunion\s+(?:all\s+)?select\b",
                    re.I
                ),

                re.compile(
                    r"(?:'|\")\s*(?:or|and)\s+\d+\s*=\s*\d+",
                    re.I
                ),

                re.compile(
                    r"\b(?:sleep|benchmark)\s*\(",
                    re.I
                ),

                re.compile(
                    r"(?:--|/\*|#)\s*(?:$|[\r\n])",
                    re.I
                ),

                re.compile(
                    r"\bselect\s+.+\s+from\s+",
                    re.I
                ),
            ],
        },

        {
            "category": "Cross-Site Scripting (XSS)",
            "severity": "High",
            "technique": "T1059.007 / Script injection pattern",
            "patterns": [
                re.compile(
                    r"<\s*script\b",
                    re.I
                ),

                re.compile(
                    r"\bjavascript\s*:",
                    re.I
                ),

                re.compile(
                    r"\bon(?:error|load|mouseover|focus)\s*=",
                    re.I
                ),

                re.compile(
                    r"<\s*(?:img|svg|iframe)\b[^>]*>",
                    re.I
                ),
            ],
        },

        {
            "category": "Directory Traversal",
            "severity": "High",
            "technique": "T1083 / Path traversal pattern",
            "patterns": [
                re.compile(
                    r"(?:\.\./|\.\.\\)",
                    re.I
                ),

                re.compile(
                    r"%2e%2e(?:%2f|%5c)",
                    re.I
                ),

                re.compile(
                    r"\b(?:etc/passwd|windows/win\.ini)\b",
                    re.I
                ),
            ],
        },

        {
            "category": "Local File Inclusion (LFI)",
            "severity": "High",
            "technique": "T1005 / Local file access pattern",
            "patterns": [
                re.compile(
                    r"\b(?:php|file|data)://",
                    re.I
                ),

                re.compile(
                    r"(?:/etc/passwd|/etc/shadow)",
                    re.I
                ),

                re.compile(
                    r"\b(?:include|require)\s*\([^)]*(?:\.\./|/etc/)",
                    re.I
                ),
            ],
        },

        {
            "category": "Command Injection",
            "severity": "Critical",
            "technique": "T1059 / OS command pattern",
            "patterns": [
                re.compile(
                    r"(?:^|[;&|])\s*(?:id|whoami|uname|cat|curl|wget|nc)\b",
                    re.I
                ),

                re.compile(
                    r"(?:\$\(.*?\)|`[^`]+`)",
                    re.I
                ),

                re.compile(
                    r"\b(?:/bin/(?:sh|bash)|cmd\.exe|powershell(?:\.exe)?)\b",
                    re.I
                ),
            ],
        },
    )

    def __init__(
        self,
        max_decodes: int = 2,
        max_evidence: int = 100
    ):
        self.max_decodes = max_decodes
        self.max_evidence = max_evidence

    def _normalize(self, value: str) -> str:
        value = value or ""
        previous = value

        for _ in range(self.max_decodes):
            current = unquote_plus(previous)

            if current == previous:
                break

            previous = current

        return previous

    def _safe_evidence(self, value: str) -> str:
        value = re.sub(
            r"[\x00-\x1f\x7f]",
            " ",
            value
        )

        return value[:self.max_evidence]

    def _request_text(self, request) -> list[tuple[str, str]]:
        fields = [
            (
                "path",
                request.path
            ),
            (
                "query",
                request.query_string.decode(
                    "utf-8",
                    errors="replace"
                )
            ),
            (
                "user-agent",
                request.headers.get(
                    "User-Agent",
                    ""
                )
            ),
            (
                "content-type",
                request.headers.get(
                    "Content-Type",
                    ""
                )
            ),
        ]

        raw_body = request.get_data(
            cache=True,
            as_text=True
        )

        if raw_body:
            fields.append(
                ("body", raw_body)
            )

        if request.is_json:
            try:
                fields.append(
                    (
                        "json",
                        json.dumps(
                            request.get_json(
                                silent=True
                            ),
                            ensure_ascii=False
                        )
                    )
                )
            except (TypeError, ValueError):
                pass

        return fields

    def inspect(self, request) -> dict[str, Any]:
        findings = []
        seen = set()

        for field, raw in self._request_text(request):
            normalized = self._normalize(raw)

            for rule in self.RULES:
                for pattern in rule["patterns"]:

                    match = pattern.search(
                        normalized
                    )

                    if not match:
                        continue

                    evidence = self._safe_evidence(
                        match.group(0)
                    )

                    key = (
                        rule["category"],
                        field,
                        evidence
                    )

                    if key not in seen:
                        findings.append(
                            Finding(
                                rule["category"],
                                rule["severity"],
                                rule["technique"],
                                evidence
                            )
                        )

                        seen.add(key)

                    break

        severity_order = {
            "Low": 1,
            "Medium": 2,
            "High": 3,
            "Critical": 4
        }

        highest = max(
            (
                finding.severity
                for finding in findings
            ),
            key=lambda x: severity_order[x],
            default="None"
        )

        return {
            "detected": bool(findings),
            "severity": highest,
            "findings": [
                finding.__dict__
                for finding in findings
            ],
        }
        
