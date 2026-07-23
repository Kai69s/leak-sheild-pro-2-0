from bisect import bisect_right
from dataclasses import dataclass
import hashlib
from html import escape

from app.engines.detection.rules import SECRET_RULES, SecretRule


MAX_FINDINGS_PER_SCAN = 250


@dataclass(frozen=True)
class DetectionFinding:
    rule: SecretRule
    secret_value: str
    value_hash: str
    value_preview: str
    line_number: int
    column_start: int
    column_end: int
    context_snippet: str


class DetectionEngine:
    def __init__(self, rules: tuple[SecretRule, ...] = SECRET_RULES) -> None:
        self.rules = rules

    def scan(self, content: str, max_findings: int = MAX_FINDINGS_PER_SCAN) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        seen: set[tuple[str, str, int]] = set()
        line_starts = [0, *(index + 1 for index, character in enumerate(content) if character == "\n")]
        for rule in self.rules:
            for match in rule.pattern.finditer(content):
                if len(findings) >= max_findings:
                    return sorted(findings, key=lambda item: (item.line_number, item.column_start))
                value = self._extract_secret_value(match)
                normalized = value.strip()
                if self._looks_like_example(normalized):
                    continue
                key = (rule.rule_id, hashlib.sha256(normalized.encode()).hexdigest(), match.start())
                if key in seen:
                    continue
                seen.add(key)
                line, col = self._line_col(line_starts, match.start())
                findings.append(
                    DetectionFinding(
                        rule=rule,
                        secret_value=normalized,
                        value_hash=hashlib.sha256(normalized.encode()).hexdigest(),
                        value_preview=self._obfuscate(normalized),
                        line_number=line,
                        column_start=col,
                        column_end=col + len(match.group(0)),
                        context_snippet=escape(self._context(content, match.start(), match.end())),
                    )
                )
        return sorted(findings, key=lambda item: (item.line_number, item.column_start))

    @staticmethod
    def _extract_secret_value(match) -> str:
        groups = [group for group in match.groups() if group]
        if groups:
            return groups[-1]
        return match.group(0)

    @staticmethod
    def _line_col(line_starts: list[int], offset: int) -> tuple[int, int]:
        line = bisect_right(line_starts, offset)
        col = offset - line_starts[line - 1] + 1
        return line, col

    def _context(self, content: str, start: int, end: int, radius: int = 90) -> str:
        left = max(0, start - radius)
        right = min(len(content), end + radius)
        snippet = content[left:right]
        for rule in self.rules:
            snippet = rule.pattern.sub(self._redact_match, snippet)
        return snippet.replace("\n", "\\n")

    @classmethod
    def _redact_match(cls, match) -> str:
        value = cls._extract_secret_value(match)
        return match.group(0).replace(value, "[REDACTED]")

    @staticmethod
    def _obfuscate(value: str) -> str:
        if len(value) <= 8:
            return "*" * len(value)
        return f"{value[:4]}...{value[-4:]}"

    @staticmethod
    def _looks_like_example(value: str) -> bool:
        lowered = value.lower()
        examples = ("example", "sample", "dummy", "changeme", "placeholder", "your_", "xxxxx")
        return any(marker in lowered for marker in examples)

