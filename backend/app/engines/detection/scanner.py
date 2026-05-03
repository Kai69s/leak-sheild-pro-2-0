from dataclasses import dataclass
import hashlib
from html import escape

from app.engines.detection.rules import SECRET_RULES, SecretRule


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

    def scan(self, content: str) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        seen: set[tuple[str, str, int]] = set()
        for rule in self.rules:
            for match in rule.pattern.finditer(content):
                value = self._extract_secret_value(match)
                normalized = value.strip()
                if self._looks_like_example(normalized):
                    continue
                key = (rule.rule_id, hashlib.sha256(normalized.encode()).hexdigest(), match.start())
                if key in seen:
                    continue
                seen.add(key)
                line, col = self._line_col(content, match.start())
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
    def _line_col(content: str, offset: int) -> tuple[int, int]:
        line = content.count("\n", 0, offset) + 1
        last_newline = content.rfind("\n", 0, offset)
        col = offset + 1 if last_newline == -1 else offset - last_newline
        return line, col

    @staticmethod
    def _context(content: str, start: int, end: int, radius: int = 90) -> str:
        left = max(0, start - radius)
        right = min(len(content), end + radius)
        return content[left:right].replace("\n", "\\n")

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

