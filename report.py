from dataclasses import dataclass, field


@dataclass
class ResultEntry:
    type: str
    description: str = ''
    recommendations: list[str] = field(default_factory=list)
    vulnerabilities: list[tuple[str, str]] = field(default_factory=list)
