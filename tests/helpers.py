from ceg.models import Finding, Kind, Location, Severity


def code(
    tool: str, rule: str, path: str, line: int, snippet: str = "", sev: Severity = Severity.HIGH, symbol: str = ""
) -> Finding:
    return Finding(
        tool=tool,
        rule=rule,
        kind=Kind.CODE,
        title=f"{rule} at {path}",
        severity=sev,
        location=Location(path, line, line, symbol=symbol, snippet=snippet),
    )
