"""From a tool's severity to an effective severity and a due date, using the risk register."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from .models import Kind, Severity
from .register import Exposure, Service
from .settings import Settings


@dataclass(frozen=True)
class Assessment:
    severity: Severity
    reason: str


def assess(tool_severity: Severity, kind: Kind, service: Service | None, settings: Settings) -> Assessment:
    """Raise findings in exposed services that hold sensitive data; lower them in internal services that
    hold none. Secrets and exposures are never lowered: an open data store is bad anywhere."""
    if service is None:
        return Assessment(tool_severity, "no service in the risk register owns this; tool severity kept")
    classes = {d.value for d in service.data} | {d.value for ds in service.datastores for d in ds.data}
    exposed = service.exposure in (Exposure.INTERNET, Exposure.PARTNER)
    sensitive_here = sorted(classes & settings.raise_if_exposed_with)
    if exposed and sensitive_here and tool_severity.rank >= Severity.LOW.rank:
        raised = Severity.from_rank(tool_severity.rank + 1)
        if raised != tool_severity:
            return Assessment(
                raised, f"raised: {service.name} is {service.exposure.value}-facing and holds {', '.join(sensitive_here)}"
            )
        return Assessment(raised, f"{service.name} is {service.exposure.value}-facing and holds {', '.join(sensitive_here)}")
    if (
        settings.lower_if_internal_without_sensitive
        and not exposed
        and not sensitive_here
        and not service.holds_sensitive
        and kind.value not in settings.never_lower
        and tool_severity.rank > Severity.INFO.rank
    ):
        return Assessment(
            Severity.from_rank(tool_severity.rank - 1),
            f"lowered: {service.name} is {service.exposure.value} and holds no sensitive data",
        )
    return Assessment(tool_severity, f"{service.name}: tool severity kept")


def due(opened_at: datetime, severity: Severity, settings: Settings) -> datetime:
    return opened_at + timedelta(days=settings.sla_days[severity.value])
