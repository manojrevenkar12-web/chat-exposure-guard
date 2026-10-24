from datetime import date

from ceg import access
from ceg.models import Severity

from .conftest import ROOT

DIR = ROOT / "examples" / "access-review"


def test_example_directory():
    fs = access.review(DIR, date(2026, 10, 20))
    got = {(f.rule, f.resource) for f in fs}
    assert got == {
        ("leaver-active", "github:miar"),
        ("leaver-active", "slack:mia.roth@companion.example"),
        ("leaver-device-active", "device:C02TEST0002"),
        ("outside-collaborator-admin", "github:lhahn-ext"),
        ("admin-without-mfa", "github:sara-l"),
        ("inactive-admin", "github:sara-l"),
        ("unknown-account", "github:old-intern-2024"),
        ("mfa-missing", "google:jonas.berg@companion.example"),
        ("service-admin-without-mfa", "cloud:ci-terraform"),
        ("stale-access-key", "cloud:anaw:A1B2"),
        ("device-unencrypted", "device:C02TEST0003"),
        ("device-os-outdated", "device:C02TEST0003"),
        ("device-silent", "device:C02TEST0004"),
    }
    sev = {(f.rule, f.resource): f.severity for f in fs}
    assert sev[("leaver-active", "github:miar")] == Severity.CRITICAL
    assert sev[("stale-access-key", "cloud:anaw:A1B2")] == Severity.HIGH  # an admin's key


def test_suspended_and_deleted_accounts_are_fine_and_contractors_expire():
    fs = access.review(DIR, date(2026, 12, 5))  # the contractor's end date has passed
    assert ("leaver-active", "github:lhahn-ext") in {(f.rule, f.resource) for f in fs}
    assert not any(f.resource == "google:mia.roth@companion.example" for f in fs)
    assert not any(f.resource.startswith("github:deploy-bot") for f in fs)
