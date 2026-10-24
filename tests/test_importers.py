"""Scanner output into findings."""

import json

from ceg import importers
from ceg.models import Kind, Severity


def test_semgrep_rule_ids_lose_their_directory_prefix_and_duplicates_collapse():
    doc = {
        "results": [
            {
                "check_id": "rules.python.ceg.sql-built-from-input",
                "path": "/ci/repo/app/a.py",
                "start": {"line": 4},
                "end": {"line": 4},
                "extra": {
                    "message": "SQL is built by string formatting. More text.",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-89: SQL Injection"], "ceg-severity": "high"},
                    "lines": "cur.execute(f'..')",
                },
            },
            {
                "check_id": "rules.python.ceg.sql-built-from-input",
                "path": "/ci/repo/app/a.py",
                "start": {"line": 4},
                "end": {"line": 4},
                "extra": {"message": "SQL is built by string formatting.", "severity": "ERROR", "metadata": {}},
            },
        ]
    }
    fs = importers.semgrep_json(doc, root="/ci/repo")
    assert len(fs) == 1
    f = fs[0]
    assert (f.rule, f.path, f.cwe, f.severity, f.title) == (
        "ceg.sql-built-from-input",
        "app/a.py",
        "CWE-89",
        Severity.HIGH,
        "SQL is built by string formatting.",
    )


def test_sarif_uses_security_severity_when_present():
    doc = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {
                                "id": "py/sql-injection",
                                "properties": {"security-severity": "8.8", "tags": ["security", "external/cwe/cwe-089"]},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "py/sql-injection",
                        "message": {"text": "This query depends on a user-provided value."},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "app/a.py"}, "region": {"startLine": 9}}}
                        ],
                    }
                ],
            }
        ]
    }
    f = importers.sarif(doc)[0]
    assert (f.tool, f.rule, f.severity, f.cwe, f.location.start_line) == (
        "codeql",
        "py/sql-injection",
        Severity.HIGH,
        "CWE-89",
        9,
    )


def test_bandit_low_confidence_is_one_level_lower():
    doc = {
        "results": [
            {
                "test_id": "B608",
                "issue_severity": "MEDIUM",
                "issue_confidence": "LOW",
                "filename": "./app/a.py",
                "line_number": 3,
                "line_range": [3],
                "issue_text": "Possible SQL injection",
                "issue_cwe": {"id": 89},
                "code": "x",
            },
            {
                "test_id": "B602",
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "filename": "./app/b.py",
                "line_number": 7,
                "line_range": [7, 8],
                "issue_text": "shell=True",
                "issue_cwe": {"id": 78},
                "code": "y",
            },
        ]
    }
    a, b = importers.bandit_json(doc)
    assert a.severity == Severity.LOW and a.path == "app/a.py" and a.cwe == "CWE-89"
    assert b.severity == Severity.HIGH and b.location.end_line == 8


def test_osv_scanner_groups_aliases_and_finds_the_fixed_version():
    doc = {
        "results": [
            {
                "source": {"path": "/r/services/chat-api/requirements.txt"},
                "packages": [
                    {
                        "package": {"name": "jinja2", "version": "3.1.2", "ecosystem": "PyPI"},
                        "groups": [{"ids": ["OSV-TEST-0001"], "max_severity": "5.4"}],
                        "vulnerabilities": [
                            {
                                "id": "OSV-TEST-0001",
                                "aliases": ["CVE-TEST-0001"],
                                "summary": "attribute injection",
                                "affected": [
                                    {
                                        "package": {"name": "Jinja2"},
                                        "ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.1.3"}]}],
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
    }
    f = importers.osv_scanner_json(doc, root="/r")[0]
    assert f.kind == Kind.DEPENDENCY and f.advisory_ids == ("CVE-TEST-0001", "OSV-TEST-0001")
    assert f.fixed_version == "3.1.3" and f.severity == Severity.MEDIUM and f.resource == "services/chat-api/requirements.txt"


def test_gitleaks_never_keeps_the_secret():
    value = "sk-ant-api03-" + "Zx9" * 14
    doc = [
        {
            "RuleID": "anthropic-api-key",
            "File": "web/.env",
            "StartLine": 2,
            "EndLine": 2,
            "Secret": value,
            "Match": f"KEY={value}",
            "Description": "Anthropic API key",
            "Commit": "abc",
        }
    ]
    f = importers.gitleaks_json(doc)[0]
    assert value not in json.dumps(f.__dict__, default=str)
    assert f.secret_hash == importers.secret_hash(value) and len(f.secret_hash) == 64


def test_zap_endpoints_are_normalised_so_ids_do_not_split_issues():
    doc = {
        "site": [
            {
                "@name": "https://api.companion.example",
                "alerts": [
                    {
                        "pluginid": "40012",
                        "alert": "Cross Site Scripting (Reflected)",
                        "riskcode": "3",
                        "cweid": "79",
                        "instances": [
                            {"uri": "https://api.companion.example/conversations/123?x=1", "method": "GET", "param": "x"},
                            {
                                "uri": "https://api.companion.example/conversations/9f1c2b3a-1111-2222-3333-444455556666",
                                "method": "GET",
                            },
                        ],
                    }
                ],
            }
        ]
    }
    fs = importers.zap_json(doc, service="chat-api")
    assert [f.resource for f in fs] == ["GET /conversations/{id}"] and fs[0].severity == Severity.HIGH


def test_pentest_yaml_and_csv():
    yml = {
        "vendor": "Acme Security",
        "date": "2026-09-30",
        "findings": [
            {
                "id": "IDOR-01",
                "title": "Conversations readable by id",
                "severity": "Critical",
                "cwe": "CWE-639",
                "service": "chat-api",
                "resource": "GET /conversations/{id}",
            }
        ],
    }
    f = importers.pentest(yml)[0]
    assert (f.kind, f.severity, f.service, f.evidence["vendor"]) == (Kind.PENTEST, Severity.CRITICAL, "chat-api", "Acme Security")
    csv_text = "id,title,severity,service,resource\nTLS-02,Weak TLS ciphers,low,chat-api,api.companion.example:443\n"
    assert importers.pentest(csv_text)[0].rule == "TLS-02"
    import pytest

    with pytest.raises(ValueError):
        importers.pentest({"findings": [{"title": "no id"}]})


def test_provider_advisories_go_to_every_service_using_the_provider(reg):
    from .conftest import EXAMPLE

    fs = importers.load("provider-advisories", EXAMPLE.parent / "provider-advisories" / "2026-10.yaml", register=reg)
    by = {(f.rule, f.service) for f in fs}
    assert ("ANT-2026-10-01", "chat-api") in by
    assert ("OAI-2026-09-17", "") in by  # no service in the register uses it: still tracked, unmapped
    assert all(f.kind == Kind.AI for f in fs)
