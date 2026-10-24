import pytest

from ceg import register

from .conftest import EXAMPLE


def test_example_register(reg):
    assert {s.name for s in reg.services} >= {"chat-api", "media-service", "mobile-app", "realtime"}
    chat = reg.get("chat-api")
    assert chat.impact == 5 and chat.likelihood == 5 and chat.inherent_risk == 25
    assert reg.get("analytics").inherent_risk == 2


def test_most_specific_path_wins(reg):
    assert reg.service_for_path("services/chat-api/app/main.py").name == "chat-api"
    assert reg.service_for_path("infra/k8s/chat-api.yaml").name == "chat-api"
    assert reg.service_for_path("docs/readme.md") is None


def test_datastore_by_resource_before_file(reg):
    svc, ds = reg.datastore_for("infra/terraform/media.tf", "aws_security_group.search")
    assert (svc.name, ds.name) == ("search", "search-cluster")
    svc, ds = reg.datastore_for("infra/terraform/media.tf", "aws_s3_bucket_policy.media_previews")
    assert ds.name == "media-bucket"


def test_invalid_registers_are_rejected(tmp_path):
    text = (EXAMPLE / "register.yaml").read_text()
    (tmp_path / "dupe.yaml").write_text(text.replace("name: media-service", "name: chat-api"))
    with pytest.raises(ValueError, match="duplicate"):
        register.load(tmp_path / "dupe.yaml")
    (tmp_path / "owner.yaml").write_text(text.replace("owner: ml-team", "owner: nobody"))
    with pytest.raises(ValueError, match="not in owners"):
        register.load(tmp_path / "owner.yaml")
    (tmp_path / "exposure.yaml").write_text(text.replace("exposure: offline", "exposure: sometimes"))
    with pytest.raises(ValueError):
        register.load(tmp_path / "exposure.yaml")
