"""Configuration checks on the example platform and on safe variants."""

import textwrap

from ceg import exposure
from ceg.models import Severity

from .conftest import EXAMPLE

EXPECTED = {
    ("k8s-datastore-auth-disabled", "chat-api"),
    ("k8s-kafka-published", "chat-api"),
    ("kafka-plaintext-listener", "chat-api"),
    ("kafka-allow-everyone", "chat-api"),
    ("redis-open", "chat-api"),
    ("firebase-rtdb-public-read", "realtime"),
    ("firebase-rtdb-any-user-read", "realtime"),
    ("firestore-any-user", "realtime"),
    ("s3-public-access-block-off", "media-service"),
    ("s3-policy-public", "media-service"),
    ("sg-datastore-open", "search"),
    ("msk-unauthenticated", "chat-api"),
}


def test_example_platform_findings_are_exactly_the_planted_ones(reg):
    got = {(f.rule, f.service) for f in exposure.check(EXAMPLE, reg)}
    assert got == EXPECTED


def test_register_context_decides_severity(reg):
    sev = {f.rule: f.severity for f in exposure.check(EXAMPLE, reg)}
    assert sev["kafka-plaintext-listener"] == Severity.CRITICAL  # the broker carries chat content
    assert sev["sg-datastore-open"] == Severity.HIGH  # the search cluster holds public data only


def write(tmp_path, name, text):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(text))


def test_safe_configurations_raise_nothing(tmp_path):
    write(
        tmp_path,
        "server.properties",
        """
        listeners=SASL_SSL://0.0.0.0:9093,PLAINTEXT://127.0.0.1:9092
        listener.security.protocol.map=SASL_SSL:SASL_SSL,PLAINTEXT:PLAINTEXT
        allow.everyone.if.no.acl.found=false
    """,
    )
    write(tmp_path, "redis.conf", "bind 0.0.0.0\nprotected-mode no\nrequirepass long-random-secret-from-vault\n")
    write(tmp_path, "database.rules.json", '{"rules": {"users": {"$uid": {".read": "auth != null && auth.uid === $uid"}}}}')
    write(
        tmp_path,
        "firestore.rules",
        """
        rules_version = '2';
        service cloud.firestore {
          match /databases/{database}/documents {
            match /chats/{userId}/messages/{m} {
              allow read: if request.auth != null && request.auth.uid == userId;
            }
          }
        }
    """,
    )
    write(
        tmp_path,
        "k8s.yaml",
        """
        apiVersion: v1
        kind: Service
        metadata:
          name: redis
          annotations:
            networking.gke.io/load-balancer-type: "Internal"
        spec:
          type: LoadBalancer
          ports: [{port: 6379}]
        ---
        apiVersion: v1
        kind: Service
        metadata: {name: kafka}
        spec:
          type: LoadBalancer
          loadBalancerSourceRanges: ["10.20.0.0/16"]
          ports: [{port: 9092}]
    """,
    )
    write(
        tmp_path,
        "main.tf",
        """
        resource "aws_security_group" "db" {
          ingress {
            from_port   = 5432
            to_port     = 5432
            protocol    = "tcp"
            cidr_blocks = ["10.0.0.0/8"]
          }
        }
        resource "aws_db_instance" "x" {
          publicly_accessible = false
        }
    """,
    )
    assert exposure.check(tmp_path) == []


def test_gcs_and_rds_and_open_any_port(tmp_path):
    write(
        tmp_path,
        "gcp.tf",
        """
        resource "google_storage_bucket_iam_member" "exports" {
          bucket = "chat-exports"
          role   = "roles/storage.objectViewer"
          member = "allUsers"
        }
        resource "aws_db_instance" "chat" {
          publicly_accessible = true
        }
        resource "aws_security_group_rule" "all" {
          type        = "ingress"
          from_port   = 0
          to_port     = 65535
          protocol    = "-1"
          cidr_blocks = ["0.0.0.0/0"]
        }
    """,
    )
    rules = sorted(f.rule for f in exposure.check(tmp_path))
    assert rules == ["gcs-public", "rds-public", "sg-datastore-open"]


def test_rules_through_helpers_ingress_cors_and_hcl_policies(tmp_path):
    write(
        tmp_path,
        "firestore.rules",
        """
        rules_version = '2';
        service cloud.firestore {
          match /databases/{database}/documents {
            function signedIn() {
              return request.auth != null;
            }
            match /users/{uid}/memories/{m} {
              allow read, write: if signedIn();
            }
            match /characters/{c} {
              allow read: if true;
            }
          }
        }
    """,
    )
    write(
        tmp_path,
        "ingress.yaml",
        """
        apiVersion: networking.k8s.io/v1
        kind: Ingress
        metadata:
          name: api
          annotations:
            nginx.ingress.kubernetes.io/enable-cors: "true"
            nginx.ingress.kubernetes.io/cors-allow-origin: "*"
            nginx.ingress.kubernetes.io/cors-allow-credentials: "true"
        spec: {}
    """,
    )
    write(
        tmp_path,
        "s3.tf",
        """
        resource "aws_s3_bucket_policy" "uploads" {
          bucket = "x"
          policy = jsonencode({
            Version = "2012-10-17"
            Statement = [{ Effect = "Allow", Principal = "*", Action = "s3:GetObject", Resource = "arn:aws:s3:::x/*" }]
          })
        }
    """,
    )
    rules = sorted(f.rule for f in exposure.check(tmp_path))
    assert rules == ["firestore-any-user", "ingress-cors-credentials-wildcard", "s3-policy-public"]
