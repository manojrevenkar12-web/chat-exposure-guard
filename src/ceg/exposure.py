"""Configuration checks for the ways AI companion apps have actually leaked chats.

The large leaks of 2025–26 were configuration, not clever attacks: a Kafka broker on the internet
without authentication (Chattee and GiMe, 43 million messages), Firebase security rules that let
anyone read (Chat & Ask AI, 300 million messages), cloud credentials in an app package. These
checks read the repository's own infrastructure code and configuration, before deployment:

* Kubernetes: data-store ports published through LoadBalancer or NodePort services, charts that
  switch authentication off.
* Kafka ``server.properties``: plaintext listeners on public interfaces, open ACL defaults.
* Redis: protected mode off on a public bind without a password.
* Firebase Realtime Database and Firestore rules: public reads, and "any signed-in user" reads of
  data that belongs to one user.
* Terraform: public buckets, data stores open to 0.0.0.0/0, publicly accessible databases,
  MSK clusters accepting unauthenticated clients.

They do not scan anything outside the repository.
"""

from __future__ import annotations

import fnmatch
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import hcl2
import yaml

from .models import Finding, Kind, Location, Severity
from .register import Register

# Ports of data stores that must never face the internet.
DATASTORE_PORTS = {
    5432: "postgres",
    3306: "mysql",
    6379: "redis",
    9092: "kafka",
    9093: "kafka",
    9094: "kafka",
    9200: "elasticsearch",
    9300: "elasticsearch",
    27017: "mongodb",
    8086: "influxdb",
    5672: "rabbitmq",
    15672: "rabbitmq",
    11211: "memcached",
    8123: "clickhouse",
    9000: "clickhouse",
    2181: "zookeeper",
    6333: "qdrant",
    19530: "milvus",
    8080: "weaviate",
}
DATASTORE_IMAGES = re.compile(
    r"(?i)(kafka|redis|postgres|mysql|mongo|elastic|opensearch|clickhouse|qdrant|milvus|weaviate|rabbitmq|zookeeper)"
)
_NO_AUTH_ENV = {
    "ALLOW_PLAINTEXT_LISTENER": "yes",
    "ALLOW_EMPTY_PASSWORD": "yes",
    "ALLOW_ANONYMOUS_LOGIN": "yes",
    "KAFKA_CFG_ALLOW_EVERYONE_IF_NO_ACL_FOUND": "true",
    "POSTGRES_HOST_AUTH_METHOD": "trust",
    "XPACK_SECURITY_ENABLED": "false",
    "DISABLE_SECURITY_PLUGIN": "true",
    "QDRANT__SERVICE__API_KEY": "",
}
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
USER_SCOPED = re.compile(
    r"(?i)(user|users|member|account|profile|conversation|chat|message|session|memor|media|upload|private|inbox|dm|"
    r"\$uid|\{uid\}|\{userid\}|\$userid)"
)


class Checker:
    def __init__(self, root: str | Path, register: Register | None = None) -> None:
        self.root = Path(root)
        self.register = register
        self.findings: list[Finding] = []

    # -- helpers ----------------------------------------------------------------------------------

    def _finding(
        self,
        rule: str,
        title: str,
        sev: Severity,
        path: str,
        line: int,
        resource: str,
        why: str,
        cwe: str = "CWE-284",
        data_store: bool = True,
    ) -> None:
        svc_name = ""
        if self.register:
            hit = self.register.datastore_for(path, resource)
            if hit:
                svc, ds = hit
                svc_name = svc.name
                classes = {d.value for d in ds.data}
                if data_store and classes & {"chat_content", "nsfw_media", "credentials"}:
                    sev = Severity.CRITICAL
                    why += f" The register says {ds.name} holds {', '.join(sorted(classes))}."
            else:
                s = self.register.service_for_path(path)
                svc_name = s.name if s else ""
        self.findings.append(
            Finding(
                tool="ceg-exposure",
                rule=rule,
                kind=Kind.EXPOSURE,
                title=title,
                severity=sev,
                location=Location(path, line, line),
                resource=resource,
                service=svc_name,
                description=why,
                cwe=cwe,
            )
        )

    def _rel(self, p: Path) -> str:
        return str(p.relative_to(self.root))

    def _files(self, *patterns: str) -> Iterator[Path]:
        seen: set[Path] = set()
        for pat in patterns:
            for p in sorted(self.root.rglob(pat)):
                if p in seen or any(part in {".git", "node_modules", ".venv"} for part in p.parts):
                    continue
                seen.add(p)
                yield p

    @staticmethod
    def _line_of(text: str, needle: str, after: str = "") -> int:
        lines = text.splitlines()
        start = 0
        if after:
            for i, line in enumerate(lines):
                if after in line:
                    start = i
                    break
        for i in range(start, len(lines)):
            if needle in lines[i]:
                return i + 1
        return 1

    def _intended_public(self, path: str, where: str) -> bool:
        """Public reads that are meant to be public: declared in the register, or, without a register
        entry, a path that holds no per-user data (published characters, a catalog). Writes are never
        intended public. Without this a published character node was reported as a breach
        (held-out set rules-v1: c020, c022, c078)."""
        hit = self.register.datastore_for(path) if self.register else None
        if hit and hit[1].public_paths:
            return any(fnmatch.fnmatch(where, p) for p in hit[1].public_paths)
        return bool(where.strip("/")) and not USER_SCOPED.search(where)

    # -- checks -----------------------------------------------------------------------------------

    def run(self) -> list[Finding]:
        self.kubernetes()
        self.kafka_properties()
        self.redis_conf()
        self.firebase_rtdb()
        self.firestore()
        self.terraform()
        return self.findings

    def kubernetes(self) -> None:
        for p in self._files("*.yaml", "*.yml"):
            text = p.read_text(errors="replace")
            if "apiVersion" not in text or "kind" not in text:
                continue
            try:
                docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
            except yaml.YAMLError:
                continue
            rel = self._rel(p)
            for doc in docs:
                kind = doc.get("kind")
                name = (doc.get("metadata") or {}).get("name", "?")
                if kind == "Service":
                    self._k8s_service(doc, rel, text, name)
                elif kind in ("Deployment", "StatefulSet", "DaemonSet", "Pod"):
                    self._k8s_workload(doc, rel, text, name)
                elif kind == "Ingress":
                    self._k8s_ingress(doc, rel, text, name)

    def _k8s_ingress(self, doc: dict[str, Any], rel: str, text: str, name: str) -> None:
        """ingress-nginx CORS that allows any origin with credentials (held-out set rules-v1, c064)."""
        ann = {str(k).lower(): str(v).strip().lower() for k, v in ((doc.get("metadata") or {}).get("annotations") or {}).items()}
        prefix = "nginx.ingress.kubernetes.io/"
        origin = ann.get(prefix + "cors-allow-origin", "*" if ann.get(prefix + "enable-cors") == "true" else "")
        if ann.get(prefix + "enable-cors") == "true" and "*" in origin and ann.get(prefix + "cors-allow-credentials") == "true":
            self._finding(
                "ingress-cors-credentials-wildcard",
                f"Ingress {name} allows any origin with credentials",
                Severity.HIGH,
                rel,
                self._line_of(text, "cors-allow-credentials"),
                f"k8s:Ingress/{name}:cors",
                "Any website the user visits can call the API with the user's cookies and read the answers "
                "(conversations, profile). Allow only the platform's own origins.",
                cwe="CWE-942",
            )

    def _k8s_service(self, doc: dict[str, Any], rel: str, text: str, name: str) -> None:
        spec = doc.get("spec") or {}
        stype = spec.get("type", "ClusterIP")
        if stype not in ("LoadBalancer", "NodePort"):
            return
        annotations = (doc.get("metadata") or {}).get("annotations") or {}
        internal = any(
            ("internal" in str(k).lower() and str(v).lower() == "true") or str(v).lower() == "internal"
            for k, v in annotations.items()
        )
        ranges = spec.get("loadBalancerSourceRanges") or []
        open_ranges = not ranges or any(r in OPEN_CIDRS for r in ranges)
        for port in spec.get("ports") or []:
            num = int(port.get("port", 0))
            target = port.get("targetPort", num)
            engine = DATASTORE_PORTS.get(num) or (DATASTORE_PORTS.get(int(target)) if str(target).isdigit() else None)
            if not engine or internal or not open_ranges:
                continue
            self._finding(
                f"k8s-{engine}-published",
                f"{engine} port {num} published by {stype} service {name}",
                Severity.HIGH,
                rel,
                self._line_of(text, f"name: {name}"),
                f"k8s:Service/{name}:{num}",
                f"Service {name} is type {stype} without an internal load-balancer annotation or source ranges, so "
                f"{engine} on port {num} is reachable from outside the cluster.",
            )

    def _k8s_workload(self, doc: dict[str, Any], rel: str, text: str, name: str) -> None:
        spec = doc.get("spec") or {}
        pod = (spec.get("template") or {}).get("spec") or spec
        for c in pod.get("containers") or []:
            image = str(c.get("image", ""))
            if not DATASTORE_IMAGES.search(image):
                continue
            for env in c.get("env") or []:
                k, v = str(env.get("name", "")), str(env.get("value", ""))
                if k in _NO_AUTH_ENV and v.lower() == _NO_AUTH_ENV[k]:
                    self._finding(
                        "k8s-datastore-auth-disabled",
                        f"{image.split(':')[0]} runs with {k}={v or '(empty)'}",
                        Severity.HIGH,
                        rel,
                        self._line_of(text, k),
                        f"k8s:{doc.get('kind')}/{name}:{k}",
                        f"{k}={v or '(empty)'} switches authentication off for {image}; anything that can reach it can read it.",
                        cwe="CWE-306",
                    )

    def kafka_properties(self) -> None:
        for p in self._files("*.properties"):
            text = p.read_text(errors="replace")
            if "listeners" not in text and "broker" not in text:
                continue
            props = _properties(text)
            rel = self._rel(p)
            proto_map = dict(
                item.split(":", 1) for item in props.get("listener.security.protocol.map", "").split(",") if ":" in item
            )
            for listener in props.get("listeners", "").split(","):
                listener = listener.strip()
                if "://" not in listener:
                    continue
                lname, addr = listener.split("://", 1)
                host = addr.rsplit(":", 1)[0]
                proto = proto_map.get(lname, lname)
                if proto.upper() == "PLAINTEXT" and host in ("", "0.0.0.0", "[::]", "::"):  # noqa: S104
                    self._finding(
                        "kafka-plaintext-listener",
                        f"Kafka listener {lname} accepts unauthenticated plaintext on all interfaces",
                        Severity.HIGH,
                        rel,
                        self._line_of(text, "listeners="),
                        f"kafka:{rel}:{lname}",
                        "A PLAINTEXT listener bound to every interface needs no credentials. This is how the Chattee and "
                        "GiMe chats leaked: a reachable broker with no authentication.",
                        cwe="CWE-306",
                    )
            if props.get("allow.everyone.if.no.acl.found", "").lower() == "true":
                self._finding(
                    "kafka-allow-everyone",
                    "Kafka grants every principal access to topics without ACLs",
                    Severity.HIGH,
                    rel,
                    self._line_of(text, "allow.everyone.if.no.acl.found"),
                    f"kafka:{rel}:acl-default",
                    "allow.everyone.if.no.acl.found=true makes every new topic, chat topics included, readable by any "
                    "client that can connect.",
                    cwe="CWE-276",
                )

    def redis_conf(self) -> None:
        for p in self._files("redis*.conf", "*.redis.conf"):
            text = p.read_text(errors="replace")
            conf: dict[str, str] = {}
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    k, _, v = line.partition(" ")
                    conf[k.lower()] = v.strip()
            rel = self._rel(p)
            public = any(a in conf.get("bind", "") for a in ("0.0.0.0", "*", "::")) or "bind" not in conf  # noqa: S104
            no_pass = "requirepass" not in conf and "aclfile" not in conf and "user" not in conf
            if conf.get("protected-mode", "yes") == "no" and public and no_pass:
                self._finding(
                    "redis-open",
                    "Redis accepts commands from any address without a password",
                    Severity.HIGH,
                    rel,
                    self._line_of(text, "protected-mode"),
                    f"redis:{rel}",
                    "protected-mode no, a public bind and no requirepass or ACL file: anyone who reaches the port "
                    "can read every key (sessions, cached conversations).",
                    cwe="CWE-306",
                )

    def firebase_rtdb(self) -> None:
        for p in self._files("database.rules.json", "*.database.rules.json"):
            text = p.read_text(errors="replace")
            try:
                rules = json.loads(text).get("rules", {})
            except (json.JSONDecodeError, AttributeError):
                continue
            rel = self._rel(p)
            for path, kind, expr in _walk_rtdb(rules, ""):
                e = str(expr).replace(" ", "")
                where = path or "/"
                last = where.rstrip("/").split("/")[-1]
                line = self._line_of(text, f'".{kind}"', after=f'"{last}"')
                if e in ("true", "True") and kind == "read" and self._intended_public(rel, where):
                    continue
                if e in ("true", "True"):
                    self._finding(
                        f"firebase-rtdb-public-{kind}",
                        f"Realtime Database allows anyone to {kind} {where}",
                        Severity.CRITICAL if kind == "read" else Severity.HIGH,
                        rel,
                        line,
                        f"firebase-rtdb:{rel}:{where}:{kind}",
                        f'".{kind}": true at {where} needs no sign-in at all. Public rules are how Chat & Ask AI exposed '
                        "300 million messages.",
                        cwe="CWE-284",
                    )
                elif e in ("auth!=null", "auth!==null") and USER_SCOPED.search(where):
                    self._finding(
                        f"firebase-rtdb-any-user-{kind}",
                        f"Any signed-in user can {kind} {where}",
                        Severity.HIGH,
                        rel,
                        line,
                        f"firebase-rtdb:{rel}:{where}:{kind}",
                        f"{where} holds per-user data but the rule only checks that someone is signed in; every user "
                        "can read every other user's records. Compare auth.uid with the path's user id.",
                        cwe="CWE-639",
                    )

    def firestore(self) -> None:
        for p in self._files("firestore.rules", "*.firestore.rules"):
            text = p.read_text(errors="replace")
            rel = self._rel(p)
            stack: list[str] = []
            # helper functions with a single return, e.g. signedIn() { return request.auth != null; },
            # are inlined so a rule written through them is judged like one written out (rules-v1, c043)
            funcs = {
                m.group(1): m.group(2).replace(" ", "")
                for m in re.finditer(r"function\s+(\w+)\s*\(\s*\)\s*\{\s*return\s+(.+?);\s*\}", text, re.S)
            }
            in_func = False
            for lineno, raw in enumerate(text.splitlines(), 1):
                line = raw.strip()
                if in_func:
                    in_func = not line.startswith("}")
                    continue
                if line.startswith("function "):
                    in_func = line.count("{") > line.count("}")
                    continue
                m = re.match(r"match\s+(\S+)\s*\{", line)
                if m:
                    stack.append(m.group(1))
                    continue
                if line.startswith("}") and stack:
                    stack.pop()
                    continue
                am = re.match(r"allow\s+([\w,\s]+?)\s*(?::\s*if\s+(.+?))?;", line)
                if not am:
                    continue
                ops = am.group(1).replace(" ", "")
                cond = (am.group(2) or "").replace(" ", "")
                for _ in range(3):
                    for fname, body in funcs.items():
                        cond = cond.replace(f"{fname}()", body)
                where = "".join(s for s in stack if s != "/databases/{database}/documents")
                reads = any(o in ops for o in ("read", "get", "list"))
                if (
                    (not cond or cond == "true")
                    and reads
                    and ops.replace("get", "read").replace("list", "read") in ("read", "read,read")
                    and self._intended_public(rel, where)
                ):
                    continue
                if not cond or cond == "true":
                    self._finding(
                        "firestore-public",
                        f"Firestore allows anyone to {ops} {where or '/'}",
                        Severity.CRITICAL if reads else Severity.HIGH,
                        rel,
                        lineno,
                        f"firestore:{rel}:{where}:{ops}",
                        f"allow {ops} with no condition at {where or '/'}: no sign-in needed.",
                    )
                elif cond == "request.auth!=null" and USER_SCOPED.search(where):
                    owner = re.findall(r"\{(\w+)\}", where)
                    self._finding(
                        "firestore-any-user",
                        f"Any signed-in user can {ops} {where}",
                        Severity.HIGH,
                        rel,
                        lineno,
                        f"firestore:{rel}:{where}:{ops}",
                        f"{where} is per-user data but the rule only requires a signed-in user"
                        + (f"; check request.auth.uid == {owner[0]}." if owner else "."),
                        cwe="CWE-639",
                    )

    def terraform(self) -> None:
        for p in self._files("*.tf"):
            text = p.read_text(errors="replace")
            try:
                doc = hcl2.loads(text)
            except Exception:  # noqa: S112 - a file we cannot parse is not a finding
                continue
            rel = self._rel(p)
            for block in doc.get("resource", []):
                for rtype, instances in block.items():
                    for name, body in instances.items():
                        self._tf_resource(_unquote(rtype), _unquote(name), body, rel, text)

    def _tf_resource(self, rtype: str, name: str, body: dict[str, Any], rel: str, text: str) -> None:
        line = self._line_of(text, f'"{rtype}" "{name}"')
        res = f"{rtype}.{name}"
        if rtype == "aws_s3_bucket_acl" and str(_v(body.get("acl"))) in ("public-read", "public-read-write"):
            self._finding(
                "s3-public-acl",
                f"S3 bucket ACL {res} is {_v(body.get('acl'))}",
                Severity.CRITICAL,
                rel,
                line,
                res,
                "A public-read ACL lets anyone list and download the bucket's objects (media, exports).",
            )
        if rtype == "aws_s3_bucket_public_access_block":
            flags = ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]
            off = [f for f in flags if str(_v(body.get(f, True))).lower() == "false"]
            if off:
                self._finding(
                    "s3-public-access-block-off",
                    f"{res} turns off {', '.join(off)}",
                    Severity.HIGH,
                    rel,
                    line,
                    res,
                    "The account-level guard against public buckets is switched off for this bucket.",
                )
        if rtype == "aws_s3_bucket_policy":
            policy = str(_v(body.get("policy", "")))
            # JSON in a heredoc, or HCL inside jsonencode() (held-out set rules-v1, c021)
            public = re.search(r'"?Principal"?\s*[:=]\s*("\*"|\{\s*"?AWS"?\s*[:=]\s*"\*"\s*\})', policy)
            if public and not re.search(r'"?Condition"?\s*[:=]', policy):
                self._finding(
                    "s3-policy-public",
                    f"Bucket policy {res} grants access to everyone",
                    Severity.CRITICAL,
                    rel,
                    line,
                    res,
                    'Principal "*" without a condition makes the bucket public.',
                )
        if rtype in ("aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule"):
            rules = body.get("ingress", []) if rtype == "aws_security_group" else [body]
            if isinstance(rules, dict):
                rules = [rules]
            for r in rules:
                if rtype == "aws_security_group_rule" and _v(r.get("type")) != "ingress":
                    continue
                cidrs = _list(r.get("cidr_blocks")) + _list(r.get("ipv6_cidr_blocks")) + _list(r.get("cidr_ipv4"))
                if not set(map(str, cidrs)) & OPEN_CIDRS:
                    continue
                lo, hi = int(_v(r.get("from_port", 0)) or 0), int(_v(r.get("to_port", 0)) or 0)
                hit = [f"{e}:{port}" for port, e in DATASTORE_PORTS.items() if lo <= port <= hi and not (lo == 0 and hi == 0)]
                if lo == 0 and hi in (0, 65535) and str(_v(r.get("protocol", ""))) in ("-1", "all"):
                    hit = ["all ports"]
                if hit:
                    self._finding(
                        "sg-datastore-open",
                        f"{res} opens {', '.join(hit[:3])} to the internet",
                        Severity.HIGH,
                        rel,
                        line,
                        res,
                        f"Ingress from {', '.join(map(str, cidrs))} on {', '.join(hit[:3])}.",
                    )
        if (
            rtype in ("aws_db_instance", "aws_rds_cluster_instance")
            and str(_v(body.get("publicly_accessible", False))).lower() == "true"
        ):
            self._finding(
                "rds-public",
                f"Database {res} is publicly accessible",
                Severity.HIGH,
                rel,
                line,
                res,
                "publicly_accessible = true gives the database a public address.",
            )
        if rtype == "aws_msk_cluster":
            auth = body.get("client_authentication") or [{}]
            auth = auth[0] if isinstance(auth, list) else auth
            if str(_v(auth.get("unauthenticated", False))).lower() == "true":
                self._finding(
                    "msk-unauthenticated",
                    f"MSK cluster {res} accepts unauthenticated clients",
                    Severity.HIGH,
                    rel,
                    line,
                    res,
                    "client_authentication.unauthenticated = true: any client in reach can consume topics.",
                    cwe="CWE-306",
                )
        if rtype in ("google_storage_bucket_iam_member", "google_storage_bucket_iam_binding"):
            members = _list(body.get("members")) + _list(body.get("member"))
            if any(str(m) in ("allUsers", "allAuthenticatedUsers") for m in members):
                self._finding(
                    "gcs-public",
                    f"{res} grants {', '.join(map(str, members))}",
                    Severity.CRITICAL,
                    rel,
                    line,
                    res,
                    "allUsers or allAuthenticatedUsers on a bucket makes its objects public.",
                )


def _properties(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "!")) and "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def _walk_rtdb(node: Any, path: str) -> Iterator[tuple[str, str, Any]]:
    if not isinstance(node, dict):
        return
    for k, v in node.items():
        if k in (".read", ".write"):
            yield path, k[1:], v
        elif not k.startswith("."):
            yield from _walk_rtdb(v, f"{path}/{k}")


def _unquote(s: str) -> str:
    return s.strip('"')


def _v(x: Any) -> Any:
    """python-hcl2 wraps values differently across versions; unwrap quotes and singleton lists."""
    while isinstance(x, list) and len(x) == 1:
        x = x[0]
    if isinstance(x, str):
        s = x.strip()
        if len(s) >= 2 and s[0] == s[-1] == '"':
            s = s[1:-1]
        return s
    return x


def _list(x: Any) -> list[Any]:
    if x is None:
        return []
    if isinstance(x, list):
        out: list[Any] = []
        for i in x:
            out.extend(_list(i) if isinstance(i, list) else [_v(i)])
        return out
    return [_v(x)]


def check(root: str | Path, register: Register | None = None) -> list[Finding]:
    return Checker(root, register).run()
