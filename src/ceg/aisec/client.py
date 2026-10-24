"""What a chat client would do with a reply: which addresses it fetches without a click, and which
links it shows.

This is deliberately more permissive than any one real client: Markdown images in every syntax,
raw HTML with every element and attribute that loads something (img, srcset, picture, video poster,
iframe, object, embed, link prefetch, CSS url() and @import, SVG image, meta refresh). If a reply
survives this renderer, it survives a real one.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

# The client's own Markdown patterns: sharing them with the render policy would hide any syntax the
# policy's patterns miss from the evaluation as well.
_MD_IMAGE = re.compile(r"!\[(?P<alt>(?:[^\[\]]|\[[^\]]*\])*)\]\(\s*<?(?P<url>[^)\s>]*)>?(?:\s+[\"'(][^)]*[\"')])?\s*\)")
_MD_REF_IMAGE = re.compile(r"!\[(?P<alt>[^\]]*)\](?:\[(?P<ref>[^\]]*)\])?")
_MD_REF_DEF = re.compile(r"^ {0,3}\[(?P<ref>[^\]]+)\]:[ \t]*<?(?P<url>[^\s>]+)>?.*$", re.M)
_MD_LINK = re.compile(r"(?<!!)\[(?P<text>(?:[^\[\]]|\[[^\]]*\])*)\]\(\s*<?(?P<url>[^)\s>]*)>?(?:\s+[\"'(][^)]*[\"')])?\s*\)")
_AUTOLINK = re.compile(r"<(?P<url>[a-zA-Z][a-zA-Z0-9+.-]{1,31}:[^>\s]+)>")
_BARE_URL = re.compile(r"(?P<url>\b(?:https?://|www\.)[^\s<>()\"'`]+)", re.I)
# Closed code fences and inline code: renderers show their content as text, never as images or links.
_CODE = re.compile(r"(^|\n)(?P<f>```|~~~)[^\n]*\n.*?\n(?P=f)[ \t]*(?=\n|$)|`[^`\n]+`", re.S)

_CSS_URL = re.compile(r"url\(\s*['\"]?([^'\")\s]+)['\"]?\s*\)|@import\s+['\"]([^'\"]+)['\"]", re.I)
_LOADING_ATTRS = {
    "img": ("src", "srcset", "lowsrc", "dynsrc"),
    "image": ("href", "xlink:href"),
    "source": ("src", "srcset"),
    "video": ("src", "poster"),
    "audio": ("src",),
    "track": ("src",),
    "iframe": ("src",),
    "frame": ("src",),
    "embed": ("src",),
    "object": ("data",),
    "script": ("src",),
    "input": ("src",),
    "body": ("background",),
    "table": ("background",),
    "td": ("background",),
    "use": ("href", "xlink:href"),
    "feimage": ("href", "xlink:href"),
}
_PRELOAD_RELS = {"prefetch", "preload", "stylesheet", "icon", "preconnect", "dns-prefetch", "prerender", "modulepreload"}


@dataclass
class Rendered:
    fetches: list[str] = field(default_factory=list)  # loaded with no user action
    links: list[str] = field(default_factory=list)  # loaded only if the user clicks
    text: str = ""


class _Collector(HTMLParser):
    def __init__(self, out: Rendered) -> None:
        super().__init__(convert_charrefs=True)
        self.out = out
        self.in_style = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._tag(tag.lower(), {k.lower(): (v or "") for k, v in attrs})

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._tag(tag.lower(), {k.lower(): (v or "") for k, v in attrs})

    def _tag(self, tag: str, a: dict[str, str]) -> None:
        if tag == "style":
            self.in_style = True
        for attr in _LOADING_ATTRS.get(tag, ()):
            if a.get(attr):
                if attr in ("srcset",):
                    self.out.fetches += [c.strip().split()[0] for c in a[attr].split(",") if c.strip()]
                else:
                    self.out.fetches.append(a[attr])
        if tag == "link" and set(a.get("rel", "").lower().split()) & _PRELOAD_RELS and a.get("href"):
            self.out.fetches.append(a["href"])
        if tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = re.search(r"url\s*=\s*(\S+)", a.get("content", ""), re.I)
            if m:
                self.out.fetches.append(m.group(1).strip("'\""))
        if "style" in a:
            self.out.fetches += [m.group(1) or m.group(2) for m in _CSS_URL.finditer(a["style"])]
        if tag == "a" and a.get("href"):
            self.out.links.append(a["href"])
        if tag == "form" and a.get("action"):
            self.out.links.append(a["action"])

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "style":
            self.in_style = False

    def handle_data(self, data: str) -> None:
        if self.in_style:
            self.out.fetches += [m.group(1) or m.group(2) for m in _CSS_URL.finditer(data)]


def _in_html_attr(text: str, pos: int) -> bool:
    """True if pos sits inside an HTML tag (<img src=...>), which the HTML pass handles."""
    lt, gt = text.rfind("<", 0, pos), text.rfind(">", 0, pos)
    return lt > gt


def render(text: str) -> Rendered:
    out = Rendered(text=text)
    text = _CODE.sub(" ", text)  # neither Markdown nor HTML is interpreted inside closed code
    refs = {m.group("ref").lower(): m.group("url") for m in _MD_REF_DEF.finditer(text)}
    out.fetches += [m.group("url") for m in _MD_IMAGE.finditer(text)]
    for m in _MD_REF_IMAGE.finditer(text):
        url = refs.get((m.group("ref") or m.group("alt")).lower())
        if url:
            out.fetches.append(url)
    out.links += [m.group("url") for m in _MD_LINK.finditer(text)]
    out.links += [m.group("url") for m in _AUTOLINK.finditer(text)]
    # Linkify bare URLs only outside Markdown image/link syntax and reference definitions, as
    # renderers do; otherwise every image would also count as a link.
    plain = _MD_REF_DEF.sub(" ", _AUTOLINK.sub(" ", _MD_LINK.sub(" ", _MD_IMAGE.sub(" ", text))))
    out.links += [m.group("url") for m in _BARE_URL.finditer(plain) if not _in_html_attr(plain, m.start())]
    # Reference-style links: [text][ref] with a definition elsewhere.
    for m in re.finditer(r"(?<!!)\[[^\]]+\]\[([^\]]*)\]", text):
        if m.group(1).lower() in refs:
            out.links.append(refs[m.group(1).lower()])
    c = _Collector(out)
    try:
        c.feed(text)  # HTML inside closed code is shown as text too
        c.close()
    except Exception:  # noqa: S110 - malformed markup renders as text
        pass
    out.fetches = [html.unescape(u) for u in out.fetches if u]
    out.links = [html.unescape(u) for u in out.links if u]
    return out
