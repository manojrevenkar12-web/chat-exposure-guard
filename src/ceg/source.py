"""Reading source code around a finding: the enclosing symbol and a normalised line.

Scanners report a path and a line. Lines move whenever code above them changes, so they make poor
identities. The enclosing function and the flagged line's normalised text survive most edits; this
module derives both from the checked-out source the scan ran on.
"""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True)
class Symbol:
    name: str  # qualified, e.g. "ConversationRoutes.get_conversation"; "<module>" at top level
    start: int  # first line of the definition (1-based); 0 for <module>


MODULE = Symbol("<module>", 0)

_JS_FUNC = re.compile(
    r"""^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?
        (?:function\s*\*?\s*(?P<f>[A-Za-z_$][\w$]*)
          |(?:const|let|var)\s+(?P<v>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>
          |(?P<m>[A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{)""",
    re.VERBOSE,
)
_JS_KEYWORDS = {"if", "for", "while", "switch", "catch", "return", "function"}


class SourceIndex:
    """Answers questions about files under one checkout root."""

    def __init__(self, root: str | Path | None) -> None:
        self.root = Path(root) if root else None

    def lines(self, path: str) -> list[str]:
        if self.root is None:
            return []
        return _read_lines(str(self.root / path))

    def line(self, path: str, lineno: int) -> str:
        ls = self.lines(path)
        return ls[lineno - 1] if 0 < lineno <= len(ls) else ""

    def symbol(self, path: str, lineno: int) -> Symbol:
        if self.root is None or lineno <= 0:
            return MODULE
        if path.endswith(".py"):
            return _python_symbol(str(self.root / path), lineno)
        if path.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs")):
            return _js_symbol(self.lines(path), lineno)
        return MODULE


def _version(full: str) -> tuple[int, int]:
    """Cache key part: the same path holds different code at different commits."""
    try:
        st = Path(full).stat()
        return st.st_mtime_ns, st.st_size
    except OSError:
        return 0, 0


def _read_lines(full: str) -> list[str]:
    return _read_lines_v(full, _version(full))


@lru_cache(maxsize=4096)
def _read_lines_v(full: str, version: tuple[int, int]) -> list[str]:
    try:
        return Path(full).read_text(errors="replace").splitlines()
    except OSError:
        return []


def _python_tree(full: str) -> list[tuple[int, int, str]]:
    return _python_tree_v(full, _version(full))


@lru_cache(maxsize=2048)
def _python_tree_v(full: str, version: tuple[int, int]) -> list[tuple[int, int, str]]:
    """(start, end, qualified name) of every function and class, outermost first."""
    try:
        tree = ast.parse("\n".join(_read_lines_v(full, version)))
    except (SyntaxError, ValueError):
        return []
    out: list[tuple[int, int, str]] = []

    def walk(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                name = f"{prefix}{child.name}"
                start = min([d.lineno for d in child.decorator_list] + [child.lineno])
                out.append((start, child.end_lineno or child.lineno, name))
                walk(child, name + ".")
            else:
                walk(child, prefix)

    walk(tree, "")
    return out


def _python_symbol(full: str, lineno: int) -> Symbol:
    best: tuple[int, int, str] | None = None
    for start, end, name in _python_tree(full):
        if start <= lineno <= end and (best is None or start >= best[0]):
            best = (start, end, name)
    return Symbol(best[2], best[0]) if best else MODULE


def _js_symbol(lines: list[str], lineno: int) -> Symbol:
    """Nearest enclosing function by brace depth: good enough for identity, not a parser."""
    depth = 0
    for i in range(min(lineno, len(lines)) - 1, -1, -1):
        text = lines[i]
        depth += text.count("}") - text.count("{")
        if depth < 0 or i == lineno - 1:
            m = _JS_FUNC.match(text)
            if m:
                name = m.group("f") or m.group("v") or m.group("m")
                if name and name not in _JS_KEYWORDS:
                    return Symbol(name, i + 1)
            if depth < 0:
                depth = 0
    return MODULE


_COMMENT = re.compile(r"\s+(#|//).*$")


def normalize(text: str) -> str:
    """Whitespace-, quote- and trailing-comment-insensitive form of a source line."""
    t = _COMMENT.sub("", text.strip())
    t = t.replace("'", '"')
    return re.sub(r"\s+", "", t)


def snippet_hash(text: str) -> str:
    n = normalize(text)
    return hashlib.sha256(n.encode()).hexdigest()[:16] if n else ""
