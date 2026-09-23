"""Every third-party package seer_api imports must be a declared dependency.

`limits` (the /mcp and per-tool MCP rate limiters) and `starlette` were
imported directly but only arrived transitively (via slowapi and fastapi), so
a release of either that dropped or re-pinned them could break seer-api at
import with no change on our side. This walks seer_api's imports and checks
each against the installed seer-api's declared requirements.
"""

from __future__ import annotations

import ast
import re
import sys
from importlib import metadata
from pathlib import Path

import pytest

import seer_api

PACKAGE_DIR = Path(seer_api.__file__).parent
_OPTIONAL_IMPORT_ERRORS = {"ImportError", "ModuleNotFoundError"}


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _guarded_by_import_error(tree: ast.AST) -> set[int]:
    """Nodes inside ``try: ... except ImportError`` — optional dependencies."""
    guarded: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Try) and any(
            isinstance(h.type, ast.Name) and h.type.id in _OPTIONAL_IMPORT_ERRORS
            for h in node.handlers
        ):
            for stmt in node.body:
                guarded.update(id(n) for n in ast.walk(stmt))
    return guarded


def _third_party_imports() -> dict[str, str]:
    """Top-level third-party module -> first file importing it (non-optional)."""
    found: dict[str, str] = {}
    for path in sorted(PACKAGE_DIR.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        optional = _guarded_by_import_error(tree)
        for node in ast.walk(tree):
            if id(node) in optional:
                continue
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                modules = [node.module]
            else:
                continue
            for module in modules:
                top = module.split(".")[0]
                if top != "seer_api" and top not in sys.stdlib_module_names:
                    found.setdefault(top, path.relative_to(PACKAGE_DIR).as_posix())
    return found


def test_every_imported_package_is_declared() -> None:
    # Needs real installed distributions to map import names to packages; the
    # conftest stub stands in for the compiled `seer` module without one.
    pytest.importorskip("seer._seer")
    try:
        requirements = metadata.requires("seer-api") or []
    except metadata.PackageNotFoundError:
        pytest.skip("seer-api is not installed")
    declared = {
        _canonical(re.match(r"[A-Za-z0-9._-]+", req).group(0))
        for req in requirements
        if "extra ==" not in req
    }
    providers = metadata.packages_distributions()

    imports = _third_party_imports()
    assert {"fastapi", "limits", "mcp", "seer"} <= set(imports), imports

    undeclared = {
        module: where
        for module, where in imports.items()
        if not any(_canonical(d) in declared for d in providers.get(module, []))
    }
    assert not undeclared, f"imported but not declared in pyproject.toml: {undeclared}"
