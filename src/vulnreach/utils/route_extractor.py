"""Static route extraction for Flask/FastAPI, Express, and Spring Boot.

Parses source files without execution to enumerate HTTP entrypoints and emits a
normalized list of routes for downstream reachability mapping.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

EXCLUDE_DIRS = {"env", "venv", ".venv", "tests", "security_findings", "build", "dist", ".git", "__pycache__"}
SUPPORTED_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}


@dataclass
class Route:
    method: str
    path: str
    handler: Optional[str]
    file: str
    framework: str
    prefix: Optional[str] = None


def extract_and_save_routes(project_root: str, output_path: str) -> int:
    routes = extract_routes(project_root)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump([asdict(r) for r in routes], fh, indent=2)
    return len(routes)


def extract_routes(project_root: str) -> List[Route]:
    routes: List[Route] = []
    for root, dirs, files in os.walk(project_root):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for name in files:
            if name.endswith(".py"):
                routes.extend(_parse_python_routes(os.path.join(root, name), project_root))
            elif name.endswith(".js"):
                routes.extend(_parse_express_routes(os.path.join(root, name), project_root))
            elif name.endswith(".java"):
                routes.extend(_parse_spring_routes(os.path.join(root, name), project_root))
    return routes


def _rel(path: str, root: str) -> str:
    try:
        return os.path.relpath(path, root)
    except Exception:
        return path


# ------------------ Python: Flask / FastAPI ------------------

def _parse_python_routes(path: str, project_root: str) -> List[Route]:
    routes: List[Route] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return routes

    pending_decorators: List[Dict[str, str]] = []

    for line in lines:
        deco = line.strip()
        route_match = re.match(r"@(\w+)\.route\(\s*['\"]([^'\"]+)", deco)
        fastapi_match = re.match(r"@(\w+)\.(get|post|put|delete|patch|options|head)\(\s*['\"]([^'\"]+)", deco, re.IGNORECASE)

        if route_match:
            obj, path_str = route_match.groups()
            methods_match = re.search(r"methods\s*=\s*\[([^\]]+)\]", deco, re.IGNORECASE)
            methods = _extract_methods(methods_match.group(1)) if methods_match else ["GET"]
            for m in methods:
                pending_decorators.append({"method": m, "path": path_str, "framework": "flask"})
            continue

        if fastapi_match:
            obj, method, path_str = fastapi_match.groups()
            pending_decorators.append({"method": method.upper(), "path": path_str, "framework": "fastapi"})
            continue

        func_match = re.match(r"def\s+(\w+)\s*\(", deco)
        if func_match and pending_decorators:
            handler = func_match.group(1)
            for deco_info in pending_decorators:
                routes.append(
                    Route(
                        method=deco_info["method"],
                        path=deco_info["path"],
                        handler=handler,
                        file=_rel(path, project_root),
                        framework=deco_info["framework"],
                    )
                )
            pending_decorators = []

    return routes


def _extract_methods(raw: str) -> List[str]:
    methods = []
    for token in raw.split(','):
        t = token.strip().strip("'\" ").upper()
        if t in SUPPORTED_METHODS:
            methods.append(t)
    return methods or ["GET"]


# ------------------ Node.js: Express ------------------

def _parse_express_routes(path: str, project_root: str) -> List[Route]:
    routes: List[Route] = []
    prefix_map: Dict[str, str] = {}
    call_re = re.compile(r"(app|router|\w+)\.(get|post|put|delete|patch|options|head)\(\s*['\"]([^'\"]+)")
    use_re = re.compile(r"app\.use\(\s*['\"]([^'\"]+)['\"]\s*,\s*(\w+)\s*\)")

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except OSError:
        return routes

    for match in use_re.finditer(content):
        prefix, router_var = match.groups()
        prefix_map[router_var] = prefix

    for match in call_re.finditer(content):
        obj, method, route_path = match.groups()
        method_upper = method.upper()
        if method_upper not in SUPPORTED_METHODS:
            continue
        prefix = prefix_map.get(obj)
        full_path = f"{prefix.rstrip('/')}{route_path}" if prefix else route_path
        handler = _extract_handler_from_call(content, match.end())
        routes.append(
            Route(
                method=method_upper,
                path=full_path,
                handler=handler,
                file=_rel(path, project_root),
                framework="express",
                prefix=prefix,
            )
        )

    return routes


def _extract_handler_from_call(content: str, start_idx: int) -> Optional[str]:
    tail = content[start_idx: content.find('\n', start_idx)]
    handler_match = re.search(r"['\"]\s*,\s*([A-Za-z_][\w]*)", tail)
    return handler_match.group(1) if handler_match else None


# ------------------ Java: Spring Boot ------------------

def _parse_spring_routes(path: str, project_root: str) -> List[Route]:
    routes: List[Route] = []
    class_prefix = None
    pending_method_annotations: List[Dict[str, str]] = []

    mapping_re = re.compile(r"@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\(([^)]*)\)")
    class_re = re.compile(r"public\s+class\s+(\w+)")
    method_re = re.compile(r"public\s+[\w<>,\s]+\s+(\w+)\s*\(")

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return routes

    for line in lines:
        line_stripped = line.strip()

        class_match = class_re.search(line_stripped)
        if class_match:
            class_prefix = None
            pending_method_annotations = []
            continue

        map_match = mapping_re.search(line_stripped)
        if map_match:
            mapping, params = map_match.groups()
            method = _spring_mapping_to_method(mapping, params)
            path_str = _spring_extract_path(params)

            if mapping == "RequestMapping" and path_str and method is None:
                class_prefix = path_str
                continue

            if method and path_str:
                pending_method_annotations.append({"method": method, "path": path_str})
            continue

        method_match = method_re.search(line_stripped)
        if method_match and pending_method_annotations:
            handler = method_match.group(1)
            for ann in pending_method_annotations:
                prefix = class_prefix or ""
                full_path = f"{prefix.rstrip('/')}{ann['path']}" if prefix else ann['path']
                routes.append(
                    Route(
                        method=ann["method"],
                        path=full_path or "/",
                        handler=handler,
                        file=_rel(path, project_root),
                        framework="spring",
                        prefix=class_prefix,
                    )
                )
            pending_method_annotations = []

    return routes


def _spring_mapping_to_method(mapping: str, params: str) -> Optional[str]:
    if mapping != "RequestMapping":
        return mapping.replace("Mapping", "").upper()
    method_match = re.search(r"method\s*=\s*RequestMethod\.([A-Z]+)", params)
    if method_match:
        return method_match.group(1)
    return None


def _spring_extract_path(params: str) -> Optional[str]:
    path_match = re.search(r"path\s*=\s*\{?['\"]([^'\"}]+)", params)
    if not path_match:
        path_match = re.search(r"value\s*=\s*\{?['\"]([^'\"}]+)", params)
    return path_match.group(1) if path_match else None

