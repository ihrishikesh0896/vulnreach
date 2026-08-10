"""Shared PyPI-name → importable-module-name resolution logic.

Used by TainterAgent and DynamicReachabilityAgent to translate the PyPI
distribution name found in vulnerability data (e.g. "Pillow", "pyyaml") into
the top-level module name that actually appears in source code (e.g. "PIL",
"yaml").

Resolution order in resolve_import_name():
  1. Curated overrides (_PYPI_TO_IMPORT) — hand-maintained, highest confidence.
  2. Target app's import_map from ScanContext (populated by MetadataAgent from
     the app's own venv — see agents/agent_metadata.py).
  3. Agent-env runtime map (_RUNTIME_IMPORT_MAP) — built at startup from the
     agent process's own installed packages, used as a fallback when the target
     app's venv was not found.
  4. Heuristic name patterns (strip python- prefix, -python suffix, etc.)
  5. Raw PyPI name as the last resort.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Optional


# ---------------------------------------------------------------------------
# Curated overrides: PyPI dist name (lowercase) → importable top-level name
# Only needed where the names genuinely differ. Alphabetical for readability.
# ---------------------------------------------------------------------------
_PYPI_TO_IMPORT: Dict[str, str] = {
    # Web frameworks and common libs whose import name is not a mechanical
    # transform of the distribution name (added after live crAPI validation, which
    # exposed djangorestframework -> rest_framework as a silent reachability miss).
    "djangorestframework": "rest_framework",
    "djangorestframework-simplejwt": "rest_framework_simplejwt",
    "django-cors-headers": "corsheaders",
    "django-filter": "django_filters",
    "django-extensions": "django_extensions",
    "graphene-django": "graphene_django",
    "flask-cors": "flask_cors",
    "flask-sqlalchemy": "flask_sqlalchemy",
    "pycryptodome": "Crypto",
    "pycryptodomex": "Cryptodome",
    "websocket-client": "websocket",
    "msgpack-python": "msgpack",
    "python-ldap": "ldap",
    # A
    "attrs": "attr",
    "azure-identity": "azure.identity",
    "azure-storage-blob": "azure.storage.blob",
    # B
    "beautifulsoup4": "bs4",
    # C
    "cryptography": "cryptography",
    # D
    "dnspython": "dns",
    # E
    "email-validator": "email_validator",
    # G
    "google-auth": "google.auth",
    "google-cloud-storage": "google.cloud.storage",
    "grpcio": "grpc",
    # H
    "httplib2": "httplib2",
    # I
    "itsdangerous": "itsdangerous",
    # J
    "jinja2": "jinja2",
    # M
    "markupsafe": "markupsafe",
    "mysqlclient": "MySQLdb",
    # O
    "opencv-python": "cv2",
    "opencv-python-headless": "cv2",
    # P
    "pillow": "PIL",
    "protobuf": "google.protobuf",
    "psycopg2-binary": "psycopg2",
    "pyasn1": "pyasn1",
    "pyasn1-modules": "pyasn1_modules",
    "pyjwt": "jwt",
    "pynacl": "nacl",
    "pyopenssl": "OpenSSL",
    "pyserial": "serial",
    "python-dateutil": "dateutil",
    "python-dotenv": "dotenv",
    "python-jose": "jose",
    "python-magic": "magic",
    "python-multipart": "multipart",
    "python-slugify": "slugify",
    "pyyaml": "yaml",
    "pyzmq": "zmq",
    # S
    "scikit-image": "skimage",
    "scikit-learn": "sklearn",
    # T
    "typing-extensions": "typing_extensions",
    # W
    "werkzeug": "werkzeug",
}

# resolve_import_name looks up by ``name.lower().replace("-", "_")``, so any
# curated key written with a hyphen would never match (it was compared against an
# underscore-normalised key). 28 entries were dead this way — e.g. scikit-learn
# never resolved to sklearn, opencv-python never to cv2 — silently falling back
# to the mechanical heuristic. Normalise the keys once so every entry is live.
_PYPI_TO_IMPORT = {k.replace("-", "_"): v for k, v in _PYPI_TO_IMPORT.items()}


def _build_runtime_import_map() -> Dict[str, str]:
    """Build a normalised dist_name → module_name map from the agent's own env."""
    try:
        from importlib.metadata import packages_distributions
        result: Dict[str, str] = {}
        for module_name, dist_names in packages_distributions().items():
            for dist in dist_names:
                key = dist.lower().replace("-", "_")
                result.setdefault(key, module_name)
        return result
    except Exception:
        return {}


# Built once at agent startup from the agent process's own installed packages.
_RUNTIME_IMPORT_MAP: Dict[str, str] = _build_runtime_import_map()


def _heuristic_import_name(pypi_name: str) -> Optional[str]:
    """Apply naming-convention heuristics when all other resolution fails.

    Handles the most common PyPI→import mismatches not covered by the curated
    list and not present in the target app's import_map:
      • "python-foo"  → "foo"   (python- prefix strip)
      • "foo-python"  → "foo"   (-python suffix strip)
      • "py-foo"      → "foo"   (py- prefix strip, less common)
      • "foo-bar"     → "foo_bar" (dashes → underscores, already normalised
                                   by the caller but kept for clarity)
    Returns None when no heuristic applies, so callers can fall through.
    """
    name = pypi_name.lower()

    if name.startswith("python-"):
        candidate = name[len("python-"):]
        if candidate:
            return candidate.replace("-", "_")

    if name.endswith("-python"):
        candidate = name[: -len("-python")]
        if candidate:
            return candidate.replace("-", "_")

    if name.startswith("py-"):
        candidate = name[len("py-"):]
        if candidate:
            return candidate.replace("-", "_")

    return None


def resolve_import_name(
    pypi_name: str,
    import_map: Optional[Dict[str, str]] = None,
) -> str:
    """Resolve a PyPI distribution name to its importable top-level module name.

    Args:
        pypi_name:  The PyPI distribution name as returned by Trivy / pip
                    (e.g. "Pillow", "pyyaml", "python-dateutil").
        import_map: Optional dict of normalised dist_name → module_name built
                    from the *target app's* venv by MetadataAgent.  Takes
                    priority over the agent-env fallback.

    Returns:
        The importable module name (e.g. "PIL", "yaml", "dateutil").
    """
    # Normalise once for all lookups below.
    key = pypi_name.lower().replace("-", "_")

    # 1. Curated overrides (highest confidence, name differs from convention).
    if resolved := _PYPI_TO_IMPORT.get(key):
        return resolved

    # 2. Target app's venv mapping (populated by MetadataAgent).
    if import_map:
        if resolved := import_map.get(key):
            return resolved

    # 3. Agent-env fallback (built at startup from the agent's own packages).
    if resolved := _RUNTIME_IMPORT_MAP.get(key):
        return resolved

    # 4. Heuristic name patterns (python-X → X, X-python → X, py-X → X).
    if resolved := _heuristic_import_name(pypi_name):
        return resolved

    # 5. Raw normalised name as last resort.
    return key


# ---------------------------------------------------------------------------
# String-matching helpers shared by tainter and dynamic-reachability agents
# ---------------------------------------------------------------------------

def word_match(name: str, text: str) -> bool:
    """Return True if *name* appears as a word token in *text*.

    Uses identifier-boundary matching so 'yaml' matches 'yaml.load'
    but NOT 'yaml_processor'.
    """
    if not name or not text:
        return False
    pattern = r"(?<![a-zA-Z0-9_])" + re.escape(name) + r"(?![a-zA-Z0-9_])"
    return bool(re.search(pattern, text, re.IGNORECASE))


def path_component_match(name: str, path: str) -> bool:
    """Return True if *name* is an exact directory component or file stem in *path*.

    'yaml' matches '.../yaml/__init__.py' but NOT '.../yaml_processor.py'.
    """
    if not name or not path:
        return False
    p = Path(path)
    components = {c.lower() for c in p.parts}
    components.add(p.stem.lower())
    return name.lower() in components
