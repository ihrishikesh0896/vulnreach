"""Unit tests for agents.ebpf.package_index.

Pure filesystem + zipfile logic — no container, kernel, Docker, or root
needed. This closes a real contributor-testability gap: package_index.py
(322 lines, the Rule R1 path->package attribution logic) previously had zero
coverage outside the Linux/root-gated P0 suite (tests/test_ebpf_observer_p0.py),
even though nothing in it touches the kernel. Runs anywhere Python does.
"""
from __future__ import annotations

import io
import zipfile

import pytest

from agents.ebpf.package_index import (
    PackageEntry, PackageIndex, build_index, build_java, build_node, build_python,
)


# ── PackageIndex.match — longest-prefix lookup ─────────────────────────────────

def test_match_picks_longest_prefix():
    idx = PackageIndex()
    idx.add(PackageEntry(name="app", ecosystem="python", path_prefix="/app/"))
    idx.add(PackageEntry(name="pkg", ecosystem="python", path_prefix="/app/pkg/"))

    match = idx.match("/app/pkg/module.py")
    assert match.name == "pkg"


def test_match_falls_back_to_shorter_prefix():
    idx = PackageIndex()
    idx.add(PackageEntry(name="app", ecosystem="python", path_prefix="/app/"))
    idx.add(PackageEntry(name="pkg", ecosystem="python", path_prefix="/app/pkg/"))

    match = idx.match("/app/other.py")
    assert match.name == "app"


def test_match_exact_dir_without_trailing_slash():
    idx = PackageIndex()
    idx.add(PackageEntry(name="pkg", ecosystem="python", path_prefix="/app/pkg/"))

    assert idx.match("/app/pkg").name == "pkg"


def test_match_returns_none_when_no_prefix_fits():
    idx = PackageIndex()
    idx.add(PackageEntry(name="pkg", ecosystem="python", path_prefix="/app/pkg/"))

    assert idx.match("/other/file.py") is None


def test_match_resorts_after_late_add():
    idx = PackageIndex()
    idx.add(PackageEntry(name="app", ecosystem="python", path_prefix="/app/"))
    assert idx.match("/app/pkg/module.py").name == "app"

    # Adding a more specific entry after an earlier match must still win —
    # `_sorted` has to invalidate on add(), not just at construction time.
    idx.add(PackageEntry(name="pkg", ecosystem="python", path_prefix="/app/pkg/"))
    assert idx.match("/app/pkg/module.py").name == "pkg"


# ── Python ──────────────────────────────────────────────────────────────────────

def test_build_python_dir_package_with_version(tmp_path):
    site = tmp_path / "usr/lib/python3.11/site-packages"
    site.mkdir(parents=True)
    (site / "flask").mkdir()
    (site / "flask" / "__init__.py").write_text("")
    (site / "flask-2.3.0.dist-info").mkdir()

    entries = build_python(str(tmp_path))
    flask = next(e for e in entries if e.name == "flask")
    assert flask.ecosystem == "python"
    assert flask.version == "2.3.0"
    assert flask.path_prefix.endswith("/flask/")
    assert flask.path_prefix.startswith("/usr/lib/python3.11/site-packages")


def test_build_python_single_file_module_with_egg_info(tmp_path):
    site = tmp_path / "site-packages"
    site.mkdir()
    (site / "six.py").write_text("")
    (site / "six-1.16.0.egg-info").mkdir()

    entries = build_python(str(tmp_path))
    six = next(e for e in entries if e.name == "six")
    assert six.version == "1.16.0"
    assert six.path_prefix == "/site-packages/six.py"  # file entry: no trailing slash


def test_build_python_skips_dist_info_and_prune_dirs(tmp_path):
    site = tmp_path / "site-packages"
    site.mkdir()
    (site / "flask-2.3.0.dist-info").mkdir()
    (site / "__pycache__").mkdir()

    entries = build_python(str(tmp_path))
    names = {e.name for e in entries}
    assert "flask-2.3.0.dist-info" not in names
    assert "__pycache__" not in names


def test_build_python_respects_max_depth(tmp_path):
    # site-packages nested deeper than max_depth must not be found.
    deep = tmp_path
    for i in range(12):
        deep = deep / f"d{i}"
    site = deep / "site-packages"
    site.mkdir(parents=True)
    (site / "mod.py").write_text("")

    entries = build_python(str(tmp_path), max_depth=3)
    assert entries == []


# ── Node ──────────────────────────────────────────────────────────────────────

def _write_package_json(pkg_dir, version):
    pkg_dir.mkdir(parents=True, exist_ok=True)
    (pkg_dir / "package.json").write_text(f'{{"version": "{version}"}}')


def test_build_node_plain_package(tmp_path):
    nm = tmp_path / "app/node_modules"
    _write_package_json(nm / "express", "4.18.0")

    entries = build_node(str(tmp_path))
    express = next(e for e in entries if e.name == "express")
    assert express.ecosystem == "node"
    assert express.version == "4.18.0"
    assert express.path_prefix.endswith("/express/")


def test_build_node_scoped_package(tmp_path):
    nm = tmp_path / "node_modules"
    _write_package_json(nm / "@scope" / "pkg", "1.0.0")

    entries = build_node(str(tmp_path))
    scoped = next(e for e in entries if e.name == "@scope/pkg")
    assert scoped.version == "1.0.0"


def test_build_node_nested_dependency_indexed_separately(tmp_path):
    # npm nests a conflicting-version dependency inside its parent's own
    # node_modules. Both the outer and nested copy must get their own entry,
    # at their own version — this is the documented Juice Shop case.
    nm = tmp_path / "node_modules"
    _write_package_json(nm / "left-pad", "1.0.0")
    _write_package_json(nm / "express" / "node_modules" / "left-pad", "1.3.0")

    entries = build_node(str(tmp_path))
    left_pads = [e for e in entries if e.name == "left-pad"]
    versions = {e.version for e in left_pads}
    assert versions == {"1.0.0", "1.3.0"}


def test_build_node_missing_package_json_yields_no_version(tmp_path):
    nm = tmp_path / "node_modules" / "broken"
    nm.mkdir(parents=True)

    entries = build_node(str(tmp_path))
    broken = next(e for e in entries if e.name == "broken")
    assert broken.version is None


# ── Java ────────────────────────────────────────────────────────────────────────

def _make_jar(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_build_java_reads_maven_coordinates(tmp_path):
    jar_bytes = _make_jar({
        "com/example/Foo.class": b"",
        "com/example/Bar.class": b"",
        "META-INF/maven/com.example/myartifact/pom.properties":
            b"artifactId=myartifact\nversion=1.2.3\n",
    })
    (tmp_path / "app.jar").write_bytes(jar_bytes)

    entries = build_java(str(tmp_path))
    assert len(entries) == 1
    e = entries[0]
    assert e.name == "myartifact"
    assert e.version == "1.2.3"
    assert e.ecosystem == "java"
    assert e.path_prefix == "com/example/"


def test_build_java_falls_back_to_filename_without_maven_metadata(tmp_path):
    jar_bytes = _make_jar({"org/acme/Widget.class": b""})
    (tmp_path / "acme-core-4.5.6.jar").write_bytes(jar_bytes)

    entries = build_java(str(tmp_path))
    e = entries[0]
    assert e.name == "acme-core"
    assert e.version == "4.5.6"
    assert e.path_prefix == "org/acme/"


def test_build_java_spring_boot_fat_jar_unpacks_nested_lib(tmp_path):
    inner_jar = _make_jar({
        "com/fasterxml/jackson/databind/ObjectMapper.class": b"",
        "META-INF/maven/com.fasterxml.jackson.core/jackson-databind/pom.properties":
            b"artifactId=jackson-databind\nversion=2.15.0\n",
    })
    outer_jar = _make_jar({
        "BOOT-INF/classes/com/myapp/Application.class": b"",
        "BOOT-INF/lib/jackson-databind-2.15.0.jar": inner_jar,
    })
    (tmp_path / "myapp.jar").write_bytes(outer_jar)

    entries = build_java(str(tmp_path))
    names = {e.name: e for e in entries}

    # Application classes: BOOT-INF/classes/ prefix stripped.
    assert "myapp" in names
    assert names["myapp"].path_prefix == "com/myapp/"

    # Nested dependency jar indexed under its own artifact, by class prefix.
    assert "jackson-databind" in names
    assert names["jackson-databind"].version == "2.15.0"
    assert names["jackson-databind"].path_prefix == "com/fasterxml/jackson/databind/"


def test_build_java_respects_max_jars(tmp_path):
    for i in range(3):
        (tmp_path / f"lib{i}.jar").write_bytes(_make_jar({f"pkg{i}/Cls.class": b""}))

    entries = build_java(str(tmp_path), max_jars=1)
    seen_jars = {e.path_prefix for e in entries}
    assert len(seen_jars) == 1


def test_build_java_ignores_corrupt_jar(tmp_path):
    (tmp_path / "broken.jar").write_bytes(b"not a real zip")

    entries = build_java(str(tmp_path))
    assert entries == []


# ── build_index dispatcher ──────────────────────────────────────────────────────

def test_build_index_default_ecosystems_exclude_java(tmp_path):
    (tmp_path / "app.jar").write_bytes(_make_jar({"a/b/C.class": b""}))
    site = tmp_path / "site-packages"
    site.mkdir()
    (site / "mod.py").write_text("")

    idx = build_index(str(tmp_path))
    names = {e.name for e in idx.entries()}
    assert "mod" in names
    assert not any(e.ecosystem == "java" for e in idx.entries())


def test_build_index_java_opt_in(tmp_path):
    (tmp_path / "app.jar").write_bytes(_make_jar({"a/b/C.class": b""}))

    idx = build_index(str(tmp_path), ecosystems=("java",))
    assert len(idx) == 1
    assert idx.entries()[0].ecosystem == "java"


def test_build_index_returns_matchable_index(tmp_path):
    site = tmp_path / "site-packages"
    site.mkdir()
    (site / "flask").mkdir()
    (site / "flask" / "app.py").write_text("")

    idx = build_index(str(tmp_path), ecosystems=("python",))
    match = idx.match("/site-packages/flask/app.py")
    assert match is not None
    assert match.name == "flask"
