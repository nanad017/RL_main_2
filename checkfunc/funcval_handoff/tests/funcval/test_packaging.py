"""Packaging tests: bundled-library resolution + env override.

These are STDLIB-ONLY (no unicorn / capstone / z3) so they run on the build
machine to confirm the wheel bundles its data and the env knob works.
"""
import funcval.oracles.proven as proven


def test_bundled_library_resolves():
    p = proven.resolve_library_path()
    assert p.exists()
    assert p.name == "equiv_library_proven_v3_cleaned.json"


def test_env_override(monkeypatch, tmp_path):
    fake = tmp_path / "lib.json"
    fake.write_text("[]")
    monkeypatch.setenv("FUNCVAL_LIBRARY_PATH", str(fake))
    assert proven.resolve_library_path() == fake
