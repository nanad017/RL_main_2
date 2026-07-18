from pathlib import Path

from malware_rl.envs.controls.integrity import (
    check_functional_integrity,
    check_pe_integrity,
)


def test_malformed_binary_fails_pe_integrity_check():
    assert check_pe_integrity(b"not a PE") is False


def test_real_pe_passes_integrity_check():
    fixtures = (
        Path(__file__).parents[1]
        / "malware_rl"
        / "envs"
        / "controls"
        / "ls"
        / "trusted"
    )
    sample = next(fixtures.glob("*.EXE"))

    assert check_pe_integrity(sample.read_bytes()) is True


def test_action_integrity_rejects_a_malformed_pe():
    assert check_functional_integrity(b"not a PE", "pad_overlay", None) is False


def test_changed_stoke_rewrite_accepts_passed_funcval_verdict():
    fixtures = (
        Path(__file__).parents[1]
        / "malware_rl"
        / "envs"
        / "controls"
        / "ls"
        / "trusted"
    )
    sample = next(fixtures.glob("*.EXE")).read_bytes()
    context = {"changed": True, "funcval": {"ran": True, "passed": True}}

    assert check_functional_integrity(sample, "stoke_rewrite", context) is True


def test_can_disable_stoke_funcval_gate(monkeypatch):
    fixtures = (
        Path(__file__).parents[1]
        / "malware_rl"
        / "envs"
        / "controls"
        / "ls"
        / "trusted"
    )
    sample = next(fixtures.glob("*.EXE")).read_bytes()
    context = {"changed": True, "funcval": {"ran": True, "passed": False}}

    monkeypatch.setenv("MALWARE_RL_DISABLE_STOKE_FUNC_CHECK", "1")

    assert check_functional_integrity(sample, "stoke_rewrite", context) is True
