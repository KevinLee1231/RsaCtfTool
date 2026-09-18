import shutil
from types import SimpleNamespace

import pytest

from RsaCtfTool.attacks.single_key import binary_polynomial_factoring
from RsaCtfTool.attacks.single_key import lattice
from RsaCtfTool.attacks.single_key import partial_d
from RsaCtfTool.lib.keys_wrapper import PrivateKey


def test_sage_attacks_declare_their_runtime_dependency():
    assert partial_d.Attack().required_binaries == ["sage"]
    assert lattice.Attack().required_binaries == ["sage"]
    assert binary_polynomial_factoring.Attack().required_binaries == ["sage"]


def test_partial_d_parses_sage_factors(monkeypatch):
    key = object.__new__(PrivateKey)
    key.n = 15
    key.e = 7
    key.d = 3
    key.p = None
    key.q = None

    monkeypatch.setattr(
        partial_d.subprocess,
        "check_output",
        lambda *args, **kwargs: "3 5\n",
    )

    private_key, plaintext = partial_d.Attack().attack(key)

    assert plaintext is None
    assert private_key.p * private_key.q == key.n


def test_lattice_parses_sage_factor_list(monkeypatch):
    key = SimpleNamespace(n=15, e=7, p=3)
    monkeypatch.setattr(
        lattice.subprocess,
        "check_output",
        lambda *args, **kwargs: "[3, 5]\n",
    )

    private_key, plaintext = lattice.Attack().attack(key)

    assert plaintext is None
    assert private_key.p * private_key.q == key.n


def test_binary_polynomial_factoring_parses_sage_factor_list(monkeypatch):
    key = SimpleNamespace(n=15, e=7)
    monkeypatch.setattr(
        binary_polynomial_factoring.subprocess,
        "check_output",
        lambda *args, **kwargs: "[3, 5]\n",
    )

    private_key, plaintext = binary_polynomial_factoring.Attack().attack(key)

    assert plaintext is None
    assert private_key.p * private_key.q == key.n


@pytest.mark.attack
def test_binary_polynomial_factoring_runs_with_sage():
    if shutil.which("sage") is None:
        pytest.skip("SageMath is not available on PATH")

    key = SimpleNamespace(n=15, e=7)
    private_key, plaintext = binary_polynomial_factoring.Attack(timeout=30).attack(
        key
    )

    assert plaintext is None
    assert private_key.p * private_key.q == key.n


class _FakeProc:
    def __init__(self, stdout):
        self._out = stdout

    def wait(self, timeout=None):
        return 0

    def communicate(self):
        return self._out, b""


def test_ecm2_parses_factor_tuple(monkeypatch):
    from RsaCtfTool.attacks.single_key import ecm2

    key = SimpleNamespace(n=15, e=7)
    monkeypatch.setattr(
        ecm2.subprocess, "Popen", lambda *a, **k: _FakeProc(b"(3, 5)\n")
    )
    # phi(15) = 8, d = 7^-1 mod 8 = 7, m=2 -> c = 2^7 mod 15 = 8
    private_key, plaintext = ecm2.Attack().attack(key, [b"\x08"])
    assert private_key is None
    assert plaintext == [b"\x02"]
