"""Regression tests pinning behaviour fixed during the source audits.

Every test in this file corresponds to a defect that existed before the
sage-compat-and-fixes branch repairs; if any of these fail, a fix has
regressed.
"""
import random

import pytest

from RsaCtfTool.lib.algos import euler, hart, lehman, mlucas, pollard_rho
from RsaCtfTool.lib.conspicuous_check import privatekey_check
from RsaCtfTool.lib.number_theory import (
    ilogb,
    inv_mod_pow_of_2,
    is_prime,
    miller_rabin,
)


def rand_semiprime(rng, bits_each):
    while True:
        a = rng.getrandbits(bits_each) | (1 << (bits_each - 1)) | 1
        b = rng.getrandbits(bits_each) | (1 << (bits_each - 1)) | 1
        if a != b and is_prime(a) and is_prime(b):
            return a * b


class TestMlucasChain:
    """mlucas must implement the MSB-first Lucas multiplication chain."""

    def test_multiplication_chain_semantics(self):
        rng = random.Random(2024)

        def V(k, P, mod):
            u, w = 2 % mod, P % mod
            if k == 0:
                return u
            for _ in range(k - 1):
                u, w = w, (P * w - u) % mod
            return w

        for _ in range(50):
            n = 3
            while not is_prime(n) or n < 1000:
                n = rng.getrandbits(40) | 1
            P = rng.randrange(3, n - 1)
            m = rng.randrange(3, 200)
            a = rng.randrange(2, 32)
            assert mlucas(V(m, P, n), a, n) == V(m * a, P, n)


class TestInvModPowOf2:
    @pytest.mark.parametrize(
        "factor,bits,expected", [(3, 8, 171), (5, 12, 3277)]
    )
    def test_known_inverses(self, factor, bits, expected):
        assert inv_mod_pow_of_2(factor, bits) == expected

    def test_round_trip_random(self):
        rng = random.Random(7)
        for _ in range(100):
            bits = rng.randrange(8, 65)
            a = rng.getrandbits(bits) | 1
            assert (a * inv_mod_pow_of_2(a, bits)) % (1 << bits) == 1

    def test_even_factor_rejected(self):
        with pytest.raises(ValueError):
            inv_mod_pow_of_2(4, 8)


class TestPrimalityEdges:
    @pytest.mark.parametrize("n", [2, 3, 5, 7, 11])
    def test_small_primes_true(self, n):
        assert miller_rabin(n) is True

    @pytest.mark.parametrize("n", [1, 4, 9, 15])
    def test_small_composites_false(self, n):
        assert miller_rabin(n) is False

    def test_ilogb_big_int_no_overflow(self):
        assert ilogb(1 << 1100, 2) == 1100
        assert ilogb(1000, 10) == 3


class TestFactoringContracts:
    """Factoring functions return valid splits or None - never garbage."""

    def test_pollard_rho_never_trivial(self):
        rng = random.Random(11)
        for _ in range(10):
            n = rand_semiprime(rng, 16)
            d = pollard_rho(n)
            assert d is None or 1 < int(d) < n and n % int(d) == 0

    def test_lehman_valid_or_none(self):
        rng = random.Random(13)
        for _ in range(10):
            n = rand_semiprime(rng, 14)
            r = lehman(n)
            assert r is None or (
                len(r) == 2 and int(r[0]) * int(r[1]) == n and 1 < int(r[0]) < n
            )

    def test_hart_valid_split(self):
        rng = random.Random(17)
        for _ in range(6):
            n = rand_semiprime(rng, 15)
            r = hart(n)
            assert isinstance(r, tuple) and int(r[0]) * int(r[1]) == n

    def test_williams_pp1_splits_smooth_plus_one(self):
        # p+1 and q+1 both smooth: the method's designed sweet spot,
        # exercising the corrected Lucas chain end-to-end.
        p, q = 601, 401          # p+1=602=2*7*43, q+1=402=2*3*67
        from RsaCtfTool.lib.algos import williams_pp1

        r = williams_pp1(p * q, max_v=80)
        assert isinstance(r, tuple) and int(r[0]) * int(r[1]) == p * q

    def test_euler_textbook_example(self):
        assert tuple(map(int, euler(1000009))) == (293, 3413)


class TestConspicuousCheck:
    def test_all_violations_reported(self):
        # p=4, q=6 composite; e=14 shares factor 2 with both; 4*6 != 15 ...
        ret, txt = privatekey_check(15, 4, 6, 3, 14)
        assert ret is True
        for needle in (
            "p IS NOT PROBABLE PRIME",
            "q IS NOT PROBABLE PRIME",
            "p and e ARE NOT RELATIVELY PRIME",
            "q and e ARE NOT RELATIVELY PRIME",
            "n IS NOT p * q",
        ):
            assert needle in txt, f"violation lost from report: {needle}"


class TestGeneratePQContract:
    def test_derives_missing_prime(self):
        from RsaCtfTool.lib.keys_wrapper import generate_pq_from_n_and_p_or_q

        assert generate_pq_from_n_and_p_or_q(15, 3, None) == (3, 5)
        assert generate_pq_from_n_and_p_or_q(15, None, 5) == (3, 5)

    def test_rejects_non_dividing_prime(self):
        from RsaCtfTool.lib.keys_wrapper import generate_pq_from_n_and_p_or_q

        with pytest.raises(ValueError):
            generate_pq_from_n_and_p_or_q(15, 4, None)

    def test_rejects_missing_primes(self):
        from RsaCtfTool.lib.keys_wrapper import generate_pq_from_n_and_p_or_q

        with pytest.raises(ValueError):
            generate_pq_from_n_and_p_or_q(15, None, None)


class TestSameNHugeE:
    """The multi-key common-modulus attack must handle gcd(e1,e2) > 1."""

    def _keys_and_ciphers(self, m, e1, e2):
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        p, q = 1009, 30071              # lcm(p-1,q-1) coprime to 15
        n = p * q
        k1 = RSA.construct((n, e1)).publickey().exportKey()
        k2 = RSA.construct((n, e2)).publickey().exportKey()
        pubs = [PublicKey(k1), PublicKey(k2)]
        c1 = pow(m, e1, n)
        c2 = pow(m, e2, n)
        ciphers = [
            c1.to_bytes((c1.bit_length() + 7) // 8, "big"),
            c2.to_bytes((c2.bit_length() + 7) // 8, "big"),
        ]
        return pubs, ciphers

    def test_shared_factor_small_message_recovered(self):
        from RsaCtfTool.attacks.multi_keys.same_n_huge_e import Attack

        m = 31                          # m^5 < n
        pubs, ciphers = self._keys_and_ciphers(m, 5, 15)
        _, plaintext = Attack(timeout=30).attack(pubs, ciphers)
        assert plaintext is not None
        assert int.from_bytes(plaintext, "big") == m

    def test_shared_factor_large_message_fails_cleanly(self):
        from RsaCtfTool.attacks.multi_keys.same_n_huge_e import Attack

        m_big = pow(7, 40, 1009 * 30071) * 3      # m^5 >> n
        pubs, ciphers = self._keys_and_ciphers(m_big, 5, 15)
        _, plains = Attack(timeout=30).attack(pubs, ciphers)
        assert plains is None or all(p is None for p in plains)


class TestSageHelperScriptPreflight:
    """Every attack that shells out to a sage helper script must declare
    it in required_scripts so a missing script is caught by can_run()."""

    SAGE_SUBPROCESS_ATTACKS = {
        "ecm": "sage/ecm.sage",
        "ecm2": "sage/ecm2.sage",
        "qs": "sage/qs.sage",
        "boneh_durfee": "sage/boneh_durfee.sage",
        "smallfraction": "sage/smallfraction.sage",
        "small_crt_exp": "sage/small_crt_exp.sage",
        "binary_polynomial_factoring": "sage/binary_polynomial_factoring.sage",
        "partial_d": "sage/partial_d.sage",
        "lattice": "sage/lattice.sage",
        "qicheng": "sage/qicheng.sage",
        "roca": "sage/roca_attack.py",
    }

    def test_scripts_declared_and_present(self):
        import importlib
        import os
        from RsaCtfTool.attacks.abstract_attack import _ROOTPATH

        for module_name, script in self.SAGE_SUBPROCESS_ATTACKS.items():
            module = importlib.import_module(
                f"RsaCtfTool.attacks.single_key.{module_name}"
            )
            attack = module.Attack(timeout=1)
            assert script in attack.required_scripts, module_name
            assert os.path.isfile(os.path.join(_ROOTPATH, script)), script


class TestWolframAlphaPreflight:
    def test_api_key_alone_does_not_enable(self, monkeypatch):
        import shutil
        from RsaCtfTool.attacks.single_key.wolframalpha import Attack

        monkeypatch.setenv("WA_API_KEY", "dummy-key")
        binary_present = shutil.which("wolframalpha") is not None
        assert Attack().can_run() is binary_present

    def test_missing_api_key_disables(self, monkeypatch):
        from RsaCtfTool.attacks.single_key.wolframalpha import Attack

        monkeypatch.delenv("WA_API_KEY", raising=False)
        assert Attack().can_run() is False
