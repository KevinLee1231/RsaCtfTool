"""Regression tests pinning behaviour fixed during the source audits.

Every test in this file corresponds to a defect that existed before the
sage-compat-and-fixes branch repairs; if any of these fail, a fix has
regressed.
"""
import random

import pytest

from RsaCtfTool.lib.algos import euler, hart, lehman, mlucas, pollard_rho
from RsaCtfTool.lib.conspicuous_check import privatekey_check
from RsaCtfTool.lib.keys_wrapper import PrivateKey
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


class TestFifthAuditRegressions:
    """Fixes from the fifth audit pass (2026-09)."""

    def test_conspicuous_accepts_phi_inverse(self):
        # The tool emits d = e^-1 mod phi; lambda | phi so it also
        # satisfies e*d == 1 (mod lambda). This used to be a false flag.
        p, q, e = 61, 53, 17
        d = pow(e, -1, (p - 1) * (q - 1))
        _, txt = privatekey_check(p * q, p, q, d, e)
        assert "d IS NOT e^(-1)" not in txt
        assert "d IS NOT < " not in txt

    def test_conspicuous_accepts_lambda_inverse(self):
        # Standard implementations emit d = e^-1 mod lambda.
        from math import lcm as _lcm

        p, q, e = 61, 53, 17
        d = pow(e, -1, _lcm(p - 1, q - 1))
        _, txt = privatekey_check(p * q, p, q, d, e)
        assert "d IS NOT e^(-1)" not in txt

    def test_conspicuous_still_rejects_wrong_d(self):
        p, q, e = 61, 53, 17
        _, txt = privatekey_check(p * q, p, q, 12345, e)
        assert "d IS NOT e^(-1)" in txt

    def test_fermat_prime_modulus_returns_none(self):
        from RsaCtfTool.lib.algos import fermat

        assert fermat(101) is None

    def test_lehmer_machine_prime_modulus_returns_none(self):
        from RsaCtfTool.lib.algos import lehmer_machine

        assert lehmer_machine(101) is None

    def test_kraitchik_prime_modulus_returns_none(self):
        from RsaCtfTool.lib.algos import kraitchik

        assert kraitchik(101) is None

    def test_fermat_composite_still_factors(self):
        from RsaCtfTool.lib.algos import fermat

        p, q = 101, 103
        assert tuple(sorted(fermat(p * q))) == (p, q)

    def test_private_key_non_coprime_e_is_inert_not_fatal(self):
        # gcd(e, phi) != 1 used to raise ZeroDivisionError out of the
        # constructor; the key must come out simply unusable instead.
        priv = PrivateKey(p=5, q=7, e=4, n=35)
        assert priv.d is None
        assert priv.key is None

    def test_timeout_nonpositive_disables_timer(self):
        import time as _time

        from RsaCtfTool.lib.utils import timeout as _timeout

        with _timeout(0):
            _time.sleep(0.2)  # must not fire an instant timeout

    def test_timeout_restores_sigterm_handler(self):
        import signal as _signal

        from RsaCtfTool.lib.utils import timeout as _timeout

        before = _signal.getsignal(_signal.SIGTERM)
        with _timeout(30):
            pass
        assert _signal.getsignal(_signal.SIGTERM) is before

    def test_fib_fallback_matches_definition(self):
        from RsaCtfTool.lib.number_theory import _fib

        assert [_fib(i) for i in range(8)] == [0, 1, 1, 2, 3, 5, 8, 13]

    def test_invmod_fallback_raises_without_inverse(self):
        from RsaCtfTool.lib.number_theory import _invmod

        with pytest.raises(ZeroDivisionError):
            _invmod(4, 100)

    def test_decrypt_emits_one_result_per_cipher(self, small_rsa_key):
        # OAEP fails on raw-RSA ciphertexts, so exactly the textbook
        # result is returned (the old code appended duplicates).
        key = small_rsa_key
        priv = PrivateKey(p=key["p"], q=key["q"], e=key["e"], n=key["n"])
        cipher_int = pow(42, key["e"], key["n"])
        cb = cipher_int.to_bytes((cipher_int.bit_length() + 7) // 8, "big")
        out = priv.decrypt([cb])
        assert len(out) == 1
        assert int.from_bytes(out[0], "big") == 42

    def test_decrypt_unusable_key_returns_ciphertext(self):
        priv = PrivateKey(p=5, q=7, e=4, n=35)
        assert priv.decrypt([b"\x01\x02"]) == [b"\x01\x02"]

    def test_reject_unusable_priv_key_drops_shell_objects(self):
        from RsaCtfTool.lib.rsa_attack import RSAAttack

        ra = object.__new__(RSAAttack)
        ra.priv_key = PrivateKey(p=5, q=7, e=4, n=35)
        ra._reject_unusable_priv_key()
        assert ra.priv_key is None

    def test_reject_unusable_priv_key_keeps_d_only_keys(self):
        # Keys with a bare d but no p/q (nonRSA output) stay usable.
        from RsaCtfTool.lib.rsa_attack import RSAAttack

        ra = object.__new__(RSAAttack)
        ra.priv_key = PrivateKey(n=1009 * 1013, e=65537, d=12345)
        ra._reject_unusable_priv_key()
        assert ra.priv_key is not None

    def test_cube_root_rejects_non_perfect_root(self):
        from types import SimpleNamespace

        from RsaCtfTool.attacks.single_key.cube_root import Attack

        priv, plain = Attack().attack(SimpleNamespace(e=3), [b"\x30\x39"])
        assert priv is None
        assert plain is None

    def test_cube_root_accepts_perfect_cube(self):
        from types import SimpleNamespace

        from RsaCtfTool.attacks.single_key.cube_root import Attack

        m = 42
        cb = (m**3).to_bytes(((m**3).bit_length() + 7) // 8, "big")
        priv, plain = Attack().attack(SimpleNamespace(e=3), [cb])
        assert plain == [b"*"]

    def test_common_modulus_filters_none_results(self):
        from types import SimpleNamespace

        from RsaCtfTool.attacks.multi_keys.common_modulus_related_message import (
            Attack,
        )

        k1 = SimpleNamespace(n=15, e=7)
        k2 = SimpleNamespace(n=35, e=5)  # different modulus -> every pair None
        priv, plains = Attack().attack([k1, k2], [b"\x01", b"\x02"])
        assert priv is None
        assert plains is None

    def test_factordb_rejects_multiprime_factor_list(self, monkeypatch):
        from types import SimpleNamespace

        from RsaCtfTool.attacks.single_key import factordb as factordb_attack

        monkeypatch.setattr(factordb_attack, "getfdb", lambda n: [3, 5, 7])
        priv, plain = factordb_attack.Attack().attack(SimpleNamespace(n=105, e=7))
        assert priv is None
        assert plain is None


class TestFifthAuditPerformanceFixes:
    """Performance-only fixes from the fifth audit; results must stay
    equivalent (or, for smallq, match its documented q < 100000 bound)."""

    def test_fermat_number_gcd_modular_equivalence(self):
        # gcd(F_x, n) == gcd(2^(2^x) mod n + 1, n) - the identity the
        # attack now relies on instead of building the full Fermat number.
        from RsaCtfTool.lib.number_theory import gcd, powmod

        rng = random.Random(99)
        n = rand_semiprime(rng, 64)
        for x in range(2, 13):
            f = (1 << (1 << x)) + 1
            assert gcd(f, n) == gcd(powmod(2, 1 << x, n) + 1, n)

    def test_close_factor_hits_close_primes(self):
        from RsaCtfTool.lib.algos import close_factor
        from RsaCtfTool.lib.number_theory import next_prime

        base = 1 << 128
        p = int(next_prime(base - 10**5))
        q = int(next_prime(base + 10**5))
        r = close_factor(p * q, 2 * 10**5, progress=False)
        assert r is not None
        assert sorted(r) == sorted([p, q])

    def test_load_system_consts_is_cached(self):
        from RsaCtfTool.lib.system_primes import load_system_consts

        first = load_system_consts()
        assert first is load_system_consts()

    def test_smallq_finds_factor_below_bound(self):
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey
        from RsaCtfTool.attacks.single_key.smallq import Attack

        key_data = RSA.construct((54311 * 1009, 65537)).publickey().exportKey()
        priv, _ = Attack().attack(PublicKey(key_data), progress=False)
        assert priv is not None


class TestFifthAuditFollowups:
    """Degenerate-result handling pinned right after the fifth audit."""

    def test_comfact_cn_cipher_multiple_of_n_misses_cleanly(self):
        # gcd(n, c) == n used to build a bogus (1, n) "key" and leave
        # publickey.p/q polluted for the remaining attacks.
        from RsaCtfTool.attacks.single_key.comfact_cn import Attack
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        n = 101 * 113
        pub = PublicKey(RSA.construct((n, 17)).publickey().exportKey())
        priv, _ = Attack(timeout=10).attack(
            pub, cipher=[(2 * n).to_bytes(3, "big")], progress=False
        )
        assert priv is None
        assert pub.p is None and pub.q is None

    def test_comfact_cn_real_shared_factor_still_recovers(self):
        from RsaCtfTool.attacks.single_key.comfact_cn import Attack
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        n = 101 * 113
        pub = PublicKey(RSA.construct((n, 17)).publickey().exportKey())
        priv, _ = Attack(timeout=10).attack(
            pub, cipher=[(101 * 7).to_bytes(3, "big")], progress=False
        )
        assert priv is not None and priv.key is not None
        assert sorted([priv.p, priv.q]) == [101, 113]

    def test_classical_shor_prime_power_modulus_misses_cleanly(self):
        # n = p**k gives a non-coprime split; the resulting wrong-phi key
        # used to be returned as a success carrying a wrong d.
        from RsaCtfTool.attacks.single_key.classical_shor import Attack
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        pub = PublicKey(RSA.construct((27, 5)).publickey().exportKey())
        assert Attack(timeout=10).attack(pub, progress=False) == (None, None)

    def test_classical_shor_semiprime_still_recovers(self):
        from RsaCtfTool.attacks.single_key.classical_shor import Attack
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        pub = PublicKey(RSA.construct((77, 13)).publickey().exportKey())
        priv, _ = Attack(timeout=10).attack(pub, progress=False)
        assert priv is not None and priv.key is not None
        assert sorted([priv.p, priv.q]) == [7, 11]

    def test_boneh_durfee_inconsistent_sage_output_misses_cleanly(
        self, monkeypatch
    ):
        # A positive but inconsistent d from the lattice script used to
        # escape as a ValueError out of RSA.construct.
        import subprocess

        from RsaCtfTool.attacks.single_key.boneh_durfee import Attack
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: b"12345")
        pub = PublicKey(RSA.construct((101 * 113, 17)).publickey().exportKey())
        assert Attack(timeout=10).attack(pub, progress=False) == (None, None)

    def test_tiny_modulus_short_circuits_single_key_mode(self):
        from types import SimpleNamespace

        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey
        from RsaCtfTool.lib.rsa_attack import RSAAttack

        attackobj = RSAAttack(SimpleNamespace(decrypt=None, attack=[]))
        pub = PublicKey(
            RSA.construct((35, 3)).publickey().exportKey(), filename="tiny"
        )
        pub.n = 1  # hand-crafted degenerate modulus
        assert attackobj.attack_single_key(pub) is True
        assert attackobj.priv_key is None
