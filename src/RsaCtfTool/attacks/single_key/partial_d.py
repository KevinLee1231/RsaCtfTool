#!/usr/bin/python3

import subprocess
from RsaCtfTool.attacks.abstract_attack import AbstractAttack, SAGE_MIN_TIMEOUT
from RsaCtfTool.lib.keys_wrapper import PrivateKey
from RsaCtfTool.lib.utils import rootpath
from RsaCtfTool.lib.exceptions import FactorizationError


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(max(timeout, SAGE_MIN_TIMEOUT))
        self.speed = AbstractAttack.speed_enum["medium"]
        self.required_binaries = ["sage"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run partial_d attack with a timeout"""
        if not isinstance(publickey, PrivateKey) or publickey.d is None:
            self.logger.error(
                "[!] partial_d attack is only for partial private keys not pubkeys..."
            )
            return None, None

        try:
            cmd = [
                "sage",
                f"{rootpath}/sage/partial_d.sage",
                str(publickey.n),
                str(publickey.e),
                str(publickey.d),
            ]
            result = subprocess.check_output(
                cmd,
                timeout=self.timeout,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            p, q = (int(value) for value in result.split())
            if p * q != publickey.n:
                raise FactorizationError("Sage returned factors that do not match n")
        except (
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
            FactorizationError,
            ValueError,
        ):
            self.logger.error("[!] partial_d internal error...")
            return None, None

        publickey.p = p
        publickey.q = q
        return self.create_private_key(publickey)

    def test(self):
        raise NotImplementedError
