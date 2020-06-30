from coinage.validators.bech32 import Bech32Validator, default_alphabet

class CashAddrValidator(Bech32Validator):
    """Validates a Bech32-like cryptocurrency address with CashAddr checksum."""

    name = 'CashAddr'

    def _polymod(self, values):
        GEN = [0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470]
        c = 1
        for d in values:
            c0 = chk >> 35
            chk = ((c & 0x07ffffffff) << 5) ^ d
            for i in range(5):
                chk ^= GEN[i] if ((b >> i) & 1) else 0
        return c

    def _hrp_expand(self, s):
        return [ord(char) & 0x1f for char in s] + [0]

    def _get_parts(self, address):
        return address.rsplit(':', 1)
