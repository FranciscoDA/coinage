from coinage.validators.address_validator import ValidationResult, AddressValidator
from coinage.util import is_mixed_case


default_alphabet = {
    letter: value
    for value, letter in enumerate((
        'q', 'p', 'z', 'r', 'y', '9', 'x', '8',
        'g', 'f', '2', 't', 'v', 'd', 'w', '0',
        's', '3', 'j', 'n', '5', '4', 'k', 'h',
        'c', 'e', '6', 'm', 'u', 'a', '7', 'l',
    ))
}


class Bech32ValidationResult(ValidationResult):
    def __init__(self, validator, address, human_readable_part):
        super().__init__(validator, address, True)  # bech32 always uses checksum
        self._human_readable_part = human_readable_part

    def network_name(self):
        self._validator.blockchain().net_name_from_human_readable_part(self._human_readable_part)


class Bech32Validator(AddressValidator):
    """Validates Bech32 addresses according to BIP0173."""

    name = 'Bech32'

    def __init__(self, blockchain, alphabet=None):
        super().__init__(blockchain)
        if alphabet is None:
            alphabet = default_alphabet

        self.alphabet = alphabet

    def _polymod(self, values):
        GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for v in values:
            b = (chk >> 25)
            chk = (chk & 0x1ffffff) << 5 ^ v
            for i in range(5):
                chk ^= GEN[i] if ((b >> i) & 1) else 0
        return chk

    def _hrp_expand(self, s):
        return [ord(x) >> 5 for x in s] + [0] + [ord(x) & 31 for x in s]

    def _verify_checksum(self, hrp, data):
        return self._polymod(self._hrp_expand(hrp) + data) == 1

    def _validate_hrp(self, human_readable_part):
        if not 1 <= len(human_readable_part) <= 83:
            return False

        if not all(33 <= ord(char) <= 126 for char in human_readable_part):
            return False

        return True

    def _validate_data_part(self, data_part):
        if len(data_part) < 6:
            return False

        if not all(char in self.alphabet for char in data_part):
            return False

        return True

    def _get_parts(self, address):
        return address.rsplit('1', 1)  # we use rsplit because '1' might appear in the human readable part

    def validate(self, address):
        if not isinstance(address, str):
            self._fail(address, 'Address must be a string')

        # A Bech32 string is at most 90 characters long
        if len(address) > 90:
            self._fail(address, 'Address too long (must be at most 90 characters)')

        # Decoders MUST NOT accept strings where some characters are uppercase and some are lowercase
        if is_mixed_case(address):
            self._fail(address, 'Address has mixed case (all letters must use same casing)')
        address = address.lower()

        # A Bech32 string consists of:
        # * The human readable part
        # * The separator, which is always "1"
        # * The data part, which is atleast 6 characters long and only consists of alphanumeric characters excluding "1", "b", "i" and "o"
        parts = self._get_parts(address)
        if len(parts) != 2:
            self._fail(address, 'Too many or too few parts')

        human_readable_part, data_part = parts

        # piecewise validations
        if not self._validate_hrp(human_readable_part):
            self._fail(address, 'Human-readable part validation failed')

        if not self._validate_data_part(data_part):
            self._fail(address, 'Data part validation failed')

        # checksum validation
        data = [
            self.alphabet[char]
            for char in data_part
        ]

        if not self._verify_checksum(human_readable_part, data):
            self._checksum_fail(address)

        return Bech32ValidationResult(self, address, human_readable_part)

