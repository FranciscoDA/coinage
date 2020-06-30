import base58check
from hashlib import sha256

from coinage.validators.address_validator import AddressValidator, ValidationResult


class Base58CheckValidationResult(ValidationResult):
    def __init__(self, validator, address, version_bytes):
        super().__init__(validator, address, True)  # base58check always uses checksum
        self._version_bytes = version_bytes

    def network_name(self):
        self._validator.blockchain().net_name_from_version_bytes(self._version_bytes)

default_alphabet = frozenset(base58check.DEFAULT_CHARSET.decode('ascii'))

class Base58CheckValidator(AddressValidator):
    """Validates Base58Check based cryptocurrency addresses."""

    name = 'Base58Check'

    def validate(self, address):
        if not isinstance(address, str):
            self._fail(address, 'Address must be a string')

        if not 25 <= len(address) <= 35:
            self._fail(address, 'Address length must be between 25 and 35 characters')

        if not all(char in default_alphabet for char in address):
            self._fail(address, 'Address has invalid characters')

        abytes = base58check.b58decode(address)

        checksum = sha256(sha256(abytes[:-4]).digest()).digest()[:4]

        if abytes[-4:] != checksum:
            self._checksum_fail(address)

        return Base58CheckValidationResult(self, address, abytes[0])

