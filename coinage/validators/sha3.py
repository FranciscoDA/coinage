import sha3
import re
from string import hexdigits

from coinage.validators.address_validator import AddressValidator, ValidationResult
from coinage.util import is_mixed_case


class Sha3ValidationResult(ValidationResult):
    def network_name(self):
        return self._validator.blockchain().ALL_NETS


class Sha3Validator(AddressValidator):
    """Validates SHA-3/Keccak-based cryptocurrency addresses with optional EIP55 checksum."""

    name = 'SHA-3 Hash'

    # This checksum generating algorithm was taken directly from the EIP55 proposal
    # If you think you can refactor or optimize this in some clever way, you're probably wrong
    # Don't modify anything below this comment until the end of the heredoc <<EOD
    def _checksum_encode(self, addr):
        # Treat the hex address as ascii/utf-8 for keccak256 hashing
        addr = addr.lower()
        hashed_address = sha3.keccak_256(addr.encode('ascii')).hexdigest()

        checksummed_buffer = ""
        # Iterate over each character in the hex address
        for nibble_index, character in enumerate(addr):

            if character in "0123456789":
                # We can't upper-case the decimal digits
                checksummed_buffer += character
            elif character in "abcdef":
                # Check if the corresponding hex digit (nibble) in the hash is 8 or higher
                hashed_address_nibble = int(hashed_address[nibble_index], 16)
                if hashed_address_nibble > 7:
                    checksummed_buffer += character.upper()
                else:
                    checksummed_buffer += character

        return "0x" + checksummed_buffer
    # EOD

    def validate(self, address):
        if not isinstance(address, str):
            self._fail(address, 'Address must be a string')

        if len(address) != 42:
            self._fail(address, 'Address must be 42 characters long')

        if not address.startswith('0x'):
            self._fail(address, 'Address must have a leading 0x')

        hexdigest = address[2:]

        if not all(char in hexdigits for char in hexdigest):
            self._fail(address, 'Hex digest has invalid characters')

        has_checksum = is_mixed_case(hexdigest)
        if has_checksum:
            checksummed_address = self._checksum_encode(hexdigest)
            if checksummed_address != address:
                self._checksum_fail(address)

        return Sha3ValidationResult(self, address, has_checksum)

