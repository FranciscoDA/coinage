
class ValidationResult:
    def __init__(self, validator, address, has_checksum):
        self._validator = validator
        self.address = address
        self._has_checksum = has_checksum

    def has_checksum(self):
        return self._has_checksum

    def network_name(self):
        raise NotImplementedError

    def is_from_main_net(self):
        self._validator.blockchain().is_main_net(self.network_name())

    def __str__(self):
        result = f'{self.address} is a valid {self.validator.name} address'
        if self._has_checksum:
            result = f'{result} with checksum'
        return result


class FailedValidation(Exception):
    def __init__(self, validator, address, *errors):
        self.validator = validator
        self.address = address
        self.errors = errors

    def get_errors(self):
        return self.errors[:]


class FailedChecksumValidation(FailedValidation):
    def __init__(self, validator, address):
        self.validator = validator
        self.address = address

    def get_errors(self):
        return ['Checksum mismatch']


class AddressValidator:
    def __init__(self, blockchain):
        self._blockchain = blockchain

    def blockchain(self):
        return self._blockchain

    def validate(self, address):
        raise NotImplementedError

    def _fail(self, address, *errors):
        raise FailedValidation(self, address, *errors)

    def _checksum_fail(self, address):
        raise FailedChecksumValidation(self, address)

