from unittest import TestCase
import unittest

from coinage import (
    ValidationResult,
    FailedValidation,
    FailedChecksumValidation,
    BitcoinBlockchain,
    EthereumBlockchain,
)
from coinage.validators.bech32 import Bech32Validator
from coinage.validators.sha3 import Sha3Validator
from coinage.validators.base58check import Base58CheckValidator


class ValidatorTestBase():
    """
    Mother of all validator test cases
    """

    def validator(self):
        raise NotImplementedError()

    def valid_vectors_with_checksum(self):
        return []

    def valid_vectors_without_checksum(self):
        return []

    def invalid_vectors(self):
        return []

    def checksum_mismatch_vectors(self):
        return []

    def invalid_addresses(self):
        return [
            '',
            100,
            None,
            [],
            tuple()
        ]

    def test_this_test_case_is_valid(self):
        """
        This is a sanity check to make sure all inheriting classes provide at least one valid
        and one invalid test vector.
        """
        self.assertGreater(len(self.valid_vectors_with_checksum()) + len(self.valid_vectors_without_checksum()), 0)
        self.assertGreater(len(self.invalid_vectors()) + len(self.checksum_mismatch_vectors()), 0)

    def test_valid_vectors_with_checksum(self):
        for address in self.valid_vectors_with_checksum():
            validator = self.validator()
            with self.subTest(vector=address):
                result = validator.validate(address)
                self.assertIsInstance(result, ValidationResult)
                self.assertTrue(result.has_checksum())

    def test_valid_vectors_without_checksum(self):
        for address in self.valid_vectors_without_checksum():
            validator = self.validator()
            with self.subTest(vector=address):
                result = validator.validate(address)
                self.assertIsInstance(result, ValidationResult)
                self.assertFalse(result.has_checksum())

    def test_invalid_vectors(self):
        for address in self.invalid_vectors() + self.invalid_addresses():
            validator = self.validator()
            with self.subTest(vector=address):
                with self.assertRaises(FailedValidation) as raised:
                    validator.validate(address)
                self.assertIsInstance(raised.exception, FailedValidation)
                # An invalid vector was detectedas a checksum mismatch.
                # Either ix the validator or classify the vector properly
                self.assertFalse(isinstance(raised.exception, FailedChecksumValidation))

    def test_checksum_mismatch_vectors(self):
        for address in self.checksum_mismatch_vectors():
            validator = self.validator()
            with self.subTest(vector=address):
                with self.assertRaises(FailedChecksumValidation):
                    validator.validate(address)


class Bech32ValidatorTestCase(ValidatorTestBase, TestCase):
    def validator(self):
        return Bech32Validator(BitcoinBlockchain())

    def valid_vectors_with_checksum(self):
        return [
            'A12UEL5L',
            'a12uel5l',
            'an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs',
            'abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw',
            '11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j',
            'split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w',
            '?1ezyfcl',
        ]

    def invalid_vectors(self):
        return [
            '\x201nwldj5',  # HRP character out of range
            '\x7F1axkwrx',  # HRP character out of range
            '\x801eym55h',  # HRP character out of range
            'an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx',  # overall max length exceeded
            'pzry9x0s0muk',  # No separator character
            '1pzry9x0s0muk',  # Empty HRP
            'x1b4n0q5v',  # Invalid data character
            'li1dgmt3',  # Too short checksum
            'de1lg7wt\xFF',  # Invalid character in checksum
            '10a06t8',  # empty HRP
            '1qzzfhee',  # empty HRP
        ]

    def checksum_mismatch_vectors(self):
        return [
            'A1G7SGD8',  # checksum calculated with uppercase form of HRP
        ]


class Sha3ValidatorTestCase(ValidatorTestBase, TestCase):
    def validator(self):
        return Sha3Validator(EthereumBlockchain())

    def valid_vectors_with_checksum(self):
        return [
            '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
            '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
            '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
            '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb',
        ]
    
    def valid_vectors_without_checksum(self):
        return [vector.lower() for vector in self.valid_vectors_with_checksum()]

    def checksum_mismatch_vectors(self):
        # just bork some capital letters from the valid vectors
        return [
            '0x' + vector[2:22].lower() + vector[2:22].upper()
            for vector in self.valid_vectors_with_checksum()
        ]

    def invalid_vectors(self):
        return [
            'aaaaaaaaa'
            '0xaaaaaaaaa'
            '0x0'
            'z'
            '0x' + 'z' * 40
        ]


class Base58CheckValidatorTestCase(ValidatorTestBase, TestCase):
    def validator(self):
        return Base58CheckValidator(BitcoinBlockchain())

    def valid_vectors_with_checksum(self):
        return [
            '1MmErJTQpfs5dHC1bTLpGqFM34MqXCaC5r',
            '1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i',
            '3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xou',
            '1Ax4gZtb7gAit2TivwejZHYtNNLT18PUXJ',
            '3QjYXhTkvuj8qPaXHTTWb5wjXhdsLAAWVy',
            '1C5bSj1iEGUgSTbziymG7Cn18ENQuT36vv',
            '3AnNxabYGoTxYiTEZwFEnerUoeFXK2Zoks',
            '1Gqk4Tv79P91Cc1STQtU3s1W6277M2CVWu',
            '33vt8ViH5jsr115AGkW6cEmEz9MpvJSwDk',
            '1JwMWBVLtiqtscbaRHai4pqHokhFCbtoB4',
            '3QCzvfL4ZRvmJFiWWBVwxfdaNBT8EtxB5y',
            '19dcawoKcZdQz365WpXWMhX6QCUpR9SY4r',
            '37Sp6Rv3y4kVd1nQ1JV5pfqXccHNyZm1x3',
            '13p1ijLwsnrcuyqcTvJXkq2ASdXqcnEBLE',
            '3ALJH9Y951VCGcVZYAdpA3KchoP9McEj1G',
        ]

    def invalid_vectors(self):
        return [
            'a',
            '1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62I',
            '3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xo0',
            '1Ax4gZtb7gAit2TivwejZHYtNNLT18PUXO',
            '3QjYXhTkvuj8qPaXHTTWb5wjXhdsLAAWVl',
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        ]

    def checksum_mismatch_vectors(self):
        return [
            '1MmErJTQpfs5dHC1bTLpGqFM34MqXCaC5R',
            'XC5bSj1iEGUgSTbziymG7Cn18ENQuT36vv',
        ]


# Test the blockchain .validate() method to make sure it works.
# We dont need to be as exhaustive regarding valid/invalid vectors
# since we have already tested them above.


class BitcoinBlockchainTestCase(TestCase):
    def test_base58check_validate_success(self):
        btc = BitcoinBlockchain()
        result = btc.validate('1MmErJTQpfs5dHC1bTLpGqFM34MqXCaC5r')
        self.assertIsInstance(result, ValidationResult)
        self.assertTrue(result.has_checksum())

    def test_bech32_validate_success(self):
        btc = BitcoinBlockchain()
        result = btc.validate('an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs')
        self.assertIsInstance(result, ValidationResult)
        self.assertTrue(result.has_checksum())

    def test_is_valid_success(self):
        btc = BitcoinBlockchain()
        result, details = btc.is_valid('1MmErJTQpfs5dHC1bTLpGqFM34MqXCaC5r')
        self.assertTrue(result)
        self.assertIsInstance(details, ValidationResult)
        

class EthereumBlockchainTestCase(TestCase):
    def test_sha3_validation(self):
        eth = EthereumBlockchain()
        result = eth.validate('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed')
        self.assertIsInstance(result, ValidationResult)
        self.assertTrue(result.has_checksum())

    def test_is_valid_success(self):
        eth = EthereumBlockchain()
        result, details = eth.is_valid('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed')
        self.assertTrue(result)
        self.assertIsInstance(details, ValidationResult)

