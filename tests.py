from unittest import TestCase

from coinage import (
    ValidationResult,
    FailedValidation,
    FailedChecksumValidation,
    BitcoinBlockchain,
    BitcoinCashBlockchain,
    EthereumBlockchain,
)
from coinage.validators.bech32 import Bech32Validator
from coinage.validators.cashaddr import CashAddrValidator
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
        Make sure all inheriting classes provide at least one valid and one invalid test vector.
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
                self.assertGreater(len(raised.exception.get_errors()), 0)
                # An invalid vector was detected as a checksum mismatch.
                # Either fix the validator or classify the vector properly
                self.assertFalse(isinstance(raised.exception, FailedChecksumValidation))

    def test_checksum_mismatch_vectors(self):
        for address in self.checksum_mismatch_vectors():
            validator = self.validator()
            with self.subTest(vector=address):
                with self.assertRaises(FailedChecksumValidation) as raised:
                    validator.validate(address)
                self.assertEqual(len(raised.exception.get_errors()), 1)


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


class CashAddrValidatorTestCase(ValidatorTestBase, TestCase):
    def validator(self):
        return CashAddrValidator(BitcoinCashBlockchain())

    def valid_vectors_with_checksum(self):
        return [
            'bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a',
            'bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy',
            'bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r',
            'bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq',
            'bitcoincash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4yc93ky28e',
            'bitcoincash:pqq3728yw0y47sqn6l2na30mcw6zm78dzq5ucqzc37',
            'bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2',
            'bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t',
            'pref:pr6m7j9njldwwzlg9v7v53unlr4jkmx6ey65nvtks5',
            'prefix:0r6m7j9njldwwzlg9v7v53unlr4jkmx6ey3qnjwsrf',
            'bitcoincash:q9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2ws4mr9g0',
            'bchtest:p9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2u94tsynr',
            'pref:p9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2khlwwk5v',
            'prefix:09adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2p29kc2lp',
            'bitcoincash:qgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcw59jxxuz',
            'bchtest:pgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcvs7md7wt',
            'pref:pgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcrsr6gzkn',
            'prefix:0gagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkc5djw8s9g',
            'bitcoincash:qvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq5nlegake',
            'bchtest:pvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq7fqng6m6',
            'pref:pvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq4k9m7qf9',
            'prefix:0vch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxqsh6jgp6w',
            'bitcoincash:qnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklv39gr3uvz',
            'bchtest:pnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklvmgm6ynej',
            'pref:pnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklv0vx5z0w3',
            'prefix:0nq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklvwsvctzqy',
            'bitcoincash:qh3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqex2w82sl',
            'bchtest:ph3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqnzf7mt6x',
            'pref:ph3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqjntdfcwg',
            'prefix:0h3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqakcssnmn',
            'bitcoincash:qmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqscw8jd03f',
            'bchtest:pmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqs6kgdsg2g',
            'pref:pmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqsammyqffl',
            'prefix:0mvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqsgjrqpnw8',
            'bitcoincash:qlg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mtky5sv5w',
            'bchtest:plg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mc773cwez',
            'pref:plg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mg7pj3lh8',
            'prefix:0lg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96ms92w6845',
        ]

    def invalid_vectors(self):
        return [
            'bitcoincashqpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a',
            'bitcoincash:qr95sy3j9x111p32xkykttr4cvcu7as4y0qverfuy',
            'bitcoincash:',
        ]

    # TODO: add some vectors with invalid checksums


# Test the blockchain .validate() method to make sure it works.
# We dont need to be as exhaustive regarding valid/invalid vectors
# since we have already tested them above.


class BitcoinBlockchainTestCase(TestCase):
    def test_base58check_validation(self):
        btc = BitcoinBlockchain()
        result = btc.validate('1MmErJTQpfs5dHC1bTLpGqFM34MqXCaC5r')
        self.assertIsInstance(result, ValidationResult)
        self.assertTrue(result.has_checksum())

    def test_bech32_validation(self):
        btc = BitcoinBlockchain()
        result = btc.validate('an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs')
        self.assertIsInstance(result, ValidationResult)
        self.assertTrue(result.has_checksum())

    def test_is_valid_success(self):
        btc = BitcoinBlockchain()
        result, details = btc.is_valid('1MmErJTQpfs5dHC1bTLpGqFM34MqXCaC5r')
        self.assertTrue(result)
        self.assertIsInstance(details, ValidationResult)

    def test_is_valid_failure(self):
        btc = BitcoinBlockchain()
        result, details = btc.is_valid('lorem ipsum')
        self.assertFalse(result)
        self.assertIsInstance(details, FailedValidation)

    def test_bech32_address_from_main_net(self):
        btc = BitcoinBlockchain()
        result = btc.validate('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')
        self.assertEqual(result.network_name(), BitcoinBlockchain.MAIN_NET)
        self.assertTrue(result.is_from_main_net())

    def test_bech32_address_from_test_net(self):
        btc = BitcoinBlockchain()
        result = btc.validate('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx')
        self.assertEqual(result.network_name(), BitcoinBlockchain.TEST_NET)
        self.assertFalse(result.is_from_main_net())


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

    def test_is_valid_failure(self):
        eth = EthereumBlockchain()
        result, details = eth.is_valid('lorem ipsum')
        self.assertFalse(result)
        self.assertIsInstance(details, FailedValidation)

    def test_is_valid_checksum_error(self):
        eth = EthereumBlockchain()
        result, details = eth.is_valid('0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaeD')
        self.assertFalse(result)
        self.assertIsInstance(details, FailedChecksumValidation)

    def test_address_from_any_net(self):
        eth = EthereumBlockchain()
        result = eth.validate('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed')
        self.assertEqual(result.network_name(), EthereumBlockchain.ALL_NETS)
        self.assertTrue(result.is_from_main_net())


class BitcoinCashBlockchainTestCase(TestCase):
    def test_cashaddr_validation(self):
        bch = BitcoinCashBlockchain()
        result = bch.validate('bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a')
        self.assertIsInstance(result, ValidationResult)
        self.assertTrue(result.has_checksum())

    def test_is_valid_success(self):
        bch = BitcoinCashBlockchain()
        result, details = bch.is_valid('bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a')
        self.assertTrue(result)
        self.assertIsInstance(details, ValidationResult)

    def test_address_from_mainnet(self):
        bch = BitcoinCashBlockchain()
        result = bch.validate('bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a')
        self.assertEqual(result.network_name(), BitcoinCashBlockchain.MAIN_NET)
        self.assertTrue(result.is_from_main_net())

    def test_is_valid_failure(self):
        bch = BitcoinCashBlockchain()
        result, details = bch.is_valid('lorem ipsum')
        self.assertFalse(result)
        self.assertIsInstance(details, FailedValidation)
