# Coinage
![Travis](https://travis-ci.org/FranciscoDA/coinage.svg?branch=master)
[![Coverage Status](https://coveralls.io/repos/github/FranciscoDA/coinage/badge.svg?branch=master)](https://coveralls.io/github/FranciscoDA/coinage?branch=master)

Coinage is a python module for validating cryptocurrency addresses with different formats among different blockchain networks.

# Installation

Coinage may be installed either from PyPi:

`pip install python-coinage`

Or directly from this repository:

`pip install git+https://github.com/franciscoda/coinage.git`

# Description

Coinage validates cryptocurrency addresses passed as strings.
The first step to validate such string is to find out to which `BlockchainNetwork`
that cryptocurrency belongs to.
Coinage doesn't provide a mapping from currencies to its
corresponding `BlockchainNetwork` objects since some blockchain networks like Ethereum
allow an arbitrary number of cryptocurrencies to run on top of them.


However, Coinage provides some `BlockchainNetwork` objects along with their
address format validators. The included implementations are listed below:

| BlockchainNetwork     | Address formats       | Net differentation              |
|-----------------------|-----------------------|---------------------------------|
| BitcoinBlockchain     | Base58Check, Bech32   | MAIN_NET, TEST_NET              |
| BitcoinCashBlockchain | Base58Check, CashAddr | MAIN_NET, TEST_NET, REGTEST_NET |
| EthereumBlockchain    | SHA-3                 | *Not possible*                  |


The result from validating an address is a `ValidationResult` object instance.
Along with the `BlockchainNetwork` it belongs to, it can answer to what net
it belongs to.

The default `validate()` method will raise a `FailedValidation` or `FailedChecksumValidation`
error where appropiate. Some address formats may have an implicit or explicit checksum which
is invalid for the given payload. If a checksum mismatch were to occur, a `FailedChecksumValidation`
will be raised.

# Examples

```py
from coinage import BitcoinBlockchain, FailedValidation, FailedChecksumValidation

btc = BitcoinBlockchain()

try:
	valid = btc.validate('abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw')
	if valid.is_from_main_net():
		print('this address looks good')
	else:
		print('this isn\'t a mainnet address')
except FailedChecksumValidation:
	print('you probably made a mistake when copying this address')
except FailedValidation:
	print('this isnt a bitcoin address')
```

Since some developers prefer a validation function that doesn't raise exceptions,
`BlockchainNetwork` objects also provide an `is_valid()` method that can be
used as follows:

```py
from coinage import BitcoinBlockchain, FailedValidation, FailedChecksumValidation

btc = BitcoinBlockchain()

result, details = btc.is_valid('abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw')

if result:
	if details.is_from_main_net():
		print('this address looks good')
	else:
		print('this isn\'t a mainnet address')
else:
	print('this isnt a valid bitcoin address')
```

# Sources
[Bitcoin wiki page about Bech32](https://en.bitcoin.it/wiki/Bech32)

[BIP-0173](https://en.bitcoin.it/wiki/BIP_0173)

[EIP-55](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md)

[CashAddr Spec](https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md)

[Coinaddr Python Module](https://pypi.org/project/coinaddr/)
