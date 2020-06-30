# Coinage
![Travis](https://travis-ci.org/FranciscoDA/coinage.svg?branch=master)

Coinage is a python module for validating cryptocurrency addresses with different formats among different blockchain networks.

# Example

```
from coinage import BitcoinBlockchain, FailedValidation, FailedChecksumValidation

btc = BicoinBlockchain()

try:
	valid = btc.validate('abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw')
	if valid.is_from_main_net(btc):
		print('this address looks good')
	else:
		print('this isn\'t a mainnet address')
except FailedValidation:
	print('this isnt a bitcoin address')
except FailedChecksumValidation:
	print('you probably made a mistake when copying this address')

```

# Sources
[Bitcoin wiki page about Bech32](https://en.bitcoin.it/wiki/Bech32)
[BIP-0173](https://en.bitcoin.it/wiki/BIP_0173)
[EIP-55](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md)
[CashAddr Spec](https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md)
[Coinaddr Python Module](https://pypi.org/project/coinaddr/)
