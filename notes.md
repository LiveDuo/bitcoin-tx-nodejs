
### Example
curl --location --request POST 'https://btc.getblock.io/testnet/' --header 'x-api-key: -' --header 'Content-Type: application/json' --data-raw '{"jsonrpc": "2.0", "method": "sendrawtransaction", "params": ["0200000001a7e576b58b3d074e4c095b2e5557968523cd9f1677a21d247acc45f4f9c733f6010000006a473044022005ec72191e65a8d182409591fc4bdc6b3b05c8e0319affe3a986388772ebb83302206f79e266e4189a941b6a1861772218e435ac20419db20af04b2fb2949e3ef9db012102e577d441d501cace792c02bfe2cc15e59672199e2195770a61fd3288fc9f934fffffffff02f4010000000000001976a9147dc70ca254627bebcb54c839984d32dad9092edf88ace8030000000000001976a914c34015187941b20ecda9378bb3cade86e80d2bfe88ac00000000"], "id": "getblock.io"}'

Successful Tx: ee3b6f4d03e93d8a2d9e2364488fe2a390d553c45c4d45a67a37852ebbf4a88a (testnet)
https://live.blockcypher.com/btc-testnet/tx/ee3b6f4d03e93d8a2d9e2364488fe2a390d553c45c4d45a67a37852ebbf4a88a/

### Testnet
https://blockstream.info/testnet/api/
https://github.com/Blockstream/esplora/blob/master/API.md

### Resources
https://github.com/bitcoinjs/bitcoin-ops/blob/master/index.json
https://en.bitcoin.it/wiki/Transaction#General_format_of_a_Bitcoin_transaction_.28inside_a_block.29
https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/payments/p2pkh.js#L58
https://www.derpturkey.com/bitcoin-p2pkh-exploration/
https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
https://appdevtools.com/base58-encoder-decoder
