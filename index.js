const crypto = require('crypto')

const secp256k1 = require('secp256k1')
const base58 = require('bs58')


////////////////////////////////////////////////////////////
/////   Utils
////////////////////////////////////////////////////////////

const OPS = { OP_DUP: 0x76, OP_EQUALVERIFY: 0x88, OP_HASH160: 0xa9, OP_CHECKSIG: 0xac, OP_PUSHDATA1: 0x4c, }

const sha256 = (data) => crypto.createHash('sha256').update(data).digest()
const ripemd160 = (data) => crypto.createHash('ripemd160').update(data).digest()

const varUintEncodingLength = (n) => (n < 0xfd ? 1 : n <= 0xffff ? 3 : n <= 0xffffffff ? 5 : 9)

const varUintEncode = (number, buffer, offset) => {
  if (!buffer) buffer = Buffer.alloc(varUintEncodingLength(number))

  // 8 bit
  if (number < 0xfd) {
    buffer.writeUInt8(number, offset)

  // 16 bit
  } else if (number <= 0xffff) {
    buffer.writeUInt8(0xfd, offset)
    buffer.writeUInt16LE(number, offset + 1)

  // 32 bit
  } else if (number <= 0xffffffff) {
    buffer.writeUInt8(0xfe, offset)
    buffer.writeUInt32LE(number, offset + 1)

  // 64 bit
  } else {
    buffer.writeUInt8(0xff, offset)
    buffer.writeUInt32LE(number >>> 0, offset + 1)
    buffer.writeUInt32LE((number / 0x100000000) | 0, offset + 5)
  }

  return buffer
}

const bip66Encode = (r, s) => {
  const rP = Buffer.from([0x30, r.length + s.length + 4, 0x02, r.length])
  const sP = Buffer.from([0x02, s.length])
  return Buffer.concat([rP, r, sP, s])
}

const fromBase58Check = (address) => Buffer.from(base58.decode(address).slice(0, -4)).subarray(1)


////////////////////////////////////////////////////////////
/////   Helpers
////////////////////////////////////////////////////////////


const compileScript = (chunks) => {
  return Buffer.concat(chunks.map(c => Buffer.isBuffer(c) ? Buffer.concat([Buffer.from([c.length]), c]) : Buffer.from([c])))
}

const getTxSize = (vins, vouts) => {
  const versionSize = 4
  const vinsSize = vins
    .map(vin => (vin.scriptSig?.length ?? vin.script.length))
    .reduce((sum, len) => sum + 40 + varUintEncodingLength(len) + len, 0) + varUintEncodingLength(vouts.length)
  const voutsSize = vouts
    .map(vout => vout.script.length)
    .reduce((sum, len) => sum + 8 + varUintEncodingLength(len) + len, 0)
  const locktime = 4
  return versionSize + varUintEncodingLength(vins.length) + vinsSize + voutsSize + locktime
}

const txToBuffer = (tx) => {
  const _buffer = Buffer.alloc(getTxSize(tx.vins, tx.vouts))
  let _position = 0
  
  // version
  _buffer.writeInt32LE(tx.version, _position)
  _position += 4

  // vin length
  b = varUintEncode(tx.vins.length)
  b.copy(_buffer, _position)
  _position += b.length

  // vin
  for (let vin of tx.vins) {
    b = vin.hash
    b.copy(_buffer, _position)
    _position += b.length
    
    _buffer.writeUInt32LE(vin.vout, _position)
    _position += 4

    if (vin.scriptSig) {
      b = varUintEncode(vin.scriptSig.length)
      b.copy(_buffer, _position)
      _position += b.length

      b = vin.scriptSig
      b.copy(_buffer, _position)
      _position += b.length
      
    } else {
      b = varUintEncode(vin.script.length)
      b.copy(_buffer, _position)
      _position += b.length

      b = vin.script
      b.copy(_buffer, _position)
      _position += b.length
    }
    _buffer.writeUInt32LE(vin.sequence, _position)
    _position += 4
  }

  // vout length
  b = varUintEncode(tx.vouts.length)
  b.copy(_buffer, _position)
  _position += b.length
  
  // vouts
  for (let vout of tx.vouts) {
    const s = Number(vout.value).toString(16).padStart(16, '0')
    const d = Buffer.from(s, 'hex').reverse()
    d.copy(_buffer, _position)
    _position += 8

    b = varUintEncode(vout.script.length)
    b.copy(_buffer, _position)
    _position += b.length
  
    b = vout.script
    b.copy(_buffer, _position)
    _position += b.length
  }

  // locktime
  _buffer.writeUInt32LE(tx.locktime, _position)
  _position += 4

  return _buffer
}

const signp2pkh = (tx, vindex, privKey, hashType) => {

  const txClone = { ...tx }

  // clean up relevant script
  txClone.vins[vindex].script = txClone.vins[vindex].script.filter(op => op !== OPS.OP_CODESEPARATOR)

  // zero out scripts of other inputs
  txClone.vins = txClone.vins.map((r, i) => i === vindex ? r : {...r, script: Buffer.alloc(0)})

  // write to buffer, extend and append hash type
  const hashTypeReverse = hashType.toString(16).padStart(8, '0').match(/[a-fA-F0-9]{2}/g).reverse().join('')
  const txBuffer = Buffer.concat([txToBuffer(txClone), Buffer.from(hashTypeReverse, 'hex')])
  
  // sign input
  const txHash = sha256(sha256(txBuffer))
  const txSig = secp256k1.sign(txHash, privKey).signature

  // encode sig
  const sigEncoded = bip66Encode(txSig.slice(0, 32), txSig.slice(32, 64))
  return Buffer.concat([sigEncoded, Buffer.from([hashType])])
}

const p2pkhScript = (pubKey) => compileScript([ OPS.OP_DUP, OPS.OP_HASH160, pubKey, OPS.OP_EQUALVERIFY, OPS.OP_CHECKSIG ])


////////////////////////////////////////////////////////////
/////   Main
////////////////////////////////////////////////////////////

const privKey = Buffer.from('60226ca8fb12f6c8096011f36c5028f8b7850b63d495bc45ec3ca478a29b473d', 'hex')

const txid = Buffer.from('f633c7f9f445cc7a241da277169fcd23859657552e5b094c4e073d8bb576e5a7', 'hex')

const pubKeySendTo = 'mrz1DDxeqypyabBs8N9y3Hybe2LEz2cYBu'

const pubKey = secp256k1.publicKeyCreate(privKey)
console.log('pubKey', pubKey.toString('hex'))
console.log()

// 1: add inputs and output for new address and change address
const vinScript = p2pkhScript(ripemd160(sha256(pubKey)))
const voutScript1 = p2pkhScript(fromBase58Check(pubKeySendTo))
const voutScript2 = p2pkhScript(ripemd160(sha256(pubKey)))
const tx = {
  version: 2,
  locktime: 0,
  vins: [{ txid: txid, vout: 1, hash: txid.reverse(), sequence: 0xffffffff, script: vinScript, scriptSig: null, }],
  vouts: [{ script: voutScript1, value: 500, }, { script: voutScript2, value: 1000, }]
}

// sign the tx by filling the script sig
tx.vins[0].scriptSig = compileScript([signp2pkh(tx, 0, privKey, 0x1), pubKey])

// 3: to hex
const result = txToBuffer(tx).toString('hex')
console.log('Tx:', result)
console.log()

console.log('Assert:', result === '0200000001a7e576b58b3d074e4c095b2e5557968523cd9f1677a21d247acc45f4f9c733f6010000006a473044022005ec72191e65a8d182409591fc4bdc6b3b05c8e0319affe3a986388772ebb83302206f79e266e4189a941b6a1861772218e435ac20419db20af04b2fb2949e3ef9db012102e577d441d501cace792c02bfe2cc15e59672199e2195770a61fd3288fc9f934fffffffff02f4010000000000001976a9147dc70ca254627bebcb54c839984d32dad9092edf88ace8030000000000001976a914c34015187941b20ecda9378bb3cade86e80d2bfe88ac00000000')


// curl --location --request POST 'https://btc.getblock.io/testnet/' --header 'x-api-key: -' --header 'Content-Type: application/json' --data-raw '{"jsonrpc": "2.0", "method": "sendrawtransaction", "params": ["0200000001a7e576b58b3d074e4c095b2e5557968523cd9f1677a21d247acc45f4f9c733f6010000006a473044022005ec72191e65a8d182409591fc4bdc6b3b05c8e0319affe3a986388772ebb83302206f79e266e4189a941b6a1861772218e435ac20419db20af04b2fb2949e3ef9db012102e577d441d501cace792c02bfe2cc15e59672199e2195770a61fd3288fc9f934fffffffff02f4010000000000001976a9147dc70ca254627bebcb54c839984d32dad9092edf88ace8030000000000001976a914c34015187941b20ecda9378bb3cade86e80d2bfe88ac00000000"], "id": "getblock.io"}'

// Successful Tx: ee3b6f4d03e93d8a2d9e2364488fe2a390d553c45c4d45a67a37852ebbf4a88a (testnet)
// https://live.blockcypher.com/btc-testnet/tx/ee3b6f4d03e93d8a2d9e2364488fe2a390d553c45c4d45a67a37852ebbf4a88a/


// Resources
// https://github.com/bitcoinjs/bitcoin-ops/blob/master/index.json
// https://en.bitcoin.it/wiki/Transaction#General_format_of_a_Bitcoin_transaction_.28inside_a_block.29
// https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/payments/p2pkh.js#L58
// https://www.derpturkey.com/bitcoin-p2pkh-exploration/

