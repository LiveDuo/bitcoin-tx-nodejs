const crypto = require('crypto')

const secp256k1 = require('secp256k1')
const base58 = require('bs58')

// https://github.com/bitcoinjs/bitcoin-ops/blob/master/index.json
const OPS = { OP_DUP: 0x76, OP_EQUALVERIFY: 0x88, OP_HASH160: 0xa9, OP_CHECKSIG: 0xac, OP_PUSHDATA1: 0x4c, }

////////////////////////////////////////////////////////////
/////   Utils
////////////////////////////////////////////////////////////

const sha256 = (data) => crypto.createHash('sha256').update(data).digest()
const ripemd160 = (data) => crypto.createHash('ripemd160').update(data).digest()

class BufferCursor {
  constructor(buffer) {
    this._buffer = buffer
    this._position = 0
  }

  writeUInt32LE(val) {
    this._buffer['writeUInt32LE'](val, this._position)
    this._position += 4
  }

  writeInt32LE(val) {
    this._buffer['writeInt32LE'](val, this._position)
    this._position += 4
  }

  writeUInt64LE(value) {
    const s = Number(value).toString(16).padStart(16, '0')
    const d = Buffer.from(s, 'hex').reverse()
    d.copy(this._buffer, this._position)
    this._position += 8
  }

  writeBytes(buffer) {
    buffer.copy(this._buffer, this._position)
    this._position += buffer.length
  }
}

const varUintEncode = (number, buffer, offset) => {
  if (!buffer) buffer = Buffer.allocUnsafe(varUintEncodingLength(number))
  if (!Buffer.isBuffer(buffer)) throw new TypeError('buffer must be a Buffer instance')
  if (!offset) offset = 0

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

const varUintEncodingLength = (n) => (n < 0xfd ? 1 : n <= 0xffff ? 3 : n <= 0xffffffff ? 5 : 9)

const bip66Encode = (r, s) => {
  const lenR = r.length
  const lenS = s.length
  if (lenR === 0) throw new Error('R length is zero')
  if (lenS === 0) throw new Error('S length is zero')
  if (lenR > 33) throw new Error('R length is too long')
  if (lenS > 33) throw new Error('S length is too long')
  if (r[0] & 0x80) throw new Error('R value is negative')
  if (s[0] & 0x80) throw new Error('S value is negative')
  if (lenR > 1 && (r[0] === 0x00) && !(r[1] & 0x80)) throw new Error('R value excessively padded')
  if (lenS > 1 && (s[0] === 0x00) && !(s[1] & 0x80)) throw new Error('S value excessively padded')

  const signature = Buffer.allocUnsafe(6 + lenR + lenS)

  // 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]
  signature[0] = 0x30
  signature[1] = signature.length - 2
  signature[2] = 0x02
  signature[3] = r.length
  r.copy(signature, 4)
  signature[4 + lenR] = 0x02
  signature[5 + lenR] = s.length
  s.copy(signature, 6 + lenR)

  return signature
}

const pushdataEncodingLength = (i) => i < OPS.OP_PUSHDATA1 ? 1 : i <= 0xff ? 2 : i <= 0xffff ? 3 : 5

const pushdataEncode = (buffer, number, offset) => {
  const size = pushdataEncodingLength(number)

  // ~6 bit
  if (size === 1) {
    buffer.writeUInt8(number, offset)

  // 8 bit
  } else if (size === 2) {
    buffer.writeUInt8(OPS.OP_PUSHDATA1, offset)
    buffer.writeUInt8(number, offset + 1)

  // 16 bit
  } else if (size === 3) {
    buffer.writeUInt8(OPS.OP_PUSHDATA2, offset)
    buffer.writeUInt16LE(number, offset + 1)

  // 32 bit
  } else {
    buffer.writeUInt8(OPS.OP_PUSHDATA4, offset)
    buffer.writeUInt32LE(number, offset + 1)
  }

  return size
}

const fromBase58Check = (address) => Buffer.from(base58.decode(address).slice(0, -4)).subarray(1)

const toDER = (x) => {
  let i = 0
  while (x[i] === 0) ++i
  if (i === x.length) return Buffer.alloc(1)
  x = x.slice(i)
  if (x[0] & 0x80) return Buffer.concat([Buffer.alloc(1), x], 1 + x.length)
  return x
}


////////////////////////////////////////////////////////////
/////   Helpers
////////////////////////////////////////////////////////////


const compileScript = (chunks) => {
  const bufferSize = chunks.reduce((accum, chunk) => {
    // data chunk
    if (Buffer.isBuffer(chunk)) {
      return accum + pushdataEncodingLength(chunk.length) + chunk.length
    }
    // opcode
    return accum + 1
  }, 0.0)

  const buffer = Buffer.alloc(bufferSize)
  let offset = 0

  chunks.forEach(chunk => {
    // data chunk
    if (Buffer.isBuffer(chunk)) {
      offset += pushdataEncode(buffer, chunk.length, offset)
      chunk.copy(buffer, offset)
      offset += chunk.length

      // opcode
    } else {
      buffer.writeUInt8(chunk, offset)
      offset += 1
    }
  })
  if (offset !== buffer.length) throw new Error('Could not decode chunks')
  return buffer
}

// https://en.bitcoin.it/wiki/Transaction#General_format_of_a_Bitcoin_transaction_.28inside_a_block.29
const getTxSize = (vins, vouts) => {
  return (
    4 + // version
    varUintEncodingLength(vins.length) +
    vins
      .map(vin => (vin.scriptSig ? vin.scriptSig.length : vin.script.length))
      .reduce((sum, len) => sum + 40 + varUintEncodingLength(len) + len, 0) +
      varUintEncodingLength(vouts.length) +
    vouts
      .map(vout => vout.script.length)
      .reduce((sum, len) => sum + 8 + varUintEncodingLength(len) + len, 0) +
    4 // locktime
  )
}

const txToBuffer = (tx) => {
  const buffer = Buffer.alloc(getTxSize(tx.vins, tx.vouts))
  const cursor = new BufferCursor(buffer)

  // version
  cursor.writeInt32LE(tx.version)

  // vin length
  cursor.writeBytes(varUintEncode(tx.vins.length))

  // vin
  for (let vin of tx.vins) {
    cursor.writeBytes(vin.hash)
    cursor.writeUInt32LE(vin.vout)
    if (vin.scriptSig) {
      cursor.writeBytes(varUintEncode(vin.scriptSig.length))
      cursor.writeBytes(vin.scriptSig)
    } else {
      cursor.writeBytes(varUintEncode(vin.script.length))
      cursor.writeBytes(vin.script)
    }
    cursor.writeUInt32LE(vin.sequence)
  }

  // vout length
  cursor.writeBytes(varUintEncode(tx.vouts.length))

  // vouts
  for (let vout of tx.vouts) {
    cursor.writeUInt64LE(vout.value)
    cursor.writeBytes(varUintEncode(vout.script.length))
    cursor.writeBytes(vout.script)
  }

  // locktime
  cursor.writeUInt32LE(tx.locktime)

  return buffer
}

const signp2pkh = (tx, vindex, privKey, hashType = 0x01) => {

  const clone = { version: tx.version, locktime: tx.locktime, vins: [], vouts: [] }
  for (let vin of tx.vins) {
    clone.vins.push({ txid: vin.txid, vout: vin.vout, hash: vin.hash,
      sequence: vin.sequence, script: vin.script, scriptPub: null, })
  }
  for (let vout of tx.vouts) {
    clone.vouts.push({ script: vout.script, value: vout.value, })
  }

  // clean up relevant script
  const filteredPrevOutScript = clone.vins[vindex].script.filter(op => op !== OPS.OP_CODESEPARATOR)
  clone.vins[vindex].script = filteredPrevOutScript

  // zero out scripts of other inputs
  for (let i = 0; i < clone.vins.length; i++) {
    if (i === vindex) continue
    clone.vins[i].script = Buffer.alloc(0)
  }

  // write to the buffer, extend and append hash type and append the hash type
  let buffer = txToBuffer(clone)
  buffer = Buffer.alloc(buffer.length + 4, buffer)
  buffer.writeInt32LE(hashType, buffer.length - 4)

  // double-sha256
  const hash = sha256(sha256(buffer))

  // sign input
  const sig = secp256k1.sign(hash, privKey).signature

  // encode sig
  const encoded = bip66Encode(toDER(sig.slice(0, 32)), toDER(sig.slice(32, 64)))
  return Buffer.concat([encoded, Buffer.from([hashType])])
}

// https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/payments/p2pkh.js#L58
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

// 2: now that tx is ready, sign and create script sig
tx.vins[0].scriptSig = compileScript([signp2pkh(tx, 0, privKey, 0x1), pubKey])

// 3: to hex
const result = txToBuffer(tx).toString('hex')
console.log('Tx:', result)
console.log()

console.log('Assert:', result === '0200000001a7e576b58b3d074e4c095b2e5557968523cd9f1677a21d247acc45f4f9c733f6010000006a473044022005ec72191e65a8d182409591fc4bdc6b3b05c8e0319affe3a986388772ebb83302206f79e266e4189a941b6a1861772218e435ac20419db20af04b2fb2949e3ef9db012102e577d441d501cace792c02bfe2cc15e59672199e2195770a61fd3288fc9f934fffffffff02f4010000000000001976a9147dc70ca254627bebcb54c839984d32dad9092edf88ace8030000000000001976a914c34015187941b20ecda9378bb3cade86e80d2bfe88ac00000000')


// curl --location --request POST 'https://btc.getblock.io/testnet/' --header 'x-api-key: -' --header 'Content-Type: application/json' --data-raw '{"jsonrpc": "2.0", "method": "sendrawtransaction", "params": ["0200000001a7e576b58b3d074e4c095b2e5557968523cd9f1677a21d247acc45f4f9c733f6010000006a473044022005ec72191e65a8d182409591fc4bdc6b3b05c8e0319affe3a986388772ebb83302206f79e266e4189a941b6a1861772218e435ac20419db20af04b2fb2949e3ef9db012102e577d441d501cace792c02bfe2cc15e59672199e2195770a61fd3288fc9f934fffffffff02f4010000000000001976a9147dc70ca254627bebcb54c839984d32dad9092edf88ace8030000000000001976a914c34015187941b20ecda9378bb3cade86e80d2bfe88ac00000000"], "id": "getblock.io"}'

// Successful Tx: ee3b6f4d03e93d8a2d9e2364488fe2a390d553c45c4d45a67a37852ebbf4a88a (testnet)
// https://live.blockcypher.com/btc-testnet/tx/ee3b6f4d03e93d8a2d9e2364488fe2a390d553c45c4d45a67a37852ebbf4a88a/

