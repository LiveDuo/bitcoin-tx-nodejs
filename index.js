const crypto = require('crypto')

const secp256k1 = require('secp256k1')
const base58 = require('bs58')


////////////////////////////////////////////////////////////
/////   Utils
////////////////////////////////////////////////////////////

const OPS = { OP_DUP: 0x76, OP_EQUALVERIFY: 0x88, OP_HASH160: 0xa9, OP_CHECKSIG: 0xac, OP_PUSHDATA1: 0x4c, }

const sha256 = (data) => crypto.createHash('sha256').update(data).digest()
const ripemd160 = (data) => crypto.createHash('ripemd160').update(data).digest()
const reverse = (data, length) => Number(data).toString(16).padStart(length, '0').match(/../g).reverse().join('')
const base58Check = (data) => Buffer.from(base58.decode(data).slice(0, -4)).subarray(1)

// TODO: should double check with larger values
const varUintEncode = (number) => {
  if (number < 2^8) return Buffer.from(reverse(number, 2), 'hex') // 8 bit
  else if (number <= 2^16) return Buffer.from(reverse(number, 4), 'hex') // 16 bit
  else if (number <= 2^32) return Buffer.from(reverse(number, 8), 'hex') // 32 bit
  else return Buffer.from(reverse(number, 16), 'hex') // 64 bit
}

const bip66Encode = (r, s) => {
  const rP = Buffer.from([0x30, r.length + s.length + 4, 0x02, r.length])
  const sP = Buffer.from([0x02, s.length])
  return Buffer.concat([rP, r, sP, s])
}

const getAddressFromPubKey = (pubKey) => {
  const networkId = '6f' // 00 for mainnet - 6f for testnet
  const hash = Buffer.concat([Buffer.from(networkId, 'hex'), ripemd160(sha256(pubKey))])
  const address = base58.encode(Buffer.concat([hash, sha256(sha256(hash)).subarray(0, 4)]))
  return address
}

////////////////////////////////////////////////////////////
/////   Helpers
////////////////////////////////////////////////////////////


const compileScript = (chunks) => {
  return Buffer.concat(chunks.map(c => Buffer.isBuffer(c) ? Buffer.concat([Buffer.from([c.length]), c]) : Buffer.from([c])))
}

const txToBuffer = (tx) => {
  const chunks = []

  // header
  chunks.push(Buffer.from(reverse(tx.version, 8), 'hex'))
  
  // vin
  chunks.push(varUintEncode(tx.vins.length))
  for (let vin of tx.vins) {
    chunks.push(vin.hash)
    chunks.push(Buffer.from(reverse(vin.vout, 8), 'hex'))
    if (vin.scriptSig) chunks.push(varUintEncode(vin.scriptSig.length), vin.scriptSig)
    else chunks.push(varUintEncode(vin.script.length), vin.script)
    chunks.push(Buffer.from(vin.sequence.toString(16), 'hex'))
  }

  // vout
  chunks.push(varUintEncode(tx.vouts.length))
  for (let vout of tx.vouts) {
    chunks.push(Buffer.from(reverse(vout.value, 16), 'hex'), varUintEncode(vout.script.length), vout.script)
  }

  // locktime
  chunks.push(Buffer.from(reverse(tx.locktime, 8), 'hex'))

  return Buffer.concat(chunks)
}

const signp2pkh = (tx, vindex, privKey, hashType) => {

  const txClone = { ...tx }

  // clean up relevant script
  txClone.vins[vindex].script = txClone.vins[vindex].script.filter(op => op !== OPS.OP_CODESEPARATOR)

  // zero out scripts of other inputs
  txClone.vins = txClone.vins.map((r, i) => i === vindex ? r : {...r, script: Buffer.alloc(0)})

  // write to buffer, extend and append hash type
  const txBuffer = Buffer.concat([txToBuffer(txClone), Buffer.from(reverse(hashType, 8), 'hex')])
  
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
console.log('Address:', getAddressFromPubKey(pubKey))
console.log()

// 1: add inputs and output for new address and change address
const vinScript = p2pkhScript(ripemd160(sha256(pubKey)))
const voutScript1 = p2pkhScript(base58Check(pubKeySendTo))
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

