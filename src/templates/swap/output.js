// OP_HASH160 {secretHash} OP_EQUALVERIFY
// OP_DUP OP_HASH160 OP_ROT
// OP_IF
//     {pubKeyHash}
// OP_ELSE
//     {nLocktime} OP_CHECKLOCKTIMEVERIFY OP_DROP
//     {refundPubKeyHash}
// OP_ENDIF
// OP_EQUALVERIFY OP_CHECKSIG

var bscript = require('../../script')
var types = require('../../types')
var crypto = require('../../crypto')
var networks = require('../../networks')
var typeforce = require('typeforce')
var OPS = require('bitcoin-ops')
var bigi = require('bigi')

function check (script) {
  var buffer = bscript.compile(script)

  return buffer.length === 80 &&
    buffer[0] === OPS.OP_DUP &&
    buffer[1] === OPS.OP_HASH160 &&
    buffer[2] === OPS.OP_2SWAP &&
    buffer[3] === OPS.OP_IF &&
    buffer[4] === OPS.OP_HASH160 &&
    buffer[5] === 0x14 &&
    buffer[26] === OPS.OP_EQUALVERIFY &&
    buffer[27] === 0x14 &&
    buffer[48] === OPS.OP_ELSE &&
    buffer[49] === 0x04 &&
    buffer[54] === OPS.OP_CHECKLOCKTIMEVERIFY &&
    buffer[55] === OPS.OP_2DROP &&
    buffer[56] === 0x14 &&
    buffer[77] === OPS.OP_ENDIF &&
    buffer[78] === OPS.OP_EQUALVERIFY &&
    buffer[79] === OPS.OP_CHECKSIG
}

check.toJSON = function () { return 'pubKeyHash2 output' }


function encode (secretHash, refundPubKeyHash, pubKeyHash, nLocktime) {
  typeforce(types.Hash160bit, secretHash)
  typeforce(types.Hash160bit, refundPubKeyHash)
  typeforce(types.Hash160bit, pubKeyHash)

  let now = Date.now();
  let nLockTime1 = Math.round(now / 1000) + nLocktime;
  let nLockTime2 = bigi.fromHex(nLockTime1.toString(16)).toBuffer();

  return bscript.compile([
    OPS.OP_DUP,
    OPS.OP_HASH160,
    OPS.OP_2SWAP,
    OPS.OP_IF,
    OPS.OP_HASH160,
    secretHash,
    OPS.OP_EQUALVERIFY,
    pubKeyHash,
    OPS.OP_ELSE,
    nLockTime2,
    OPS.OP_CHECKLOCKTIMEVERIFY,
    OPS.OP_2DROP,
    refundPubKeyHash,
    OPS.OP_ENDIF,
    OPS.OP_EQUALVERIFY,
    OPS.OP_CHECKSIG
  ])
}

function decode (buffer) {
  typeforce(check, buffer)

  return {
    secretHash: buffer.slice(6, 26),
    pubKeyHash: buffer.slice(28, 48),
    nLockTime: buffer.slice(50, 54),
    refundPubKeyHash: buffer.slice(57, 77)
  }
}


function createP2SH (redeemScript, network) {
  network = network || networks.bitcoin
  var address = require('../../address');
  var scriptPubKey = bscript.scriptHash.output.encode(crypto.hash160(redeemScript));
  var addy = address.fromOutputScript(scriptPubKey, network);
  return addy;
}

module.exports = {
  check: check,
  decode: decode,
  encode: encode,
  createP2SH: createP2SH
}
