// OP_DUP OP_HASH160 {secretHash} OP_EQUALVERIFY {pubKeyHash} OP_CHECKSIG

var bscript = require('../../script')
var types = require('../../types')
var crypto = require('../../crypto')
var typeforce = require('typeforce')
var OPS = require('bitcoin-ops')
var bigi = require('bigi')

function check (script) {
  var buffer = bscript.compile(script)

  return buffer.length === 83 &&
    buffer[0] === OPS.OP_IF &&
    buffer[1] === OPS.OP_DUP &&
    buffer[2] === OPS.OP_HASH160 &&
    buffer[3] === 0x14 &&
    buffer[24] === OPS.OP_EQUALVERIFY &&
    buffer[25] === OPS.OP_CHECKSIGVERIFY &&
    buffer[26] === OPS.OP_HASH160 &&
    buffer[27] === 0x14 &&
    buffer[48] === OPS.OP_EQUAL &&
    buffer[49] === OPS.OP_ELSE &&
    buffer[50] === 0x04 &&
    buffer[55] === OPS.OP_CHECKLOCKTIMEVERIFY &&
    buffer[56] === OPS.OP_DROP &&
    buffer[57] === OPS.OP_DUP &&
    buffer[58] === OPS.OP_HASH160 &&
    buffer[59] === 0x14 &&
    buffer[80] === OPS.OP_EQUALVERIFY &&
    buffer[81] === OPS.OP_CHECKSIG &&
    buffer[82] === OPS.OP_ENDIF
}

check.toJSON = function () { return 'pubKeyHash2 output' }


function encode (secretHash, refundPubKeyHash, pubKeyHash, nLocktime) {
  typeforce(types.Hash160bit, secretHash)
  typeforce(types.Hash160bit, refundPubKeyHash)
  typeforce(types.Hash160bit, pubKeyHash)

  let now = new Date();
  let nLockTime1 = Math.round(now.getTime() / 1000) + nLocktime;
  let nLockTime2 = bigi.fromHex(nLockTime1.toString(16)).toBuffer();

  return bscript.compile([
    OPS.OP_HASH160,
    secretHash,
    OPS.OP_EQUALVERIFY,
    OPS.OP_IF,
    OPS.OP_DUP,
    OPS.OP_HASH160,
    pubKeyHash,
    OPS.OP_ELSE,
    nLockTime2,
    OPS.OP_CHECKLOCKTIMEVERIFY,
    OPS.OP_DROP,
    OPS.OP_DUP,
    OPS.OP_HASH160,
    refundPubKeyHash,
    OPS.OP_ENDIF,
    OPS.OP_EQUALVERIFY,
    OPS.OP_CHECKSIG
  ])
}

function decode (buffer) {
  typeforce(check, buffer)

  return buffer.slice(3, 23)
}


function createP2SH(redeemScript, network) {
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
