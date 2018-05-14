// {signature} {pubKey}
var bscript = require('../../script')
var typeforce = require('typeforce')
var OPS = require('bitcoin-ops')

function check (script) {
  var chunks = bscript.decompile(script)

  return chunks.length === 2 &&
    bscript.isCanonicalSignature(chunks[0]) &&
    bscript.isCanonicalPubKey(chunks[1])
}
check.toJSON = function () { return 'pubKeyHash input' }

function encodeStack (signature, pubKey, secret, isRedeem) {
  typeforce({
    signature: bscript.isCanonicalSignature,
    pubKey: bscript.isCanonicalPubKey,
    secret: bscript.isCanonicalSecret
  }, {
    signature: signature,
    pubKey: pubKey,
    secret: secret
  })

  const redeem = isRedeem ? OPS.OP_TRUE : OPS.OP_FALSE

  return [signature, redeem, pubKey, secret]
}

function encode (signature, pubKey, secret, isRedeem) {
  return bscript.compile(encodeStack(signature, pubKey, secret, isRedeem))
}

function decodeStack (stack) {
  typeforce(typeforce.Array, stack)
  typeforce(check, stack)

  return {
    signature: stack[0],
    redeem: stack[1],
    pubKey: stack[2],
    secret: stack[3]
  }
}

function decode (buffer) {
  var stack = bscript.decompile(buffer)
  return decodeStack(stack)
}

module.exports = {
  check: check,
  decode: decode,
  decodeStack: decodeStack,
  encode: encode,
  encodeStack: encodeStack
}
