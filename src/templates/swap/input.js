// {signature} {pubKey}
var bscript = require('../../script')
var typeforce = require('typeforce')
var OPS = require('bitcoin-ops')

function check (script) {
  var chunks = bscript.decompile(script)

  return chunks.length === 4 &&
    bscript.isCanonicalSignature(chunks[0]) &&
    bscript.isCanonicalPubKey(chunks[3])
}
check.toJSON = function () { return 'swap input' }

function checkRedeem (script) {
  var chunks = bscript.decompile(script)

  return check(script) &&
    chunks[2] === 1
}

function checkRefund (script) {
  var chunks = bscript.decompile(script)

  return check(script) &&
    chunks[2] === 0 &&
    chunks[1] === 0
}

function encodeStack (signature, pubKey, isRedeem, secret) {
  typeforce({
    signature: bscript.isCanonicalSignature,
    pubKey: bscript.isCanonicalPubKey
  }, {
    signature: signature,
    pubKey: pubKey
  })

  const redeem = isRedeem ? OPS.OP_TRUE : OPS.OP_FALSE
  secret = isRedeem ? secret : OPS.OP_0

  return [signature, secret, redeem, pubKey]
}

function encode (signature, pubKey, isRedeem, secret) {
  return bscript.compile(encodeStack(signature, pubKey, isRedeem, secret))
}

function decodeStack (stack) {
  typeforce(typeforce.Array, stack)
  typeforce(check, stack)

  return {
    signature: stack[0],
    secret: stack[1],
    redeem: stack[2],
    pubKey: stack[3]
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
