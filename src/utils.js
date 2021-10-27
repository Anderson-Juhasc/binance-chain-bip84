const { bech32 } = require('bech32');
const hexEncoding = require("crypto-js/enc-hex")
const RIPEMD160 = require("crypto-js/ripemd160")
const SHA256 = require("crypto-js/sha256")
const SHA3 = require("crypto-js/sha3")
const { ec: EC, curve } = require("elliptic")

const ab2hexstring = (arr) => {
  if (typeof arr !== "object") {
    throw new Error("ab2hexstring expects an array")
  }
  let result = ""
  for (let i = 0; i < arr.length; i++) {
    let str = arr[i].toString(16)
    str = str.length === 0 ? "00" : str.length === 1 ? "0" + str : str
    result += str
  }
  return result
}

const sha256ripemd160 = (hex) => {
  if (typeof hex !== "string")
    throw new Error("sha256ripemd160 expects a string")
  if (hex.length % 2 !== 0) throw new Error(`invalid hex string length: ${hex}`)
  const hexEncoded = hexEncoding.parse(hex)
  const ProgramSha256 = SHA256(hexEncoded)
  return RIPEMD160(ProgramSha256).toString()
}

const encodeAddress = (
  value,
  prefix = "tbnb",
  type = "hex"
) => {
  let words
  if (Buffer.isBuffer(value)) {
    words = bech32.toWords(Buffer.from(value))
  } else {
    words = bech32.toWords(Buffer.from(value, type))
  }
  return bech32.encode(prefix, words)
}

const getAddressFromPublicKey = (
  publicKeyHex,
  prefix
) => {
  const CURVE = "secp256k1"
  const ec = new EC(CURVE)
  const pubKey = ec.keyFromPublic(publicKeyHex, "hex")
  const pubPoint = pubKey.getPublic()
  const compressed = pubPoint.encodeCompressed()
  const hexed = ab2hexstring(compressed)
  const hash = sha256ripemd160(hexed) // https://git.io/fAn8N
  const address = encodeAddress(hash, prefix)
  return address
}

module.exports = {
  getAddressFromPublicKey
}
