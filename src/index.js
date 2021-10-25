const { bip32 } = require('bitcoinjs-lib')
    , { ab2hexstring, sha256ripemd160, encodeAddress } = require('./utils')
    , { ec: EC, curve } = require("elliptic")
    , BIP84 = require('bip84')

const CURVE = "secp256k1"

const getAddressFromPublicKey = (
  publicKeyHex,
  prefix
) => {
  const ec = new EC(CURVE)
  const pubKey = ec.keyFromPublic(publicKeyHex, "hex")
  const pubPoint = pubKey.getPublic()
  const compressed = pubPoint.encodeCompressed()
  const hexed = ab2hexstring(compressed)
  const hash = sha256ripemd160(hexed) // https://git.io/fAn8N
  const address = encodeAddress(hash, prefix)
  return address
}

function fromMnemonic(mnemonic, password, isTestnet) {
  BIP84.fromMnemonic.call(this, mnemonic, password, isTestnet, 714)
}

fromMnemonic.prototype = Object.create(BIP84.fromMnemonic.prototype)

function fromZPrv(zprv) {
  BIP84.fromZPrv.call(this, zprv)
}

fromZPrv.prototype = Object.create(BIP84.fromZPrv.prototype)

fromZPrv.prototype.getPrivateKey = function(index, isChange) {
  let change = isChange === true ? 1 : 0
    , prvKey = bip32.fromBase58(this.zprv, this.network).derive(change).derive(index).privateKey

  return prvKey.toString('hex')
}

fromZPrv.prototype.getPublicKey = function(index, isChange) {
  let change = isChange === true ? 1 : 0
    , pubKey = bip32.fromBase58(this.zprv, this.network).derive(change).derive(index).publicKey.toString('hex')

  return pubKey
}

fromZPrv.prototype.getAddress = function(index, isChange) {
  let change = isChange === true ? 1 : 0
    , pubKey = bip32.fromBase58(this.zprv, this.network).derive(change).derive(index).publicKey
    , prefix = this.isTestnet ? 'tbnb' : 'bnb'
    , address = getAddressFromPublicKey(pubKey, prefix)

  return address
}

function fromZPub(zpub) {
  BIP84.fromZPub.call(this, zpub)
}

fromZPub.prototype = Object.create(BIP84.fromZPub.prototype)

fromZPub.prototype.getPublicKey = function(index, isChange) {
  let change = isChange === true ? 1 : 0
    , pubKey = bip32.fromBase58(this.zpub, this.network).derive(change).derive(index).publicKey

  return pubKey.toString('hex')
}


fromZPub.prototype.getAddress = function(index, isChange) {
  let change = isChange === true ? 1 : 0
    , pubKey = bip32.fromBase58(this.zpub, this.network).derive(change).derive(index).publicKey
    , prefix = this.isTestnet ? 'tbnb' : 'bnb'
    , address = getAddressFromPublicKey(pubKey, prefix)

  return address
}

module.exports = {
  generateMnemonic: BIP84.generateMnemonic,
  entropyToMnemonic: BIP84.entropyToMnemonic,
  fromMnemonic: fromMnemonic,
  fromZPrv: fromZPrv,
  fromZPub: fromZPub
}
