'use strict';

import * as _ from 'lodash';
import $ from './util/preconditions';
import { ERROR_TYPES, BitcoreError } from './errors';
import { Base58Check } from './encoding';
import { PublicKey, Network } from '.';
import { Hash } from './crypto';
import { JSUtil } from './util';
import { Script } from './script';

export declare namespace Address {
  export type AddressData =
    | string
    | Buffer
    | Uint8Array
    | PublicKey
    | Script
    | Partial<AddressObj>;
  export interface AddressObj {
    hashBuffer: Buffer;
    network: Network;
    type: string;
  }
}
/**
 * Instantiate an address from an address String or Buffer, a public key or script hash Buffer,
 * or an instance of {@link PublicKey} or {@link Script}.
 *
 * This is an immutable class, and if the first parameter provided to this constructor is an
 * `Address` instance, the same argument will be returned.
 *
 * An address has two key properties: `network` and `type`. The type is either
 * `Address.PayToPublicKeyHash` (value is the `'pubkeyhash'` string)
 * or `Address.PayToScriptHash` (the string `'scripthash'`). The network is an instance of {@link Network}.
 * You can quickly check whether an address is of a given kind by using the methods
 * `isPayToPublicKeyHash` and `isPayToScriptHash`
 *
 * @example
 * ```javascript
 * // validate that an input field is valid
 * var error = Address.getValidationError(input, 'testnet');
 * if (!error) {
 *   var address = Address(input, 'testnet');
 * } else {
 *   // invalid network or checksum (typo?)
 *   var message = error.messsage;
 * }
 *
 * // get an address from a public key
 * var address = Address(publicKey, 'testnet').toString();
 * ```
 *
 * @param {*} data - The encoded data in various formats
 * @param {Network|String|number=} network - The network: 'livenet' or 'testnet'
 * @param {string=} type - The type of address: 'script' or 'pubkey'
 * @returns {Address} A new valid and frozen instance of an Address
 * @constructor
 */
export class Address {
  /** @static */
  public static PayToPublicKeyHash = 'pubkeyhash';
  public static PayToScriptHash = 'scripthash';

  public type: 'pubkeyhash' | 'scripthash';
  public network: Network;
  public hashBuffer: Buffer;

  constructor(
    data: Address.AddressData | Address,
    network?: Network | number | string,
    type?: string
  ) {
    /* jshint maxcomplexity: 12 */
    /* jshint maxstatements: 20 */

    if (!(this instanceof Address)) {
      return new Address(data, network, type);
    }

    if (typeof network === 'number' && _.isArray(data) && _.isNumber(network)) {
      return Address.createMultisig(data, network, type);
    }

    if (data instanceof Address) {
      // Immutable instance
      return data;
    }

    $.checkArgument(
      data,
      'First argument is required, please include address data.',
      'guide/address.html'
    );

    if (network && !Network.get(network)) {
      throw new TypeError('Second argument must be "livenet" or "testnet".');
    }

    if (
      type &&
      (type !== Address.PayToPublicKeyHash && type !== Address.PayToScriptHash)
    ) {
      throw new TypeError(
        'Third argument must be "pubkeyhash" or "scripthash".'
      );
    }

    const info = this._classifyArguments(data, network, type);

    // set defaults if not set
    info.network =
      info.network || Network.get(network) || Network.defaultNetwork;
    info.type = info.type || type || Address.PayToPublicKeyHash;
  }
  /**
   * Internal function used to split different kinds of arguments of the constructor
   * @param {*} data - The encoded data in various formats
   * @param {Network|String|number=} network - The network: 'livenet' or 'testnet'
   * @param {string=} type - The type of address: 'script' or 'pubkey'
   * @returns {Object} An "info" object with "type", "network", and "hashBuffer"
   */
  public _classifyArguments(data, network, type) {
    /* jshint maxcomplexity: 10 */
    // transform and validate input data
    if (
      (data instanceof Buffer || data instanceof Uint8Array) &&
      data.length === 20
    ) {
      return Address._transformHash(data);
    } else if (
      (data instanceof Buffer || data instanceof Uint8Array) &&
      data.length === 21
    ) {
      return Address._transformBuffer(data, network, type);
    } else if (data instanceof PublicKey) {
      return Address._transformPublicKey(data);
    } else if (data instanceof Script) {
      return Address._transformScript(data, network);
    } else if (typeof data === 'string') {
      return Address._transformString(data, network, type);
    } else if (_.isObject(data)) {
      return Address._transformObject(data);
    } else {
      throw new TypeError('First argument is an unrecognized data format.');
    }
  }

  /**
   * @param {Buffer} hash - An instance of a hash Buffer
   * @returns {Object} An object with keys: hashBuffer
   * @private
   */
  public static _transformHash = hash => {
    const info = {};
    if (!(hash instanceof Buffer) && !(hash instanceof Uint8Array)) {
      throw new TypeError('Address supplied is not a buffer.');
    }
    if (hash.length !== 20) {
      throw new TypeError('Address hashbuffers must be exactly 20 bytes.');
    }
    return { hashBuffer: hash };
  };

  /**
   * Deserializes an address serialized through `Address#toObject()`
   * @param {Object} data
   * @param {string} data.hash - the hash that this address encodes
   * @param {string} data.type - either 'pubkeyhash' or 'scripthash'
   * @param {Network=} data.network - the name of the network associated
   * @return {Address}
   */
  public static _transformObject(data) {
    $.checkArgument(
      data.hash || data.hashBuffer,
      'Must provide a `hash` or `hashBuffer` property'
    );
    $.checkArgument(data.type, 'Must provide a `type` property');
    return {
      hashBuffer: data.hash ? Buffer.from(data.hash, 'hex') : data.hashBuffer,
      network: Network.get(data.network) || Network.defaultNetwork,
      type: data.type
    };
  }

  /**
   * Internal function to discover the network and type based on the first data byte
   *
   * @param {Buffer} buffer - An instance of a hex encoded address Buffer
   * @returns {Object} An object with keys: network and type
   * @private
   */
  public static _classifyFromVersion(buffer) {
    const pubkeyhashNetwork = Network.get(buffer[0], 'pubkeyhash');
    const scripthashNetwork = Network.get(buffer[0], 'scripthash');

    if (pubkeyhashNetwork) {
      return {
        network: pubkeyhashNetwork,
        type: Address.PayToPublicKeyHash
      };
    } else if (scripthashNetwork) {
      return {
        network: scripthashNetwork,
        type: Address.PayToScriptHash
      };
    } else {
      return {};
    }
  }

  /**
   * Internal function to transform a bitcoin address buffer
   *
   * @param {Buffer} buffer - An instance of a hex encoded address Buffer
   * @param {string=} network - The network: 'livenet' or 'testnet'
   * @param {string=} type - The type: 'pubkeyhash' or 'scripthash'
   * @returns {Object} An object with keys: hashBuffer, network and type
   * @private
   */
  public static _transformBuffer(buffer, network, type) {
    /* jshint maxcomplexity: 9 */
    if (!(buffer instanceof Buffer) && !(buffer instanceof Uint8Array)) {
      throw new TypeError('Address supplied is not a buffer.');
    }
    if (buffer.length !== 1 + 20) {
      throw new TypeError('Address buffers must be exactly 21 bytes.');
    }

    const networkObj = Network.get(network);
    const bufferVersion = Address._classifyFromVersion(buffer);

    if (network && !networkObj) {
      throw new TypeError('Unknown network');
    }

    if (
      !bufferVersion.network ||
      (networkObj && networkObj !== bufferVersion.network)
    ) {
      throw new TypeError('Address has mismatched network type.');
    }

    if (!bufferVersion.type || (type && type !== bufferVersion.type)) {
      throw new TypeError('Address has mismatched type.');
    }

    const info = {
      hashBuffer: buffer.slice(1),
      network: bufferVersion.network,
      type: bufferVersion.type
    };
    return info;
  }

  /**
   * Internal function to transform a {@link PublicKey}
   *
   * @param {PublicKey} pubkey - An instance of PublicKey
   * @returns {Object} An object with keys: hashBuffer, type
   * @private
   */
  public static _transformPublicKey(pubkey) {
    if (!(pubkey instanceof PublicKey)) {
      throw new TypeError('Address must be an instance of PublicKey.');
    }
    const info = {
      hashBuffer: Hash.sha256ripemd160(pubkey.toBuffer()),
      type: Address.PayToPublicKeyHash
    };
    return info;
  }

  /**
   * Internal function to transform a {@link Script} into a `info` object.
   *
   * @param {Script} script - An instance of Script
   * @returns {Object} An object with keys: hashBuffer, type
   * @private
   */
  public static _transformScript(script, network) {
    $.checkArgument(
      script instanceof Script,
      'script must be a Script instance'
    );
    const info = script.getAddressInfo(network);
    if (!info) {
      throw new BitcoreError(
        ERROR_TYPES.Script.errors.CantDeriveAddress,
        script
      );
    }
    return info;
  }

  /**
   * Creates a P2SH address from a set of public keys and a threshold.
   *
   * The addresses will be sorted lexicographically, as that is the trend in bitcoin.
   * To create an address from unsorted public keys, use the {@link Script#buildMultisigOut}
   * interface.
   *
   * @param {Array} publicKeys - a set of public keys to create an address
   * @param {number} threshold - the number of signatures needed to release the funds
   * @param {String|Network} network - either a Network instance, 'livenet', or 'testnet'
   * @param {boolean=} nestedWitness - if the address uses a nested p2sh witness
   * @return {Address}
   */
  public static createMultisig(
    publicKeys,
    threshold: number,
    network: string | Network,
    nestedWitness = false
  ) {
    network = network || publicKeys[0].network || Network.defaultNetwork;
    const redeemScript = Script.buildMultisigOut(publicKeys, threshold);
    if (nestedWitness) {
      return Address.payingTo(
        Script.buildWitnessMultisigOutFromScript(redeemScript),
        network
      );
    }
    return Address.payingTo(redeemScript, network);
  }

  /**
   * Internal function to transform a bitcoin address string
   *
   * @param {string} data
   * @param {String|Network=} network - either a Network instance, 'livenet', or 'testnet'
   * @param {string=} type - The type: 'pubkeyhash' or 'scripthash'
   * @returns {Object} An object with keys: hashBuffer, network and type
   * @private
   */
  public static _transformString(data, network, type) {
    if (typeof data !== 'string') {
      throw new TypeError('data parameter supplied is not a string.');
    }
    data = data.trim();
    const addressBuffer = Base58Check.decode(data);
    const info = Address._transformBuffer(addressBuffer, network, type);
    return info;
  }

  /**
   * Instantiate an address from a PublicKey instance
   *
   * @param {PublicKey} data
   * @param {String|Network} network - either a Network instance, 'livenet', or 'testnet'
   * @returns {Address} A new valid and frozen instance of an Address
   */
  public static fromPublicKey(data, network) {
    const info = Address._transformPublicKey(data);
    network = network || Network.defaultNetwork;
    return new Address(info.hashBuffer, network, info.type);
  }

  /**
   * Instantiate an address from a ripemd160 public key hash
   *
   * @param {Buffer} hash - An instance of buffer of the hash
   * @param {String|Network} network - either a Network instance, 'livenet', or 'testnet'
   * @returns {Address} A new valid and frozen instance of an Address
   */
  public static fromPublicKeyHash(hash, network) {
    const info = Address._transformHash(hash);
    return new Address(info.hashBuffer, network, Address.PayToPublicKeyHash);
  }

  /**
   * Instantiate an address from a ripemd160 script hash
   *
   * @param {Buffer} hash - An instance of buffer of the hash
   * @param {String|Network} network - either a Network instance, 'livenet', or 'testnet'
   * @returns {Address} A new valid and frozen instance of an Address
   */
  public static fromScriptHash(hash, network) {
    $.checkArgument(hash, 'hash parameter is required');
    const info = Address._transformHash(hash);
    return new Address(info.hashBuffer, network, Address.PayToScriptHash);
  }

  /**
   * Builds a p2sh address paying to script. This will hash the script and
   * use that to create the address.
   * If you want to extract an address associated with a script instead,
   * see {{Address#fromScript}}
   *
   * @param {Script} script - An instance of Script
   * @param {String|Network} network - either a Network instance, 'livenet', or 'testnet'
   * @returns {Address} A new valid and frozen instance of an Address
   */
  public static payingTo(script, network) {
    $.checkArgument(script, 'script is required');
    $.checkArgument(
      script instanceof Script,
      'script must be instance of Script'
    );
    return Address.fromScriptHash(
      Hash.sha256ripemd160(script.toBuffer()),
      network
    );
  }

  /**
   * Extract address from a Script. The script must be of one
   * of the following types: p2pkh input, p2pkh output, p2sh input
   * or p2sh output.
   * This will analyze the script and extract address information from it.
   * If you want to transform any script to a p2sh Address paying
   * to that script's hash instead, use {{Address#payingTo}}
   *
   * @param {Script} script - An instance of Script
   * @param {String|Network} network - either a Network instance, 'livenet', or 'testnet'
   * @returns {Address} A new valid and frozen instance of an Address
   */
  public static fromScript(script, network) {
    $.checkArgument(
      script instanceof Script,
      'script must be a Script instance'
    );
    const info = Address._transformScript(script, network);
    return new Address(info.hashBuffer, network, info.type);
  }

  /**
   * Instantiate an address from a buffer of the address
   *
   * @param {Buffer} buffer - An instance of buffer of the address
   * @param {String|Network=} network - either a Network instance, 'livenet', or 'testnet'
   * @param {string=} type - The type of address: 'script' or 'pubkey'
   * @returns {Address} A new valid and frozen instance of an Address
   */
  public static fromBuffer(buffer, network, type) {
    const info = Address._transformBuffer(buffer, network, type);
    return new Address(info.hashBuffer, info.network, info.type);
  }

  /**
   * Instantiate an address from an address string
   *
   * @param {string} str - An string of the bitcoin address
   * @param {String|Network=} network - either a Network instance, 'livenet', or 'testnet'
   * @param {string=} type - The type of address: 'script' or 'pubkey'
   * @returns {Address} A new valid and frozen instance of an Address
   */
  public static fromString(
    str: string,
    network?: Network | string,
    type?: string
  ) {
    const info = Address._transformString(str, network, type);
    return new Address(info.hashBuffer, info.network, info.type);
  }

  /**
   * Instantiate an address from an Object
   *
   * @param {string} json - An JSON string or Object with keys: hash, network and type
   * @returns {Address} A new valid instance of an Address
   */
  public static fromObject(obj) {
    $.checkState(
      JSUtil.isHexa(obj.hash),
      'Unexpected hash property, "' + obj.hash + '", expected to be hex.'
    );
    const hashBuffer = Buffer.from(obj.hash, 'hex');
    return new Address(hashBuffer, obj.network, obj.type);
  }

  /**
   * Will return a validation error if exists
   *
   * @example
   * ```javascript
   * // a network mismatch error
   * var error = Address.getValidationError('15vkcKf7gB23wLAnZLmbVuMiiVDc1Nm4a2', 'testnet');
   * ```
   *
   * @param {string} data - The encoded data
   * @param {String|Network} network - either a Network instance, 'livenet', or 'testnet'
   * @param {string} type - The type of address: 'script' or 'pubkey'
   * @returns {null|Error} The corresponding error message
   */
  public static getValidationError(
    data: string,
    network: string | Network,
    type: string
  ) {
    let error;
    try {
      /* jshint nonew: false */
      const addr = new Address(data, network, type);
    } catch (e) {
      error = e;
    }
    return error;
  }

  /**
   * Will return a boolean if an address is valid
   *
   * @example
   * ```javascript
   * assert(Address.isValid('15vkcKf7gB23wLAnZLmbVuMiiVDc1Nm4a2', 'livenet'));
   * ```
   *
   * @param {string} data - The encoded data
   * @param {String|Network} network - either a Network instance, 'livenet', or 'testnet'
   * @param {string} type - The type of address: 'script' or 'pubkey'
   * @returns {boolean} The corresponding error message
   */
  public static isValid(data, network?: Network, type?: 'script' | 'pubkey') {
    return !Address.getValidationError(data, network, type);
  }

  /**
   * Returns true if an address is of pay to public key hash type
   * @return boolean
   */
  public isPayToPublicKeyHash() {
    return this.type === Address.PayToPublicKeyHash;
  }

  /**
   * Returns true if an address is of pay to script hash type
   * @return boolean
   */
  public isPayToScriptHash() {
    return this.type === Address.PayToScriptHash;
  }

  /**
   * Will return a buffer representation of the address
   *
   * @returns {Buffer} Bitcoin address buffer
   */
  public toBuffer() {
    const version = Buffer.from([this.network[this.type]]);
    return Buffer.concat([version, this.hashBuffer]);
  }

  /**
   * @returns {Object} A plain object with the address information
   */
  public toObject() {
    return {
      hash: this.hashBuffer.toString('hex'),
      type: this.type,
      network: this.network.toString()
    };
  }

  /**
   * Will return a the string representation of the address
   *
   * @returns {string} Bitcoin address
   */
  public toString() {
    return Base58Check.encode(this.toBuffer());
  }

  /**
   * Will return a string formatted for the console
   *
   * @returns {string} Bitcoin address
   */
  public inspect() {
    return (
      '<Address: ' +
      this.toString() +
      ', type: ' +
      this.type +
      ', network: ' +
      this.network +
      '>'
    );
  }
}

module.exports = Address;
