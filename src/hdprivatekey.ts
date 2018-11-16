import { ERROR_TYPES } from './errors/spec';
import assert from 'assert';
import * as _ from 'lodash';
import $ from './util/preconditions';
import { Buffer } from 'buffer';
import { Base58Check, Base58 } from './encoding';
import { BitcoreBN, Random, Hash, Point } from './crypto';
import { BitcoreError } from './errors';
import { JSUtil, BufferUtil } from './util';
import { Network, PrivateKey, HDPublicKey, PublicKey } from '.';

const hdErrors = ERROR_TYPES.HDPrivateKey.errors;
const MINIMUM_ENTROPY_BITS = 128;
const BITS_TO_BYTES = 1 / 8;
const MAXIMUM_ENTROPY_BITS = 512;

export namespace HDPrivateKey {
  export interface HDPrivateKeyObj {
    network: Network;
    depth: number;
    fingerPrint: Buffer;
    parentFingerPrint: Buffer;
    childIndex: Buffer;
    chainCode: string;
    privateKey: string;
    checksum: Buffer;
    xprivkey: Buffer;
    version: Buffer;
  }
}
/**
 * Represents an instance of an hierarchically derived private key.
 *
 * More info on https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 *
 * @constructor
 * @param {string|Buffer|Object} arg
 */
export class HDPrivateKey {
  public static DefaultDepth = 0;
  public static DefaultFingerprint = 0;
  public static DefaultChildIndex = 0;
  public static Hardened = 0x80000000;
  public static MaxIndex = 2 * HDPrivateKey.Hardened;

  public static RootElementAlias = ['m', 'M', "m'", "M'"];

  public static VersionSize = 4;
  public static DepthSize = 1;
  public static ParentFingerPrintSize = 4;
  public static ChildIndexSize = 4;
  public static ChainCodeSize = 32;
  public static PrivateKeySize = 32;
  public static CheckSumSize = 4;

  public static DataLength = 78;
  public static SerializedByteSize = 82;

  public static VersionStart = 0;
  public static VersionEnd =
    HDPrivateKey.VersionStart + HDPrivateKey.VersionSize;
  public static DepthStart = HDPrivateKey.VersionEnd;
  public static DepthEnd = HDPrivateKey.DepthStart + HDPrivateKey.DepthSize;
  public static ParentFingerPrintStart = HDPrivateKey.DepthEnd;
  public static ParentFingerPrintEnd =
    HDPrivateKey.ParentFingerPrintStart + HDPrivateKey.ParentFingerPrintSize;
  public static ChildIndexStart = HDPrivateKey.ParentFingerPrintEnd;
  public static ChildIndexEnd =
    HDPrivateKey.ChildIndexStart + HDPrivateKey.ChildIndexSize;
  public static ChainCodeStart = HDPrivateKey.ChildIndexEnd;
  public static ChainCodeEnd =
    HDPrivateKey.ChainCodeStart + HDPrivateKey.ChainCodeSize;
  public static PrivateKeyStart = HDPrivateKey.ChainCodeEnd + 1;
  public static PrivateKeyEnd =
    HDPrivateKey.PrivateKeyStart + HDPrivateKey.PrivateKeySize;
  public static ChecksumStart = HDPrivateKey.PrivateKeyEnd;
  public static ChecksumEnd =
    HDPrivateKey.ChecksumStart + HDPrivateKey.CheckSumSize;

  public publicKey: PublicKey;
  public _hdPublicKey: HDPublicKey;
  public _buffers: HDPrivateKey.HDPrivateKeyObj;
  public network: Network;
  public depth: number;
  public fingerPrint: Buffer;
  public parentFingerPrint: Buffer;
  public childIndex: Buffer;
  public chainCode: string;
  public privateKey: PrivateKey;
  public checksum: Buffer;
  public xprivkey: Buffer;
  public version: Buffer;

  constructor(arg) {
    /* jshint maxcomplexity: 10 */
    if (arg instanceof HDPrivateKey) {
      return arg;
    }
    if (!(this instanceof HDPrivateKey)) {
      return new HDPrivateKey(arg);
    }
    if (!arg) {
      return this._generateRandomly();
    }

    if (Network.get(arg)) {
      return this._generateRandomly(arg);
    } else if (_.isString(arg) || BufferUtil.isBuffer(arg)) {
      if (HDPrivateKey.isValidSerialized(arg)) {
        this._buildFromSerialized(arg);
      } else if (JSUtil.isValidJSON(arg)) {
        this._buildFromJSON(arg);
      } else if (
        BufferUtil.isBuffer(arg) &&
        HDPrivateKey.isValidSerialized(arg.toString())
      ) {
        this._buildFromSerialized(arg.toString());
      } else {
        throw HDPrivateKey.getSerializedError(arg);
      }
    } else if (_.isObject(arg)) {
      this._buildFromObject(arg);
    } else {
      throw new BitcoreError(
        ERROR_TYPES.HDPrivateKey.errors.UnrecognizedArgument,
        arg
      );
    }
  }

  /**
   * Verifies that a given path is valid.
   *
   * @param {string|number} arg
   * @param {boolean?} hardened
   * @return {boolean}
   */
  public static isValidPath(arg, hardened = false) {
    if (_.isString(arg)) {
      const indexes = HDPrivateKey._getDerivationIndexes(arg);
      return indexes !== null && _.every(indexes, HDPrivateKey.isValidPath);
    }

    if (_.isNumber(arg)) {
      if (arg < HDPrivateKey.Hardened && hardened === true) {
        arg += HDPrivateKey.Hardened;
      }
      return arg >= 0 && arg < HDPrivateKey.MaxIndex;
    }

    return false;
  }

  /**
   * Internal function that splits a string path into a derivation index array.
   * It will return null if the string path is malformed.
   * It does not validate if indexes are in bounds.
   *
   * @param {string} path
   * @return {Array}
   */
  public static _getDerivationIndexes(path): Array<string> {
    const steps = path.split('/');

    // Special cases:
    if (_.includes(HDPrivateKey.RootElementAlias, path)) {
      return [];
    }

    if (!_.includes(HDPrivateKey.RootElementAlias, steps[0])) {
      return null;
    }

    const indexes = steps.slice(1).map(step => {
      const isHardened = step.slice(-1) === "'";
      if (isHardened) {
        step = step.slice(0, -1);
      }
      if (!step || step[0] === '-') {
        return NaN;
      }
      let index = +step; // cast to number
      if (isHardened) {
        index += HDPrivateKey.Hardened;
      }

      return index;
    });

    return _.some(indexes, isNaN) ? null : indexes;
  }

  /**
   * WARNING: This method is deprecated. Use deriveChild or deriveNonCompliantChild instead. This is not BIP32 compliant
   *
   *
   * Get a derived child based on a string or number.
   *
   * If the first argument is a string, it's parsed as the full path of
   * derivation. Valid values for this argument include "m" (which returns the
   * same private key), "m/0/1/40/2'/1000", where the ' quote means a hardened
   * derivation.
   *
   * If the first argument is a number, the child with that index will be
   * derived. If the second argument is truthy, the hardened version will be
   * derived. See the example usage for clarification.
   *
   * @example
   * ```javascript
   * var parent = new HDPrivateKey('xprv...');
   * var child_0_1_2h = parent.derive(0).derive(1).derive(2, true);
   * var copy_of_child_0_1_2h = parent.derive("m/0/1/2'");
   * assert(child_0_1_2h.xprivkey === copy_of_child_0_1_2h);
   * ```
   *
   * @param {string|number} arg
   * @param {boolean?} hardened
   */
  public derive(arg, hardened) {
    return this.deriveNonCompliantChild(arg, hardened);
  }

  /**
   * WARNING: This method will not be officially supported until v1.0.0.
   *
   *
   * Get a derived child based on a string or number.
   *
   * If the first argument is a string, it's parsed as the full path of
   * derivation. Valid values for this argument include "m" (which returns the
   * same private key), "m/0/1/40/2'/1000", where the ' quote means a hardened
   * derivation.
   *
   * If the first argument is a number, the child with that index will be
   * derived. If the second argument is truthy, the hardened version will be
   * derived. See the example usage for clarification.
   *
   * WARNING: The `nonCompliant` option should NOT be used, except for older implementation
   * that used a derivation strategy that used a non-zero padded private key.
   *
   * @example
   * ```javascript
   * var parent = new HDPrivateKey('xprv...');
   * var child_0_1_2h = parent.deriveChild(0).deriveChild(1).deriveChild(2, true);
   * var copy_of_child_0_1_2h = parent.deriveChild("m/0/1/2'");
   * assert(child_0_1_2h.xprivkey === copy_of_child_0_1_2h);
   * ```
   *
   * @param {string|number} arg
   * @param {boolean?} hardened
   */
  public deriveChild(arg, hardened) {
    if (_.isNumber(arg)) {
      return this._deriveWithNumber(arg, hardened);
    } else if (_.isString(arg)) {
      return this._deriveFromString(arg);
    } else {
      throw new BitcoreError(
        ERROR_TYPES.HDPrivateKey.errors.InvalidDerivationArgument,
        arg
      );
    }
  }

  /**
   * WARNING: This method will not be officially supported until v1.0.0
   *
   *
   * WARNING: If this is a new implementation you should NOT use this method, you should be using
   * `derive` instead.
   *
   * This method is explicitly for use and compatibility with an implementation that
   * was not compliant with BIP32 regarding the derivation algorithm. The private key
   * must be 32 bytes hashing, and this implementation will use the non-zero padded
   * serialization of a private key, such that it's still possible to derive the privateKey
   * to recover those funds.
   *
   * @param {string|number} arg
   * @param {boolean?} hardened
   */
  public deriveNonCompliantChild(arg, hardened) {
    if (_.isNumber(arg)) {
      return this._deriveWithNumber(arg, hardened, true);
    } else if (_.isString(arg)) {
      return this._deriveFromString(arg, true);
    } else {
      throw new BitcoreError(
        ERROR_TYPES.HDPrivateKey.errors.InvalidDerivationArgument,
        arg
      );
    }
  }

  public _deriveWithNumber(index, hardened, nonCompliant = false) {
    /* jshint maxstatements: 20 */
    /* jshint maxcomplexity: 10 */
    if (!HDPrivateKey.isValidPath(index, hardened)) {
      throw new BitcoreError(hdErrors.InvalidPath, index);
    }

    hardened = index >= HDPrivateKey.Hardened ? true : hardened;
    if (index < HDPrivateKey.Hardened && hardened === true) {
      index += HDPrivateKey.Hardened;
    }

    const indexBuffer = BufferUtil.integerAsBuffer(index);
    let data;
    if (hardened && nonCompliant) {
      // The private key serialization in this case will not be exactly 32 bytes and can be
      // any value less, and the value is not zero-padded.
      const nonZeroPadded = this.privateKey.bn.toBuffer();
      data = BufferUtil.concat([new Buffer([0]), nonZeroPadded, indexBuffer]);
    } else if (hardened) {
      // This will use a 32 byte zero padded serialization of the private key
      const privateKeyBuffer = this.privateKey.bn.toBitcoreBuffer({ size: 32 });
      assert(
        privateKeyBuffer.length === 32,
        'length of private key buffer is expected to be 32 bytes'
      );
      data = BufferUtil.concat([
        new Buffer([0]),
        privateKeyBuffer,
        indexBuffer
      ]);
    } else {
      data = BufferUtil.concat([this.publicKey.toBuffer(), indexBuffer]);
    }
    const hash = Hash.sha512hmac(data, this._buffers.chainCode);
    const leftPart = BitcoreBN.fromBuffer(hash.slice(0, 32), {
      size: 32
    });
    const chainCode = hash.slice(32, 64);

    const privateKey = new BitcoreBN(
      leftPart.add(this.privateKey.toBigNumber()).umod(Point.getN())
    ).toBitcoreBuffer({
      size: 32
    });

    if (!PrivateKey.isValid(privateKey)) {
      // Index at this point is already hardened, we can pass null as the hardened arg
      return this._deriveWithNumber(index + 1, null, nonCompliant);
    }

    const derived = new HDPrivateKey({
      network: this.network,
      depth: this.depth + 1,
      parentFingerPrint: this.fingerPrint,
      childIndex: index,
      chainCode,
      privateKey
    });

    return derived;
  }

  public _deriveFromString(path, nonCompliant = false) {
    if (!HDPrivateKey.isValidPath(path)) {
      throw new BitcoreError(hdErrors.InvalidPath, path);
    }

    const indexes = HDPrivateKey._getDerivationIndexes(path);
    const derived = indexes.reduce((prev, index) => {
      return prev._deriveWithNumber(index, null, nonCompliant);
    }, this);

    return derived;
  }

  /**
   * Verifies that a given serialized private key in base58 with checksum format
   * is valid.
   *
   * @param {string|Buffer} data - the serialized private key
   * @param {string|Network=} network - optional, if present, checks that the
   *     network provided matches the network serialized.
   * @return {boolean}
   */
  public static isValidSerialized(data, network?: Network) {
    return !HDPrivateKey.getSerializedError(data, network);
  }

  /**
   * Checks what's the error that causes the validation of a serialized private key
   * in base58 with checksum to fail.
   *
   * @param {string|Buffer} data - the serialized private key
   * @param {string|Network=} network - optional, if present, checks that the
   *     network provided matches the network serialized.
   * @return {errors.InvalidArgument|null}
   */
  public static getSerializedError(data, network?: Network) {
    /* jshint maxcomplexity: 10 */
    if (!(_.isString(data) || BufferUtil.isBuffer(data))) {
      return new BitcoreError(
        hdErrors.UnrecognizedArgument,
        'Expected string or buffer'
      );
    }
    if (!Base58.validCharacters(data)) {
      return new BitcoreError(ERROR_TYPES.InvalidB58Char, '(unknown)', data);
    }
    try {
      data = Base58Check.decode(data);
    } catch (e) {
      return new BitcoreError(ERROR_TYPES.InvalidB58Checksum, data);
    }
    if (data.length !== HDPrivateKey.DataLength) {
      return new BitcoreError(hdErrors.InvalidLength, data);
    }
    if (!_.isUndefined(network)) {
      const error = HDPrivateKey._validateNetwork(data, network);
      if (error) {
        return error;
      }
    }
    return null;
  }

  public static _validateNetwork(data, networkArg) {
    const network = Network.get(networkArg);
    if (!network) {
      return new BitcoreError(ERROR_TYPES.InvalidNetworkArgument, networkArg);
    }
    const version = data.slice(0, 4);
    if (BufferUtil.integerFromBuffer(version) !== network.xprivkey) {
      return new BitcoreError(ERROR_TYPES.InvalidNetwork, version);
    }
    return null;
  }

  public static fromString(arg) {
    $.checkArgument(_.isString(arg), 'No valid string was provided');
    return new HDPrivateKey(arg);
  }

  public static fromObject(arg) {
    $.checkArgument(_.isObject(arg), 'No valid argument was provided');
    return new HDPrivateKey(arg);
  }

  public _buildFromJSON(arg) {
    return this._buildFromObject(JSON.parse(arg));
  }

  public _buildFromObject(arg) {
    /* jshint maxcomplexity: 12 */
    // TODO: Type validation
    const buffers = {
      version: arg.network
        ? BufferUtil.integerAsBuffer(Network.get(arg.network).xprivkey)
        : arg.version,
      depth: _.isNumber(arg.depth)
        ? BufferUtil.integerAsSingleByteBuffer(arg.depth)
        : arg.depth,
      parentFingerPrint: _.isNumber(arg.parentFingerPrint)
        ? BufferUtil.integerAsBuffer(arg.parentFingerPrint)
        : arg.parentFingerPrint,
      childIndex: _.isNumber(arg.childIndex)
        ? BufferUtil.integerAsBuffer(arg.childIndex)
        : arg.childIndex,
      chainCode: _.isString(arg.chainCode)
        ? BufferUtil.hexToBuffer(arg.chainCode)
        : arg.chainCode,
      privateKey:
        _.isString(arg.privateKey) && JSUtil.isHexa(arg.privateKey)
          ? BufferUtil.hexToBuffer(arg.privateKey)
          : arg.privateKey,
      checksum: arg.checksum
        ? arg.checksum.length
          ? arg.checksum
          : BufferUtil.integerAsBuffer(arg.checksum)
        : undefined
    };
    return this._buildFromBuffers(buffers);
  }

  public _buildFromSerialized(arg) {
    const decoded = Base58Check.decode(arg);
    const buffers = {
      version: decoded.slice(
        HDPrivateKey.VersionStart,
        HDPrivateKey.VersionEnd
      ),
      depth: decoded.slice(HDPrivateKey.DepthStart, HDPrivateKey.DepthEnd),
      parentFingerPrint: decoded.slice(
        HDPrivateKey.ParentFingerPrintStart,
        HDPrivateKey.ParentFingerPrintEnd
      ),
      childIndex: decoded.slice(
        HDPrivateKey.ChildIndexStart,
        HDPrivateKey.ChildIndexEnd
      ),
      chainCode: decoded.slice(
        HDPrivateKey.ChainCodeStart,
        HDPrivateKey.ChainCodeEnd
      ),
      privateKey: decoded.slice(
        HDPrivateKey.PrivateKeyStart,
        HDPrivateKey.PrivateKeyEnd
      ),
      checksum: decoded.slice(
        HDPrivateKey.ChecksumStart,
        HDPrivateKey.ChecksumEnd
      ),
      xprivkey: arg
    };
    return this._buildFromBuffers(buffers);
  }

  public _generateRandomly(network?: Network) {
    return HDPrivateKey.fromSeed(Random.getRandomBuffer(64), network);
  }

  /**
   * Generate a private key from a seed, as described in BIP32
   *
   * @param {string|Buffer} hexa
   * @param {*} network
   * @return HDPrivateKey
   */
  public static fromSeed(hexa, network) {
    /* jshint maxcomplexity: 8 */
    if (JSUtil.isHexaString(hexa)) {
      hexa = BufferUtil.hexToBuffer(hexa);
    }
    if (!Buffer.isBuffer(hexa)) {
      throw new BitcoreError(hdErrors.InvalidEntropyArgument, hexa);
    }
    if (hexa.length < MINIMUM_ENTROPY_BITS * BITS_TO_BYTES) {
      throw new BitcoreError(
        hdErrors.InvalidEntropyArgument.errors.NotEnoughEntropy,
        hexa
      );
    }
    if (hexa.length > MAXIMUM_ENTROPY_BITS * BITS_TO_BYTES) {
      throw new BitcoreError(
        hdErrors.InvalidEntropyArgument.errors.TooMuchEntropy,
        hexa
      );
    }
    const hash = Hash.sha512hmac(hexa, new Buffer('Bitcoin seed'));

    return new HDPrivateKey({
      network: Network.get(network) || Network.defaultNetwork,
      depth: 0,
      parentFingerPrint: 0,
      childIndex: 0,
      privateKey: hash.slice(0, 32),
      chainCode: hash.slice(32, 64)
    });
  }

  public _calcHDPublicKey() {
    if (!this._hdPublicKey) {
      this._hdPublicKey = new HDPublicKey(this);
    }
  }

  /**
   * Receives a object with buffers in all the properties and populates the
   * internal structure
   *
   * @param {Object} arg
   * @param {buffer.Buffer} arg.version
   * @param {buffer.Buffer} arg.depth
   * @param {buffer.Buffer} arg.parentFingerPrint
   * @param {buffer.Buffer} arg.childIndex
   * @param {buffer.Buffer} arg.chainCode
   * @param {buffer.Buffer} arg.privateKey
   * @param {buffer.Buffer} arg.checksum
   * @param {string=} arg.xprivkey - if set, don't recalculate the base58
   *      representation
   * @return {HDPrivateKey} this
   */
  public _buildFromBuffers(arg) {
    /* jshint maxcomplexity: 8 */
    /* jshint maxstatements: 20 */

    HDPrivateKey._validateBufferArguments(arg);

    JSUtil.defineImmutable(this, {
      _buffers: arg
    });

    const sequence = [
      arg.version,
      arg.depth,
      arg.parentFingerPrint,
      arg.childIndex,
      arg.chainCode,
      BufferUtil.emptyBuffer(1),
      arg.privateKey
    ];
    const concat = Buffer.concat(sequence);
    if (!arg.checksum || !arg.checksum.length) {
      arg.checksum = Base58Check.checksum(concat);
    } else {
      if (arg.checksum.toString() !== Base58Check.checksum(concat).toString()) {
        throw new BitcoreError(ERROR_TYPES.InvalidB58Checksum, concat);
      }
    }

    const network = Network.get(BufferUtil.integerFromBuffer(arg.version));
    let xprivkey;
    xprivkey = Base58Check.encode(Buffer.concat(sequence));
    arg.xprivkey = Buffer.from(xprivkey);

    const privateKey = new PrivateKey(
      BitcoreBN.fromBuffer(arg.privateKey),
      network
    );
    const publicKey = privateKey.toPublicKey();
    const size = HDPrivateKey.ParentFingerPrintSize;
    const fingerPrint = Hash.sha256ripemd160(publicKey.toBuffer()).slice(
      0,
      size
    );

    JSUtil.defineImmutable(this, {
      xprivkey,
      network,
      depth: BufferUtil.integerFromSingleByteBuffer(arg.depth),
      privateKey,
      publicKey,
      fingerPrint
    });

    this._hdPublicKey = null;

    return this;
  }
  public get xpubkey() {
    this._calcHDPublicKey();
    return this._hdPublicKey.xpubkey;
  }

  public get hdPublicKey() {
    this._calcHDPublicKey();
    return this._hdPublicKey;
  }

  public static _validateBufferArguments(arg) {
    const checkBuffer = (name, size) => {
      const buff = arg[name];
      assert(BufferUtil.isBuffer(buff), name + ' argument is not a buffer');
      assert(
        buff.length === size,
        name +
          ' has not the expected size: found ' +
          buff.length +
          ', expected ' +
          size
      );
    };
    checkBuffer('version', HDPrivateKey.VersionSize);
    checkBuffer('depth', HDPrivateKey.DepthSize);
    checkBuffer('parentFingerPrint', HDPrivateKey.ParentFingerPrintSize);
    checkBuffer('childIndex', HDPrivateKey.ChildIndexSize);
    checkBuffer('chainCode', HDPrivateKey.ChainCodeSize);
    checkBuffer('privateKey', HDPrivateKey.PrivateKeySize);
    if (arg.checksum && arg.checksum.length) {
      checkBuffer('checksum', HDPrivateKey.CheckSumSize);
    }
  }

  /**
   * Returns the string representation of this private key (a string starting
   * with "xprv..."
   *
   * @return string
   */
  public toString() {
    return this.xprivkey;
  }

  /**
   * Returns the console representation of this extended private key.
   * @return string
   */
  public inspect() {
    return '<HDPrivateKey: ' + this.xprivkey + '>';
  }

  /**
   * Returns a plain object with a representation of this private key.
   *
   * Fields include:<ul>
   * <li> network: either 'livenet' or 'testnet'
   * <li> depth: a number ranging from 0 to 255
   * <li> fingerPrint: a number ranging from 0 to 2^32-1, taken from the hash of the
   * <li>     associated public key
   * <li> parentFingerPrint: a number ranging from 0 to 2^32-1, taken from the hash
   * <li>     of this parent's associated public key or zero.
   * <li> childIndex: the index from which this child was derived (or zero)
   * <li> chainCode: an hexa string representing a number used in the derivation
   * <li> privateKey: the private key associated, in hexa representation
   * <li> xprivkey: the representation of this extended private key in checksum
   * <li>     base58 format
   * <li> checksum: the base58 checksum of xprivkey
   * </ul>
   *  @return {Object}
   */
  public toObject() {
    return {
      network: Network.get(
        BufferUtil.integerFromBuffer(this._buffers.version),
        'xprivkey'
      ).name,
      depth: BufferUtil.integerFromSingleByteBuffer(this._buffers.depth),
      fingerPrint: BufferUtil.integerFromBuffer(this.fingerPrint),
      parentFingerPrint: BufferUtil.integerFromBuffer(
        this._buffers.parentFingerPrint
      ),
      childIndex: BufferUtil.integerFromBuffer(this._buffers.childIndex),
      chainCode: BufferUtil.bufferToHex(this._buffers.chainCode),
      privateKey: this.privateKey.toBuffer().toString('hex'),
      checksum: BufferUtil.integerFromBuffer(this._buffers.checksum),
      xprivkey: this.xprivkey
    };
  }

  /**
   * Build a HDPrivateKey from a buffer
   *
   * @param {Buffer} arg
   * @return {HDPrivateKey}
   */
  public static fromBuffer(arg) {
    return new HDPrivateKey(arg.toString());
  }

  /**
   * Returns a buffer representation of the HDPrivateKey
   *
   * @return {string}
   */
  public toBuffer() {
    return BufferUtil.copy(this._buffers.xprivkey);
  }
}
assert(HDPrivateKey.ChecksumEnd === HDPrivateKey.SerializedByteSize);
