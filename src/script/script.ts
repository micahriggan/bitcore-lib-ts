import $ from '../util/preconditions';
import * as _ from 'lodash';
import { Network } from '../networks';
import { Address } from '../address';
import { BufferReader } from '../encoding/bufferreader';
import { BufferWriter } from '../encoding/bufferwriter';
import { Hash } from '../crypto/hash';
import { Opcode, OP_CODES } from '../opcode';
import { PublicKey } from '../publickey';
import { Signature } from '../crypto/signature';
import { BitcoreError } from '../errors';
import { Buffer } from 'buffer';
import { BufferUtil } from '../util/buffer';
import { JSUtil } from '../util/js';
import { ERROR_TYPES } from '../errors/spec';

/**
 * A bitcoin transaction script. Each transaction's inputs and outputs
 * has a script that is evaluated to validate it's spending.
 *
 * See https://en.bitcoin.it/wiki/Script
 *
 * @constructor
 * @param {Object|string|Buffer=} from optional data to populate script
 */
export interface InfoType {
  hashBuffer: Buffer;
  type: string;
  network: Network;
}
export declare namespace Script {
  export interface Chunk {
    buf?: Buffer;
    len?: number;
    opcodenum: number;
  }
}
export class Script {
  public chunks: Array<Script.Chunk>;
  public _isInput = false;
  public _isOutput = false;
  public _network: Network;

  constructor(from?) {
    if (!(this instanceof Script)) {
      return new Script(from);
    }
    this.chunks = [];

    if (BufferUtil.isBuffer(from)) {
      return Script.fromBuffer(from);
    } else if (from instanceof Address) {
      return Script.fromAddress(from);
    } else if (from instanceof Script) {
      return Script.fromBuffer(from.toBuffer());
    } else if (_.isString(from)) {
      return Script.fromString(from);
    } else if (_.isObject(from) && _.isArray(from.chunks)) {
      this.set(from);
    }
  }
  public set(obj) {
    $.checkArgument(_.isObject(obj));
    $.checkArgument(_.isArray(obj.chunks));
    this.chunks = obj.chunks;
    return this;
  }

  public static fromBuffer(buffer) {
    const script = new Script();
    script.chunks = [];

    const br = new BufferReader(buffer);
    while (!br.finished()) {
      try {
        const opcodenum = br.readUInt8();

        let len, buf;
        if (opcodenum > 0 && opcodenum < OP_CODES.OP_PUSHDATA1) {
          len = opcodenum;
          script.chunks.push({
            buf: br.read(len),
            len,
            opcodenum
          });
        } else if (opcodenum === OP_CODES.OP_PUSHDATA1) {
          len = br.readUInt8();
          buf = br.read(len);
          script.chunks.push({
            buf,
            len,
            opcodenum
          });
        } else if (opcodenum === OP_CODES.OP_PUSHDATA2) {
          len = br.readUInt16LE();
          buf = br.read(len);
          script.chunks.push({
            buf,
            len,
            opcodenum
          });
        } else if (opcodenum === OP_CODES.OP_PUSHDATA4) {
          len = br.readUInt32LE();
          buf = br.read(len);
          script.chunks.push({
            buf,
            len,
            opcodenum
          });
        } else {
          script.chunks.push({
            opcodenum
          });
        }
      } catch (e) {
        if (e instanceof RangeError) {
          throw new BitcoreError(
            ERROR_TYPES.Script.errors.InvalidBuffer,
            buffer.toString('hex')
          );
        }
        throw e;
      }
    }

    return script;
  }

  public toBuffer() {
    const bw = new BufferWriter();

    for (let i = 0; i < this.chunks.length; i++) {
      const chunk = this.chunks[i];
      const opcodenum = chunk.opcodenum;
      bw.writeUInt8(chunk.opcodenum);
      if (chunk.buf) {
        if (opcodenum < OP_CODES.OP_PUSHDATA1) {
          bw.write(chunk.buf);
        } else if (opcodenum === OP_CODES.OP_PUSHDATA1) {
          bw.writeUInt8(chunk.len);
          bw.write(chunk.buf);
        } else if (opcodenum === OP_CODES.OP_PUSHDATA2) {
          bw.writeUInt16LE(chunk.len);
          bw.write(chunk.buf);
        } else if (opcodenum === OP_CODES.OP_PUSHDATA4) {
          bw.writeUInt32LE(chunk.len);
          bw.write(chunk.buf);
        }
      }
    }

    return bw.concat();
  }

  public static fromASM(str) {
    const script = new Script();
    script.chunks = [];

    const tokens = str.split(' ');
    let i = 0;
    while (i < tokens.length) {
      const token = tokens[i];
      const opcode = new Opcode(token);
      const opcodenum = opcode.toNumber();

      if (_.isUndefined(opcodenum)) {
        const buf = Buffer.from(tokens[i], 'hex');
        script.chunks.push({
          buf,
          len: buf.length,
          opcodenum: buf.length
        });
        i = i + 1;
      } else if (
        opcodenum === OP_CODES.OP_PUSHDATA1 ||
        opcodenum === OP_CODES.OP_PUSHDATA2 ||
        opcodenum === OP_CODES.OP_PUSHDATA4
      ) {
        script.chunks.push({
          buf: Buffer.from(tokens[i + 2], 'hex'),
          len: parseInt(tokens[i + 1]),
          opcodenum
        });
        i = i + 3;
      } else {
        script.chunks.push({
          opcodenum
        });
        i = i + 1;
      }
    }
    return script;
  }

  public static fromHex(str) {
    return new Script(new Buffer(str, 'hex'));
  }

  public static fromString(str) {
    if (JSUtil.isHexa(str) || str.length === 0) {
      return new Script(new Buffer(str, 'hex'));
    }
    const script = new Script();
    script.chunks = [];

    const tokens = str.split(' ');
    let i = 0;
    while (i < tokens.length) {
      const token = tokens[i];
      const opcode = new Opcode(token);
      let opcodenum = opcode.toNumber();

      if (_.isUndefined(opcodenum)) {
        opcodenum = parseInt(token);
        if (opcodenum > 0 && opcodenum < OP_CODES.OP_PUSHDATA1) {
          script.chunks.push({
            buf: Buffer.from(tokens[i + 1].slice(2), 'hex'),
            len: opcodenum,
            opcodenum
          });
          i = i + 2;
        } else {
          throw new Error('Invalid script: ' + JSON.stringify(str));
        }
      } else if (
        opcodenum === OP_CODES.OP_PUSHDATA1 ||
        opcodenum === OP_CODES.OP_PUSHDATA2 ||
        opcodenum === OP_CODES.OP_PUSHDATA4
      ) {
        if (tokens[i + 2].slice(0, 2) !== '0x') {
          throw new Error('Pushdata data must start with 0x');
        }
        script.chunks.push({
          buf: Buffer.from(tokens[i + 2].slice(2), 'hex'),
          len: parseInt(tokens[i + 1]),
          opcodenum
        });
        i = i + 3;
      } else {
        script.chunks.push({
          opcodenum
        });
        i = i + 1;
      }
    }
    return script;
  }

  public _chunkToString(chunk: Script.Chunk, type?: string) {
    const opcodenum = chunk.opcodenum;
    const asm = type === 'asm';
    let str = '';
    if (!chunk.buf) {
      // no data chunk
      if (typeof Opcode.reverseMap[opcodenum] !== 'undefined') {
        if (asm) {
          // A few cases where the opcode name differs from reverseMap
          // aside from 1 to 16 data pushes.
          if (opcodenum === 0) {
            // OP_0 -> 0
            str = str + ' 0';
          } else if (opcodenum === 79) {
            // OP_1NEGATE -> 1
            str = str + ' -1';
          } else {
            str = str + ' ' + new Opcode(opcodenum).toString();
          }
        } else {
          str = str + ' ' + new Opcode(opcodenum).toString();
        }
      } else {
        let numstr = opcodenum.toString(16);
        if (numstr.length % 2 !== 0) {
          numstr = '0' + numstr;
        }
        if (asm) {
          str = str + ' ' + numstr;
        } else {
          str = str + ' ' + '0x' + numstr;
        }
      }
    } else {
      // data chunk
      if (
        (!asm && opcodenum === OP_CODES.OP_PUSHDATA1) ||
        opcodenum === OP_CODES.OP_PUSHDATA2 ||
        opcodenum === OP_CODES.OP_PUSHDATA4
      ) {
        str = str + ' ' + new Opcode(opcodenum).toString();
      }
      if (chunk.len > 0) {
        if (asm) {
          str = str + ' ' + chunk.buf.toString('hex');
        } else {
          str = str + ' ' + chunk.len + ' ' + '0x' + chunk.buf.toString('hex');
        }
      }
    }
    return str;
  }

  public toASM() {
    let str = '';
    for (let i = 0; i < this.chunks.length; i++) {
      const chunk = this.chunks[i];
      str += this._chunkToString(chunk, 'asm');
    }

    return str.substr(1);
  }

  public toString() {
    let str = '';
    for (let i = 0; i < this.chunks.length; i++) {
      const chunk = this.chunks[i];
      str += this._chunkToString(chunk);
    }

    return str.substr(1);
  }

  public toHex() {
    return this.toBuffer().toString('hex');
  }

  public inspect() {
    return '<Script: ' + this.toString() + '>';
  }

  // script classification methods

  /**
   * @returns {boolean} if this is a pay to pubkey hash output script
   */
  public isPublicKeyHashOut() {
    return !!(
      this.chunks.length === 5 &&
      this.chunks[0].opcodenum === OP_CODES.OP_DUP &&
      this.chunks[1].opcodenum === OP_CODES.OP_HASH160 &&
      this.chunks[2].buf &&
      this.chunks[2].buf.length === 20 &&
      this.chunks[3].opcodenum === OP_CODES.OP_EQUALVERIFY &&
      this.chunks[4].opcodenum === OP_CODES.OP_CHECKSIG
    );
  }

  /**
   * @returns {boolean} if this is a pay to public key hash input script
   */
  public isPublicKeyHashIn() {
    if (this.chunks.length === 2) {
      const signatureBuf = this.chunks[0].buf;
      const pubkeyBuf = this.chunks[1].buf;
      if (
        signatureBuf &&
        signatureBuf.length &&
        signatureBuf[0] === 0x30 &&
        pubkeyBuf &&
        pubkeyBuf.length
      ) {
        const version = pubkeyBuf[0];
        if (
          (version === 0x04 || version === 0x06 || version === 0x07) &&
          pubkeyBuf.length === 65
        ) {
          return true;
        } else if (
          (version === 0x03 || version === 0x02) &&
          pubkeyBuf.length === 33
        ) {
          return true;
        }
      }
    }
    return false;
  }

  public getPublicKey() {
    $.checkState(
      this.isPublicKeyOut(),
      "Can't retrieve PublicKey from a non-PK output"
    );
    return this.chunks[0].buf;
  }

  public getPublicKeyHash() {
    $.checkState(
      this.isPublicKeyHashOut(),
      "Can't retrieve PublicKeyHash from a non-PKH output"
    );
    return this.chunks[2].buf;
  }

  /**
   * @returns {boolean} if this is a public key output script
   */
  public isPublicKeyOut() {
    if (
      this.chunks.length === 2 &&
      this.chunks[0].buf &&
      this.chunks[0].buf.length &&
      this.chunks[1].opcodenum === OP_CODES.OP_CHECKSIG
    ) {
      const pubkeyBuf = this.chunks[0].buf;
      const version = pubkeyBuf[0];
      let isVersion = false;
      if (
        (version === 0x04 || version === 0x06 || version === 0x07) &&
        pubkeyBuf.length === 65
      ) {
        isVersion = true;
      } else if (
        (version === 0x03 || version === 0x02) &&
        pubkeyBuf.length === 33
      ) {
        isVersion = true;
      }
      if (isVersion) {
        return PublicKey.isValid(pubkeyBuf);
      }
    }
    return false;
  }

  /**
   * @returns {boolean} if this is a pay to public key input script
   */
  public isPublicKeyIn() {
    if (this.chunks.length === 1) {
      const signatureBuf = this.chunks[0].buf;
      if (signatureBuf && signatureBuf.length && signatureBuf[0] === 0x30) {
        return true;
      }
    }
    return false;
  }

  /**
   * @returns {boolean} if this is a p2sh output script
   */
  public isScriptHashOut() {
    const buf = this.toBuffer();
    return (
      buf.length === 23 &&
      buf[0] === OP_CODES.OP_HASH160 &&
      buf[1] === 0x14 &&
      buf[buf.length - 1] === OP_CODES.OP_EQUAL
    );
  }

  /**
   * @returns {boolean} if this is a p2wsh output script
   */
  public isWitnessScriptHashOut() {
    const buf = this.toBuffer();
    return buf.length === 34 && buf[0] === 0 && buf[1] === 32;
  }

  /**
   * @returns {boolean} if this is a p2wpkh output script
   */
  public isWitnessPublicKeyHashOut() {
    const buf = this.toBuffer();
    return buf.length === 22 && buf[0] === 0 && buf[1] === 20;
  }

  /**
   * @param {Object=} values - The return values
   * @param {Number} values.version - Set with the witness version
   * @param {Buffer} values.program - Set with the witness program
   * @returns {boolean} if this is a p2wpkh output script
   */
  public isWitnessProgram(values) {
    if (!values) {
      values = {};
    }
    const buf = this.toBuffer();
    if (buf.length < 4 || buf.length > 42) {
      return false;
    }
    if (
      buf[0] !== OP_CODES.OP_0 &&
      !(buf[0] >= OP_CODES.OP_1 && buf[0] <= OP_CODES.OP_16)
    ) {
      return false;
    }

    if (buf.length === buf[1] + 2) {
      values.version = buf[0];
      values.program = buf.slice(2, buf.length);
      return true;
    }

    return false;
  }

  /**
   * @returns {boolean} if this is a p2sh input script
   * Note that these are frequently indistinguishable from pubkeyhashin
   */
  public isScriptHashIn() {
    if (this.chunks.length <= 1) {
      return false;
    }
    const redeemChunk = this.chunks[this.chunks.length - 1];
    const redeemBuf = redeemChunk.buf;
    if (!redeemBuf) {
      return false;
    }

    let redeemScript;
    try {
      redeemScript = Script.fromBuffer(redeemBuf);
    } catch (e) {
      if (e instanceof BitcoreError) {
        return false;
      }
      throw e;
    }
    const type = redeemScript.classify();
    return type !== Script.types.UNKNOWN;
  }

  /**
   * @returns {boolean} if this is a mutlsig output script
   */
  public isMultisigOut() {
    return (
      this.chunks.length > 3 &&
      Opcode.isSmallIntOp(this.chunks[0].opcodenum) &&
      this.chunks.slice(1, this.chunks.length - 2).every(function(obj) {
        return obj.buf && BufferUtil.isBuffer(obj.buf);
      }) &&
      Opcode.isSmallIntOp(this.chunks[this.chunks.length - 2].opcodenum) &&
      this.chunks[this.chunks.length - 1].opcodenum ===
        OP_CODES.OP_CHECKMULTISIG
    );
  }

  /**
   * @returns {boolean} if this is a multisig input script
   */
  public isMultisigIn() {
    return (
      this.chunks.length >= 2 &&
      this.chunks[0].opcodenum === 0 &&
      this.chunks.slice(1, this.chunks.length).every(function(obj) {
        return (
          obj.buf && BufferUtil.isBuffer(obj.buf) && Signature.isTxDER(obj.buf)
        );
      })
    );
  }

  /**
   * @returns {boolean} true if this is a valid standard OP_RETURN output
   */
  public isDataOut() {
    return (
      this.chunks.length >= 1 &&
      this.chunks[0].opcodenum === OP_CODES.OP_RETURN &&
      (this.chunks.length === 1 ||
        (this.chunks.length === 2 &&
          this.chunks[1].buf &&
          this.chunks[1].buf.length <= Script.OP_RETURN_STANDARD_SIZE &&
          this.chunks[1].len === this.chunks.length))
    );
  }

  /**
   * Retrieve the associated data for this script.
   * In the case of a pay to public key hash or P2SH, return the hash.
   * In the case of a standard OP_RETURN, return the data
   * @returns {Buffer}
   */
  public getData() {
    if (this.isDataOut() || this.isScriptHashOut()) {
      if (_.isUndefined(this.chunks[1])) {
        return Buffer.alloc(0);
      } else {
        return Buffer.from(this.chunks[1].buf);
      }
    }
    if (this.isPublicKeyHashOut()) {
      return Buffer.from(this.chunks[2].buf);
    }
    throw new Error('Unrecognized script type to get data from');
  }

  /**
   * @returns {boolean} if the script is only composed of data pushing
   * opcodes or small int opcodes (OP_0, OP_1, ..., OP_16)
   */
  public isPushOnly() {
    return _.every(this.chunks, function(chunk) {
      return chunk.opcodenum <= OP_CODES.OP_16;
    });
  }

  public static types = {
    UNKNOWN: 'Unknown',
    PUBKEY_OUT: 'Pay to public key',
    PUBKEY_IN: 'Spend from public key',
    PUBKEYHASH_OUT: 'Pay to public key hash',
    PUBKEYHASH_IN: 'Spend from public key hash',
    SCRIPTHASH_OUT: 'Pay to script hash',
    SCRIPTHASH_IN: 'Spend from script hash',
    MULTISIG_OUT: 'Pay to multisig',
    MULTISIG_IN: 'Spend from multisig',
    DATA_OUT: 'Data push'
  };
  public static OP_RETURN_STANDARD_SIZE = 80;

  /**
   * @returns {object} The Script type if it is a known form,
   * or Script.UNKNOWN if it isn't
   */
  public classify() {
    if (this._isInput) {
      return this.classifyInput();
    } else if (this._isOutput) {
      return this.classifyOutput();
    } else {
      const outputType = this.classifyOutput();
      return outputType != Script.types.UNKNOWN
        ? outputType
        : this.classifyInput();
    }
  }

  public outputIdentifiers = {
    PUBKEY_OUT: this.isPublicKeyOut,
    PUBKEYHASH_OUT: this.isPublicKeyHashOut,
    MULTISIG_OUT: this.isMultisigOut,
    SCRIPTHASH_OUT: this.isScriptHashOut,
    DATA_OUT: this.isDataOut
  };

  /**
   * @returns {object} The Script type if it is a known form,
   * or Script.UNKNOWN if it isn't
   */
  public classifyOutput() {
    for (const type in this.outputIdentifiers) {
      if (this.outputIdentifiers[type].bind(this)()) {
        return Script.types[type];
      }
    }
    return Script.types.UNKNOWN;
  }

  public inputIdentifiers = {
    PUBKEY_IN: this.isPublicKeyIn,
    PUBKEYHASH_IN: this.isPublicKeyHashIn,
    MULTISIG_IN: this.isMultisigIn,
    SCRIPTHASH_IN: this.isScriptHashIn
  };

  /**
   * @returns {object} The Script type if it is a known form,
   * or Script.UNKNOWN if it isn't
   */
  public classifyInput() {
    for (const type in this.inputIdentifiers) {
      if (this.inputIdentifiers[type].bind(this)()) {
        return Script.types[type];
      }
    }
    return Script.types.UNKNOWN;
  }

  /**
   * @returns {boolean} if script is one of the known types
   */
  public isStandard() {
    // TODO: Add BIP62 compliance
    return this.classify() !== Script.types.UNKNOWN;
  }

  // Script construction methods

  /**
   * Adds a script element at the start of the script.
   * @param {*} obj a string, number, Opcode, Buffer, or object to add
   * @returns {Script} this script instance
   */
  public prepend(obj) {
    this._addByType(obj, true);
    return this;
  }

  /**
   * Compares a script with another script
   */
  public equals(script) {
    $.checkState(script instanceof Script, 'Must provide another script');
    if (this.chunks.length !== script.chunks.length) {
      return false;
    }
    let i;
    for (i = 0; i < this.chunks.length; i++) {
      if (
        BufferUtil.isBuffer(this.chunks[i].buf) &&
        !BufferUtil.isBuffer(script.chunks[i].buf)
      ) {
        return false;
      }
      if (
        BufferUtil.isBuffer(this.chunks[i].buf) &&
        !BufferUtil.equals(this.chunks[i].buf, script.chunks[i].buf)
      ) {
        return false;
      } else if (this.chunks[i].opcodenum !== script.chunks[i].opcodenum) {
        return false;
      }
    }
    return true;
  }

  /**
   * Adds a script element to the end of the script.
   *
   * @param {*} obj a string, number, Opcode, Buffer, or object to add
   * @returns {Script} this script instance
   *
   */
  public add(obj) {
    this._addByType(obj, false);
    return this;
  }

  public _addByType(obj, prepend) {
    if (typeof obj === 'string') {
      this._addOpcode(obj, prepend);
    } else if (typeof obj === 'number') {
      this._addOpcode(obj, prepend);
    } else if (obj instanceof Opcode) {
      this._addOpcode(obj, prepend);
    } else if (BufferUtil.isBuffer(obj)) {
      this._addBuffer(obj, prepend);
    } else if (obj instanceof Script) {
      this.chunks = this.chunks.concat(obj.chunks);
    } else if (typeof obj === 'object') {
      this._insertAtPosition(obj, prepend);
    } else {
      throw new Error('Invalid script chunk');
    }
  }

  public _insertAtPosition(op, prepend) {
    if (prepend) {
      this.chunks.unshift(op);
    } else {
      this.chunks.push(op);
    }
  }

  public _addOpcode(opcode, prepend) {
    let op;
    if (typeof opcode === 'number') {
      op = opcode;
    } else if (opcode instanceof Opcode) {
      op = opcode.toNumber();
    } else {
      op = new Opcode(opcode).toNumber();
    }
    this._insertAtPosition(
      {
        opcodenum: op
      },
      prepend
    );
    return this;
  }

  public _addBuffer(buf, prepend) {
    let opcodenum;
    const len = buf.length;
    if (len >= 0 && len < OP_CODES.OP_PUSHDATA1) {
      opcodenum = len;
    } else if (len < Math.pow(2, 8)) {
      opcodenum = OP_CODES.OP_PUSHDATA1;
    } else if (len < Math.pow(2, 16)) {
      opcodenum = OP_CODES.OP_PUSHDATA2;
    } else if (len < Math.pow(2, 32)) {
      opcodenum = OP_CODES.OP_PUSHDATA4;
    } else {
      throw new Error("You can't push that much data");
    }
    this._insertAtPosition(
      {
        buf,
        len,
        opcodenum
      },
      prepend
    );
    return this;
  }

  public hasCodeseparators() {
    for (let i = 0; i < this.chunks.length; i++) {
      if (this.chunks[i].opcodenum === OP_CODES.OP_CODESEPARATOR) {
        return true;
      }
    }
    return false;
  }

  public removeCodeseparators() {
    const chunks = [];
    for (let i = 0; i < this.chunks.length; i++) {
      if (this.chunks[i].opcodenum !== OP_CODES.OP_CODESEPARATOR) {
        chunks.push(this.chunks[i]);
      }
    }
    this.chunks = chunks;
    return this;
  }

  // high level script builder methods

  /**
   * @returns {Script} a new Multisig output script for given public keys,
   * requiring m of those public keys to spend
   * @param {PublicKey[]} publicKeys - list of all public keys controlling the output
   * @param {number} threshold - amount of required signatures to spend the output
   * @param {Object=} opts - Several options:
   *        - noSorting: defaults to false, if true, don't sort the given
   *                      public keys before creating the script
   */
  public static buildMultisigOut(
    publicKeys: Array<PublicKey>,
    threshold: number,
    opts?: { noSorting?: boolean }
  ) {
    $.checkArgument(
      threshold <= publicKeys.length,
      'Number of required signatures must be less than or equal to the number of public keys'
    );
    opts = opts || {};
    const script = new Script();
    script.add(Opcode.smallInt(threshold));
    publicKeys = _.map(publicKeys, key => new PublicKey(key));
    let sorted = publicKeys;
    if (!opts.noSorting) {
      sorted = _.sortBy(publicKeys, function(publicKey) {
        return publicKey.toString();
      });
    }
    for (let i = 0; i < sorted.length; i++) {
      const publicKey = sorted[i];
      script.add(publicKey.toBuffer());
    }
    script.add(Opcode.smallInt(publicKeys.length));
    script.add(OP_CODES.OP_CHECKMULTISIG);
    return script;
  }

  public static buildWitnessMultisigOutFromScript(script) {
    if (script instanceof Script) {
      const s = new Script();
      s.add(OP_CODES.OP_0);
      s.add(Hash.sha256(script.toBuffer()));
      return s;
    } else {
      throw new TypeError('First argument is expected to be a p2sh script');
    }
  }

  /**
   * A new Multisig input script for the given public keys, requiring m of those public keys to spend
   *
   * @param {PublicKey[]} pubkeys list of all public keys controlling the output
   * @param {number} threshold amount of required signatures to spend the output
   * @param {Array} signatures and array of signature buffers to append to the script
   * @param {Object=} opts
   * @param {boolean=} opts.noSorting don't sort the given public keys before creating the script (false by default)
   * @param {Script=} opts.cachedMultisig don't recalculate the redeemScript
   *
   * @returns {Script}
   */
  public static buildMultisigIn(
    pubkeys: Array<PublicKey>,
    threshold: number,
    signatures: Array<Buffer>,
    opts?: any
  ) {
    $.checkArgument(_.isArray(pubkeys));
    $.checkArgument(_.isNumber(threshold));
    $.checkArgument(_.isArray(signatures));
    opts = opts || {};
    const s = new Script();
    s.add(OP_CODES.OP_0);
    _.each(signatures, function(signature) {
      $.checkArgument(
        BufferUtil.isBuffer(signature),
        'Signatures must be an array of Buffers'
      );
      // TODO: allow signatures to be an array of Signature objects
      s.add(signature);
    });
    return s;
  }

  /**
   * A new P2SH Multisig input script for the given public keys, requiring m of those public keys to spend
   *
   * @param {PublicKey[]} pubkeys list of all public keys controlling the output
   * @param {number} threshold amount of required signatures to spend the output
   * @param {Array} signatures and array of signature buffers to append to the script
   * @param {Object=} opts
   * @param {boolean=} opts.noSorting don't sort the given public keys before creating the script (false by default)
   * @param {Script=} opts.cachedMultisig don't recalculate the redeemScript
   *
   * @returns {Script}
   */
  public static buildP2SHMultisigIn(pubkeys, threshold, signatures, opts) {
    $.checkArgument(_.isArray(pubkeys));
    $.checkArgument(_.isNumber(threshold));
    $.checkArgument(_.isArray(signatures));
    opts = opts || {};
    const s = new Script();
    s.add(OP_CODES.OP_0);
    _.each(signatures, function(signature) {
      $.checkArgument(
        BufferUtil.isBuffer(signature),
        'Signatures must be an array of Buffers'
      );
      // TODO: allow signatures to be an array of Signature objects
      s.add(signature);
    });
    s.add(
      (
        opts.cachedMultisig || Script.buildMultisigOut(pubkeys, threshold, opts)
      ).toBuffer()
    );
    return s;
  }

  /**
   * @returns {Script} a new pay to public key hash output for the given
   * address or public key
   * @param {(Address|PublicKey)} to - destination address or public key
   */
  public static buildPublicKeyHashOut(to) {
    $.checkArgument(!_.isUndefined(to));
    $.checkArgument(
      to instanceof PublicKey || to instanceof Address || _.isString(to)
    );
    if (to instanceof PublicKey) {
      to = to.toAddress();
    } else if (_.isString(to)) {
      to = new Address(to as Address.AddressData);
    }
    const s = new Script();
    s.add(OP_CODES.OP_DUP)
      .add(OP_CODES.OP_HASH160)
      .add(to.hashBuffer)
      .add(OP_CODES.OP_EQUALVERIFY)
      .add(OP_CODES.OP_CHECKSIG);
    s._network = to.network;
    return s;
  }

  /**
   * @returns {Script} a new pay to public key output for the given
   *  public key
   */
  public static buildPublicKeyOut(pubkey) {
    $.checkArgument(pubkey instanceof PublicKey);
    const s = new Script();
    s.add(pubkey.toBuffer()).add(OP_CODES.OP_CHECKSIG);
    return s;
  }

  /**
   * @returns {Script} a new OP_RETURN script with data
   * @param {(string|Buffer)} data - the data to embed in the output
   * @param {(string)} encoding - the type of encoding of the string
   */
  public static buildDataOut(data: string | Buffer, encoding?: string) {
    $.checkArgument(
      _.isUndefined(data) || _.isString(data) || BufferUtil.isBuffer(data)
    );
    if (typeof data === 'string') {
      data = Buffer.from(data, encoding);
    }
    const s = new Script();
    s.add(OP_CODES.OP_RETURN);
    if (!_.isUndefined(data)) {
      s.add(data);
    }
    return s;
  }

  /**
   * @param {Script|Address} script - the redeemScript for the new p2sh output.
   *    It can also be a p2sh address
   * @returns {Script} new pay to script hash script for given script
   */
  public static buildScriptHashOut(script) {
    $.checkArgument(
      script instanceof Script ||
        (script instanceof Address && script.isPayToScriptHash())
    );
    const s = new Script();
    s.add(OP_CODES.OP_HASH160)
      .add(
        script instanceof Address
          ? script.hashBuffer
          : Hash.sha256ripemd160(script.toBuffer())
      )
      .add(OP_CODES.OP_EQUAL);

    s._network = script._network || script.network;
    return s;
  }

  /**
   * Builds a scriptSig (a script for an input) that signs a public key output script.
   *
   * @param {Signature|Buffer} signature - a Signature object, or the signature in DER canonical encoding
   * @param {number=} sigtype - the type of the signature (defaults to SIGHASH_ALL)
   */
  public static buildPublicKeyIn(signature, sigtype) {
    $.checkArgument(
      signature instanceof Signature || BufferUtil.isBuffer(signature)
    );
    $.checkArgument(_.isUndefined(sigtype) || _.isNumber(sigtype));
    if (signature instanceof Signature) {
      signature = signature.toBuffer();
    }
    const script = new Script();
    script.add(
      BufferUtil.concat([
        signature,
        BufferUtil.integerAsSingleByteBuffer(sigtype || Signature.SIGHASH_ALL)
      ])
    );
    return script;
  }

  /**
   * Builds a scriptSig (a script for an input) that signs a public key hash
   * output script.
   *
   * @param {Buffer|string|PublicKey} publicKey
   * @param {Signature|Buffer} signature - a Signature object, or the signature in DER canonical encoding
   * @param {number=} sigtype - the type of the signature (defaults to SIGHASH_ALL)
   */
  public static buildPublicKeyHashIn(publicKey, signature, sigtype) {
    $.checkArgument(
      signature instanceof Signature || BufferUtil.isBuffer(signature)
    );
    $.checkArgument(_.isUndefined(sigtype) || _.isNumber(sigtype));
    if (signature instanceof Signature) {
      signature = signature.toBuffer();
    }
    const script = new Script()
      .add(
        BufferUtil.concat([
          signature,
          BufferUtil.integerAsSingleByteBuffer(sigtype || Signature.SIGHASH_ALL)
        ])
      )
      .add(new PublicKey(publicKey).toBuffer());
    return script;
  }

  /**
   * @returns {Script} an empty script
   */
  public static empty() {
    return new Script();
  }

  /**
   * @returns {Script} a new pay to script hash script that pays to this script
   */
  public toScriptHashOut() {
    return Script.buildScriptHashOut(this);
  }

  /**
   * @return {Script} an output script built from the address
   */
  public static fromAddress(address) {
    address = new Address(address);
    if (address.isPayToScriptHash()) {
      return Script.buildScriptHashOut(address);
    } else if (address.isPayToPublicKeyHash()) {
      return Script.buildPublicKeyHashOut(address);
    }
    throw new BitcoreError(
      ERROR_TYPES.Script.errors.UnrecognizedAddress,
      address
    );
  }

  /**
   * Will return the associated address information object
   * @return {Address|boolean}
   */
  public getAddressInfo() {
    if (this._isInput) {
      return this._getInputAddressInfo();
    } else if (this._isOutput) {
      return this._getOutputAddressInfo();
    } else {
      const info = this._getOutputAddressInfo();
      if (!info) {
        return this._getInputAddressInfo();
      }
      return info;
    }
  }

  /**
   * Will return the associated output scriptPubKey address information object
   * @return {Address|boolean}
   * @private
   */
  public _getOutputAddressInfo() {
    const info = {} as Address.AddressObj;
    if (this.isScriptHashOut()) {
      info.hashBuffer = this.getData();
      info.type = Address.PayToScriptHash;
    } else if (this.isPublicKeyHashOut()) {
      info.hashBuffer = this.getData();
      info.type = Address.PayToPublicKeyHash;
    } else {
      return false;
    }
    return info;
  }

  /**
   * Will return the associated input scriptSig address information object
   * @return {Address|boolean}
   * @private
   */
  public _getInputAddressInfo() {
    const info = {} as Address.AddressObj;
    if (this.isPublicKeyHashIn()) {
      // hash the publickey found in the scriptSig
      info.hashBuffer = Hash.sha256ripemd160(this.chunks[1].buf);
      info.type = Address.PayToPublicKeyHash;
    } else if (this.isScriptHashIn()) {
      // hash the redeemscript found at the end of the scriptSig
      info.hashBuffer = Hash.sha256ripemd160(
        this.chunks[this.chunks.length - 1].buf
      );
      info.type = Address.PayToScriptHash;
    } else {
      return false;
    }
    return info;
  }

  /**
   * @param {Network=} network
   * @return {Address|boolean} the associated address for this script if possible, or false
   */
  public toAddress(network) {
    const info = this.getAddressInfo();
    if (!info) {
      return false;
    }
    info.network =
      Network.get(network) || this._network || Network.defaultNetwork;
    return new Address(info);
  }

  /**
   * Analogous to bitcoind's FindAndDelete. Find and delete equivalent chunks,
   * typically used with push data chunks.  Note that this will find and delete
   * not just the same data, but the same data with the same push data op as
   * produced by default. i.e., if a pushdata in a tx does not use the minimal
   * pushdata op, then when you try to remove the data it is pushing, it will not
   * be removed, because they do not use the same pushdata op.
   */
  public findAndDelete(script) {
    const buf = script.toBuffer();
    const hex = buf.toString('hex');
    for (let i = 0; i < this.chunks.length; i++) {
      const script2 = new Script({
        chunks: [this.chunks[i]]
      });
      const buf2 = script2.toBuffer();
      const hex2 = buf2.toString('hex');
      if (hex === hex2) {
        this.chunks.splice(i, 1);
      }
    }
    return this;
  }

  /**
   * Comes from bitcoind's script interpreter CheckMinimalPush function
   * @returns {boolean} if the chunk {i} is the smallest way to push that particular data.
   */
  public checkMinimalPush(i) {
    const chunk = this.chunks[i];
    const buf = chunk.buf;
    const opcodenum = chunk.opcodenum;
    if (!buf) {
      return true;
    }
    if (buf.length === 0) {
      // Could have used OP_0.
      return opcodenum === OP_CODES.OP_0;
    } else if (buf.length === 1 && buf[0] >= 1 && buf[0] <= 16) {
      // Could have used OP_1 .. OP_16.
      return opcodenum === OP_CODES.OP_1 + (buf[0] - 1);
    } else if (buf.length === 1 && buf[0] === 0x81) {
      // Could have used OP_1NEGATE
      return opcodenum === OP_CODES.OP_1NEGATE;
    } else if (buf.length <= 75) {
      // Could have used a direct push (opcode indicating number of bytes pushed + those bytes).
      return opcodenum === buf.length;
    } else if (buf.length <= 255) {
      // Could have used OP_PUSHDATA.
      return opcodenum === OP_CODES.OP_PUSHDATA1;
    } else if (buf.length <= 65535) {
      // Could have used OP_PUSHDATA2.
      return opcodenum === OP_CODES.OP_PUSHDATA2;
    }
    return true;
  }

  /**
   * Comes from bitcoind's script DecodeOP_N function
   * @param {number} opcode
   * @returns {number} numeric value in range of 0 to 16
   */
  public _decodeOP_N(opcode) {
    if (opcode === OP_CODES.OP_0) {
      return 0;
    } else if (opcode >= OP_CODES.OP_1 && opcode <= OP_CODES.OP_16) {
      return opcode - (OP_CODES.OP_1 - 1);
    } else {
      throw new Error('Invalid opcode: ' + JSON.stringify(opcode));
    }
  }

  /**
   * Comes from bitcoind's script GetSigOpCount(boolean) function
   * @param {boolean} use current (true) or pre-version-0.6 (false) logic
   * @returns {number} number of signature operations required by this script
   */
  public getSignatureOperationsCount(accurate) {
    accurate = _.isUndefined(accurate) ? true : accurate;
    const self = this;
    let n = 0;
    let lastOpcode = OP_CODES.OP_INVALIDOPCODE;
    _.each(self.chunks, function getChunk(chunk) {
      const opcode = chunk.opcodenum;
      if (
        opcode == OP_CODES.OP_CHECKSIG ||
        opcode == OP_CODES.OP_CHECKSIGVERIFY
      ) {
        n++;
      } else if (
        opcode == OP_CODES.OP_CHECKMULTISIG ||
        opcode == OP_CODES.OP_CHECKMULTISIGVERIFY
      ) {
        if (
          accurate &&
          lastOpcode >= OP_CODES.OP_1 &&
          lastOpcode <= OP_CODES.OP_16
        ) {
          n += self._decodeOP_N(lastOpcode);
        } else {
          n += 20;
        }
      }
      lastOpcode = opcode;
    });
    return n;
  }
}
