'use strict';

import * as _ from 'lodash';
import { BitcoreBN } from '../crypto/bn';
import { BufferUtil } from '../util/buffer';
import { BufferReader } from '../encoding/bufferreader';
import { BufferWriter } from '../encoding/bufferwriter';
import { Hash } from '../crypto/hash';
import { JSUtil } from '../util/js';
import $ from '../util/preconditions';
import BN from 'bn.js';

const GENESIS_BITS = 0x1d00ffff;

export namespace BlockHeader {
  export interface GenericBlockHeaderObj<T> {
    version: number;
    hash: string;
    prevHash: T;
    merkleRoot: T;
    time: number;
    timestamp: number;
    bits: number;
    nonce: number;
  }
  export interface SerializedBlockHeaderObj
    extends GenericBlockHeaderObj<string> {}

  export interface DeserializedBlockHeaderObj
    extends GenericBlockHeaderObj<Buffer> {}

  export interface BlockHeaderObj
    extends GenericBlockHeaderObj<string | Buffer> {}
}
export class BlockHeader {
  public _id: string;
  public version: number;
  public prevHash: Buffer;
  public merkleRoot: Buffer;
  public time: number;
  public timestamp: number;
  public bits: number;
  public nonce: number;

  /**
   * Instantiate a BlockHeader from a Buffer, JSON object, or Object with
   * the properties of the BlockHeader
   *
   * @param {*} - A Buffer, JSON string, or Object
   * @returns {BlockHeader} - An instance of block header
   * @constructor
   */
  constructor(arg) {
    if (!(this instanceof BlockHeader)) {
      return new BlockHeader(arg);
    }
    const info = BlockHeader._from(arg);
    this.version = info.version;
    this.prevHash = info.prevHash;
    this.merkleRoot = info.merkleRoot;
    this.time = info.time;
    this.timestamp = info.time;
    this.bits = info.bits;
    this.nonce = info.nonce;

    if (info.hash) {
      $.checkState(
        this.hash === info.hash,
        'Argument object hash property does not match block hash.'
      );
    }

    return this;
  }

  /**
   * @param {*} - A Buffer, JSON string or Object
   * @returns {Object} - An object representing block header data
   * @throws {TypeError} - If the argument was not recognized
   * @private
   */
  public static _from(arg: Buffer | BlockHeader.DeserializedBlockHeaderObj) {
    let info: Partial<BlockHeader.DeserializedBlockHeaderObj> = {};
    if (BufferUtil.isBuffer(arg)) {
      info = BlockHeader._fromBufferReader(new BufferReader(arg));
    } else if (_.isObject(arg)) {
      info = BlockHeader._fromObject(
        arg as BlockHeader.DeserializedBlockHeaderObj
      );
    } else {
      throw new TypeError('Unrecognized argument for BlockHeader');
    }
    return info;
  }

  /**
   * @param {Object} - A JSON string
   * @returns {Object} - An object representing block header data
   * @private
   */
  public static _fromObject(
    data:
      | BlockHeader.DeserializedBlockHeaderObj
      | BlockHeader.SerializedBlockHeaderObj
  ): BlockHeader.DeserializedBlockHeaderObj {
    $.checkArgument(data, 'data is required');

    const prevHash =
      typeof data.prevHash === 'string'
        ? BufferUtil.reverse(Buffer.from(data.prevHash, 'hex'))
        : (data.prevHash as Buffer);

    const merkleRoot =
      typeof data.merkleRoot === 'string'
        ? BufferUtil.reverse(Buffer.from(data.merkleRoot, 'hex'))
        : (data.prevHash as Buffer);

    const info = {
      hash: data.hash,
      version: data.version,
      prevHash,
      merkleRoot,
      time: data.time,
      timestamp: data.time,
      bits: data.bits,
      nonce: data.nonce
    };
    return info;
  }

  /**
   * @param {Object} - A plain JavaScript object
   * @returns {BlockHeader} - An instance of block header
   */
  public static fromObject(obj) {
    const info = BlockHeader._fromObject(obj);
    return new BlockHeader(info);
  }

  /**
   * @param {Binary} - Raw block binary data or buffer
   * @returns {BlockHeader} - An instance of block header
   */
  public static fromRawBlock(data) {
    if (!BufferUtil.isBuffer(data)) {
      data = Buffer.from(data, 'binary');
    }
    const br = new BufferReader(data);
    br.pos = BlockHeader.Constants.START_OF_HEADER;
    const info = BlockHeader._fromBufferReader(br);
    return new BlockHeader(info);
  }

  /**
   * @param {Buffer} - A buffer of the block header
   * @returns {BlockHeader} - An instance of block header
   */
  public static fromBuffer(buf) {
    const info = BlockHeader._fromBufferReader(new BufferReader(buf));
    return new BlockHeader(info);
  }

  /**
   * @param {string} - A hex encoded buffer of the block header
   * @returns {BlockHeader} - An instance of block header
   */
  public static fromString(str) {
    const buf = Buffer.from(str, 'hex');
    return BlockHeader.fromBuffer(buf);
  }

  /**
   * @param {BufferReader} - A BufferReader of the block header
   * @returns {Object} - An object representing block header data
   * @private
   */
  public static _fromBufferReader(br) {
    const info: Partial<BlockHeader.DeserializedBlockHeaderObj> = {};
    info.version = br.readInt32LE();
    info.prevHash = br.read(32);
    info.merkleRoot = br.read(32);
    info.time = br.readUInt32LE();
    info.bits = br.readUInt32LE();
    info.nonce = br.readUInt32LE();
    return info;
  }

  /**
   * @param {BufferReader} - A BufferReader of the block header
   * @returns {BlockHeader} - An instance of block header
   */
  public static fromBufferReader(br) {
    const info = BlockHeader._fromBufferReader(br);
    return new BlockHeader(info);
  }

  /**
   * @returns {Object} - A plain object of the BlockHeader
   */
  public toObject(): BlockHeader.SerializedBlockHeaderObj {
    return {
      hash: this.hash,
      version: this.version,
      prevHash: BufferUtil.reverse(this.prevHash).toString('hex'),
      merkleRoot: BufferUtil.reverse(this.merkleRoot).toString('hex'),
      time: this.time,
      timestamp: this.time,
      bits: this.bits,
      nonce: this.nonce
    };
  }
  public toJSON = this.toObject;

  /**
   * @returns {Buffer} - A Buffer of the BlockHeader
   */
  public toBuffer() {
    return this.toBufferWriter().concat();
  }

  /**
   * @returns {string} - A hex encoded string of the BlockHeader
   */
  public toString() {
    return this.toBuffer().toString('hex');
  }

  /**
   * @param {BufferWriter} - An existing instance BufferWriter
   * @returns {BufferWriter} - An instance of BufferWriter representation of the BlockHeader
   */
  public toBufferWriter(bw?: BufferWriter) {
    if (!bw) {
      bw = new BufferWriter();
    }
    bw.writeInt32LE(this.version);
    bw.write(this.prevHash);
    bw.write(this.merkleRoot);
    bw.writeUInt32LE(this.time);
    bw.writeUInt32LE(this.bits);
    bw.writeUInt32LE(this.nonce);
    return bw;
  }

  /**
   * Returns the target difficulty for this block
   * @param {Number} bits
   * @returns {BN} An instance of BN with the decoded difficulty bits
   */
  public getTargetDifficulty(bits?: number): BN {
    bits = bits || this.bits;
    let target = new BN(bits & 0xffffff);
    let mov = 8 * ((bits >>> 24) - 3);
    while (mov-- > 0) {
      target = target.mul(new BN(2));
    }
    return target;
  }

  /**
   * @link https://en.bitcoin.it/wiki/Difficulty
   * @return {Number}
   */
  public getDifficulty() {
    const difficulty1TargetBN = this.getTargetDifficulty(GENESIS_BITS).mul(
      new BN(Math.pow(10, 8))
    );
    const currentTargetBN = this.getTargetDifficulty();

    let difficultyString = difficulty1TargetBN
      .div(currentTargetBN)
      .toString(10);
    const decimalPos = difficultyString.length - 8;
    difficultyString =
      difficultyString.slice(0, decimalPos) +
      '.' +
      difficultyString.slice(decimalPos);

    return parseFloat(difficultyString);
  }

  /**
   * @returns {Buffer} - The little endian hash buffer of the header
   */
  public _getHash() {
    const buf = this.toBuffer();
    return Hash.sha256sha256(buf);
  }

  private _getId() {
    if (!this._id) {
      this._id = new BufferReader(this._getHash())
        .readReverse()
        .toString('hex');
    }
    return this._id;
  }

  public get id() {
    return this._getId();
  }

  public get hash() {
    return this._getId();
  }

  /**
   * @returns {Boolean} - If timestamp is not too far in the future
   */
  public validTimestamp() {
    const currentTime = Math.round(new Date().getTime() / 1000);
    if (this.time > currentTime + BlockHeader.Constants.MAX_TIME_OFFSET) {
      return false;
    }
    return true;
  }

  /**
   * @returns {Boolean} - If the proof-of-work hash satisfies the target difficulty
   */
  public validProofOfWork() {
    const pow = new BN(this.id, 16);
    const target = this.getTargetDifficulty();

    if (pow.cmp(target) > 0) {
      return false;
    }
    return true;
  }

  /**
   * @returns {string} - A string formatted for the console
   */
  public inspect() {
    return '<BlockHeader ' + this.id + '>';
  }

  public static Constants = {
    START_OF_HEADER: 8, // Start buffer position in raw block data
    MAX_TIME_OFFSET: 2 * 60 * 60, // The max a timestamp can be in the future
    LARGEST_HASH: new BN(
      '10000000000000000000000000000000000000000000000000000000000000000',
      'hex'
    )
  };
}
