import * as _ from 'lodash';
import { BlockHeader } from './blockheader';
import { BitcoreBN } from '../crypto/bn';
import { BufferUtil } from '../util/buffer';
import { BufferReader } from '../encoding/bufferreader';
import { BufferWriter } from '../encoding/bufferwriter';
import { Hash } from '../crypto/hash';
import { Transaction } from '../transaction';
const $ = require('../util/preconditions');

export namespace Block {
  export interface BlockObj {
    transactions: Array<Transaction>;
    header: BlockHeader;
  }
}
/**
 * Instantiate a Block from a Buffer, JSON object, or Object with
 * the properties of the Block
 *
 * @param {*} - A Buffer, JSON string, or Object
 * @returns {Block}
 * @constructor
 */
export class Block {
  public transactions: Array<Transaction>;
  public _id: string;
  public header: BlockHeader;

  constructor(arg?: Partial<Block.BlockObj> | Buffer) {
    if (!(this instanceof Block)) {
      return new Block(arg);
    }
    _.extend(this, Block._from(arg));
    return this;
  }

  // https://github.com/bitcoin/bitcoin/blob/b5fa132329f0377d787a4a21c1686609c2bfaece/src/primitives/block.h#L14
  public static MAX_BLOCK_SIZE = 1000000;

  /**
   * @param {*} - A Buffer, JSON string or Object
   * @returns {Object} - An object representing block data
   * @throws {TypeError} - If the argument was not recognized
   * @private
   */
  public static _from(arg) {
    let info = {};
    if (BufferUtil.isBuffer(arg)) {
      info = Block._fromBufferReader(new BufferReader(arg));
    } else if (_.isObject(arg)) {
      info = Block._fromObject(arg);
    } else {
      throw new TypeError('Unrecognized argument for Block');
    }
    return info;
  }

  /**
   * @param {Object} - A plain JavaScript object
   * @returns {Object} - An object representing block data
   * @private
   */
  public static _fromObject(data) {
    const transactions = [];
    data.transactions.forEach(tx => {
      if (tx instanceof Transaction) {
        transactions.push(tx);
      } else {
        transactions.push(new Transaction().fromObject(tx));
      }
    });
    const info = {
      header: BlockHeader.fromObject(data.header),
      transactions
    };
    return info;
  }

  /**
   * @param {Object} - A plain JavaScript object
   * @returns {Block} - An instance of block
   */
  public static fromObject(obj) {
    const info = Block._fromObject(obj);
    return new Block(info);
  }

  /**
   * @param {BufferReader} - Block data
   * @returns {Object} - An object representing the block data
   * @private
   */
  public static _fromBufferReader(br) {
    const info: Partial<Block.BlockObj> = {};
    $.checkState(!br.finished(), 'No block data received');
    info.header = BlockHeader.fromBufferReader(br);
    const transactions = br.readVarintNum();
    info.transactions = [];
    for (let i = 0; i < transactions; i++) {
      info.transactions.push(new Transaction().fromBufferReader(br));
    }
    return info;
  }

  /**
   * @param {BufferReader} - A buffer reader of the block
   * @returns {Block} - An instance of block
   */
  public static fromBufferReader(br) {
    $.checkArgument(br, 'br is required');
    const info = Block._fromBufferReader(br);
    return new Block(info);
  }

  /**
   * @param {Buffer} - A buffer of the block
   * @returns {Block} - An instance of block
   */
  public static fromBuffer(buf) {
    return Block.fromBufferReader(new BufferReader(buf));
  }

  /**
   * @param {string} - str - A hex encoded string of the block
   * @returns {Block} - A hex encoded string of the block
   */
  public static fromString(str) {
    const buf = Buffer.from(str, 'hex');
    return Block.fromBuffer(buf);
  }

  /**
   * @param {Binary} - Raw block binary data or buffer
   * @returns {Block} - An instance of block
   */
  public static fromRawBlock(data) {
    if (!BufferUtil.isBuffer(data)) {
      data = Buffer.from(data, 'binary');
    }
    const br = new BufferReader(data);
    br.pos = Block.Values.START_OF_BLOCK;
    const info = Block._fromBufferReader(br);
    return new Block(info);
  }

  /**
   * @returns {Object} - A plain object with the block properties
   */
  public toObject() {
    const transactions = [];
    this.transactions.forEach(tx => {
      transactions.push(tx.toObject());
    });
    return {
      header: this.header.toObject(),
      transactions
    };
  }

  public toJSON = this.toObject;

  /**
   * @returns {Buffer} - A buffer of the block
   */
  public toBuffer() {
    return this.toBufferWriter().concat();
  }

  /**
   * @returns {string} - A hex encoded string of the block
   */
  public toString() {
    return this.toBuffer().toString('hex');
  }

  /**
   * @param {BufferWriter} - An existing instance of BufferWriter
   * @returns {BufferWriter} - An instance of BufferWriter representation of the Block
   */
  public toBufferWriter(bw?: BufferWriter) {
    if (!bw) {
      bw = new BufferWriter();
    }
    bw.write(this.header.toBuffer());
    bw.writeVarintNum(this.transactions.length);
    for (const transaction of this.transactions) {
      transaction.toBufferWriter(bw);
    }
    return bw;
  }

  /**
   * Will iterate through each transaction and return an array of hashes
   * @returns {Array} - An array with transaction hashes
   */
  public getTransactionHashes() {
    const hashes = [];
    if (this.transactions.length === 0) {
      return [Block.Values.NULL_HASH];
    }
    for (const transaction of this.transactions) {
      hashes.push(transaction._getHash());
    }
    return hashes;
  }

  /**
   * Will build a merkle tree of all the transactions, ultimately arriving at
   * a single point, the merkle root.
   * @link https://en.bitcoin.it/wiki/Protocol_specification#Merkle_Trees
   * @returns {Array} - An array with each level of the tree after the other.
   */
  public getMerkleTree() {
    const tree = this.getTransactionHashes();

    let j = 0;
    for (
      let size = this.transactions.length;
      size > 1;
      size = Math.floor((size + 1) / 2)
    ) {
      for (let i = 0; i < size; i += 2) {
        const i2 = Math.min(i + 1, size - 1);
        const buf = Buffer.concat([tree[j + i], tree[j + i2]]);
        tree.push(Hash.sha256sha256(buf));
      }
      j += size;
    }

    return tree;
  }

  /**
   * Calculates the merkleRoot from the transactions.
   * @returns {Buffer} - A buffer of the merkle root hash
   */
  public getMerkleRoot() {
    const tree = this.getMerkleTree();
    return tree[tree.length - 1];
  }

  /**
   * Verifies that the transactions in the block match the header merkle root
   * @returns {Boolean} - If the merkle roots match
   */
  public validMerkleRoot() {
    const h = new BitcoreBN(this.header.merkleRoot.toString('hex'), 'hex');
    const c = new BitcoreBN(this.getMerkleRoot().toString('hex'), 'hex');

    if (h.cmp(c) !== 0) {
      return false;
    }

    return true;
  }

  /**
   * @returns {Buffer} - The little endian hash buffer of the header
   */
  public _getHash() {
    return this.header._getHash();
  }

  public get hash() {
    return this.id;
  }
  public get id() {
    if (!this._id) {
      this._id = this.header.id;
    }
    return this._id;
  }

  /**
   * @returns {string} - A string formatted for the console
   */
  public inspect() {
    return '<Block ' + this.id + '>';
  }

  public static Values = {
    START_OF_BLOCK: 8, // Start of block in raw block data
    NULL_HASH: Buffer.from(
      '0000000000000000000000000000000000000000000000000000000000000000',
      'hex'
    )
  };
}
