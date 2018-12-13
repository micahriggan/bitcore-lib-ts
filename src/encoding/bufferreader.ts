import * as _ from 'lodash';
import $ from '../util/preconditions';
import { BufferUtil } from '../util';
import { BitcoreBN } from '../crypto';
import BN from 'bn.js';

export class BufferReader {
  public buf: Buffer;
  public pos: number;

  constructor(buf?: BufferReader | Buffer | string | object) {
    if (!(this instanceof BufferReader)) {
      return new BufferReader(buf);
    }
    if (_.isUndefined(buf)) {
      return;
    }
    if (Buffer.isBuffer(buf)) {
      this.set({
        buf
      });
    } else if (typeof buf === 'string') {
      this.set({
        buf: Buffer.from(buf, 'hex')
      });
    } else if (_.isObject(buf)) {
      const obj = buf;
      this.set(obj);
    } else {
      throw new TypeError('Unrecognized argument for BufferReader');
    }
  }
  public set(obj: { buf?: Buffer; pos?: number }) {
    this.buf = obj.buf || this.buf || undefined;
    this.pos = obj.pos || this.pos || 0;
    return this;
  }

  public eof() {
    return this.pos >= this.buf.length;
  }

  public finished = this.eof;

  public read(len) {
    $.checkArgument(!_.isUndefined(len), 'Must specify a length');
    const buf = this.buf.slice(this.pos, this.pos + len);
    this.pos = this.pos + len;
    return buf;
  }

  public readAll() {
    const buf = this.buf.slice(this.pos, this.buf.length);
    this.pos = this.buf.length;
    return buf;
  }

  public readUInt8() {
    const val = this.buf.readUInt8(this.pos);
    this.pos = this.pos + 1;
    return val;
  }

  public readUInt16BE() {
    const val = this.buf.readUInt16BE(this.pos);
    this.pos = this.pos + 2;
    return val;
  }

  public readUInt16LE() {
    const val = this.buf.readUInt16LE(this.pos);
    this.pos = this.pos + 2;
    return val;
  }

  public readUInt32BE() {
    const val = this.buf.readUInt32BE(this.pos);
    this.pos = this.pos + 4;
    return val;
  }

  public readUInt32LE() {
    const val = this.buf.readUInt32LE(this.pos);
    this.pos = this.pos + 4;
    return val;
  }

  public readInt32LE() {
    const val = this.buf.readInt32LE(this.pos);
    this.pos = this.pos + 4;
    return val;
  }

  public readUInt64BEBN() {
    const buf = this.buf.slice(this.pos, this.pos + 8);
    const bigNum = BitcoreBN.fromBuffer(buf);
    this.pos = this.pos + 8;
    return bigNum;
  }

  public readUInt64LEBN() {
    const second = this.buf.readUInt32LE(this.pos);
    const first = this.buf.readUInt32LE(this.pos + 4);
    const combined = first * 0x100000000 + second;
    const MAX_SAFE_NUM = 0x1fffffffffffff;
    // Instantiating an instance of BN with a number is faster than with an
    // array or string. However, the maximum safe number for a double precision
    // floating point is 2 ^ 52 - 1 (0x1fffffffffffff), thus we can safely use
    // non-floating point numbers less than this amount (52 bits). And in the case
    // that the number is larger, we can instatiate an instance of BN by passing
    // an array from the buffer (slower) and specifying the endianness.
    let bn;
    if (combined <= MAX_SAFE_NUM) {
      bn = new BitcoreBN(combined);
    } else {
      const data = Array.prototype.slice.call(this.buf, this.pos, this.pos + 8);
      const BASE_10 = 10;
      bn = new BitcoreBN(data, BASE_10, 'le');
    }
    this.pos = this.pos + 8;
    return bn;
  }

  public readVarintNum() {
    const first = this.readUInt8();
    switch (first) {
      case 0xfd:
        return this.readUInt16LE();
      case 0xfe:
        return this.readUInt32LE();
      case 0xff:
        const bn = this.readUInt64LEBN();
        const n = bn.toNumber();
        if (n <= Math.pow(2, 53)) {
          return n;
        } else {
          throw new Error(
            'number too large to retain precision - use readVarintBN'
          );
        }
        break;
      default:
        return first;
    }
  }

  /**
   * reads a length prepended buffer
   */
  public readVarLengthBuffer() {
    const len = this.readVarintNum();
    const buf = this.read(len);
    $.checkState(
      buf.length === len,
      'Invalid length while reading varlength buffer. ' +
        'Expected to read: ' +
        len +
        ' and read ' +
        buf.length
    );
    return buf;
  }

  public readVarintBuf() {
    const first = this.buf.readUInt8(this.pos);
    switch (first) {
      case 0xfd:
        return this.read(1 + 2);
      case 0xfe:
        return this.read(1 + 4);
      case 0xff:
        return this.read(1 + 8);
      default:
        return this.read(1);
    }
  }

  public readVarintBN() {
    const first = this.readUInt8();
    switch (first) {
      case 0xfd:
        return new BitcoreBN(this.readUInt16LE());
      case 0xfe:
        return new BitcoreBN(this.readUInt32LE());
      case 0xff:
        return this.readUInt64LEBN();
      default:
        return new BitcoreBN(first);
    }
  }

  public reverse() {
    const buf = Buffer.alloc(this.buf.length);
    for (let i = 0; i < buf.length; i++) {
      buf[i] = this.buf[this.buf.length - 1 - i];
    }
    this.buf = buf;
    return this;
  }

  public readReverse(len?: number) {
    if (_.isUndefined(len)) {
      len = this.buf.length;
    }
    const buf = this.buf.slice(this.pos, this.pos + len);
    this.pos = this.pos + len;
    return BufferUtil.reverse(buf);
  }
}
