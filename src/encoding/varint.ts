'use strict';

import { BufferWriter } from './bufferwriter';
import { BufferReader } from './bufferreader';
import { BitcoreBN } from '../crypto/bn';

export class Varint {
  public buf: Buffer;
  constructor(buf: Buffer | BitcoreBN | number) {
    if (!(this instanceof Varint)) {
      return new Varint(buf);
    }
    if (Buffer.isBuffer(buf)) {
      this.buf = buf;
    } else if (typeof buf === 'number') {
      const num = buf;
      this.fromNumber(num);
    } else if (buf instanceof BitcoreBN) {
      const bn = buf;
      this.fromBN(bn);
    } else if (buf) {
      const obj = buf;
      this.set(obj);
    }
  }

  public set(obj) {
    this.buf = obj.buf || this.buf;
    return this;
  }

  public fromString(str) {
    this.set({
      buf: Buffer.from(str, 'hex')
    });
    return this;
  }

  public toString() {
    return this.buf.toString('hex');
  }

  public fromBuffer(buf) {
    this.buf = buf;
    return this;
  }

  public fromBufferReader(br) {
    this.buf = br.readVarintBuf();
    return this;
  }

  public fromBN(bn) {
    this.buf = new BufferWriter().writeVarintBN(bn).concat();
    return this;
  }

  public fromNumber(num) {
    this.buf = new BufferWriter().writeVarintNum(num).concat();
    return this;
  }

  public toBuffer() {
    return this.buf;
  }

  public toBN() {
    return new BufferReader(this.buf).readVarintBN();
  }

  public toNumber() {
    return new BufferReader(this.buf).readVarintNum();
  }
}
