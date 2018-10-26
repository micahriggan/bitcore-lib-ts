'use strict';

import { BufferUtil } from '../util/buffer';
import assert from 'assert';

export class BufferWriter {
  public bufs: Array<Uint8Array>;
  public bufLen: number;
  constructor(obj?: { bufs: Array<Uint8Array> }) {
    if (!(this instanceof BufferWriter)) {
      return new BufferWriter(obj);
    }
    this.bufLen = 0;
    if (obj) {
      this.set(obj);
    } else {
      this.bufs = [];
    }
  }

  public set(obj) {
    this.bufs = obj.bufs || this.bufs || [];
    this.bufLen = this.bufs.reduce((prev, buf) => {
      return prev + buf.length;
    }, 0);
    return this;
  }

  public toBuffer() {
    return this.concat();
  }

  public concat() {
    return Buffer.concat(this.bufs, this.bufLen);
  }

  public write(buf) {
    assert(bufferUtil.isBuffer(buf));
    this.bufs.push(buf);
    this.bufLen += buf.length;
    return this;
  }

  public writeReverse(buf) {
    assert(bufferUtil.isBuffer(buf));
    this.bufs.push(bufferUtil.reverse(buf));
    this.bufLen += buf.length;
    return this;
  }

  public writeUInt8(n) {
    const buf = Buffer.alloc(1);
    buf.writeUInt8(n, 0);
    this.write(buf);
    return this;
  }

  public writeUInt16BE(n) {
    const buf = Buffer.alloc(2);
    buf.writeUInt16BE(n, 0);
    this.write(buf);
    return this;
  }

  public writeUInt16LE(n) {
    const buf = Buffer.alloc(2);
    buf.writeUInt16LE(n, 0);
    this.write(buf);
    return this;
  }

  public writeUInt32BE(n) {
    const buf = Buffer.alloc(4);
    buf.writeUInt32BE(n, 0);
    this.write(buf);
    return this;
  }

  public writeInt32LE(n) {
    const buf = Buffer.alloc(4);
    buf.writeInt32LE(n, 0);
    this.write(buf);
    return this;
  }

  public writeUInt32LE(n) {
    const buf = Buffer.alloc(4);
    buf.writeUInt32LE(n, 0);
    this.write(buf);
    return this;
  }

  public writeUInt64BEBN(bn) {
    const buf = bn.toBuffer({ size: 8 });
    this.write(buf);
    return this;
  }

  public writeUInt64LEBN(bn) {
    const buf = bn.toBuffer({ size: 8 });
    this.writeReverse(buf);
    return this;
  }

  public writeVarintNum(n) {
    const buf = BufferWriter.varintBufNum(n);
    this.write(buf);
    return this;
  }

  public writeVarintBN(bn) {
    const buf = BufferWriter.varintBufBN(bn);
    this.write(buf);
    return this;
  }

  public static varintBufNum(n) {
    let buf;
    if (n < 253) {
      buf = Buffer.alloc(1);
      buf.writeUInt8(n, 0);
    } else if (n < 0x10000) {
      buf = Buffer.alloc(1 + 2);
      buf.writeUInt8(253, 0);
      buf.writeUInt16LE(n, 1);
    } else if (n < 0x100000000) {
      buf = Buffer.alloc(1 + 4);
      buf.writeUInt8(254, 0);
      buf.writeUInt32LE(n, 1);
    } else {
      buf = Buffer.alloc(1 + 8);
      buf.writeUInt8(255, 0);
      buf.writeInt32LE(n & -1, 1);
      buf.writeUInt32LE(Math.floor(n / 0x100000000), 5);
    }
    return buf;
  }

  public static varintBufBN(bn) {
    let buf;
    const n = bn.toNumber();
    if (n < 253) {
      buf = Buffer.alloc(1);
      buf.writeUInt8(n, 0);
    } else if (n < 0x10000) {
      buf = Buffer.alloc(1 + 2);
      buf.writeUInt8(253, 0);
      buf.writeUInt16LE(n, 1);
    } else if (n < 0x100000000) {
      buf = Buffer.alloc(1 + 4);
      buf.writeUInt8(254, 0);
      buf.writeUInt32LE(n, 1);
    } else {
      const bw = new BufferWriter();
      bw.writeUInt8(255);
      bw.writeUInt64LEBN(bn);
      buf = bw.concat();
    }
    return buf;
  }
}
