'use strict';

import { BufferUtil } from '../util/buffer';
import assert from 'assert';
import { BitcoreBN } from '../crypto/bn';

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

  public set(obj: { bufs: Array<Uint8Array> }) {
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

  public write(buf: Buffer) {
    assert(BufferUtil.isBuffer(buf));
    this.bufs.push(buf);
    this.bufLen += buf.length;
    return this;
  }

  public writeReverse(buf: Buffer) {
    assert(BufferUtil.isBuffer(buf));
    this.bufs.push(BufferUtil.reverse(buf));
    this.bufLen += buf.length;
    return this;
  }

  public writeUInt8(n: number) {
    const buf = Buffer.alloc(1);
    buf.writeUInt8(n, 0);
    this.write(buf);
    return this;
  }

  public writeUInt16BE(n: number) {
    const buf = Buffer.alloc(2);
    buf.writeUInt16BE(n, 0);
    this.write(buf);
    return this;
  }

  public writeUInt16LE(n: number) {
    const buf = Buffer.alloc(2);
    buf.writeUInt16LE(n, 0);
    this.write(buf);
    return this;
  }

  public writeUInt32BE(n: number) {
    const buf = Buffer.alloc(4);
    buf.writeUInt32BE(n, 0);
    this.write(buf);
    return this;
  }

  public writeInt32LE(n: number) {
    const buf = Buffer.alloc(4);
    buf.writeInt32LE(n, 0);
    this.write(buf);
    return this;
  }

  public writeUInt32LE(n: number) {
    const buf = Buffer.alloc(4);
    buf.writeUInt32LE(n, 0);
    this.write(buf);
    return this;
  }

  public writeUInt64BEBN(bn: BitcoreBN) {
    const buf = bn.toBitcoreBuffer({ size: 8 });
    this.write(buf);
    return this;
  }

  public writeUInt64LEBN(bn) {
    const buf = bn.toBuffer({ size: 8 });
    this.writeReverse(buf);
    return this;
  }

  public writeVarintNum(n: number) {
    const buf = BufferWriter.varintBufNum(n);
    this.write(buf);
    return this;
  }

  public writeVarintBN(bn: BitcoreBN) {
    const buf = BufferWriter.varintBufBN(bn);
    this.write(buf);
    return this;
  }

  public static varintBufNum(n: number) {
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

  public static varintBufBN(bn: BitcoreBN) {
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
