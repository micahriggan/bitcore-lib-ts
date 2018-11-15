'use strict';

import * as _ from 'lodash';
import { Base58 } from './base58';
import { Buffer } from 'buffer';
import { Hash } from '../crypto/hash';
const sha256sha256 = Hash.sha256sha256;

export class Base58Check {
  public buf: Buffer;

  constructor(obj) {
    if (!(this instanceof Base58Check)) {
      return new Base58Check(obj);
    }
    if (Buffer.isBuffer(obj)) {
      const buf = obj;
      this.fromBuffer(buf);
    } else if (typeof obj === 'string') {
      const str = obj;
      this.fromString(str);
    } else if (obj) {
      this.set(obj);
    }
  }

  public set(obj) {
    this.buf = obj.buf || this.buf || undefined;
    return this;
  }

  public static validChecksum(data, checksum) {
    if (_.isString(data)) {
      data = new Buffer(Base58.decode(data));
    }
    if (_.isString(checksum)) {
      checksum = new Buffer(Base58.decode(checksum));
    }
    if (!checksum) {
      checksum = data.slice(-4);
      data = data.slice(0, -4);
    }
    return (
      Base58Check.checksum(data).toString('hex') === checksum.toString('hex')
    );
  }

  public static decode(s) {
    if (typeof s !== 'string') {
      throw new Error('Input must be a string');
    }

    const buf = Buffer.from(Base58.decode(s));

    if (buf.length < 4) {
      throw new Error('Input string too short');
    }

    const data = buf.slice(0, -4);
    const csum = buf.slice(-4);

    const hash = sha256sha256(data);
    const hash4 = hash.slice(0, 4);

    if (csum.toString('hex') !== hash4.toString('hex')) {
      throw new Error('Checksum mismatch');
    }

    return data;
  }

  public static checksum(buffer) {
    return sha256sha256(buffer).slice(0, 4);
  }

  public static encode(buf) {
    if (!Buffer.isBuffer(buf)) {
      throw new Error('Input must be a buffer');
    }
    const checkedBuf = Buffer.alloc(buf.length + 4);
    const hash = Base58Check.checksum(buf);
    buf.copy(checkedBuf);
    hash.copy(checkedBuf, buf.length);
    return Base58.encode(checkedBuf);
  }

  public fromBuffer(buf) {
    this.buf = buf;
    return this;
  }

  public fromString(str) {
    const buf = Base58Check.decode(str);
    this.buf = buf;
    return this;
  }

  public toBuffer() {
    return this.buf;
  }

  public toString() {
    return Base58Check.encode(this.buf);
  }
}
