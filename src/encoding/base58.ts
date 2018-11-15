import * as _ from 'lodash';
import { bs58 } from 'bs58';
import { Buffer } from 'buffer';

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'.split(
  ''
);

export class Base58 {
  public buf: Buffer;

  constructor(obj) {
    /* jshint maxcomplexity: 8 */
    if (!(this instanceof Base58)) {
      return new Base58(obj);
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

  public static validCharacters(chars) {
    if (Buffer.isBuffer(chars)) {
      chars = chars.toString();
    }
    return _.every(_.map(chars, char => _.includes(ALPHABET, char)));
  }

  public set(obj) {
    this.buf = obj.buf || this.buf || undefined;
    return this;
  }

  public static encode(buf) {
    if (!Buffer.isBuffer(buf)) {
      throw new Error('Input should be a buffer');
    }
    return bs58.encode(buf);
  }

  public static decode(str) {
    if (typeof str !== 'string') {
      throw new Error('Input should be a string');
    }
    return Buffer.from(bs58.decode(str));
  }

  public fromBuffer(buf) {
    this.buf = buf;
    return this;
  }

  public fromString(str) {
    const buf = Base58.decode(str);
    this.buf = buf;
    return this;
  }

  public toBuffer() {
    return this.buf;
  }

  public toString() {
    return Base58.encode(this.buf);
  }
}
