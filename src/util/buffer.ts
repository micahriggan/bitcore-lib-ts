import { Buffer } from 'buffer';
import { JSUtil } from './js';
import $ from './preconditions';
import assert from 'assert';

const NULL_HASH_LENGTH = 32;
const MAX_256 = 0xff;
const ONE_BYTE = 8;
const TWO_BYTES = 16;
const THREE_BYTES = 24;

export class BufferUtil {
  /**
   * Fill a buffer with a value.
   *
   * @param {Buffer} buffer
   * @param {number} value
   * @return {Buffer}
   */
  public static fill(buffer: Buffer, value = 0): Buffer {
    $.checkArgumentType(buffer, 'Buffer', 'buffer');
    $.checkArgumentType(value, 'number', 'value');
    const length = buffer.length;
    for (let i = 0; i < length; i++) {
      buffer[i] = value;
    }
    return buffer;
  }

  /**
   * Return a copy of a buffer
   *
   * @param {Buffer} original
   * @return {Buffer}
   */
  public static copy(original: Buffer): Buffer {
    const buffer = Buffer.alloc(original.length);
    original.copy(buffer);
    return buffer;
  }

  /**
   * Returns true if the given argument is an instance of a buffer. Tests for
   * both node's Buffer and Uint8Array
   *
   * @param {*} arg
   * @return {boolean}
   */
  public static isBuffer(arg): boolean {
    return Buffer.isBuffer(arg) || arg instanceof Uint8Array;
  }

  /**
   * Returns a zero-filled byte array
   *
   * @param {number} bytes
   * @return {Buffer}
   */
  public static emptyBuffer(bytes: number): Buffer {
    $.checkArgumentType(bytes, 'number', 'bytes');
    const result = new Buffer(bytes);
    for (let i = 0; i < bytes; i++) {
      result.write('\0', i);
    }
    return result;
  }

  public static equal(a, b): boolean {
    if (a.length !== b.length) {
      return false;
    }
    const length = a.length;
    for (let i = 0; i < length; i++) {
      if (a[i] !== b[i]) {
        return false;
      }
    }
    return true;
  }
  public static equals = BufferUtil.equal;

  /**
   * Transforms a number from 0 to 255 into a Buffer of size 1 with that value
   *
   * @param {number} integer
   * @return {Buffer}
   */
  public static integerAsSingleByteBuffer(integer: number): Buffer {
    $.checkArgumentType(integer, 'number', 'integer');
    return new Buffer([integer & MAX_256]);
  }

  /**
   * Transform a 4-byte integer into a Buffer of length 4.
   *
   * @param {number} integer
   * @return {Buffer}
   */
  public static integerAsBuffer(integer: number): Buffer {
    $.checkArgumentType(integer, 'number', 'integer');
    const bytes = [];
    bytes.push((integer >> THREE_BYTES) & MAX_256);
    bytes.push((integer >> TWO_BYTES) & MAX_256);
    bytes.push((integer >> ONE_BYTE) & MAX_256);
    bytes.push(integer & MAX_256);
    return Buffer.from(bytes);
  }

  /**
   * Transform the first 4 values of a Buffer into a number, in little endian encoding
   *
   * @param {Buffer} buffer
   * @return {number}
   */
  public static integerFromBuffer(buffer: Buffer): number {
    $.checkArgumentType(buffer, 'Buffer', 'buffer');
    return (
      (buffer[0] << THREE_BYTES) |
      (buffer[1] << TWO_BYTES) |
      (buffer[2] << ONE_BYTE) |
      buffer[3]
    );
  }

  /**
   * Transforms the first byte of an array into a number ranging from -128 to 127
   * @param {Buffer} buffer
   * @return {number}
   */
  public static integerFromSingleByteBuffer(buffer): number {
    $.checkArgumentType(buffer, 'Buffer', 'buffer');
    return buffer[0];
  }

  /**
   * Transforms a buffer into a string with a number in hexa representation
   *
   * Shorthand for <tt>buffer.toString('hex')</tt>
   *
   * @param {Buffer} buffer
   * @return {string}
   */
  public static bufferToHex(buffer): string {
    $.checkArgumentType(buffer, 'Buffer', 'buffer');
    return buffer.toString('hex');
  }

  /**
   * Reverse a buffer
   * @param {Buffer} param
   * @return {Buffer}
   */
  public static reverse(param): Buffer {
    const ret = new Buffer(param.length);
    for (let i = 0; i < param.length; i++) {
      ret[i] = param[param.length - i - 1];
    }
    return ret;
  }

  /**
   * Transforms an hexa encoded string into a Buffer with binary values
   *
   * Shorthand for <tt>Buffer(string, 'hex')</tt>
   *
   * @param {string} string
   * @return {Buffer}
   */
  public static hexToBuffer(str: string): Buffer {
    assert(JSUtil.isHexa(str));
    return new Buffer(str, 'hex');
  }

  public static NULL_HASH = BufferUtil.fill(Buffer.alloc(NULL_HASH_LENGTH), 0);
  public static EMPTY_BUFFER = Buffer.alloc(0);
  /**
   * Concatenates a buffer
   *
   * Shortcut for <tt>Buffer.concat</tt>
   */
  public static concat = Buffer.concat;

  public static toBufferIfString(value: string | Buffer): Buffer {
    return typeof value === 'string'
      ? Buffer.from(value, 'hex')
      : (value as Buffer);
  }
}
