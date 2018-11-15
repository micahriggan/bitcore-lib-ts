import * as crypto from 'crypto';
import { BufferUtil } from '../util/buffer';
import $ from '../util/preconditions';

type HashFunctions = 'sha256' | 'sha512' | 'sha1';
const BlockSizes: { [fnName in HashFunctions]: number } = {
  sha1: 512,
  sha512: 1024,
  sha256: 512
};
export class Hash {
  public static sha1(buf) {
    $.checkArgument(BufferUtil.isBuffer(buf));
    return crypto
      .createHash('sha1')
      .update(buf)
      .digest();
  }

  public static sha256(buf) {
    $.checkArgument(BufferUtil.isBuffer(buf));
    return crypto
      .createHash('sha256')
      .update(buf)
      .digest();
  }

  public static sha256sha256(buf) {
    $.checkArgument(BufferUtil.isBuffer(buf));
    return Hash.sha256(Hash.sha256(buf));
  }

  public static ripemd160(buf) {
    $.checkArgument(BufferUtil.isBuffer(buf));
    return crypto
      .createHash('ripemd160')
      .update(buf)
      .digest();
  }

  public static sha256ripemd160(buf) {
    $.checkArgument(BufferUtil.isBuffer(buf));
    return Hash.ripemd160(Hash.sha256(buf));
  }

  public static sha512(buf) {
    $.checkArgument(BufferUtil.isBuffer(buf));
    return crypto
      .createHash('sha512')
      .update(buf)
      .digest();
  }

  public static hmac(hashFnName: HashFunctions, data: Buffer, key: Buffer) {
    // http://en.wikipedia.org/wiki/Hash-based_message_authentication_code
    // http://tools.ietf.org/html/rfc4868#section-2
    $.checkArgument(BufferUtil.isBuffer(data));
    $.checkArgument(BufferUtil.isBuffer(key));

    const hashFnBlockSize = BlockSizes[hashFnName];
    const hashf = Hash[hashFnName];
    $.checkArgument(hashFnBlockSize);

    const blocksize = hashFnBlockSize / 8;

    if (key.length > blocksize) {
      key = hashf(key);
    } else if (key.length < blocksize) {
      const fill = Buffer.alloc(blocksize);
      fill.fill(0);
      key.copy(fill);
      key = fill;
    }

    const o_key = Buffer.alloc(blocksize);
    o_key.fill(0x5c);

    const i_key = Buffer.alloc(blocksize);
    i_key.fill(0x36);

    const o_key_pad = Buffer.alloc(blocksize);
    const i_key_pad = Buffer.alloc(blocksize);
    for (let i = 0; i < blocksize; i++) {
      o_key_pad[i] = o_key[i] ^ key[i];
      i_key_pad[i] = i_key[i] ^ key[i];
    }

    return hashf(
      Buffer.concat([o_key_pad, hashf(Buffer.concat([i_key_pad, data]))])
    );
  }

  public static sha256hmac(data, key) {
    return Hash.hmac('sha256', data, key);
  }

  public static sha512hmac(data, key) {
    return Hash.hmac('sha512', data, key);
  }
}
