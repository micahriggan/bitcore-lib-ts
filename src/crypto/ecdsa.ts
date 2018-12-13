import { PublicKey } from '../publickey';
import { BufferUtil } from '../util';
import * as _ from 'lodash';
import $ from '../util/preconditions';
import { PrivateKey } from '../privatekey';
import { Signature } from './signature';
import { BitcoreBN } from './bn';
import { Point } from './point';
import { Random } from './random';
import { Hash } from './hash';

export namespace ECDSA {
  export interface ECDSAObj {
    hashbuf: string | Buffer;
    endian: string; // the endianness of hashbuf
    privkey: string;
    pubkey: string;
    sig: string | Signature;
    k: string;
    verified: boolean;
  }
}
export class ECDSA {
  public hashbuf: Buffer;
  public endian: 'big' | 'little'; // the endianness of hashbuf
  public privkey: PrivateKey;
  public pubkey: PublicKey;
  public sig: Signature;
  public k: BitcoreBN;
  public verified: boolean;

  constructor(obj?: Partial<ECDSA.ECDSAObj> | ECDSA) {
    if (!(this instanceof ECDSA)) {
      return new ECDSA(obj);
    }
    if (obj) {
      this.set(obj);
    }
  }

  /* jshint maxcomplexity: 9 */
  public set(obj) {
    this.hashbuf = obj.hashbuf || this.hashbuf;
    this.endian = obj.endian || this.endian; // the endianness of hashbuf
    this.privkey = obj.privkey || this.privkey;
    this.pubkey =
      obj.pubkey || (this.privkey ? this.privkey.publicKey : this.pubkey);
    this.sig = obj.sig || this.sig;
    this.k = obj.k || this.k;
    this.verified = obj.verified || this.verified;
    return this;
  }

  public privkey2pubkey() {
    this.pubkey = this.privkey.toPublicKey();
  }

  public calci() {
    for (let i = 0; i < 4; i++) {
      this.sig.i = i;
      let Qprime;
      try {
        Qprime = this.toPublicKey();
      } catch (e) {
        console.error(e);
        continue;
      }

      if (Qprime.point.eq(this.pubkey.point)) {
        this.sig.compressed = this.pubkey.compressed;
        return this;
      }
    }

    this.sig.i = undefined;
    throw new Error('Unable to find valid recovery factor');
  }

  public static fromString(str) {
    const obj = JSON.parse(str);
    return new ECDSA(obj);
  }

  public randomK() {
    const N = Point.getN();
    let k;
    do {
      k = BitcoreBN.fromBuffer(Random.getRandomBuffer(32));
    } while (!(k.lt(N) && k.gt(BitcoreBN.Zero)));
    this.k = k;
    return this;
  }

  // https://tools.ietf.org/html/rfc6979#section-3.2
  public deterministicK(badrs = 0) {
    /* jshint maxstatements: 25 */
    // if r or s were invalid when this function was used in signing,
    // we do not want to actually compute r, s here for efficiency, so,
    // we can increment badrs. explained at end of RFC 6979 section 3.2
    if (_.isUndefined(badrs)) {
      badrs = 0;
    }
    let v = Buffer.alloc(32);
    v.fill(0x01);
    let k = Buffer.alloc(32);
    k.fill(0x00);
    const x = this.privkey.bn.toBuffer({
      size: 32
    });
    const hashbuf =
      this.endian === 'little'
        ? BufferUtil.reverse(this.hashbuf)
        : this.hashbuf;
    k = Hash.sha256hmac(Buffer.concat([v, Buffer.from([0x00]), x, hashbuf]), k);
    v = Hash.sha256hmac(v, k);
    k = Hash.sha256hmac(Buffer.concat([v, Buffer.from([0x01]), x, hashbuf]), k);
    v = Hash.sha256hmac(v, k);
    v = Hash.sha256hmac(v, k);
    let T = BitcoreBN.fromBuffer(v);
    const N = Point.getN();

    // also explained in 3.2, we must ensure T is in the proper range (0, N)
    for (let i = 0; i < badrs || !(T.lt(N) && T.gt(BitcoreBN.Zero)); i++) {
      k = Hash.sha256hmac(Buffer.concat([v, Buffer.from([0x00])]), k);
      v = Hash.sha256hmac(v, k);
      v = Hash.sha256hmac(v, k);
      T = BitcoreBN.fromBuffer(v);
    }

    this.k = T;
    return this;
  }

  // Information about public key recovery:
  // https://bitcointalk.org/index.php?topic=6430.0
  // http://stackoverflow.com/questions/19665491/how-do-i-get-an-ecdsa-public-key-from-just-a-bitcoin-signature-sec1-4-1-6-k
  public toPublicKey() {
    /* jshint maxstatements: 25 */
    const i = this.sig.i;
    $.checkArgument(
      i === 0 || i === 1 || i === 2 || i === 3,
      new Error('i must be equal to 0, 1, 2, or 3')
    );

    const e = BitcoreBN.fromBuffer(this.hashbuf);
    const r = this.sig.r;
    const s = this.sig.s;

    // A set LSB signifies that the y-coordinate is odd
    const isYOdd = i & 1;

    // The more significant bit specifies whether we should use the
    // first or second candidate key.
    const isSecondKey = i >> 1;

    const n = Point.getN();
    const G = Point.getG();

    // 1.1 Let x = r + jn
    const x = isSecondKey ? r.add(n) : r;
    const R = Point.fromX(isYOdd, x);

    // 1.4 Check that nR is at infinity
    const nR = R.mul(n);

    if (!nR.isInfinity()) {
      throw new Error('nR is not a valid curve point');
    }

    // Compute -e from e
    const eNeg = e.neg().umod(n);

    // 1.6.1 Compute Q = r^-1 (sR - eG)
    // Q = r^-1 (sR + -eG)
    const rInv = r.invm(n);

    // var Q = R.multiplyTwo(s, G, eNeg).mul(rInv);
    const Q = R.mul(s)
      .add(G.mul(eNeg))
      .mul(rInv);

    const pubkey = PublicKey.fromPoint(Q, this.sig.compressed);

    return pubkey;
  }

  public sigError() {
    /* jshint maxstatements: 25 */
    if (!BufferUtil.isBuffer(this.hashbuf) || this.hashbuf.length !== 32) {
      return 'hashbuf must be a 32 byte buffer';
    }

    const r = this.sig.r;
    const s = this.sig.s;
    if (
      !(r.gt(BitcoreBN.Zero) && r.lt(Point.getN())) ||
      !(s.gt(BitcoreBN.Zero) && s.lt(Point.getN()))
    ) {
      return 'r and s not in range';
    }

    const e = BitcoreBN.fromBuffer(
      this.hashbuf,
      this.endian
        ? {
            endian: this.endian
          }
        : undefined
    );
    const n = Point.getN();
    const sinv = s.invm(n);
    const u1 = sinv.mul(e).umod(n);
    const u2 = sinv.mul(r).umod(n);

    const p = Point.getG().mulAdd(u1, this.pubkey.point, u2);
    if (p.isInfinity()) {
      return 'p is infinity';
    }

    if (
      p
        .getX()
        .umod(n)
        .cmp(r) !== 0
    ) {
      return 'Invalid signature';
    } else {
      return false;
    }
  }

  public static toLowS(s) {
    // enforce low s
    // see BIP 62, "low S values in signatures"
    if (
      s.gt(
        BitcoreBN.fromBuffer(
          Buffer.from(
            '7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0',
            'hex'
          )
        )
      )
    ) {
      s = Point.getN().sub(s);
    }
    return s;
  }

  public _findSignature(d, e): Signature.SignatureObj {
    const N = Point.getN();
    const G = Point.getG();
    // try different values of k until r, s are valid
    let badrs = 0;
    let k;
    let Q;
    let r;
    let s;
    do {
      if (!this.k || badrs > 0) {
        this.deterministicK(badrs);
      }
      badrs++;
      k = this.k;
      Q = G.mul(k);
      r = Q.x.umod(N);
      s = k
        .invm(N)
        .mul(e.add(d.mul(r)))
        .umod(N);
    } while (r.cmp(BitcoreBN.Zero) <= 0 || s.cmp(BitcoreBN.Zero) <= 0);

    s = ECDSA.toLowS(s);
    return {
      s,
      r
    };
  }

  public sign() {
    const hashbuf = this.hashbuf;
    const privkey = this.privkey;
    const d = privkey.bn;

    $.checkState(hashbuf && privkey && d, new Error('invalid parameters'));
    $.checkState(
      BufferUtil.isBuffer(hashbuf) && hashbuf.length === 32,
      new Error('hashbuf must be a 32 byte buffer')
    );

    const e = BitcoreBN.fromBuffer(
      hashbuf,
      this.endian
        ? {
            endian: this.endian
          }
        : undefined
    );

    const obj = this._findSignature(d, e);
    obj.compressed = this.pubkey.compressed;

    this.sig = new Signature(obj);
    return this;
  }

  public signRandomK() {
    this.randomK();
    return this.sign();
  }

  public toString() {
    const obj: Partial<ECDSA.ECDSAObj> = {};
    if (this.hashbuf) {
      obj.hashbuf = this.hashbuf.toString('hex');
    }
    if (this.privkey) {
      obj.privkey = this.privkey.toString();
    }
    if (this.pubkey) {
      obj.pubkey = this.pubkey.toString();
    }
    if (this.sig) {
      obj.sig = this.sig.toString();
    }
    if (this.k) {
      obj.k = this.k.toString();
    }
    return JSON.stringify(obj);
  }

  public verify() {
    this.verified = !this.sigError();
    return this;
  }

  public static sign(hashbuf: Buffer, privkey: PrivateKey, endian?: string) {
    return new ECDSA()
      .set({
        hashbuf,
        endian,
        privkey
      })
      .sign().sig;
  }

  public static verify(
    hashbuf: Buffer,
    sig: Signature,
    pubkey: PublicKey,
    endian?: string
  ) {
    return new ECDSA()
      .set({
        hashbuf,
        endian,
        sig,
        pubkey
      })
      .verify().verified;
  }
}
