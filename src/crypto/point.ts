import { BitcoreBN } from '.';
import { BufferUtil } from '../util/buffer';
import { ec, curve } from 'elliptic';
import BN from 'bn.js';
const secp256k1 = new ec('secp256k1');
const curveInstance = secp256k1.curve as Curve;
const ecPointFromX = curveInstance.pointFromX.bind(secp256k1.curve);

declare class EcPoint {
  public validate(): void;
  public isInfinity(): boolean;
  public mul(num: BitcoreBN): EcPoint;
  public pointFromX(x: number, isOdd: boolean): EcPoint;
  public y: BN;
  public x: BN;                    
  public dblp(k: number):EcPoint;
  public encode(encoding: string, compressed: boolean): BN
  public encodeCompressed(compressed: boolean): BN
  public eq(other: EcPoint);
  public precompute(power: number): EcPoint;
}

interface PointConstructor {
  new (x: number, y: number, isRed: boolean): EcPoint;
}
declare class Curve {
  public pointFromX(x: number, odd: boolean): Point;
  public validate(): boolean;
  public point: PointConstructor;
}

/**
 *
 * Instantiate a valid secp256k1 Point from the X and Y coordinates.
 *
 * @param {BN|String} x - The X coordinate
 * @param {BN|String} y - The Y coordinate
 * @link https://github.com/indutny/elliptic
 * @augments elliptic.curve.point
 * @throws {Error} A validation error if exists
 * @returns {Point} An instance of Point
 * @constructor
 */
export class Point extends curveInstance.point {
  public point: any;
  constructor(x, y, isRed = false) {
    super(x, y, isRed);
    try {
      super.validate();
      this.validate();
    } catch (e) {
      throw new Error('Invalid Point');
    }
  }

  /**
   *
   * Instantiate a valid secp256k1 Point from only the X coordinate
   *
   * @param {boolean} odd - If the Y coordinate is odd
   * @param {BN|String} x - The X coordinate
   * @throws {Error} A validation error if exists
   * @returns {Point} An instance of Point
   */
  public static fromX(odd, x) {
    try {
      const point = ecPointFromX(x, odd);
      point.validate();
      return point;
    } catch (e) {
      throw new Error('Invalid X');
    }
  }

  /**
   *
   * Will return a secp256k1 ECDSA base point.
   *
   * @link https://en.bitcoin.it/wiki/Secp256k1
   * @returns {Point} An instance of the base point.
   */
  public static getG() {
    return secp256k1.curve.g;
  }

  /**
   *
   * Will return the max of range of valid private keys as governed by the secp256k1 ECDSA standard.
   *
   * @link https://en.bitcoin.it/wiki/Private_key#Range_of_valid_ECDSA_private_keys
   * @returns {BN} A BN instance of the number of points on the curve
   */
  public static getN = function getN() {
    return new BitcoreBN(secp256k1.curve.n.toArray());
  };

  public _getX = this.getX;

  /**
   *
   * Will return the X coordinate of the Point
   *
   * @returns {BN} A BN instance of the X coordinate
   */
  public getX() {
    return new BitcoreBN(this._getX().toArray());
  }

  public _getY = this.getY;

  /**
   *
   * Will return the Y coordinate of the Point
   *
   * @returns {BN} A BN instance of the Y coordinate
   */
  public getY() {
    return new BitcoreBN(this._getY().toArray());
  }

  /**
   *
   * Will determine if the point is valid
   *
   * @link https://www.iacr.org/archive/pkc2003/25670211/25670211.pdf
   * @param {Point} An instance of Point
   * @throws {Error} A validation error if exists
   * @returns {Point} An instance of the same Point
   */
  public validate() {
    if (this.isInfinity()) {
      throw new Error('Point cannot be equal to Infinity');
    }

    let p2;
    try {
      p2 = this.pointFromX(this.getX(), this.getY().isOdd());
    } catch (e) {
      throw new Error('Point does not lie on the curve');
    }

    if (p2.y.cmp(this.y) !== 0) {
      throw new Error('Invalid y value for curve.');
    }

    // todo: needs test case
    if (!this.mul(Point.getN()).isInfinity()) {
      throw new Error('Point times N must be infinity');
    }

    return this;
  }

  public static pointToCompressed(point) {
    const xbuf = point.getX().toBuffer({ size: 32 });
    const ybuf = point.getY().toBuffer({ size: 32 });

    const odd = ybuf[ybuf.length - 1] % 2;
    const prefix = odd ? Buffer.from([0x03]) : Buffer.from([0x02]);
    return BufferUtil.concat([prefix, xbuf]);
  }
}
