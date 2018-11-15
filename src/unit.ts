import * as _ from 'lodash';
import { BitcoreError } from './errors';
import $ from './util/preconditions';
import { ERROR_TYPES } from './errors/spec';

var UNITS = {
  BTC: [1e8, 8],
  mBTC: [1e5, 5],
  uBTC: [1e2, 2],
  bits: [1e2, 2],
  satoshis: [1, 0]
};
const UNIT_ERRORS = ERROR_TYPES.Unit.errors;
/**
 * Utility for handling and converting bitcoins units. The supported units are
 * BTC, mBTC, bits (also named uBTC) and satoshis. A unit instance can be created with an
 * amount and a unit code, or alternatively using static methods like {fromBTC}.
 * It also allows to be created from a fiat amount and the exchange rate, or
 * alternatively using the {fromFiat} static method.
 * You can consult for different representation of a unit instance using it's
 * {to} method, the fixed unit methods like {toSatoshis} or alternatively using
 * the unit accessors. It also can be converted to a fiat amount by providing the
 * corresponding BTC/fiat exchange rate.
 *
 * @example
 * ```javascript
 * var sats = Unit.fromBTC(1.3).toSatoshis();
 * var mili = Unit.fromBits(1.3).to(Unit.mBTC);
 * var bits = Unit.fromFiat(1.3, 350).bits;
 * var btc = new Unit(1.3, Unit.bits).BTC;
 * ```
 *
 * @param {Number} amount - The amount to be represented
 * @param {String|Number} code - The unit of the amount or the exchange rate
 * @returns {Unit} A new instance of an Unit
 * @constructor
 */
export class Unit {
  public get BTC() {
    return this.to([1e8, 8]);
  }

  public get mBTC() {
    return this.to([1e5, 5]);
  }

  public get uBTC() {
    return this.to([1e2, 2]);
  }

  public get bits() {
    return this.to([1e2, 2]);
  }

  public get satoshis() {
    return this.to([1, 0]);
  }

  _value: number;
  constructor(amount, code) {
    if (!(this instanceof Unit)) {
      return new Unit(amount, code);
    }

    // convert fiat to BTC
    if (_.isNumber(code)) {
      if (code <= 0) {
        throw new BitcoreError(UNIT_ERRORS.InvalidRate, code);
      }
      amount = amount / code;
      code = this.BTC;
    }

    this._value = this._from(amount, code);

    var self = this;
    var defineAccesor = function(key) {
      Object.defineProperty(self, key, {
        get: function() {
          return this.to(key);
        },
        enumerable: true
      });
    };

    Object.keys(UNITS).forEach(defineAccesor);
  }

  /**
   * Returns a Unit instance created from JSON string or object
   *
   * @param {String|Object} json - JSON with keys: amount and code
   * @returns {Unit} A Unit instance
   */
  public static fromObject(data) {
    $.checkArgument(_.isObject(data), 'Argument is expected to be an object');
    return new Unit(data.amount, data.code);
  }

  /**
   * Returns a Unit instance created from an amount in BTC
   *
   * @param {Number} amount - The amount in BTC
   * @returns {Unit} A Unit instance
   */
  public static fromBTC(amount) {
    return new Unit(amount, UNITS.BTC);
  }

  /**
   * Returns a Unit instance created from an amount in mBTC
   *
   * @param {Number} amount - The amount in mBTC
   * @returns {Unit} A Unit instance
   */
  public static fromMilis(amount) {
    return new Unit(amount, UNITS.mBTC);
  }

  /**
   * Returns a Unit instance created from an amount in bits
   *
   * @param {Number} amount - The amount in bits
   * @returns {Unit} A Unit instance
   */
  public static fromMicros(amount) {
    return new Unit(amount, UNITS.bits);
  }

  public static fromBits = Unit.fromMicros;

  /**
   * Returns a Unit instance created from an amount in satoshis
   *
   * @param {Number} amount - The amount in satoshis
   * @returns {Unit} A Unit instance
   */
  public static fromSatoshis(amount) {
    return new Unit(amount, UNITS.satoshis);
  }

  /**
   * Returns a Unit instance created from a fiat amount and exchange rate.
   *
   * @param {Number} amount - The amount in fiat
   * @param {Number} rate - The exchange rate BTC/fiat
   * @returns {Unit} A Unit instance
   */
  public static fromFiat(amount, rate) {
    return new Unit(amount, rate);
  }

  public _from(amount, code) {
    if (!UNITS[code]) {
      throw new BitcoreError(UNIT_ERRORS.UnknownCode, code);
    }
    return parseInt((amount * UNITS[code][0]).toFixed());
  }

  /**
   * Returns the value represented in the specified unit
   *
   * @param {String|Number} code - The unit code or exchange rate
   * @returns {Number} The converted value
   */
  public to(code) {
    if (_.isNumber(code)) {
      if (code <= 0) {
        throw new BitcoreError(UNIT_ERRORS.InvalidRate, code);
      }
      return parseFloat((this.BTC * code).toFixed(2));
    }

    if (!UNITS[code]) {
      throw new BitcoreError(UNIT_ERRORS.UnknownCode, code);
    }

    var value = this._value / UNITS[code][0];
    return parseFloat(value.toFixed(UNITS[code][1]));
  }

  /**
   * Returns the value represented in BTC
   *
   * @returns {Number} The value converted to BTC
   */
  public toBTC() {
    return this.to(this.BTC);
  }

  /**
   * Returns the value represented in mBTC
   *
   * @returns {Number} The value converted to mBTC
   */
  public toMillis() {
    return this.to(this.mBTC);
  }

  public toMilis = this.toMillis;
  /**
   * Returns the value represented in bits
   *
   * @returns {Number} The value converted to bits
   */
  public toMicros() {
    return this.to(this.bits);
  }
  public toBits = this.toMicros;
  /**
   * Returns the value represented in satoshis
   *
   * @returns {Number} The value converted to satoshis
   */
  public toSatoshis() {
    return this.to(this.satoshis);
  }

  /**
   * Returns the value represented in fiat
   *
   * @param {string} rate - The exchange rate between BTC/currency
   * @returns {Number} The value converted to satoshis
   */
  public atRate(rate) {
    return this.to(rate);
  }

  /**
   * Returns a the string representation of the value in satoshis
   *
   * @returns {string} the value in satoshis
   */
  public toString() {
    return this.satoshis + ' satoshis';
  }

  /**
   * Returns a plain object representation of the Unit
   *
   * @returns {Object} An object with the keys: amount and code
   */
  public toObject() {
    return {
      amount: this.BTC,
      code: this.BTC
    };
  }

  public toJSON = this.toObject;

  /**
   * Returns a string formatted for the console
   *
   * @returns {string} the value in satoshis
   */
  public inspect() {
    return '<Unit: ' + this.toString() + '>';
  }
}
