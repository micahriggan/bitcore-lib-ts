'use strict';

import * as _ from 'lodash';
import { URL, parse, format } from 'url';
import { Address } from './address';
import { Unit } from './unit';
import { Network } from './networks';

export namespace URI {
  export type URIObj = {
    amount: number;
    message: string;
    label: string;
    r: number;
  };
}
/**
 * Bitcore URI
 *
 * Instantiate an URI from a bitcoin URI String or an Object. An URI instance
 * can be created with a bitcoin uri string or an object. All instances of
 * URI are valid, the static method isValid allows checking before instantiation.
 *
 * All standard parameters can be found as members of the class, the address
 * is represented using an {Address} instance and the amount is represented in
 * satoshis. Any other non-standard parameters can be found under the extra member.
 *
 * @example
 * ```javascript
 *
 * var uri = new URI('bitcoin:12A1MyfXbW6RhdRAZEqofac5jCQQjwEPBu?amount=1.2');
 * console.log(uri.address, uri.amount);
 * ```
 *
 * @param {string|Object} data - A bitcoin URI string or an Object
 * @param {Array.<string>=} knownParams - Required non-standard params
 * @throws {TypeError} Invalid bitcoin address
 * @throws {TypeError} Invalid amount
 * @throws {Error} Unknown required argument
 * @returns {URI} A new valid and frozen instance of URI
 * @constructor
 */
export class URI {
  amount: number;
  message: string;
  label: string;
  r: number;
  extras = {};
  knownParams: string[];
  address: Address;
  network: Network;

  constructor(data, knownParams?) {
    if (!(this instanceof URI)) {
      return new URI(data, knownParams);
    }

    this.extras = {};
    this.knownParams = knownParams || [];
    this.address = this.network = this.amount = this.message = null;

    if (typeof data === 'string') {
      var params = URI.parse(data);
      if (params.amount) {
        params.amount = this._parseAmount(params.amount);
      }
      this._fromObject(params);
    } else if (typeof data === 'object') {
      this._fromObject(data);
    } else {
      throw new TypeError('Unrecognized data format.');
    }
  }

  /**
   * Instantiate a URI from a String
   *
   * @param {string} str - JSON string or object of the URI
   * @returns {URI} A new instance of a URI
   */
  public static fromString(str) {
    if (typeof str !== 'string') {
      throw new TypeError('Expected a string');
    }
    return new URI(str);
  }

  /**
   * Instantiate a URI from an Object
   *
   * @param {Object} data - object of the URI
   * @returns {URI} A new instance of a URI
   */
  public static fromObject(json) {
    return new URI(json);
  }

  /**
   * Check if an bitcoin URI string is valid
   *
   * @example
   * ```javascript
   *
   * var valid = public static isValid('bitcoin:12A1MyfXbW6RhdRAZEqofac5jCQQjwEPBu');
   * // true
   * ```
   *
   * @param {string|Object} data - A bitcoin URI string or an Object
   * @param {Array.<string>=} knownParams - Required non-standard params
   * @returns {boolean} Result of uri validation
   */
  public static isValid(arg, knownParams) {
    try {
      new URI(arg, knownParams);
    } catch (err) {
      return false;
    }
    return true;
  }

  /**
   * Convert a bitcoin URI string into a simple object.
   *
   * @param {string} uri - A bitcoin URI string
   * @throws {TypeError} Invalid bitcoin URI
   * @returns {Object} An object with the parsed params
   */
  public static parse(uri) {
    var info = parse(uri, true);

    if (info.protocol !== 'bitcoin:') {
      throw new TypeError('Invalid bitcoin URI');
    }

    // workaround to host insensitiveness
    var group = /[^:]*:\/?\/?([^?]*)/.exec(uri);
    info.query.address = (group && group[1]) || undefined;

    return info.query;
  }

  public static Members = ['address', 'amount', 'message', 'label', 'r'];

  /**
   * Internal function to load the URI instance with an object.
   *
   * @param {Object} obj - Object with the information
   * @throws {TypeError} Invalid bitcoin address
   * @throws {TypeError} Invalid amount
   * @throws {Error} Unknown required argument
   */
  public _fromObject(obj) {
    /* jshint maxcomplexity: 10 */

    if (!Address.isValid(obj.address)) {
      throw new TypeError('Invalid bitcoin address');
    }

    this.address = new Address(obj.address);
    this.network = this.address.network;
    this.amount = obj.amount;

    for (var key in obj) {
      if (key === 'address' || key === 'amount') {
        continue;
      }

      if (/^req-/.exec(key) && this.knownParams.indexOf(key) === -1) {
        throw Error('Unknown required argument ' + key);
      }

      var destination = URI.Members.indexOf(key) > -1 ? this : this.extras;
      destination[key] = obj[key];
    }
  }

  /**
   * Internal function to transform a BTC string amount into satoshis
   *
   * @param {string} amount - Amount BTC string
   * @throws {TypeError} Invalid amount
   * @returns {Object} Amount represented in satoshis
   */
  public _parseAmount(amount) {
    amount = Number(amount);
    if (isNaN(amount)) {
      throw new TypeError('Invalid amount');
    }
    return Unit.fromBTC(amount).toSatoshis();
  }

  public toObject = function toObject() {
    var json = {};
    for (var i = 0; i < URI.Members.length; i++) {
      var m = URI.Members[i];
      if (this.hasOwnProperty(m) && typeof this[m] !== 'undefined') {
        json[m] = this[m].toString();
      }
    }
    _.extend(json, this.extras);
    return json;
  };
  public toJSON = this.toObject;
  /**
   * Will return a the string representation of the URI
   *
   * @returns {string} Bitcoin URI string
   */
  public toString() {
    var query = {} as URI.URIObj;
    if (this.amount) {
      query.amount = Unit.fromSatoshis(this.amount).toBTC();
    }
    if (this.message) {
      query.message = this.message;
    }
    if (this.label) {
      query.label = this.label;
    }
    if (this.r) {
      query.r = this.r;
    }
    _.extend(query, this.extras);

    return format({
      protocol: 'bitcoin:',
      host: this.address.toString(),
      query: query
    });
  }

  /**
   * Will return a string formatted for the console
   *
   * @returns {string} Bitcoin URI
   */
  public inspect() {
    return '<URI: ' + this.toString() + '>';
  }
}

module.exports = URI;
