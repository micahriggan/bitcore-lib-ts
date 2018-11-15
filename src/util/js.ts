'use strict';

import * as _ from 'lodash';

export class JSUtil {
  /**
   * Determines whether a string contains only hexadecimal values
   *
   * @name JSUtil.isHexa
   * @param {string} value
   * @return {boolean} true if the string is the hexa representation of a number
   */
  public static isHexa(value) {
    if (!_.isString(value)) {
      return false;
    }
    return /^[0-9a-fA-F]+$/.test(value);
  }

  public static isHexaString = JSUtil.isHexa;

  /**
   * @namespace JSUtil
   */
  /**
   * Test if an argument is a valid JSON object. If it is, returns a truthy
   * value (the json object decoded), so no double JSON.parse call is necessary
   *
   * @param {string} arg
   * @return {Object|boolean} false if the argument is not a JSON string.
   */
  public static isValidJSON(arg) {
    let parsed;
    if (!_.isString(arg)) {
      return false;
    }
    try {
      parsed = JSON.parse(arg);
    } catch (e) {
      return false;
    }
    if (typeof parsed === 'object') {
      return true;
    }
    return false;
  }

  /**
   * Clone an array
   */
  public static cloneArray(array) {
    return [].concat(array);
  }

  /**
   * Define immutable properties on a target object
   *
   * @param {Object} target - An object to be extended
   * @param {Object} values - An object of properties
   * @return {Object} The target object
   */
  public static defineImmutable(target, values) {
    Object.keys(values).forEach(key => {
      Object.defineProperty(target, key, {
        configurable: false,
        enumerable: true,
        value: values[key]
      });
    });
    return target;
  }
  /**
   * Checks that a value is a natural number, a positive integer or zero.
   *
   * @param {*} value
   * @return {Boolean}
   */
  public static isNaturalNumber(value) {
    return (
      typeof value === 'number' &&
      isFinite(value) &&
      Math.floor(value) === value &&
      value >= 0
    );
  }

  public static booleanToNumber(bool: boolean) {
    return bool ? 1 : 0;
  }
}
