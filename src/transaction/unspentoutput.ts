'use strict';

import * as _ from 'lodash';
import $ from '../util/preconditions';
import { JSUtil } from '../util/js';

import { Script } from '../script';
import { Address } from '../address';
import { Unit } from '../unit';
import { BitcoreError } from '../errors';

export namespace UnspentOutput {
  export interface UnspentOutputObj {
    address?: string | Address;
    txId?: string;
    vout?: number;
    value?: number;
    scriptPubKey?: string;
    outputIndex?: number;
    amount?: number;
    satoshis?: number;
    script?: string | Script;
  }
}
/**
 * Represents an unspent output information: its script, associated amount and address,
 * transaction id and output index.
 *
 * @constructor
 * @param {object} data
 * @param {string} data.txid the previous transaction id
 * @param {string=} data.txId alias for `txid`
 * @param {number} data.vout the index in the transaction
 * @param {number=} data.outputIndex alias for `vout`
 * @param {string|Script} data.scriptPubKey the script that must be resolved to release the funds
 * @param {string|Script=} data.script alias for `scriptPubKey`
 * @param {number} data.amount amount of bitcoins associated
 * @param {number=} data.satoshis alias for `amount`, but expressed in satoshis (1 BTC = 1e8 satoshis)
 * @param {string|Address=} data.address the associated address to the script, if provided
 */
export class UnspentOutput {
  public address?: Address | string;
  public txId: string;
  public vout?: number;
  public scriptPubKey?: string;
  public amount?: number;
  public satoshis: number;
  public script?: Script;
  public outputIndex: number;
  constructor(data: UnspentOutput | UnspentOutput.UnspentOutputObj) {
    /* jshint maxcomplexity: 20 */
    /* jshint maxstatements: 20 */
    if (!(this instanceof UnspentOutput)) {
      return new UnspentOutput(data);
    } else {
      data = data as UnspentOutput.UnspentOutputObj;

      $.checkArgument(
        _.isObject(data),
        'Must provide an object from where to extract data'
      );
      const address = data.address ? new Address(data.address) : undefined;
      const txId = data.txId;
      if (!txId || !JSUtil.isHexaString(txId) || txId.length > 64) {
        // TODO: Use the errors library
        throw new BitcoreError('InvalidArgument', data);
      }
      const outputIndex = _.isUndefined(data.vout)
        ? data.outputIndex
        : data.vout;
      if (!_.isNumber(outputIndex)) {
        throw new Error('Invalid outputIndex, received ' + outputIndex);
      }
      $.checkArgument(
        !_.isUndefined(data.scriptPubKey) || !_.isUndefined(data.script),
        'Must provide the scriptPubKey for that output!'
      );
      const script = new Script(data.scriptPubKey || data.script);
      let amount = !_.isUndefined(data.amount)
        ? Unit.fromBTC(data.amount).toSatoshis()
        : data.satoshis;
      amount = amount || (data as UnspentOutput.UnspentOutputObj).value;
      $.checkArgument(amount, 'Must provide an amount for the output');
      $.checkArgument(_.isNumber(amount), 'Amount must be a number');
      JSUtil.defineImmutable(this, {
        address,
        txId,
        outputIndex,
        script,
        satoshis: amount
      });
    }
  }

  /**
   * Provide an informative output when displaying this object in the console
   * @returns string
   */
  public inspect() {
    return (
      '<UnspentOutput: ' +
      this.txId +
      ':' +
      this.outputIndex +
      ', satoshis: ' +
      this.satoshis +
      ', address: ' +
      this.address +
      '>'
    );
  }

  /**
   * String representation: just "txid:index"
   * @returns string
   */
  public toString() {
    return this.txId + ':' + this.outputIndex;
  }

  /**
   * Deserialize an UnspentOutput from an object
   * @param {object|string} data
   * @return UnspentOutput
   */
  public static fromObject(data) {
    return new UnspentOutput(data);
  }

  /**
   * Returns a plain object (no prototype or methods) with the associated info for this output
   * @return {object}
   */
  public toObject() {
    return {
      address: this.address ? this.address.toString() : undefined,
      txid: this.txId,
      vout: this.outputIndex,
      scriptPubKey: this.script.toBuffer().toString('hex'),
      amount: Unit.fromSatoshis(this.satoshis).toBTC()
    };
  }

  public toJSON = this.toObject;
}
