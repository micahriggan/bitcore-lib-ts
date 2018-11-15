import { ERROR_TYPES } from '../../errors/spec';
import * as _ from 'lodash';
import BN from 'bn.js';
import $ from '../../util/preconditions';
import { BitcoreError } from '../../errors';
import { BufferWriter } from '../../encoding/bufferwriter';
import { Buffer } from 'buffer';
import { BufferUtil } from '../../util/buffer';
import { JSUtil } from '../../util/js';
import { Script } from '../../script';
import { sighash, Sighash } from '../sighash';
import { Output } from '../output';
import { Transaction } from '../transaction';
import { Signature } from '../../crypto/signature';
import { TransactionSignature } from '../signature';
import { PublicKey } from '../../publickey';

const MAXINT = 0xffffffff; // Math.pow(2, 32) - 1;
const DEFAULT_RBF_SEQNUMBER = MAXINT - 2;
const DEFAULT_SEQNUMBER = MAXINT;
const DEFAULT_LOCKTIME_SEQNUMBER = MAXINT - 1;

export namespace Input {
  export interface InputObj {
    prevTxId?: string | Buffer;
    txidbuf?: Buffer;
    outputIndex?: number;
    sequenceNumber?: number;
    script?: string | Script;
    output?: Output.OutputObj;
    txoutnum?: number;
    seqnum?: number;
    scriptBuffer?: Buffer;
    scriptString?: string;
  }
}
export class Input {
  public static MAXINT = MAXINT;
  public static DEFAULT_SEQNUMBER = DEFAULT_SEQNUMBER;
  public static DEFAULT_LOCKTIME_SEQNUMBER = DEFAULT_LOCKTIME_SEQNUMBER;
  public static DEFAULT_RBF_SEQNUMBER = DEFAULT_RBF_SEQNUMBER;

  public _scriptBuffer: Buffer;
  public _script: Script;
  public _satoshis: number;
  public _satoshisBN: BN;
  public witnesses: Array<string>;
  public output: Output;
  public prevTxId: Buffer;
  public outputIndex: number;
  public sequenceNumber: number;

  constructor(
    input?: Input.InputObj,
    pubkeys?: Array<PublicKey>,
    threshold?: number,
    signatures?: Array<Signature>,
    nestedWitness?: boolean
  ) {
    if (!(this instanceof Input)) {
      return new Input(input, pubkeys, threshold, signatures, nestedWitness);
    }
    if (input) {
      return this._fromObject(input);
    }
  }

  public get script() {
    if (this.isNull()) {
      return null;
    }
    if (!this._script) {
      this._script = new Script(this._scriptBuffer);
      this._script._isInput = true;
    }
    return this._script;
  }

  public static fromObject(obj) {
    $.checkArgument(_.isObject(obj));
    const input = new Input();
    return input._fromObject(obj);
  }

  public _fromObject(params: Input.InputObj) {
    let prevTxId;
    if (_.isString(params.prevTxId) && JSUtil.isHexa(params.prevTxId)) {
      prevTxId = new Buffer(params.prevTxId, 'hex');
    } else {
      prevTxId = params.prevTxId;
    }
    this.witnesses = [];
    this.output = params.output
      ? params.output instanceof Output
        ? params.output
        : new Output(params.output)
      : undefined;
    this.prevTxId = prevTxId || params.txidbuf;
    this.outputIndex = _.isUndefined(params.outputIndex)
      ? params.txoutnum
      : params.outputIndex;
    this.sequenceNumber = _.isUndefined(params.sequenceNumber)
      ? _.isUndefined(params.seqnum)
        ? DEFAULT_SEQNUMBER
        : params.seqnum
      : params.sequenceNumber;
    if (_.isUndefined(params.script) && _.isUndefined(params.scriptBuffer)) {
      throw new BitcoreError(
        ERROR_TYPES.Transaction.errors.Input.errors.MissingScript
      );
    }
    this.setScript(params.scriptBuffer || params.script);
    return this;
  }

  public toObject() {
    const obj: Input.InputObj = {
      prevTxId: this.prevTxId.toString('hex'),
      outputIndex: this.outputIndex,
      sequenceNumber: this.sequenceNumber,
      script: this._scriptBuffer.toString('hex')
    };
    // add human readable form if input contains valid script
    if (this.script) {
      obj.scriptString = this.script.toString();
    }
    if (this.output) {
      obj.output = this.output.toObject();
    }
    return obj;
  }

  public toJSON = this.toObject;

  public static fromBufferReader(br) {
    const input = new Input();
    input.prevTxId = br.readReverse(32);
    input.outputIndex = br.readUInt32LE();
    input._scriptBuffer = br.readVarLengthBuffer();
    input.sequenceNumber = br.readUInt32LE();
    // TODO: return different classes according to which input it is
    // e.g: CoinbaseInput, PublicKeyHashInput, MultiSigScriptHashInput, etc.
    return input;
  }

  public toBufferWriter(writer?: BufferWriter) {
    if (!writer) {
      writer = new BufferWriter();
    }
    writer.writeReverse(this.prevTxId);
    writer.writeUInt32LE(this.outputIndex);
    const script = this._scriptBuffer;
    writer.writeVarintNum(script.length);
    writer.write(script);
    writer.writeUInt32LE(this.sequenceNumber);
    return writer;
  }

  public setScript(script: Script | string | Buffer) {
    this._script = null;
    if (script instanceof Script) {
      this._script = script;
      this._script._isInput = true;
      this._scriptBuffer = script.toBuffer();
    } else if (JSUtil.isHexa(script) && typeof script === 'string') {
      // hex string script
      this._scriptBuffer = new Buffer(script, 'hex');
    } else if (_.isString(script)) {
      // human readable string script
      this._script = new Script(script);
      this._script._isInput = true;
      this._scriptBuffer = this._script.toBuffer();
    } else if (BufferUtil.isBuffer(script)) {
      // buffer script
      this._scriptBuffer = new Buffer(script);
    } else {
      throw new TypeError('Invalid argument type: script');
    }
    return this;
  }

  /**
   * Retrieve signatures for the provided PrivateKey.
   *
   * @param {Transaction} transaction - the transaction to be signed
   * @param {PrivateKey} privateKey - the private key to use when signing
   * @param {number} inputIndex - the index of this input in the provided transaction
   * @param {number} sigType - defaults to Signature.SIGHASH_ALL
   * @param {Buffer} addressHash - if provided, don't calculate the hash of the
   *     public key associated with the private key provided
   * @abstract
   */
  /*
   *public getSignatures(): Array<TransactionSignature> {
   *  throw new errors.AbstractMethodInvoked(
   *    'Trying to sign unsupported output type (only P2PKH and P2SH multisig inputs are supported)' +
   *      ' for input: ' +
   *      JSON.stringify(this)
   *  );
   *}
   */

  public getSatoshisBuffer() {
    $.checkState(
      this.output instanceof Output,
      'output property should be an Output'
    );
    $.checkState(
      this.output._satoshisBN,
      'output._satoshisBN property should be a BigNum'
    );
    return new BufferWriter()
      .writeUInt64LEBN(this.output._satoshisBN)
      .toBuffer();
  }

  /*
   *public isFullySigned() {
   *  throw new errors.AbstractMethodInvoked('Input#isFullySigned');
   *}
   */

  public isFinal() {
    return this.sequenceNumber !== 4294967295;
  }
  /*
   *
   *  public addSignature() {
   *    throw new errors.AbstractMethodInvoked('Input#addSignature');
   *  }
   *
   *  public clearSignatures() {
   *    throw new errors.AbstractMethodInvoked('Input#clearSignatures');
   *  }
   *
   */
  public hasWitnesses() {
    if (this.witnesses && this.witnesses.length > 0) {
      return true;
    }
    return false;
  }

  public getWitnesses() {
    return this.witnesses;
  }

  public setWitnesses(witnesses) {
    this.witnesses = witnesses;
  }

  public isValidSignature(
    transaction: Transaction,
    signature: TransactionSignature
  ) {
    // FIXME: Refactor signature so this is not necessary
    signature.signature.nhashtype = signature.sigtype;
    return Sighash.verify(
      transaction,
      signature.signature,
      signature.publicKey,
      signature.inputIndex,
      this.output.script
    );
  }

  /**
   * @returns true if this is a coinbase input (represents no input)
   */
  public isNull() {
    return (
      this.prevTxId.toString('hex') ===
        '0000000000000000000000000000000000000000000000000000000000000000' &&
      this.outputIndex === 0xffffffff
    );
  }

  public _estimateSize() {
    return this.toBufferWriter().toBuffer().length;
  }
}

module.exports = Input;
