import * as _ from 'lodash';
import $ from '../util/preconditions';
import { JSUtil, BufferUtil } from '../util';
import { PublicKey } from '../publickey';
import { ERROR_TYPES, BitcoreError } from '../errors';
import { Signature } from '../crypto/signature';

export declare namespace TransactionSignature {
  export interface TransactionSignatureObj {
    publicKey: string;
    prevTxId: Buffer | string;
    outputIndex: number;
    inputIndex: number;
    signature: string | Signature;
    sigtype: number;
  }
}

/**
 * @desc
 * Wrapper around Signature with fields related to signing a transaction specifically
 *
 * @param {Object|string|TransactionSignature} arg
 * @constructor
 */
export class TransactionSignature extends Signature {
  public publicKey: PublicKey;
  public prevTxId: Buffer;
  public outputIndex: number;
  public inputIndex: number;
  public signature: Signature;
  public sigtype: number;

  constructor(arg: TransactionSignature | TransactionSignature.TransactionSignatureObj | string) {
    super();
    if (!(this instanceof TransactionSignature)) {
      return new TransactionSignature(arg);
    }
    if (arg instanceof TransactionSignature) {
      return arg;
    }
    if (_.isObject(arg)) {
      return this._fromObject(arg as TransactionSignature.TransactionSignatureObj);
    }
    throw new BitcoreError(
      ERROR_TYPES.InvalidArgument,
      'TransactionSignatures must be instantiated from an object'
    );
  }

  public _fromObject = function(
    arg: TransactionSignature.TransactionSignatureObj
  ) {
    this._checkObjectArgs(arg);
    this.publicKey = new PublicKey(arg.publicKey);
    this.prevTxId =
      typeof arg.prevTxId === 'string'
        ? Buffer.from(arg.prevTxId, 'hex')
        : arg.prevTxId;
    this.outputIndex = arg.outputIndex;
    this.inputIndex = arg.inputIndex;
    this.signature =
      arg.signature instanceof Signature
        ? arg.signature
        : BufferUtil.isBuffer(arg.signature)
          ? Signature.fromBuffer(arg.signature)
          : Signature.fromString(arg.signature);
    this.sigtype = arg.sigtype;
    return this;
  };

  public _checkObjectArgs(arg) {
    $.checkArgument(new PublicKey(arg.publicKey), 'publicKey');
    $.checkArgument(!_.isUndefined(arg.inputIndex), 'inputIndex');
    $.checkArgument(!_.isUndefined(arg.outputIndex), 'outputIndex');
    $.checkState(_.isNumber(arg.inputIndex), 'inputIndex must be a number');
    $.checkState(_.isNumber(arg.outputIndex), 'outputIndex must be a number');
    $.checkArgument(arg.signature, 'signature');
    $.checkArgument(arg.prevTxId, 'prevTxId');
    $.checkState(
      arg.signature instanceof Signature ||
        BufferUtil.isBuffer(arg.signature) ||
        JSUtil.isHexa(arg.signature),
      'signature must be a buffer or hexa value'
    );
    $.checkState(
      BufferUtil.isBuffer(arg.prevTxId) || JSUtil.isHexa(arg.prevTxId),
      'prevTxId must be a buffer or hexa value'
    );
    $.checkArgument(arg.sigtype, 'sigtype');
    $.checkState(_.isNumber(arg.sigtype), 'sigtype must be a number');
  }

  /**
   * Serializes a transaction to a plain JS object
   * @return {Object}
   */
  public toObject() {
    return {
      publicKey: this.publicKey.toString(),
      prevTxId: this.prevTxId.toString('hex'),
      outputIndex: this.outputIndex,
      inputIndex: this.inputIndex,
      signature: this.signature.toString(),
      sigtype: this.sigtype
    };
  }
  public toJSON = this.toObject;
  /**
   * Builds a TransactionSignature from an object
   * @param {Object} object
   * @return {TransactionSignature}
   */
  public static fromObject(object) {
    $.checkArgument(object);
    return new TransactionSignature(object);
  }
}
