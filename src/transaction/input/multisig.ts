import $ from '../../util/preconditions';
import * as _ from 'lodash';
import { Transaction } from '../transaction';
import { Input } from './input';
import { Output } from '../output';
import { Script } from '../../script';
import { Signature } from '../../crypto/signature';
import { sighash, Sighash } from '../sighash';
import { PublicKey } from '../../publickey';
import { BufferUtil } from '../../util/buffer';
import { TransactionSignature } from '../signature';
import { PrivateKey } from '../../privatekey';

/**
 * @constructor
 */
export class MultiSigInput extends Input {
  public static OPCODES_SIZE = 1; // 0
  public static SIGNATURE_SIZE = 73; // size (1) + DER (<=72)

  public nestedWitness: boolean;
  public publicKeys: Array<PublicKey>;
  public redeemScript: Script;
  public output: Output;
  public threshold: number;
  public signatures: Array<TransactionSignature>;
  public publicKeyIndex = {};

  constructor(input, pubkeys, threshold, signatures) {
    super();
    Input.apply(this, arguments);
    const self = this;
    pubkeys = pubkeys || input.publicKeys;
    threshold = threshold || input.threshold;
    signatures = signatures || input.signatures;
    this.publicKeys = _.sortBy(pubkeys, function(publicKey) {
      return publicKey.toString('hex');
    });
    $.checkState(
      Script.buildMultisigOut(this.publicKeys, threshold).equals(
        this.output.script
      ),
      "Provided public keys don't match to the provided output script"
    );
    this.publicKeyIndex = {};
    _.each(this.publicKeys, function(publicKey, index) {
      self.publicKeyIndex[publicKey.toString()] = index;
    });
    this.threshold = threshold;
    // Empty array of signatures
    this.signatures = signatures
      ? this._deserializeSignatures(signatures)
      : new Array(this.publicKeys.length);
  }

  public toObject() {
    const obj = Input.prototype.toObject.apply(this, arguments);
    obj.threshold = this.threshold;
    obj.publicKeys = _.map(this.publicKeys, function(publicKey) {
      return publicKey.toString();
    });
    obj.signatures = this._serializeSignatures();
    return obj;
  }

  public _deserializeSignatures(signatures) {
    return _.map(signatures, function(signature) {
      if (!signature) {
        return undefined;
      }
      return new TransactionSignature(signature);
    });
  }

  public _serializeSignatures() {
    return _.map(this.signatures, function(signature) {
      if (!signature) {
        return undefined;
      }
      return signature.toObject();
    });
  }

  public getSignatures(
    transaction: Transaction,
    privateKey: PrivateKey,
    index: number,
    sigtype: number,
    hashData: Buffer
  ): Array<TransactionSignature> {
    $.checkState(
      this.output instanceof Output,
      'output property should be an Output'
    );
    sigtype = sigtype || Signature.SIGHASH_ALL;

    const self = this;
    const results = [];
    _.each(this.publicKeys, function(publicKey) {
      if (publicKey.toString() === privateKey.publicKey.toString()) {
        results.push(
          new TransactionSignature({
            publicKey: privateKey.publicKey,
            prevTxId: self.prevTxId,
            outputIndex: self.outputIndex,
            inputIndex: index,
            signature: Sighash.sign(
              transaction,
              privateKey,
              sigtype,
              index,
              self.output.script
            ),
            sigtype
          })
        );
      }
    });

    return results;
  }

  public addSignature(
    transaction: Transaction,
    signature: TransactionSignature
  ) {
    $.checkState(
      !this.isFullySigned(),
      'All needed signatures have already been added'
    );
    $.checkArgument(
      !_.isUndefined(this.publicKeyIndex[signature.publicKey.toString()]),
      'Signature has no matching public key'
    );
    $.checkState(
      this.isValidSignature(transaction, signature),
      'Signature must be valid'
    );
    this.signatures[
      this.publicKeyIndex[signature.publicKey.toString()]
    ] = signature;
    this._updateScript();
    return this;
  }

  public _updateScript() {
    this.setScript(
      Script.buildMultisigIn(
        this.publicKeys,
        this.threshold,
        this._createSignatures()
      )
    );
    return this;
  }

  public _createSignatures() {
    return _.map(
      _.filter(this.signatures, function(signature) {
        return !_.isUndefined(signature);
      }),
      function(signature) {
        return BufferUtil.concat([
          signature.signature.toDER(),
          BufferUtil.integerAsSingleByteBuffer(signature.sigtype)
        ]);
      }
    );
  }

  public clearSignatures() {
    this.signatures = new Array(this.publicKeys.length);
    this._updateScript();
  }

  public isFullySigned() {
    return this.countSignatures() === this.threshold;
  }

  public countMissingSignatures() {
    return this.threshold - this.countSignatures();
  }

  public countSignatures() {
    return _.reduce(
      this.signatures,
      function(sum, signature) {
        return sum + (!!signature ? 1 : 0);
      },
      0
    );
  }

  public publicKeysWithoutSignature() {
    const self = this;
    return _.filter(this.publicKeys, function(publicKey) {
      return !self.signatures[self.publicKeyIndex[publicKey.toString()]];
    });
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
   *
   * @param {Buffer[]} signatures
   * @param {PublicKey[]} publicKeys
   * @param {Transaction} transaction
   * @param {Integer} inputIndex
   * @param {Input} input
   * @returns {TransactionSignature[]}
   */
  public static normalizeSignatures(
    transaction,
    input,
    inputIndex,
    signatures,
    publicKeys
  ) {
    return publicKeys.map(function(pubKey) {
      let signatureMatch = null;
      signatures = signatures.filter(function(signatureBuffer) {
        if (signatureMatch) {
          return true;
        }

        const signature = new TransactionSignature({
          signature: Signature.fromTxFormat(signatureBuffer),
          publicKey: pubKey,
          prevTxId: input.prevTxId,
          outputIndex: input.outputIndex,
          inputIndex,
          sigtype: Signature.SIGHASH_ALL
        });

        signature.signature.nhashtype = signature.sigtype;
        const isMatch = Sighash.verify(
          transaction,
          signature.signature,
          signature.publicKey,
          signature.inputIndex,
          input.output.script
        );

        if (isMatch) {
          signatureMatch = signature;
          return false;
        }

        return true;
      });

      return signatureMatch ? signatureMatch : null;
    });
  }

  public _estimateSize() {
    return (
      MultiSigInput.OPCODES_SIZE + this.threshold * MultiSigInput.SIGNATURE_SIZE
    );
  }
}
module.exports = MultiSigInput;
