'use strict';

/* jshint maxparams:5 */

import * as _ from 'lodash';
import { Input } from './input';
import { Output } from '../output';
import $ from '../../util/preconditions';

import { Script } from '../../script';
import { Signature } from '../../crypto/signature';
import { sighash, Sighash } from '../sighash';
import { SighashWitness } from '../sighashwitness';
import { BufferWriter } from '../../encoding/bufferwriter';
import { BufferUtil } from '../../util/buffer';
import { TransactionSignature } from '../signature';
import { PublicKey } from '../../publickey';
import { Transaction } from '../transaction';
import { PrivateKey } from '../../privatekey';
import { JSUtil } from '../../util/js';

/**
 * @constructor
 */
export class MultiSigScriptHashInput extends Input {
  public static OPCODES_SIZE = 7; // serialized size (<=3) + 0 .. N .. M OP_CHECKMULTISIG
  public static SIGNATURE_SIZE = 74; // size (1) + DER (<=72) + sighash (1)
  public static PUBKEY_SIZE = 34; // size (1) + DER (<=33)

  public nestedWitness: boolean;
  public publicKeys: Array<PublicKey>;
  public redeemScript: Script;
  public output: Output;
  public threshold: number;
  public signatures: Array<TransactionSignature>;
  public publicKeyIndex = {};

  constructor(
    input: MultiSigScriptHashInput,
    pubkeys: Array<PublicKey>,
    threshold: number,
    signatures: Array<Signature>,
    nestedWitness?: boolean
  ) {
    /* jshint maxstatements:20 */
    super();
    const self = this;
    pubkeys = pubkeys || input.publicKeys;
    threshold = threshold || input.threshold;
    signatures = signatures || input.signatures;
    this.nestedWitness = nestedWitness ? true : false;
    this.publicKeys = _.sortBy(pubkeys, function(publicKey) {
      return publicKey.toString();
    });
    this.redeemScript = Script.buildMultisigOut(this.publicKeys, threshold);
    if (this.nestedWitness) {
      const nested = Script.buildWitnessMultisigOutFromScript(
        this.redeemScript
      );
      $.checkState(
        Script.buildScriptHashOut(nested).equals(this.output.script),
        "Provided public keys don't hash to the provided output (nested witness)"
      );
      const scriptSig = new Script();
      scriptSig.add(nested.toBuffer());
      this.setScript(scriptSig);
    } else {
      $.checkState(
        Script.buildScriptHashOut(this.redeemScript).equals(this.output.script),
        "Provided public keys don't hash to the provided output"
      );
    }

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

  public getScriptCode() {
    const writer = new BufferWriter();
    if (!this.redeemScript.hasCodeseparators()) {
      const redeemScriptBuffer = this.redeemScript.toBuffer();
      writer.writeVarintNum(redeemScriptBuffer.length);
      writer.write(redeemScriptBuffer);
    } else {
      throw new Error('@TODO');
    }
    return writer.toBuffer();
  }

  public getSighash(transaction, privateKey, index, sigtype) {
    const self = this;
    let hash;
    if (self.nestedWitness) {
      const scriptCode = self.getScriptCode();
      const satoshisBuffer = self.getSatoshisBuffer();
      hash = SighashWitness.sighash(
        transaction,
        sigtype,
        index,
        scriptCode,
        satoshisBuffer
      );
    } else {
      hash = Sighash.sighash(transaction, sigtype, index, self.redeemScript);
    }
    return hash;
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
      'output property must be an Output'
    );
    sigtype = sigtype || Signature.SIGHASH_ALL;

    const self = this;
    const results = [];
    _.each(this.publicKeys, function(publicKey) {
      if (publicKey.toString() === privateKey.publicKey.toString()) {
        let signature;
        if (self.nestedWitness) {
          const scriptCode = self.getScriptCode();
          const satoshisBuffer = self.getSatoshisBuffer();
          signature = SighashWitness.sign(
            transaction,
            privateKey,
            sigtype,
            index,
            scriptCode,
            satoshisBuffer
          );
        } else {
          signature = Sighash.sign(
            transaction,
            privateKey,
            sigtype,
            index,
            self.redeemScript
          );
        }
        results.push(
          new TransactionSignature({
            publicKey: privateKey.publicKey,
            prevTxId: self.prevTxId,
            outputIndex: self.outputIndex,
            inputIndex: index,
            signature,
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
      'Must have a valid signature'
    );
    this.signatures[
      this.publicKeyIndex[signature.publicKey.toString()]
    ] = signature;
    this._updateScript();
    return this;
  }

  public _updateScript() {
    if (this.nestedWitness) {
      const stack = [new Buffer(0)];
      const signatures = this._createSignatures();
      for (let i = 0; i < signatures.length; i++) {
        stack.push(signatures[i]);
      }
      stack.push(this.redeemScript.toBuffer());
      this.setWitnesses(stack);
    } else {
      const scriptSig = Script.buildP2SHMultisigIn(
        this.publicKeys,
        this.threshold,
        this._createSignatures(),
        { cachedMultisig: this.redeemScript }
      );
      this.setScript(scriptSig);
    }
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
        return sum + JSUtil.booleanToNumber(!!signature);
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
    if (this.nestedWitness) {
      signature.signature.nhashtype = signature.sigtype;
      const scriptCode = this.getScriptCode();
      const satoshisBuffer = this.getSatoshisBuffer();
      return SighashWitness.verify(
        transaction,
        signature.signature,
        signature.publicKey,
        signature.inputIndex,
        scriptCode,
        satoshisBuffer
      );
    } else {
      // FIXME: Refactor signature so this is not necessary
      signature.signature.nhashtype = signature.sigtype;
      return Sighash.verify(
        transaction,
        signature.signature,
        signature.publicKey,
        signature.inputIndex,
        this.redeemScript
      );
    }
  }

  public _estimateSize() {
    return (
      MultiSigScriptHashInput.OPCODES_SIZE +
      this.threshold * MultiSigScriptHashInput.SIGNATURE_SIZE +
      this.publicKeys.length * MultiSigScriptHashInput.PUBKEY_SIZE
    );
  }
}
