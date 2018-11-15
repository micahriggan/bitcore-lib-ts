import $ from '../../util/preconditions';
import { Input } from './input';
import { BufferUtil } from '../../util/buffer';
import { Output } from '../output';
import { sighash, Sighash } from '../sighash';
import { Script } from '../../script';
import { Signature } from '../../crypto/signature';
import { TransactionSignature } from '../signature';
import { Transaction } from '../transaction';
import { PrivateKey } from '../../privatekey';

/**
 * Represents a special kind of input of PayToPublicKey kind.
 * @constructor
 */
export class PublicKeyInput extends Input {
  constructor(args) {
    super(args);
  }

  /**
   * @param {Transaction} transaction - the transaction to be signed
   * @param {PrivateKey} privateKey - the private key with which to sign the transaction
   * @param {number} index - the index of the input in the transaction input vector
   * @param {number=} sigtype - the type of signature, defaults to Signature.SIGHASH_ALL
   * @return {Array} of objects that can be
   */
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
    const publicKey = privateKey.toPublicKey();
    if (
      publicKey.toString() === this.output.script.getPublicKey().toString('hex')
    ) {
      return [
        new TransactionSignature({
          publicKey,
          prevTxId: this.prevTxId,
          outputIndex: this.outputIndex,
          inputIndex: index,
          signature: Sighash.sign(
            transaction,
            privateKey,
            sigtype,
            index,
            this.output.script
          ),
          sigtype
        })
      ];
    }
    return [];
  }

  /**
   * Add the provided signature
   *
   * @param {Object} signature
   * @param {PublicKey} signature.publicKey
   * @param {Signature} signature.signature
   * @param {number=} signature.sigtype
   * @return {PublicKeyInput} this, for chaining
   */
  public addSignature(
    transaction: Transaction,
    signature: TransactionSignature
  ) {
    $.checkState(
      this.isValidSignature(transaction, signature),
      'Signature is invalid'
    );
    this.setScript(
      Script.buildPublicKeyIn(signature.signature.toDER(), signature.sigtype)
    );
    return this;
  }

  /**
   * Clear the input's signature
   * @return {PublicKeyHashInput} this, for chaining
   */
  public clearSignatures() {
    this.setScript(Script.empty());
    return this;
  }

  /**
   * Query whether the input is signed
   * @return {boolean}
   */
  public isFullySigned() {
    return this.script.isPublicKeyIn();
  }

  public static SCRIPT_MAX_SIZE = 73; // sigsize (1 + 72)

  public _estimateSize() {
    return PublicKeyInput.SCRIPT_MAX_SIZE;
  }
}
module.exports = PublicKeyInput;
