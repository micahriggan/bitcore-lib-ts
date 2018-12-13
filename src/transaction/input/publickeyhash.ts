import $ from '../../util/preconditions';
import { BufferUtil } from '../../util/buffer';
import { Hash } from '../../crypto/hash';
import { Input } from './input';
import { Output } from '../output';
import { sighash, Sighash } from '../sighash';
import { Script } from '../../script';
import { Signature } from '../../crypto/signature';
import { TransactionSignature } from '../signature';
import { Transaction } from '../transaction';
import { PrivateKey } from '../../privatekey';

/**
 * Represents a special kind of input of PayToPublicKeyHash kind.
 * @constructor
 */
export class PublicKeyHashInput extends Input {
  public static SCRIPT_MAX_SIZE = 73 + 34; // sigsize (1 + 72) + pubkey (1 + 33)

  constructor(args) {
    super(args);
  }

  /* jshint maxparams: 5 */
  /**
   * @param {Transaction} transaction - the transaction to be signed
   * @param {PrivateKey} privateKey - the private key with which to sign the transaction
   * @param {number} index - the index of the input in the transaction input vector
   * @param {number=} sigtype - the type of signature, defaults to Signature.SIGHASH_ALL
   * @param {Buffer=} hashData - the precalculated hash of the public key associated with the privateKey provided
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
      'Output property must be an Output'
    );
    hashData =
      hashData || Hash.sha256ripemd160(privateKey.publicKey.toBuffer());
    sigtype = sigtype || Signature.SIGHASH_ALL;

    if (BufferUtil.equals(hashData, this.output.script.getPublicKeyHash())) {
      return [
        new TransactionSignature({
          publicKey: privateKey.publicKey,
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
  /* jshint maxparams: 3 */

  /**
   * Add the provided signature
   *
   * @param {Object} signature
   * @param {PublicKey} signature.publicKey
   * @param {Signature} signature.signature
   * @param {number=} signature.sigtype
   * @return {PublicKeyHashInput} this, for chaining
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
      Script.buildPublicKeyHashIn(
        signature.publicKey,
        signature.signature.toDER(),
        signature.sigtype
      )
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
    return this.script.isPublicKeyHashIn();
  }

  public _estimateSize() {
    return PublicKeyHashInput.SCRIPT_MAX_SIZE;
  }
}
