import $ from '../util/preconditions';
import * as _ from 'lodash';
import { Buffer } from 'buffer';
import { Script } from '../script';
import { Transaction, InputTypes, Output } from '.';
import { BufferWriter, BufferReader } from '../encoding';
import { Hash, ECDSA, BitcoreBN } from '../crypto';
import { Signature } from '../crypto/signature';

const SIGHASH_SINGLE_BUG =
  '0000000000000000000000000000000000000000000000000000000000000001';
const BITS_64_ON = 'ffffffffffffffff';

export const Sighash = {
  sighash,
  verify,
  sign
};
/**
 * Returns a buffer of length 32 bytes with the hash that needs to be signed
 * for OP_CHECKSIG.
 *
 * @name Signing.sighash
 * @param {Transaction} transaction the transaction to sign
 * @param {number} sighashType the type of the hash
 * @param {number} inputNumber the input index for the signature
 * @param {Script} subscript the script that will be signed
 */
export function sighash(transaction, sighashType, inputNumber, subscript) {
  let i;
  // Copy transaction
  const txcopy = Transaction.shallowCopy(transaction);
  const blankInputs = new Array<Input>();

  // Copy script
  subscript = new Script(subscript);
  subscript.removeCodeseparators();

  for (i = 0; i < txcopy.inputs.length; i++) {
    // Blank signatures for other inputs
    blankInputs.push(new Input(txcopy.inputs[i]).setScript(Script.empty()));
  }

  blankInputs[inputNumber] = new Input(txcopy.inputs[inputNumber]).setScript(
    subscript
  );

  Object.assign(txcopy.inputs, blankInputs);

  if (
    (sighashType & 31) === Signature.SIGHASH_NONE ||
    (sighashType & 31) === Signature.SIGHASH_SINGLE
  ) {
    // clear all sequenceNumbers
    for (i = 0; i < txcopy.inputs.length; i++) {
      if (i !== inputNumber) {
        txcopy.inputs[i].sequenceNumber = 0;
      }
    }
  }

  if ((sighashType & 31) === Signature.SIGHASH_NONE) {
    txcopy.outputs = [];
  } else if ((sighashType & 31) === Signature.SIGHASH_SINGLE) {
    // The SIGHASH_SINGLE bug.
    // https://bitcointalk.org/index.php?topic=260595.0
    if (inputNumber >= txcopy.outputs.length) {
      return Buffer.from(SIGHASH_SINGLE_BUG, 'hex');
    }

    txcopy.outputs.length = inputNumber + 1;

    for (i = 0; i < inputNumber; i++) {
      txcopy.outputs[i] = new Output({
        satoshis: BitcoreBN.fromBuffer(new Buffer(BITS_64_ON, 'hex')),
        script: Script.empty()
      });
    }
  }

  if (sighashType & Signature.SIGHASH_ANYONECANPAY) {
    txcopy.inputs = [txcopy.inputs[inputNumber]];
  }

  const buf = new BufferWriter()
    .write(txcopy.toBuffer())
    .writeInt32LE(sighashType)
    .toBuffer();
  let ret = Hash.sha256sha256(buf);
  ret = new BufferReader(ret).readReverse();
  return ret;
}

/**
 * Create a signature
 *
 * @name Signing.sign
 * @param {Transaction} transaction
 * @param {PrivateKey} privateKey
 * @param {number} sighash
 * @param {number} inputIndex
 * @param {Script} subscript
 * @return {Signature}
 */
export function sign(
  transaction,
  privateKey,
  sighashType,
  inputIndex,
  subscript
) {
  const hashbuf = sighash(transaction, sighashType, inputIndex, subscript);
  const sig = ECDSA.sign(hashbuf, privateKey, 'little').set({
    nhashtype: sighashType
  });
  return sig;
}

/**
 * Verify a signature
 *
 * @name Signing.verify
 * @param {Transaction} transaction
 * @param {Signature} signature
 * @param {PublicKey} publicKey
 * @param {number} inputIndex
 * @param {Script} subscript
 * @return {boolean}
 */
export function verify(
  transaction,
  signature,
  publicKey,
  inputIndex,
  subscript
) {
  $.checkArgument(!_.isUndefined(transaction));
  $.checkArgument(
    !_.isUndefined(signature) && !_.isUndefined(signature.nhashtype)
  );
  const hashbuf = sighash(
    transaction,
    signature.nhashtype,
    inputIndex,
    subscript
  );
  return ECDSA.verify(hashbuf, signature, publicKey, 'little');
}
