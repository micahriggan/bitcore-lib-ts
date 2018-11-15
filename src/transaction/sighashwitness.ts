import { PublicKey } from '../publickey';
import $ from '../util/preconditions';
import * as _ from 'lodash';
import { Signature } from '../crypto/signature';
import { Script } from '../script';
import { Output } from './output';
import { BufferReader } from '../encoding/bufferreader';
import { BufferWriter } from '../encoding/bufferwriter';
import { BitcoreBN } from '../crypto/bn';
import { Hash } from '../crypto/hash';
import { ECDSA } from '../crypto/ecdsa';
import { Transaction } from './transaction';
import { PrivateKey } from '../privatekey';
/**
 * Returns a buffer of length 32 bytes with the hash that needs to be signed
 * for witness programs as defined by:
 * https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
 *
 * @name Signing.sighash
 * @param {Transaction} transaction the transaction to sign
 * @param {number} sighashType the type of the hash
 * @param {number} inputNumber the input index for the signature
 * @param {Buffer} scriptCode
 * @param {Buffer} satoshisBuffer
 */
export function sighash(
  transaction: Transaction,
  sighashType: number,
  inputNumber: number,
  scriptCode: Buffer,
  satoshisBuffer: Buffer
) {
  /* jshint maxstatements: 50 */

  let hashPrevouts;
  let hashSequence;
  let hashOutputs;

  if (!(sighashType & Signature.SIGHASH_ANYONECANPAY)) {
    const buffers = [];
    for (const input of transaction.inputs) {
      const prevTxIdBuffer = new BufferReader(input.prevTxId).readReverse();
      buffers.push(prevTxIdBuffer);
      const outputIndexBuffer = new Buffer(new Array(4));
      outputIndexBuffer.writeUInt32LE(input.outputIndex, 0);
      buffers.push(outputIndexBuffer);
    }
    hashPrevouts = Hash.sha256sha256(Buffer.concat(buffers));
  }

  if (
    !(sighashType & Signature.SIGHASH_ANYONECANPAY) &&
    (sighashType & 0x1f) !== Signature.SIGHASH_SINGLE &&
    (sighashType & 0x1f) !== Signature.SIGHASH_NONE
  ) {
    const sequenceBuffers = [];
    for (const input of transaction.inputs) {
      const sequenceBuffer = new Buffer(new Array(4));
      sequenceBuffer.writeUInt32LE(input.sequenceNumber, 0);
      sequenceBuffers.push(sequenceBuffer);
    }
    hashSequence = Hash.sha256sha256(Buffer.concat(sequenceBuffers));
  }

  const outputWriter = new BufferWriter();
  if (
    (sighashType & 0x1f) !== Signature.SIGHASH_SINGLE &&
    (sighashType & 0x1f) !== Signature.SIGHASH_NONE
  ) {
    for (const output of transaction.outputs) {
      output.toBufferWriter(outputWriter);
    }
    hashOutputs = Hash.sha256sha256(outputWriter.toBuffer());
  } else if (
    (sighashType & 0x1f) === Signature.SIGHASH_SINGLE &&
    inputNumber < transaction.outputs.length
  ) {
    transaction.outputs[inputNumber].toBufferWriter(outputWriter);
    hashOutputs = Hash.sha256sha256(outputWriter.toBuffer());
  }

  // Version
  const writer = new BufferWriter();
  writer.writeUInt32LE(transaction.version);

  // Input prevouts/nSequence (none/all, depending on flags)
  writer.write(hashPrevouts);
  writer.write(hashSequence);

  // The input being signed (replacing the scriptSig with scriptCode + amount)
  // The prevout may already be contained in hashPrevout, and the nSequence
  // may already be contain in hashSequence.
  const outpointId = new BufferReader(
    transaction.inputs[inputNumber].prevTxId
  ).readReverse();
  writer.write(outpointId);
  writer.writeUInt32LE(transaction.inputs[inputNumber].outputIndex);

  writer.write(scriptCode);

  writer.write(satoshisBuffer);

  writer.writeUInt32LE(transaction.inputs[inputNumber].sequenceNumber);

  // Outputs (none/one/all, depending on flags)
  writer.write(hashOutputs);

  // Locktime
  writer.writeUInt32LE(transaction.nLockTime);

  // Sighash type
  writer.writeInt32LE(sighashType);

  return Hash.sha256sha256(writer.toBuffer());
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
  transaction: Transaction,
  privateKey: PrivateKey,
  sighashType: number,
  inputIndex: number,
  scriptCode: Buffer,
  satoshisBuffer: Buffer
) {
  const hashbuf = sighash(
    transaction,
    sighashType,
    inputIndex,
    scriptCode,
    satoshisBuffer
  );
  const sig = ECDSA.sign(hashbuf, privateKey).set({
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
  transaction: Transaction,
  signature: Signature,
  publicKey: PublicKey,
  inputIndex: number,
  scriptCode: Buffer,
  satoshisBuffer: Buffer
) {
  $.checkArgument(!_.isUndefined(transaction));
  $.checkArgument(
    !_.isUndefined(signature) && !_.isUndefined(signature.nhashtype)
  );
  const hashbuf = sighash(
    transaction,
    signature.nhashtype,
    inputIndex,
    scriptCode,
    satoshisBuffer
  );
  return ECDSA.verify(hashbuf, signature, publicKey);
}

/**
 * @namespace Signing
 */
export const SighashWitness = {
  sighash,
  sign,
  verify
};
