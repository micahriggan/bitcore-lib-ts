import { Input } from './input/input';
interface Recepient {
  address: string;
  satoshis: number;
}
import { Signature } from '../crypto/signature';
import * as _ from 'lodash';
import $ from '../util/preconditions';
import { ERROR_TYPES, BitcoreError } from '../errors';
import { JSUtil, BufferUtil } from '../util';
import { BufferWriter, BufferReader } from '../encoding';
import { BitcoreBN, Hash } from '../crypto';
import { Address } from '../address';
import {
  Output,
  InputTypes,
  TransactionSignature,
  MultiSigInput,
  MultiSigScriptHashInput,
  PublicKeyInput,
  PublicKeyHashInput
} from '.';
import { Script } from '../script';
import { PrivateKey } from '../privatekey';
import { PublicKey } from '../publickey';
import { Sighash } from './sighash';
import { SighashWitness } from './sighashwitness';
import { UnspentOutput } from './unspentoutput';

const compare = Buffer.compare || require('buffer-compare');

const CURRENT_VERSION = 1;
const DEFAULT_NLOCKTIME = 0;
const MAX_BLOCK_SIZE = 1000000;

export declare namespace Transaction {
  export type TxInput =
    | PublicKeyHashInput
    | PublicKeyInput
    | MultiSigScriptHashInput
    | MultiSigInput;

  export interface TransactionObj {
    changeScript?: string;
    changeIndex?: number;
    inputs: Array<Transaction.TxInput | InputTypes.InputObj>;
    outputs: Array<Output | Output.OutputObj>;
    nLockTime: number;
    version: number;
    hash: string;
    fee?: number;
  }
}
/**
 * Represents a transaction, a set of inputs and outputs to change ownership of tokens
 *
 * @param {*} serialized
 * @constructor
 */
export class Transaction {
  public static Input = Input;
  public static Output = Output;
  public static Signature = TransactionSignature;
  public static SighashWitness = SighashWitness;
  public static Sighash = Sighash;
  public inputs: Array<Transaction.TxInput>;
  public outputs: Array<Output>;
  public nLockTime: number;
  public version: number;
  public _inputAmount: number;
  public _outputAmount: number;
  public _hash: string;
  public _fee: number;
  public _changeScript: Script;
  public _changeIndex: number;
  public _feePerKb: number;

  constructor(
    serialized?: Transaction | string | Transaction.TransactionObj | Buffer
  ) {
    if (!(this instanceof Transaction)) {
      return new Transaction(serialized);
    }
    this.inputs = [];
    this.outputs = [];
    this._inputAmount = undefined;
    this._outputAmount = undefined;

    if (serialized) {
      if (serialized instanceof Transaction) {
        return Transaction.shallowCopy(serialized);
      } else if (JSUtil.isHexa(serialized) && typeof serialized === 'string') {
        this.fromString(serialized);
      } else if (BufferUtil.isBuffer(serialized)) {
        this.fromBuffer(serialized);
      } else if (_.isObject(serialized)) {
        this.fromObject(serialized);
      } else {
        throw new BitcoreError(
          ERROR_TYPES.InvalidArgument,
          'Must provide an object or string to deserialize a transaction'
        );
      }
    } else {
      this._newTransaction();
    }
  }
  // Minimum amount for an output for it not to be considered a dust output
  public static DUST_AMOUNT = 546;

  // Margin of error to allow fees in the vecinity of the expected value but doesn't allow a big difference
  public static FEE_SECURITY_MARGIN = 150;

  // max amount of satoshis in circulation
  public static MAX_MONEY = 21000000 * 1e8;

  // nlocktime limit to be considered block height rather than a timestamp
  public static NLOCKTIME_BLOCKHEIGHT_LIMIT = 5e8;

  // Max value for an unsigned 32 bit value
  public static NLOCKTIME_MAX_VALUE = 4294967295;

  // Value used for fee estimation (satoshis per kilobyte)
  public static FEE_PER_KB = 100000;

  // Safe upper bound for change address script size in bytes
  public static CHANGE_OUTPUT_MAX_SIZE = 20 + 4 + 34 + 4;
  public static MAXIMUM_EXTRA_SIZE = 4 + 9 + 9 + 4;

  /* Constructors and Serialization */

  /**
   * Create a 'shallow' copy of the transaction, by serializing and deserializing
   * it dropping any additional information that inputs and outputs may have hold
   *
   * @param {Transaction} transaction
   * @return {Transaction}
   */
  public static shallowCopy(transaction) {
    const copy = new Transaction(transaction.toBuffer());
    return copy;
  }

  public get hash() {
    this._hash = new BufferReader(this._getHash())
      .readReverse()
      .toString('hex');
    return this._hash;
  }

  public get id() {
    return this.id;
  }

  public get witnessHash() {
    return new BufferReader(this._getWitnessHash())
      .readReverse()
      .toString('hex');
  }

  public get inputAmount() {
    return this._getInputAmount();
  }

  public get outputAmount() {
    return this._getOutputAmount();
  }

  /**
   * Retrieve the little endian hash of the transaction (used for serialization)
   * @return {Buffer}
   */
  public _getHash() {
    return Hash.sha256sha256(this.toBuffer(true));
  }

  /**
   * Retrieve the little endian hash of the transaction including witness data
   * @return {Buffer}
   */
  public _getWitnessHash() {
    return Hash.sha256sha256(this.toBuffer(false));
  }

  /**
   * Retrieve a hexa string that can be used with bitcoind's CLI interface
   * (decoderawtransaction, sendrawtransaction)
   *
   * @param {Object|boolean=} unsafe if true, skip all tests. if it's an object,
   *   it's expected to contain a set of flags to skip certain tests:
   * * `disableAll`: disable all checks
   * * `disableSmallFees`: disable checking for fees that are too small
   * * `disableLargeFees`: disable checking for fees that are too large
   * * `disableIsFullySigned`: disable checking if all inputs are fully signed
   * * `disableDustOutputs`: disable checking if there are no outputs that are dust amounts
   * * `disableMoreOutputThanInput`: disable checking if the transaction spends more bitcoins than the sum of the input amounts
   * @return {string}
   */
  public serialize(
    unsafe?:
      | boolean
      | Partial<{
          disableAll: boolean;
          disableSmallFees: boolean;
          disableLargeFees: boolean;
          disableIsFullySigned: boolean;
          disableDustOutputs: boolean;
          disableMoreOutputThanInput: boolean;
        }>
  ) {
    if (true === unsafe || (unsafe && unsafe.disableAll)) {
      return this.uncheckedSerialize();
    } else {
      return this.checkedSerialize(unsafe);
    }
  }

  public uncheckedSerialize() {
    return this.toBuffer().toString('hex');
  }

  /**
   * Retrieve a hexa string that can be used with bitcoind's CLI interface
   * (decoderawtransaction, sendrawtransaction)
   *
   * @param {Object} opts allows to skip certain tests. {@see Transaction#serialize}
   * @return {string}
   */
  public checkedSerialize(opts) {
    const serializationError = this.getSerializationError(opts);
    if (serializationError) {
      serializationError.message +=
        ' - For more information please see: ' +
        'https://bitcore.io/api/lib/transaction#serialization-checks';
      throw serializationError;
    }
    return this.uncheckedSerialize();
  }

  public invalidSatoshis() {
    let invalid = false;
    for (const output of this.outputs) {
      if (output.invalidSatoshis()) {
        invalid = true;
      }
    }
    return invalid;
  }

  /**
   * Retrieve a possible error that could appear when trying to serialize and
   * broadcast this transaction.
   *
   * @param {Object} opts allows to skip certain tests. {@see Transaction#serialize}
   * @return {bitcore.Error}
   */
  public getSerializationError(opts) {
    opts = opts || {};

    if (this.invalidSatoshis()) {
      return new BitcoreError(ERROR_TYPES.Transaction.errors.InvalidSatoshis);
    }

    const unspent = this._getUnspentValue();
    let unspentError;
    if (unspent < 0) {
      if (!opts.disableMoreOutputThanInput) {
        unspentError = new BitcoreError(
          ERROR_TYPES.Transaction.errors.InvalidOutputAmountSum
        );
      }
    } else {
      unspentError = this._hasFeeError(opts, unspent);
    }

    return (
      unspentError ||
      this._hasDustOutputs(opts) ||
      this._isMissingSignatures(opts)
    );
  }

  public _hasFeeError(opts, unspent) {
    if (!_.isUndefined(this._fee) && this._fee !== unspent) {
      return new BitcoreError(
        ERROR_TYPES.Transaction.errors.FeeError.errors.Different,
        'Unspent value is ' + unspent + ' but specified fee is ' + this._fee
      );
    }

    if (!opts.disableLargeFees) {
      const maximumFee = Math.floor(
        Transaction.FEE_SECURITY_MARGIN * this._estimateFee()
      );
      if (unspent > maximumFee) {
        if (this._missingChange()) {
          return new BitcoreError(
            ERROR_TYPES.Transaction.errors.ChangeAddressMissing,
            'Fee is too large and no change address was provided'
          );
        }
        return new BitcoreError(
          ERROR_TYPES.Transaction.errors.FeeError.errors.TooLarge,
          'expected less than ' + maximumFee + ' but got ' + unspent
        );
      }
    }

    if (!opts.disableSmallFees) {
      const minimumFee = Math.ceil(
        this._estimateFee() / Transaction.FEE_SECURITY_MARGIN
      );
      if (unspent < minimumFee) {
        return new BitcoreError(
          ERROR_TYPES.Transaction.errors.FeeError.errors.TooSmall,
          'expected more than ' + minimumFee + ' but got ' + unspent
        );
      }
    }
  }

  public _missingChange() {
    return !this._changeScript;
  }

  public _hasDustOutputs(opts) {
    if (opts.disableDustOutputs) {
      return;
    }
    for (const output of this.outputs) {
      if (
        output.satoshis < Transaction.DUST_AMOUNT &&
        !output.script.isDataOut()
      ) {
        return new BitcoreError(ERROR_TYPES.Transaction.errors.DustOutputs);
      }
    }
  }

  public _isMissingSignatures(opts) {
    if (opts.disableIsFullySigned) {
      return;
    }
    if (!this.isFullySigned()) {
      return new BitcoreError(ERROR_TYPES.Transaction.errors.MissingSignatures);
    }
  }

  public inspect() {
    return '<Transaction: ' + this.uncheckedSerialize() + '>';
  }

  public toBuffer(noWitness = false) {
    const writer = new BufferWriter();
    return this.toBufferWriter(writer, noWitness).toBuffer();
  }

  public hasWitnesses() {
    for (const input of this.inputs) {
      if ( input.hasWitnesses()) {
        return true;
      }
    }
    return false;
  }

  public toBufferWriter(writer, noWitness = false) {
    writer.writeInt32LE(this.version);

    const hasWitnesses = this.hasWitnesses();

    if (hasWitnesses && !noWitness) {
      writer.write(new Buffer('0001', 'hex'));
    }

    writer.writeVarintNum(this.inputs.length);

    _.each(this.inputs, input => {
      input.toBufferWriter(writer);
    });

    writer.writeVarintNum(this.outputs.length);
    _.each(this.outputs, output => {
      output.toBufferWriter(writer);
    });

    if (hasWitnesses && !noWitness) {
      _.each(this.inputs, input => {
        const witnesses = input.getWitnesses();
        writer.writeVarintNum(witnesses.length);
        for (const witness of witnesses) {
          writer.writeVarintNum(witness.length);
          writer.write(witness);
        }
      });
    }

    writer.writeUInt32LE(this.nLockTime);
    return writer;
  }

  public fromBuffer(buffer) {
    const reader = new BufferReader(buffer);
    return this.fromBufferReader(reader);
  }

  public fromBufferReader(reader) {
    $.checkArgument(!reader.finished(), 'No transaction data received');

    this.version = reader.readInt32LE();
    let sizeTxIns = reader.readVarintNum();

    // check for segwit
    let hasWitnesses = false;
    if (sizeTxIns === 0 && reader.buf[reader.pos] !== 0) {
      reader.pos += 1;
      hasWitnesses = true;
      sizeTxIns = reader.readVarintNum();
    }

    for (let i = 0; i < sizeTxIns; i++) {
      const input = Input.fromBufferReader(reader);
      this.inputs.push(input as Transaction.TxInput);
    }

    const sizeTxOuts = reader.readVarintNum();
    for (let j = 0; j < sizeTxOuts; j++) {
      this.outputs.push(Output.fromBufferReader(reader));
    }

    if (hasWitnesses) {
      for (let k = 0; k < sizeTxIns; k++) {
        const itemCount = reader.readVarintNum();
        const witnesses = [];
        for (let l = 0; l < itemCount; l++) {
          const size = reader.readVarintNum();
          const item = reader.read(size);
          witnesses.push(item);
        }
        this.inputs[k].setWitnesses(witnesses);
      }
    }

    this.nLockTime = reader.readUInt32LE();
    return this;
  }

  public toObject() {
    const inputs = [];
    this.inputs.forEach(input => {
      inputs.push(input.toObject());
    });
    const outputs = [];
    this.outputs.forEach(output => {
      outputs.push(output.toObject());
    });
    const obj: Transaction.TransactionObj = {
      hash: this.hash,
      version: this.version,
      inputs,
      outputs,
      nLockTime: this.nLockTime,
      changeIndex: this._changeIndex,
      changeScript: this._changeScript.toString(),
      fee: this._fee
    };
    return obj;
  }

  public toJSON = this.toObject;

  public fromObject(arg) {
    /* jshint maxstatements: 20 */
    $.checkArgument(_.isObject(arg) || arg instanceof Transaction);
    const transaction = arg instanceof Transaction ? arg.toObject() : arg;
    _.each(transaction.inputs, input => {
      if (!input.output || !input.output.script) {
        this.uncheckedAddInput(new Input(input));
        return;
      }
      const script = new Script(input.output.script);
      let txin;
      if (script.isPublicKeyHashOut()) {
        txin = new PublicKeyHashInput(input);
      } else if (
        script.isScriptHashOut() &&
        input.publicKeys &&
        input.threshold
      ) {
        txin = new MultiSigScriptHashInput(
          input,
          input.publicKeys,
          input.threshold,
          input.signatures
        );
      } else if (script.isPublicKeyOut()) {
        txin = new PublicKey(input);
      } else {
        throw new BitcoreError(
          ERROR_TYPES.Transaction.errors.Input.errors.UnsupportedScript,
          input.output.script
        );
      }
      this.addInput(txin);
    });
    _.each(transaction.outputs, output => {
      this.addOutput(new Output(output));
    });
    if (transaction.changeIndex) {
      this._changeIndex = transaction.changeIndex;
    }
    if (transaction.changeScript) {
      this._changeScript = new Script(transaction.changeScript);
    }
    if (transaction.fee) {
      this._fee = transaction.fee;
    }
    this.nLockTime = transaction.nLockTime;
    this.version = transaction.version;
    this._checkConsistency(arg);
    return this;
  }
  public fromJSON = this.fromObject;

  public _checkConsistency(arg) {
    if (!_.isUndefined(this._changeIndex)) {
      $.checkState(this._changeScript, 'Change script is expected.');
      $.checkState(
        this.outputs[this._changeIndex],
        'Change index points to undefined output.'
      );
      $.checkState(
        this.outputs[this._changeIndex].script.toString() ===
          this._changeScript.toString(),
        'Change output has an unexpected script.'
      );
    }
    if (arg && arg.hash) {
      $.checkState(
        arg.hash === this.hash,
        'Hash in object does not match transaction hash.'
      );
    }
  }

  /**
   * Sets nLockTime so that transaction is not valid until the desired date(a
   * timestamp in seconds since UNIX epoch is also accepted)
   *
   * @param {Date | Number} time
   * @return {Transaction} this
   */
  public lockUntilDate(time) {
    $.checkArgument(time);
    if (_.isNumber(time) && time < Transaction.NLOCKTIME_BLOCKHEIGHT_LIMIT) {
      throw new BitcoreError(ERROR_TYPES.Transaction.errors.LockTimeTooEarly);
    }
    if (_.isDate(time)) {
      time = time.getTime() / 1000;
    }

    for (const input of this.inputs) {
      if (input.sequenceNumber === Input.DEFAULT_SEQNUMBER) {
        input.sequenceNumber = Input.DEFAULT_LOCKTIME_SEQNUMBER;
      }
    }

    this.nLockTime = time;
    return this;
  }

  /**
   * Sets nLockTime so that transaction is not valid until the desired block
   * height.
   *
   * @param {Number} height
   * @return {Transaction} this
   */
  public lockUntilBlockHeight(height) {
    $.checkArgument(_.isNumber(height));
    if (height >= Transaction.NLOCKTIME_BLOCKHEIGHT_LIMIT) {
      throw new BitcoreError(ERROR_TYPES.Transaction.errors.BlockHeightTooHigh);
    }
    if (height < 0) {
      throw new BitcoreError(
        ERROR_TYPES.Transaction.errors.NLockTimeOutOfRange
      );
    }

    for (const input of this.inputs) {
      if (input.sequenceNumber === Input.DEFAULT_SEQNUMBER) {
        input.sequenceNumber = Input.DEFAULT_LOCKTIME_SEQNUMBER;
      }
    }

    this.nLockTime = height;
    return this;
  }

  /**
   *  Returns a semantic version of the transaction's nLockTime.
   *  @return {Number|Date}
   *  If nLockTime is 0, it returns null,
   *  if it is < 500000000, it returns a block height (number)
   *  else it returns a Date object.
   */
  public getLockTime() {
    if (!this.nLockTime) {
      return null;
    }
    if (this.nLockTime < Transaction.NLOCKTIME_BLOCKHEIGHT_LIMIT) {
      return this.nLockTime;
    }
    return new Date(1000 * this.nLockTime);
  }

  public fromString(str: string) {
    this.fromBuffer(Buffer.from(str, 'hex'));
  }

  public _newTransaction() {
    this.version = CURRENT_VERSION;
    this.nLockTime = DEFAULT_NLOCKTIME;
  }

  /* Transaction creation interface */

  /**
   * @typedef {Object} Transaction~fromObject
   * @property {string} prevTxId
   * @property {number} outputIndex
   * @property {(Buffer|string|Script)} script
   * @property {number} satoshis
   */

  /**
   * Add an input to this transaction. This is a high level interface
   * to add an input, for more control, use @{link Transaction#addInput}.
   *
   * Can receive, as output information, the output of bitcoind's `listunspent` command,
   * and a slightly fancier format recognized by bitcore:
   *
   * ```
   * {
   *  address: 'mszYqVnqKoQx4jcTdJXxwKAissE3Jbrrc1',
   *  txId: 'a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458',
   *  outputIndex: 0,
   *  script: Script.empty(),
   *  satoshis: 1020000
   * }
   * ```
   * Where `address` can be either a string or a bitcore Address object. The
   * same is true for `script`, which can be a string or a bitcore Script.
   *
   * Beware that this resets all the signatures for inputs (in further versions,
   * SIGHASH_SINGLE or SIGHASH_NONE signatures will not be reset).
   *
   * @example
   * ```javascript
   * var transaction = new Transaction();
   *
   * // From a pay to public key hash output from bitcoind's listunspent
   * transaction.from({'txid': '0000...', vout: 0, amount: 0.1, scriptPubKey: 'OP_DUP ...'});
   *
   * // From a pay to public key hash output
   * transaction.from({'txId': '0000...', outputIndex: 0, satoshis: 1000, script: 'OP_DUP ...'});
   *
   * // From a multisig P2SH output
   * transaction.from({'txId': '0000...', inputIndex: 0, satoshis: 1000, script: '... OP_HASH'},
   *                  ['03000...', '02000...'], 2);
   * ```
   *
   * @param {(Array.<Transaction~fromObject>|Transaction~fromObject)} utxo
   * @param {Array=} pubkeys
   * @param {number=} threshold
   * @param {boolean=} nestedWitness - Indicates that the utxo is nested witness p2sh
   */
  public from(
    utxo:
      | UnspentOutput.UnspentOutputObj
      | Array<UnspentOutput.UnspentOutputObj>,
    pubkeys?: Array<PublicKey>,
    threshold?: number,
    nestedWitness = false
  ) {
    if (utxo instanceof Array && _.isArray(utxo)) {
      _.each(utxo, utx => {
        this.from(utx, pubkeys, threshold);
      });
      return this;
    }
    const exists = _.some(this.inputs, input => {
      // TODO: Maybe prevTxId should be a string? Or defined as read only property?
      utxo = utxo as UnspentOutput.UnspentOutputObj;
      return (
        input.prevTxId.toString('hex') === utxo.txId &&
        input.outputIndex === utxo.outputIndex
      );
    });
    if (exists) {
      return this;
    }
    if (pubkeys && threshold) {
      this._fromMultisigUtxo(utxo, pubkeys, threshold, nestedWitness);
    } else {
      this._fromNonP2SH(utxo as UnspentOutput.UnspentOutputObj);
    }
    return this;
  }

  public _fromNonP2SH(utxo: UnspentOutput | UnspentOutput.UnspentOutputObj) {
    let clazz;
    const newutxo = new UnspentOutput(utxo);
    if (newutxo.script.isPublicKeyHashOut()) {
      clazz = PublicKeyHashInput;
    } else if (newutxo.script.isPublicKeyOut()) {
      clazz = PublicKeyInput;
    } else {
      clazz = Input;
    }
    this.addInput(
      new clazz({
        output: new Output({
          script: newutxo.script,
          satoshis: newutxo.satoshis
        }),
        prevTxId: newutxo.txId,
        outputIndex: newutxo.outputIndex,
        script: Script.empty()
      })
    );
  }

  public _fromMultisigUtxo(utxo, pubkeys, threshold, nestedWitness) {
    $.checkArgument(
      threshold <= pubkeys.length,
      'Number of required signatures must be greater than the number of public keys'
    );
    let clazz;
    utxo = new UnspentOutput(utxo);
    if (utxo.script.isMultisigOut()) {
      clazz = MultiSigInput;
    } else if (utxo.script.isScriptHashOut()) {
      clazz = MultiSigScriptHashInput;
    } else {
      throw new Error('@TODO');
    }
    this.addInput(
      new Input(
        {
          output: new Output({
            script: utxo.script,
            satoshis: utxo.satoshis
          }),
          prevTxId: utxo.txId,
          outputIndex: utxo.outputIndex,
          script: Script.empty()
        },
        pubkeys,
        threshold,
        [],
        nestedWitness
      )
    );
  }

  /**
   * Add an input to this transaction. The input must be an instance of the `Input` class.
   * It should have information about the Output that it's spending, but if it's not already
   * set, two additional parameters, `outputScript` and `satoshis` can be provided.
   *
   * @param {Input} input
   * @param {String|Script} outputScript
   * @param {number} satoshis
   * @return Transaction this, for chaining
   */
  public addInput(
    input: Input,
    outputScript?: Script | string,
    satoshis?: number
  ) {
    $.checkArgumentType(input, Input, 'input');
    if (
      !input.output &&
      (_.isUndefined(outputScript) || _.isUndefined(satoshis))
    ) {
      throw new BitcoreError(
        ERROR_TYPES.Transaction.errors.NeedMoreInfo,
        'Need information about the UTXO script and satoshis'
      );
    }
    if (!input.output && outputScript && !_.isUndefined(satoshis)) {
      outputScript =
        outputScript instanceof Script
          ? outputScript
          : new Script(outputScript);
      $.checkArgumentType(satoshis, 'number', 'satoshis');
      input.output = new Output({
        script: outputScript,
        satoshis
      });
    }
    return this.uncheckedAddInput(input);
  }

  /**
   * Add an input to this transaction, without checking that the input has information about
   * the output that it's spending.
   *
   * @param {Input} input
   * @return Transaction this, for chaining
   */
  public uncheckedAddInput(input) {
    $.checkArgumentType(input, Input, 'input');
    this.inputs.push(input);
    this._inputAmount = undefined;
    this._updateChangeOutput();
    return this;
  }

  /**
   * Returns true if the transaction has enough info on all inputs to be correctly validated
   *
   * @return {boolean}
   */
  public hasAllUtxoInfo() {
    return _.every(
      this.inputs.map(input => {
        return !!input.output;
      })
    );
  }

  /**
   * Manually set the fee for this transaction. Beware that this resets all the signatures
   * for inputs (in further versions, SIGHASH_SINGLE or SIGHASH_NONE signatures will not
   * be reset).
   *
   * @param {number} amount satoshis to be sent
   * @return {Transaction} this, for chaining
   */
  public fee(amount) {
    $.checkArgument(_.isNumber(amount), 'amount must be a number');
    this._fee = amount;
    this._updateChangeOutput();
    return this;
  }

  /**
   * Manually set the fee per KB for this transaction. Beware that this resets all the signatures
   * for inputs (in further versions, SIGHASH_SINGLE or SIGHASH_NONE signatures will not
   * be reset).
   *
   * @param {number} amount satoshis per KB to be sent
   * @return {Transaction} this, for chaining
   */
  public feePerKb(amount) {
    $.checkArgument(_.isNumber(amount), 'amount must be a number');
    this._feePerKb = amount;
    this._updateChangeOutput();
    return this;
  }

  /* Output management */

  /**
   * Set the change address for this transaction
   *
   * Beware that this resets all the signatures for inputs (in further versions,
   * SIGHASH_SINGLE or SIGHASH_NONE signatures will not be reset).
   *
   * @param {Address} address An address for change to be sent to.
   * @return {Transaction} this, for chaining
   */
  public change(address) {
    $.checkArgument(address, 'address is required');
    this._changeScript = Script.fromAddress(address);
    this._updateChangeOutput();
    return this;
  }

  /**
   * @return {Output} change output, if it exists
   */
  public getChangeOutput() {
    if (!_.isUndefined(this._changeIndex)) {
      return this.outputs[this._changeIndex];
    }
    return null;
  }

  /**
   * @typedef {Object} Transaction~toObject
   * @property {(string|Address)} address
   * @property {number} satoshis
   */

  /**
   * Add an output to the transaction.
   *
   * Beware that this resets all the signatures for inputs (in further versions,
   * SIGHASH_SINGLE or SIGHASH_NONE signatures will not be reset).
   *
   * @param {(string|Address|Array.<Transaction~toObject>)} address
   * @param {number} amount in satoshis
   * @return {Transaction} this, for chaining
   */
  public to(address: string | Address | Array<Recepient>, amount?: number) {
    if (_.isArray(address)) {
      _.each(address, to => {
        this.to(to.address, to.satoshis);
      });
      return this;
    }

    $.checkArgument(
      JSUtil.isNaturalNumber(amount),
      'Amount is expected to be a positive integer'
    );
    this.addOutput(
      new Output({
        script: new Script(new Address(address)),
        satoshis: amount
      })
    );
    return this;
  }

  /**
   * Add an OP_RETURN output to the transaction.
   *
   * Beware that this resets all the signatures for inputs (in further versions,
   * SIGHASH_SINGLE or SIGHASH_NONE signatures will not be reset).
   *
   * @param {Buffer|string} value the data to be stored in the OP_RETURN output.
   *    In case of a string, the UTF-8 representation will be stored
   * @return {Transaction} this, for chaining
   */
  public addData(value) {
    this.addOutput(
      new Output({
        script: Script.buildDataOut(value),
        satoshis: 0
      })
    );
    return this;
  }

  /**
   * Add an output to the transaction.
   *
   * @param {Output} output the output to add.
   * @return {Transaction} this, for chaining
   */
  public addOutput(output) {
    $.checkArgumentType(output, Output, 'output');
    this._addOutput(output);
    this._updateChangeOutput();
    return this;
  }

  /**
   * Remove all outputs from the transaction.
   *
   * @return {Transaction} this, for chaining
   */
  public clearOutputs() {
    this.outputs = [];
    this._clearSignatures();
    this._outputAmount = undefined;
    this._changeIndex = undefined;
    this._updateChangeOutput();
    return this;
  }

  public _addOutput(output) {
    this.outputs.push(output);
    this._outputAmount = undefined;
  }

  /**
   * Calculates or gets the total output amount in satoshis
   *
   * @return {Number} the transaction total output amount
   */
  public _getOutputAmount() {
    if (_.isUndefined(this._outputAmount)) {
      this._outputAmount = 0;
      _.each(this.outputs, output => {
        this._outputAmount += output.satoshis;
      });
    }
    return this._outputAmount;
  }

  /**
   * Calculates or gets the total input amount in satoshis
   *
   * @return {Number} the transaction total input amount
   */
  public _getInputAmount() {
    if (_.isUndefined(this._inputAmount)) {
      this._inputAmount = 0;
      _.each(this.inputs, input => {
        if (_.isUndefined(input.output)) {
          throw new BitcoreError(
            ERROR_TYPES.Transaction.errors.Input.errors.MissingPreviousOutput
          );
        }
        this._inputAmount += input.output.satoshis;
      });
    }
    return this._inputAmount;
  }

  public _updateChangeOutput() {
    if (!this._changeScript) {
      return;
    }
    this._clearSignatures();
    if (!_.isUndefined(this._changeIndex)) {
      this._removeOutput(this._changeIndex);
    }
    const available = this._getUnspentValue();
    const fee = this.getFee();
    const changeAmount = available - fee;
    if (changeAmount > 0) {
      this._changeIndex = this.outputs.length;
      this._addOutput(
        new Output({
          script: this._changeScript,
          satoshis: changeAmount
        })
      );
    } else {
      this._changeIndex = undefined;
    }
  }
  /**
   * Calculates the fee of the transaction.
   *
   * If there's a fixed fee set, return that.
   *
   * If there is no change output set, the fee is the
   * total value of the outputs minus inputs. Note that
   * a serialized transaction only specifies the value
   * of its outputs. (The value of inputs are recorded
   * in the previous transaction outputs being spent.)
   * This method therefore raises a "MissingPreviousOutput"
   * error when called on a serialized transaction.
   *
   * If there's no fee set and no change address,
   * estimate the fee based on size.
   *
   * @return {Number} fee of this transaction in satoshis
   */
  public getFee() {
    if (this.isCoinbase()) {
      return 0;
    }
    if (!_.isUndefined(this._fee)) {
      return this._fee;
    }
    // if no change output is set, fees should equal all the unspent amount
    if (!this._changeScript) {
      return this._getUnspentValue();
    }
    return this._estimateFee();
  }

  /**
   * Estimates fee from serialized transaction size in bytes.
   */
  public _estimateFee() {
    const estimatedSize = this._estimateSize();
    const available = this._getUnspentValue();
    return Transaction._estimateFee(estimatedSize, available, this._feePerKb);
  }

  public _getUnspentValue() {
    return this._getInputAmount() - this._getOutputAmount();
  }

  public _clearSignatures() {
    _.each(this.inputs, input => {
      (input as Transaction.TxInput).clearSignatures();
    });
  }

  public static _estimateFee = (size, amountAvailable, feePerKb) => {
    const fee = Math.ceil(size / 1000) * (feePerKb || Transaction.FEE_PER_KB);
    if (amountAvailable > fee) {
      size += Transaction.CHANGE_OUTPUT_MAX_SIZE;
    }
    return Math.ceil(size / 1000) * (feePerKb || Transaction.FEE_PER_KB);
  };

  public _estimateSize() {
    let result = Transaction.MAXIMUM_EXTRA_SIZE;
    _.each(this.inputs, input => {
      result += input._estimateSize();
    });
    _.each(this.outputs, output => {
      result += output.script.toBuffer().length + 9;
    });
    return result;
  }

  public _removeOutput(index) {
    const output = this.outputs[index];
    this.outputs = _.without(this.outputs, output);
    this._outputAmount = undefined;
  }

  public removeOutput(index) {
    this._removeOutput(index);
    this._updateChangeOutput();
  }

  /**
   * Sort a transaction's inputs and outputs according to BIP69
   *
   * @see {https://github.com/bitcoin/bips/blob/master/bip-0069.mediawiki}
   * @return {Transaction} this
   */
  public sort() {
    this.sortInputs(inputs => {
      const copy = Array.prototype.concat.apply([], inputs);
      copy.sort((first, second) => {
        return (
          compare(first.prevTxId, second.prevTxId) ||
          first.outputIndex - second.outputIndex
        );
      });
      return copy;
    });
    this.sortOutputs(outputs => {
      const copy = Array.prototype.concat.apply([], outputs);
      copy.sort((first, second) => {
        return (
          first.satoshis - second.satoshis ||
          compare(first.script.toBuffer(), second.script.toBuffer())
        );
      });
      return copy;
    });
    return this;
  }

  /**
   * Randomize this transaction's outputs ordering. The shuffling algorithm is a
   * version of the Fisher-Yates shuffle, provided by lodash's _.shuffle().
   *
   * @return {Transaction} this
   */
  public shuffleOutputs() {
    return this.sortOutputs(_.shuffle);
  }

  /**
   * Sort this transaction's outputs, according to a given sorting function that
   * takes an array as argument and returns a new array, with the same elements
   * but with a different order. The argument function MUST NOT modify the order
   * of the original array
   *
   * @param {Function} sortingFunction
   * @return {Transaction} this
   */
  public sortOutputs(sortingFunction) {
    const outs = sortingFunction(this.outputs);
    return this._newOutputOrder(outs);
  }

  /**
   * Sort this transaction's inputs, according to a given sorting function that
   * takes an array as argument and returns a new array, with the same elements
   * but with a different order.
   *
   * @param {Function} sortingFunction
   * @return {Transaction} this
   */
  public sortInputs(sortingFunction) {
    this.inputs = sortingFunction(this.inputs);
    this._clearSignatures();
    return this;
  }

  public _newOutputOrder(newOutputs) {
    const isInvalidSorting =
      this.outputs.length !== newOutputs.length ||
      _.difference(this.outputs, newOutputs).length !== 0;
    if (isInvalidSorting) {
      throw new BitcoreError(ERROR_TYPES.Transaction.errors.InvalidSorting);
    }

    if (!_.isUndefined(this._changeIndex)) {
      const changeOutput = this.outputs[this._changeIndex];
      this._changeIndex = _.findIndex(newOutputs, changeOutput);
    }

    this.outputs = newOutputs;
    return this;
  }

  public removeInput(txId, outputIndex = txId) {
    let index;
    if (!outputIndex && _.isNumber(txId)) {
      index = txId;
    } else {
      index = _.findIndex(this.inputs, i => {
        return (
          i.prevTxId.toString('hex') === txId && i.outputIndex === outputIndex
        );
      });
    }
    if (index < 0 || index >= this.inputs.length) {
      throw new BitcoreError(
        ERROR_TYPES.Transaction.errors.InvalidIndex,
        index,
        this.inputs.length
      );
    }
    const input = this.inputs[index];
    this.inputs = _.without(this.inputs, input);
    this._inputAmount = undefined;
    this._updateChangeOutput();
  }

  /* Signature handling */

  /**
   * Sign the transaction using one or more private keys.
   *
   * It tries to sign each input, verifying that the signature will be valid
   * (matches a public key).
   *
   * @param {Array|String|PrivateKey} privateKey
   * @param {number} sigtype
   * @return {Transaction} this, for chaining
   */
  public sign(privateKey, sigtype = Signature.SIGHASH_ALL) {
    $.checkState(
      this.hasAllUtxoInfo(),
      'Not all utxo information is available to sign the transaction.'
    );
    if (_.isArray(privateKey)) {
      _.each(privateKey, key => {
        this.sign(key, sigtype);
      });
      return this;
    }
    _.each(this.getSignatures(privateKey, sigtype), signature => {
      this.applySignature(signature);
    });
    return this;
  }

  public getSignatures(privKey, sigtype = Signature.SIGHASH_ALL) {
    privKey = new PrivateKey(privKey);
    sigtype = sigtype || Signature.SIGHASH_ALL;
    const results = [];
    const hashData = Hash.sha256ripemd160(privKey.publicKey.toBuffer());
    _.each(this.inputs, function forEachInput(input, index) {
      _.each(
        (input as Transaction.TxInput).getSignatures(
          this,
          privKey,
          index,
          sigtype,
          hashData
        ),
        signature => {
          results.push(signature);
        }
      );
    });
    return results;
  }

  private asTransactionInput(input: Input) {
    return input as Transaction.TxInput;
  }

  /**
   * Add a signature to the transaction
   *
   * @param {Object} signature
   * @param {number} signature.inputIndex
   * @param {number} signature.sigtype
   * @param {PublicKey} signature.publicKey
   * @param {Signature} signature.signature
   * @return {Transaction} this, for chaining
   */
  public applySignature(signature) {
    this.asTransactionInput(this.inputs[signature.inputIndex]).addSignature(
      this,
      signature
    );
    return this;
  }

  public isFullySigned() {
    _.each(this.inputs, input => {
      if (!this.asTransactionInput(input).isFullySigned) {
        throw new BitcoreError(
          ERROR_TYPES.Transaction.errors.UnableToVerifySignature,
          'Unrecognized script kind, or not enough information to execute script.' +
            'This usually happens when creating a transaction from a serialized transaction'
        );
      }
    });
    return _.every(
      _.map(this.inputs, input => {
        return this.asTransactionInput(input).isFullySigned();
      })
    );
  }

  public isValidSignature(signature: Partial<TransactionSignature>) {
    if (this.inputs[signature.inputIndex].isValidSignature) {
      throw new BitcoreError(
        ERROR_TYPES.Transaction.errors.UnableToVerifySignature,
        'Unrecognized script kind, or not enough information to execute script.' +
          'This usually happens when creating a transaction from a serialized transaction'
      );
    }
    return this.inputs[signature.inputIndex].isValidSignature(this, signature);
  }

  /**
   * @returns {bool} whether the signature is valid for this transaction input
   */
  public verifySignature(
    sig: TransactionSignature,
    pubkey: PublicKey,
    nin: number,
    subscript,
    sigversion: number,
    satoshis: number
  ) {
    if (_.isUndefined(sigversion)) {
      sigversion = 0;
    }

    if (sigversion === 1) {
      const subscriptBuffer = subscript.toBuffer();
      const scriptCodeWriter = new BufferWriter();
      scriptCodeWriter.writeVarintNum(subscriptBuffer.length);
      scriptCodeWriter.write(subscriptBuffer);

      let satoshisBuffer;
      if (satoshis) {
        $.checkState(
          JSUtil.isNaturalNumber(satoshis),
          'Satoshis should be a number'
        );
        satoshisBuffer = new BufferWriter()
          .writeUInt64LEBN(new BitcoreBN(satoshis))
          .toBuffer();
      } else {
        satoshisBuffer = this.inputs[nin].getSatoshisBuffer();
      }
      const verified = SighashWitness.verify(
        this,
        sig,
        pubkey,
        nin,
        scriptCodeWriter.toBuffer(),
        satoshisBuffer
      );
      return verified;
    }

    return Sighash.verify(this, sig, pubkey, nin, subscript);
  }

  /**
   * Check that a transaction passes basic sanity tests. If not, return a string
   * describing the error. This function contains the same logic as
   * CheckTransaction in bitcoin core.
   */
  public verify() {
    // Basic checks that don't depend on any context
    if (this.inputs.length === 0) {
      return 'transaction txins empty';
    }

    if (this.outputs.length === 0) {
      return 'transaction txouts empty';
    }

    // Check for negative or overflow output values
    let valueoutbn = new BitcoreBN(0);
    for (let i = 0; i < this.outputs.length; i++) {
      const txout = this.outputs[i];

      if (txout.invalidSatoshis()) {
        return 'transaction txout ' + i + ' satoshis is invalid';
      }
      if (txout._satoshisBN.gt(new BitcoreBN(Transaction.MAX_MONEY, 10))) {
        return 'transaction txout ' + i + ' greater than MAX_MONEY';
      }
      valueoutbn = new BitcoreBN(valueoutbn.add(txout._satoshisBN));
      if (valueoutbn.gt(new BitcoreBN(Transaction.MAX_MONEY))) {
        return (
          'transaction txout ' + i + ' total output greater than MAX_MONEY'
        );
      }
    }

    // Size limits
    if (this.toBuffer().length > MAX_BLOCK_SIZE) {
      return 'transaction over the maximum block size';
    }

    // Check for duplicate inputs
    const txinmap = {};
    for (let i = 0; i < this.inputs.length; i++) {
      const txin = this.inputs[i];

      const inputid = txin.prevTxId + ':' + txin.outputIndex;
      if (!_.isUndefined(txinmap[inputid])) {
        return 'transaction input ' + i + ' duplicate input';
      }
      txinmap[inputid] = true;
    }

    const isCoinbase = this.isCoinbase();
    if (isCoinbase) {
      const buf = this.inputs[0]._scriptBuffer;
      if (buf.length < 2 || buf.length > 100) {
        return 'coinbase transaction script size invalid';
      }
    } else {
      for (let i = 0; i < this.inputs.length; i++) {
        if (this.inputs[i].isNull()) {
          return 'transaction input ' + i + ' has null input';
        }
      }
    }
    return true;
  }

  /**
   * Analogous to bitcoind's IsCoinBase function in transaction.h
   */
  public isCoinbase() {
    return this.inputs.length === 1 && this.inputs[0].isNull();
  }

  /**
   * Determines if this transaction can be replaced in the mempool with another
   * transaction that provides a sufficiently higher fee (RBF).
   */
  public isRBF() {
    for (const input of this.inputs) {
      if (input.sequenceNumber < Input.MAXINT - 1) {
        return true;
      }
    }
    return false;
  }

  /**
   * Enable this transaction to be replaced in the mempool (RBF) if a transaction
   * includes a sufficiently higher fee. It will set the sequenceNumber to
   * DEFAULT_RBF_SEQNUMBER for all inputs if the sequence number does not
   * already enable RBF.
   */
  public enableRBF() {
    for (const input of this.inputs) {
      if (input.sequenceNumber >= Input.MAXINT - 1) {
        input.sequenceNumber = Input.DEFAULT_RBF_SEQNUMBER;
      }
    }
    return this;
  }
}
