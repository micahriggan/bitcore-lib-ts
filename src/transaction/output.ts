import * as _ from 'lodash';
import BN from 'bn.js';
import { BitcoreBN } from '../crypto/bn';
import { Buffer } from 'buffer';
import { BufferUtil } from '../util/buffer';
import { JSUtil } from '../util/js';
import { BufferWriter } from '../encoding/bufferwriter';
import { Script } from '../script';
import $ from '../util/preconditions';
import { BitcoreError } from '../errors';
import { BufferReader } from '../encoding/bufferreader';

const MAX_SAFE_INTEGER = 0x1fffffffffffff;

export namespace Output {
  export interface OutputObj {
    satoshis: number | BitcoreBN;
    script: Script | Buffer | string;
  }
}
export class Output {
  public _scriptBuffer: Buffer;
  public _script: Script;
  public _satoshis: number;
  public _satoshisBN: BN;

  constructor(args: Output.OutputObj) {
    if (!(this instanceof Output)) {
      return new Output(args);
    }
    if (_.isObject(args)) {
      this.setSatoshis(args.satoshis);
      if (BufferUtil.isBuffer(args.script)) {
        this._scriptBuffer = args.script as Buffer;
      } else {
        let script;
        if (_.isString(args.script) && JSUtil.isHexa(args.script)) {
          script = new Buffer(args.script, 'hex');
        } else {
          script = args.script;
        }
        this.setScript(script);
      }
    } else {
      throw new TypeError('Unrecognized argument for Output');
    }
  }

  public get script() {
    if (this._script) {
      return this._script;
    } else {
      this.setScriptFromBuffer(this._scriptBuffer);
      return this._script;
    }
  }

  public get satoshis(): number {
    return this._satoshis;
  }

  public setSatoshis(num: number | string | BitcoreBN) {
    if (num instanceof BN) {
      this._satoshisBN = num;
      this._satoshis = num.toNumber();
    } else if (typeof num == 'string') {
      this._satoshis = parseInt(num);
      this._satoshisBN = BitcoreBN.fromNumber(this._satoshis);
    } else {
      $.checkArgument(
        JSUtil.isNaturalNumber(num),
        'Output satoshis is not a natural number'
      );
      this._satoshisBN = BitcoreBN.fromNumber(num);
      this._satoshis = num;
    }
    $.checkState(
      JSUtil.isNaturalNumber(this._satoshis),
      'Output satoshis is not a natural number'
    );
  }

  public invalidSatoshis() {
    if (this._satoshis > MAX_SAFE_INTEGER) {
      return 'transaction txout satoshis greater than max safe integer';
    }
    if (this._satoshis !== this._satoshisBN.toNumber()) {
      return 'transaction txout satoshis has corrupted value';
    }
    if (this._satoshis < 0) {
      return 'transaction txout negative';
    }
    return false;
  }

  public toObject(): Output.OutputObj {
    const obj = {
      satoshis: this.satoshis,
      script: this._scriptBuffer.toString('hex')
    };
    return obj;
  }

  public toJSON = this.toObject;

  public static fromObject(data: Output.OutputObj) {
    return new Output(data);
  }

  public setScriptFromBuffer(buffer: Buffer) {
    this._scriptBuffer = buffer;
    try {
      this._script = Script.fromBuffer(this._scriptBuffer);
      this._script._isOutput = true;
    } catch (e) {
      if (e instanceof BitcoreError) {
        this._script = null;
      } else {
        throw e;
      }
    }
  }

  public setScript(script: Script | string | Buffer) {
    if (script instanceof Script) {
      this._scriptBuffer = script.toBuffer();
      this._script = script;
      this._script._isOutput = true;
    } else if (typeof script === 'string') {
      this._script = Script.fromString(script);
      this._scriptBuffer = this._script.toBuffer();
      this._script._isOutput = true;
    } else if (BufferUtil.isBuffer(script)) {
      this.setScriptFromBuffer(script);
    } else {
      throw new TypeError('Invalid argument type: script');
    }
    return this;
  }

  public inspect() {
    let scriptStr;
    if (this.script) {
      scriptStr = this.script.inspect();
    } else {
      scriptStr = this._scriptBuffer.toString('hex');
    }
    return '<Output (' + this.satoshis + ' sats) ' + scriptStr + '>';
  }

  public static fromBufferReader(br: BufferReader) {
    const obj = {} as Output.OutputObj;
    obj.satoshis = br.readUInt64LEBN();
    const size = br.readVarintNum();
    if (size !== 0) {
      obj.script = br.read(size);
    } else {
      obj.script = new Buffer([]);
    }
    return new Output(obj);
  }

  public toBufferWriter(writer) {
    if (!writer) {
      writer = new BufferWriter();
    }
    writer.writeUInt64LEBN(this._satoshisBN);
    const script = this._scriptBuffer;
    writer.writeVarintNum(script.length);
    writer.write(script);
    return writer;
  }
}
