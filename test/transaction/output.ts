'use strict';

import * as _ from 'lodash';

import { BitcoreLib } from '../../src';
import { should } from 'chai';
const BN = BitcoreLib.crypto.BN;
const BufferWriter = BitcoreLib.encoding.BufferWriter;
const BufferReader = BitcoreLib.encoding.BufferReader;
const Output = BitcoreLib.Transaction.Output;
const Script = BitcoreLib.Script;

const errors = BitcoreLib.errors;

describe('Output', () => {
  const output = new Output({
    satoshis: 0,
    script: Script.empty()
  });

  it('throws error with unrecognized argument', () => {
    (() => {
      const out = new Output(12345 as any);
    }).should.throw(TypeError);
  });

  it('can be assigned a satoshi amount in big number', () => {
    const newOutput = new Output({
      satoshis: new BN(100),
      script: Script.empty()
    });
    newOutput.satoshis.should.equal(100);
  });

  it('can be assigned a satoshi amount with a string', () => {
    const newOutput = new Output({
      satoshis: '100',
      script: Script.empty()
    });
    newOutput.satoshis.should.equal(100);
  });

  describe('will error if output is not a positive integer', () => {
    it('-100', () => {
      (() => {
        const newOutput = new Output({
          satoshis: -100,
          script: Script.empty()
        });
      }).should.throw('Output satoshis is not a natural number');
    });

    it('1.1', () => {
      (() => {
        const newOutput = new Output({
          satoshis: 1.1,
          script: Script.empty()
        });
      }).should.throw('Output satoshis is not a natural number');
    });

    it('NaN', () => {
      (() => {
        const newOutput = new Output({
          satoshis: NaN,
          script: Script.empty()
        });
      }).should.throw('Output satoshis is not a natural number');
    });

    it('Infinity', () => {
      (() => {
        const newOutput = new Output({
          satoshis: Infinity,
          script: Script.empty()
        });
      }).should.throw('Output satoshis is not a natural number');
    });
  });

  const expectEqualOutputs = (a, b) => {
    a.satoshis.should.equal(b.satoshis);
    a.script.toString().should.equal(b.script.toString());
  };

  it('deserializes correctly a simple output', () => {
    const writer = new BufferWriter();
    output.toBufferWriter(writer);
    const deserialized = Output.fromBufferReader(
      new BufferReader(writer.toBuffer())
    );
    expectEqualOutputs(output, deserialized);
  });

  it('can instantiate from an object', () => {
    const out = new Output(output.toObject());
    should().exist(out);
  });

  it('can set a script from a buffer', () => {
    const newOutput = new Output(output.toObject());
    newOutput.setScript(new Script().add(0).toBuffer());
    newOutput.inspect().should.equal('<Output (0 sats) <Script: OP_0>>');
  });

  it('has a inspect property', () => {
    output.inspect().should.equal('<Output (0 sats) <Script: >>');
  });

  const output2 = new Output({
    satoshis: 1100000000,
    script: new Script(
      'OP_2 21 0x038282263212c609d9ea2a6e3e172de238d8c39' +
        'cabd5ac1ca10646e23fd5f51508 21 0x038282263212c609d9ea2a6e3e172de23' +
        '8d8c39cabd5ac1ca10646e23fd5f51508 OP_2 OP_CHECKMULTISIG OP_EQUAL'
    )
  });

  it('toBufferWriter', () => {
    output2
      .toBufferWriter()
      .toBuffer()
      .toString('hex')
      .should.equal(
        '00ab904100000000485215038282263212c609d9ea2a6e3e172de2' +
          '38d8c39cabd5ac1ca10646e23fd5f5150815038282263212c609d9ea2a6e3e172d' +
          'e238d8c39cabd5ac1ca10646e23fd5f5150852ae87'
      );
  });

  it('roundtrips to/from object', () => {
    const newOutput = new Output({
      satoshis: 50,
      script: new Script().add(0)
    });
    const otherOutput = new Output(newOutput.toObject());
    expectEqualOutputs(newOutput, otherOutput);
  });

  it('toObject will handle an invalid (null) script', () => {
    // block 000000000000000b7e48f88e86ceee3e97b4df7c139f5411d14735c1b3c36791 (livenet)
    // transaction index 2
    // txid ebc9fa1196a59e192352d76c0f6e73167046b9d37b8302b6bb6968dfd279b767
    const transaction = new BitcoreLib.Transaction();
    transaction.fromString(
      '01000000019ac03d5ae6a875d970128ef9086cef276a1919684a6988023cc7254691d97e6d010000006b4830450221009d41dc793ba24e65f571473d40b299b6459087cea1509f0d381740b1ac863cb6022039c425906fcaf51b2b84d8092569fb3213de43abaff2180e2a799d4fcb4dd0aa012102d5ede09a8ae667d0f855ef90325e27f6ce35bbe60a1e6e87af7f5b3c652140fdffffffff080100000000000000010101000000000000000202010100000000000000014c0100000000000000034c02010100000000000000014d0100000000000000044dffff010100000000000000014e0100000000000000064effffffff0100000000'
    );
    const obj = transaction.toObject();
    obj.outputs[2].script.should.equal('4c');
    obj.outputs[4].script.should.equal('4d');
    obj.outputs[6].script.should.equal('4e');
  });

  it('#toObject roundtrip will handle an invalid (null) script', () => {
    const invalidOutputScript = new Buffer('0100000000000000014c', 'hex');
    const br = new BitcoreLib.encoding.BufferReader(invalidOutputScript);
    const output3 = Output.fromBufferReader(br);
    const output4 = new Output(output.toObject());
    should().equal(output3.script, null);
    should().equal(output3._scriptBuffer.toString('hex'), '4c');
  });

  it('inspect will work with an invalid (null) script', () => {
    const invalidOutputScript = new Buffer('0100000000000000014c', 'hex');
    const br = new BitcoreLib.encoding.BufferReader(invalidOutputScript);
    const output3 = Output.fromBufferReader(br);
    output3.inspect().should.equal('<Output (1 sats) 4c>');
  });

  it('roundtrips to/from JSON', () => {
    const json = JSON.stringify(output2);
    const o3 = new Output(JSON.parse(json));
    JSON.stringify(o3).should.equal(json);
  });

  it('setScript fails with invalid input', () => {
    const out = new Output(output2.toJSON());
    out.setScript.bind(out, 45).should.throw('Invalid argument type: script');
  });

  it('sets script to null if it is an InvalidBuffer', () => {
    const output3 = new Output({
      satoshis: 1000,
      script: new Buffer('4c', 'hex')
    });
    should().equal(output3.script, null);
  });
});
