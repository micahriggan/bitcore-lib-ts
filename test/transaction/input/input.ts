'use strict';

import { BitcoreLib } from '../../../src';
import { BitcoreError } from '../../../src/errors';

const errors = BitcoreLib.errors;
const PrivateKey = BitcoreLib.PrivateKey;
const Address = BitcoreLib.Address;
const Script = BitcoreLib.Script;
const Networks = BitcoreLib.Network;
const Input = BitcoreLib.Transaction.Input;

describe('Transaction.Input', () => {
  const privateKey = new PrivateKey(
    'KwF9LjRraetZuEjR8VqEq539z137LW5anYDUnVK11vM3mNMHTWb4'
  );
  const publicKey = privateKey.publicKey;
  const address = new Address(publicKey, Networks.livenet);
  const output = {
    address: '33zbk2aSZYdNbRsMPPt6jgy6Kq1kQreqeb',
    prevTxId:
      '66e64ef8a3b384164b78453fa8c8194de9a473ba14f89485a0e433699daec140',
    outputIndex: 0,
    script: new Script(address),
    satoshis: 1000000
  };
  const coinbase = {
    prevTxId:
      '0000000000000000000000000000000000000000000000000000000000000000',
    outputIndex: 0xffffffff,
    script: new Script(),
    satoshis: 1000000
  };

  const coinbaseJSON = JSON.stringify({
    prevTxId:
      '0000000000000000000000000000000000000000000000000000000000000000',
    outputIndex: 4294967295,
    script: ''
  });

  const otherJSON = JSON.stringify({
    txidbuf: 'a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458',
    txoutnum: 0,
    seqnum: 4294967295,
    script:
      '71 0x3044022006553276ec5b885ddf5cc1d79e1e3dadbb404b60ad4cc00318e21565' +
      '4f13242102200757c17b36e3d0492fb9cf597032e5afbea67a59274e64af5a05d12e5ea2303901 ' +
      '33 0x0223078d2942df62c45621d209fab84ea9a7a23346201b7727b9b45a29c4e76f5e',
    output: {
      satoshis: 100000,
      script:
        'OP_DUP OP_HASH160 20 0x88d9931ea73d60eaf7e5671efc0552b912911f2a ' +
        'OP_EQUALVERIFY OP_CHECKSIG'
    }
  });

  it('has abstract methods: "getSignatures", "isFullySigned", "addSignature", "clearSignatures"', () => {
    const input = new Input(output);
    _.each(
      ['getSignatures', 'isFullySigned', 'addSignature', 'clearSignatures'],
      method => {
        expect(() => {
          return input[method]();
        }).to.throw(new BitcoreError(errors.Types.AbstractMethodInvoked));
      }
    );
  });
  it('detects coinbase transactions', () => {
    new Input(output).isNull().should.equal(false);
    const ci = new Input(coinbase);
    ci.isNull().should.equal(true);
  });

  describe('instantiation', () => {
    it('works without new', () => {
      const input = Input();
      should.exist(input);
    });
    it('fails with no script info', () => {
      expect(() => {
        const input = new Input({});
        input.toString();
      }).to.throw('Need a script to create an input');
    });
    it('fromObject should work', () => {
      const jsonData = JSON.parse(coinbaseJSON);
      const input = Input.fromObject(jsonData);
      should.exist(input);
      input.prevTxId.toString('hex').should.equal(jsonData.prevTxId);
      input.outputIndex.should.equal(jsonData.outputIndex);
    });
    it('fromObject should work', () => {
      const input = Input.fromObject(JSON.parse(coinbaseJSON));
      const obj = input.toObject();
      Input.fromObject(obj).should.deep.equal(input);
      obj.script = 42;
      Input.fromObject
        .bind(null, obj)
        .should.throw('Invalid argument type: script');
    });
  });

  it('_estimateSize returns correct size', () => {
    const input = new Input(output);
    input._estimateSize().should.equal(66);
  });
});
