import * as _ from 'lodash';
import { MultiSigScriptHashInput } from '../../../src/transaction/input/multisigscripthash';
import { BitcoreLib } from '../../../src';
const Transaction = BitcoreLib.Transaction;
const PrivateKey = BitcoreLib.PrivateKey;
const Address = BitcoreLib.Address;
const Script = BitcoreLib.Script;
const Signature = BitcoreLib.crypto.Signature;

describe('MultiSigScriptHashInput', () => {
  const privateKey1 = new PrivateKey(
    'KwF9LjRraetZuEjR8VqEq539z137LW5anYDUnVK11vM3mNMHTWb4'
  );
  const privateKey2 = new PrivateKey(
    'L4PqnaPTCkYhAqH3YQmefjxQP6zRcF4EJbdGqR8v6adtG9XSsadY'
  );
  const privateKey3 = new PrivateKey(
    'L4CTX79zFeksZTyyoFuPQAySfmP7fL3R41gWKTuepuN7hxuNuJwV'
  );
  const public1 = privateKey1.publicKey;
  const public2 = privateKey2.publicKey;
  const public3 = privateKey3.publicKey;
  const address = new Address('33zbk2aSZYdNbRsMPPt6jgy6Kq1kQreqeb');

  const output = {
    address: '33zbk2aSZYdNbRsMPPt6jgy6Kq1kQreqeb',
    txId: '66e64ef8a3b384164b78453fa8c8194de9a473ba14f89485a0e433699daec140',
    outputIndex: 0,
    script: new Script(address),
    satoshis: 1000000
  };
  it('can count missing signatures', () => {
    const transaction = new Transaction()
      .from(output, [public1, public2, public3], 2)
      .to(address, 1000000);
    const input = transaction.inputs[0] as MultiSigScriptHashInput;

    input.countSignatures().should.equal(0);

    transaction.sign(privateKey1);
    input.countSignatures().should.equal(1);
    input.countMissingSignatures().should.equal(1);
    input.isFullySigned().should.equal(false);

    transaction.sign(privateKey2);
    input.countSignatures().should.equal(2);
    input.countMissingSignatures().should.equal(0);
    input.isFullySigned().should.equal(true);
  });
  it('returns a list of public keys with missing signatures', () => {
    const transaction = new Transaction()
      .from(output, [public1, public2, public3], 2)
      .to(address, 1000000);
    const input = transaction.inputs[0] as MultiSigScriptHashInput;

    _.every(input.publicKeysWithoutSignature(), publicKeyMissing => {
      const serialized = publicKeyMissing.toString();
      return (
        serialized === public1.toString() ||
        serialized === public2.toString() ||
        serialized === public3.toString()
      );
    }).should.equal(true);
    transaction.sign(privateKey1);
    _.every(input.publicKeysWithoutSignature(), publicKeyMissing => {
      const serialized = publicKeyMissing.toString();
      return (
        serialized === public2.toString() || serialized === public3.toString()
      );
    }).should.equal(true);
  });
  it('can clear all signatures', () => {
    const transaction = new Transaction()
      .from(output, [public1, public2, public3], 2)
      .to(address, 1000000)
      .sign(privateKey1)
      .sign(privateKey2);

    const input = transaction.inputs[0];
    input.isFullySigned().should.equal(true);
    input.clearSignatures();
    input.isFullySigned().should.equal(false);
  });
  it('can estimate how heavy is the output going to be', () => {
    const transaction = new Transaction()
      .from(output, [public1, public2, public3], 2)
      .to(address, 1000000);
    const input = transaction.inputs[0];
    input._estimateSize().should.equal(257);
  });
  it('uses SIGHASH_ALL by default', () => {
    const transaction = new Transaction()
      .from(output, [public1, public2, public3], 2)
      .to(address, 1000000);
    const input = transaction.inputs[0];
    const sigs = input.getSignatures(transaction, privateKey1, 0);
    sigs[0].sigtype.should.equal(Signature.SIGHASH_ALL);
  });
  it('roundtrips to/from object', () => {
    const transaction = new Transaction()
      .from(output, [public1, public2, public3], 2)
      .to(address, 1000000)
      .sign(privateKey1);
    const input = transaction.inputs[0];
    const roundtrip = new MultiSigScriptHashInput(input.toObject());
    roundtrip.toObject().should.deep.equal(input.toObject());
  });
  it('roundtrips to/from object when not signed', () => {
    const transaction = new Transaction()
      .from(output, [public1, public2, public3], 2)
      .to(address, 1000000);
    const input = transaction.inputs[0];
    const roundtrip = new MultiSigScriptHashInput(input.toObject());
    roundtrip.toObject().should.deep.equal(input.toObject());
  });
  it('will get the scriptCode for nested witness', () => {
    const address2 = Address.createMultisig(
      [public1, public2, public3],
      2,
      'testnet',
      true
    );
    const utxo = {
      address: address2.toString(),
      txId: '66e64ef8a3b384164b78453fa8c8194de9a473ba14f89485a0e433699daec140',
      outputIndex: 0,
      script: new Script(address2),
      satoshis: 1000000
    };
    const transaction = new Transaction()
      .from(utxo, [public1, public2, public3], 2, true)
      .to(address, 1000000);
    const input = transaction.inputs[0] as MultiSigScriptHashInput;
    const scriptCode = input.getScriptCode();
    scriptCode
      .toString('hex')
      .should.equal(
        '695221025c95ec627038e85b5688a9b3d84d28c5ebe66e8c8d697d498e20fe96e3b1ab1d2102cdddfc974d41a62f1f80081deee70592feb7d6e6cf6739d6592edbe7946720e72103c95924e02c240b5545089c69c6432447412b58be43fd671918bd184a5009834353ae'
      );
  });
  it('will get the satoshis buffer for nested witness', () => {
    const address2 = Address.createMultisig(
      [public1, public2, public3],
      2,
      'testnet',
      true
    );
    const utxo = {
      address: address2.toString(),
      txId: '66e64ef8a3b384164b78453fa8c8194de9a473ba14f89485a0e433699daec140',
      outputIndex: 0,
      script: new Script(address),
      satoshis: 1000000
    };
    const transaction = new Transaction()
      .from(utxo, [public1, public2, public3], 2, true)
      .to(address2, 1000000);
    const input = transaction.inputs[0];
    const satoshisBuffer = input.getSatoshisBuffer();
    satoshisBuffer.toString('hex').should.equal('40420f0000000000');
  });
});
