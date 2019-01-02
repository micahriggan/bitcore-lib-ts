'use strict';
/* jshint unused: false */

import * as _ from 'lodash';

import { BitcoreLib } from '../../../src';
import { should, expect } from 'chai';
const Transaction = BitcoreLib.Transaction;
const PrivateKey = BitcoreLib.PrivateKey;
const Address = BitcoreLib.Address;
const Script = BitcoreLib.Script;
const Networks = BitcoreLib.Network;
const Signature = BitcoreLib.crypto.Signature;

describe('PublicKeyHashInput', () => {
  const privateKey = new PrivateKey(
    'KwF9LjRraetZuEjR8VqEq539z137LW5anYDUnVK11vM3mNMHTWb4'
  );
  const publicKey = privateKey.publicKey;
  const address = new Address(publicKey, Networks.livenet);

  const output = {
    address: '33zbk2aSZYdNbRsMPPt6jgy6Kq1kQreqeb',
    txId: '66e64ef8a3b384164b78453fa8c8194de9a473ba14f89485a0e433699daec140',
    outputIndex: 0,
    script: new Script(address),
    satoshis: 1000000
  };
  it('can count missing signatures', () => {
    const transaction = new Transaction().from(output).to(address, 1000000);
    const input = transaction.inputs[0];

    input.isFullySigned().should.equal(false);
    transaction.sign(privateKey);
    input.isFullySigned().should.equal(true);
  });
  it("it's size can be estimated", () => {
    const transaction = new Transaction().from(output).to(address, 1000000);
    const input = transaction.inputs[0];
    input._estimateSize().should.equal(107);
  });
  it("it's signature can be removed", () => {
    const transaction = new Transaction().from(output).to(address, 1000000);
    const input = transaction.inputs[0];

    transaction.sign(privateKey);
    input.clearSignatures();
    input.isFullySigned().should.equal(false);
  });
  it('returns an empty array if private key mismatches', () => {
    const transaction = new Transaction().from(output).to(address, 1000000);
    const input = transaction.inputs[0];
    const signatures = input.getSignatures(transaction, new PrivateKey(), 0);
    signatures.length.should.equal(0);
  });
});
