'use strict';

import { Buffer } from 'buffer';

import { BitcoreLib } from '../../src';
const Script = BitcoreLib.Script;
const Transaction = BitcoreLib.Transaction;
const sighash = Transaction.Sighash;

const vectors_sighash = require('../data/sighash.json');

describe('sighash', () => {
  vectors_sighash.forEach((vector, i) => {
    if (i === 0) {
      // First element is just a row describing the next ones
      return;
    }
    it(
      'test vector from bitcoind #' +
        i +
        ' (' +
        vector[4].substring(0, 16) +
        ')',
      () => {
        const txbuf = new Buffer(vector[0], 'hex');
        const scriptbuf = new Buffer(vector[1], 'hex');
        const subscript = new Script(scriptbuf);
        const nin = vector[2];
        const nhashtype = vector[3];
        const sighashbuf = new Buffer(vector[4], 'hex');
        const tx = new Transaction(txbuf);

        // make sure transacion to/from buffer is isomorphic
        tx.uncheckedSerialize().should.equal(txbuf.toString('hex'));

        // sighash ought to be correct
        sighash
          .sighash(tx, nhashtype, nin, subscript)
          .toString('hex')
          .should.equal(sighashbuf.toString('hex'));
      }
    );
  });
});
