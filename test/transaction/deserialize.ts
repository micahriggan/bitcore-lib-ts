'use strict';

import { Transaction } from '../../src/transaction/transaction';
const vectors_valid = require('../data/bitcoind/tx_valid.json');
const vectors_invalid = require('../data/bitcoind/tx_invalid.json');

describe('Transaction deserialization', () => {
  describe('valid transaction test case', () => {
    let index = 0;
    vectors_valid.forEach((vector) => {
      it('vector #' + index, () => {
        if (vector.length > 1) {
          const hexa = vector[1];
          new Transaction(hexa)
            .serialize(true)
            .should.equal(hexa);
          index++;
        }
      });
    });
  });
  describe('invalid transaction test case', () => {
    let index = 0;
    vectors_invalid.forEach((vector) => {
      it('invalid vector #' + index, () => {
        if (vector.length > 1) {
          const hexa = vector[1];
          new Transaction(hexa)
            .serialize(true)
            .should.equal(hexa);
          index++;
        }
      });
    });
  });
});
