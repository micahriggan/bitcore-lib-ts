'use strict';

import { BitcoreLib } from '../../src';
const BN = BitcoreLib.crypto.BN;
const BufferReader = BitcoreLib.encoding.BufferReader;
const BufferWriter = BitcoreLib.encoding.BufferWriter;
const Varint = BitcoreLib.encoding.Varint;

describe('Varint', () => {
  it('should make a new varint', () => {
    const buf = new Buffer('00', 'hex');
    let varint = new Varint(buf);
    should.exist(varint);
    varint.buf.toString('hex').should.equal('00');
    varint = new Varint(buf);
    should.exist(varint);
    varint.buf.toString('hex').should.equal('00');

    // various ways to use the constructor
    new Varint(new Varint(0).toBuffer()).toNumber().should.equal(0);
    new Varint(0).toNumber().should.equal(0);
    new Varint(new BN(0)).toNumber().should.equal(0);
  });

  describe('#set', () => {
    it('should set a buffer', () => {
      const buf = new Buffer('00', 'hex');
      const varint = new Varint().set({ buf });
      varint.buf.toString('hex').should.equal('00');
      varint.set({});
      varint.buf.toString('hex').should.equal('00');
    });
  });

  describe('#fromString', () => {
    it('should set a buffer', () => {
      const buf = new BufferWriter().writeVarintNum(5).concat();
      const varint = new Varint().fromString(buf.toString('hex'));
      varint.toNumber().should.equal(5);
    });
  });

  describe('#toString', () => {
    it('should return a buffer', () => {
      const buf = new BufferWriter().writeVarintNum(5).concat();
      const varint = new Varint().fromString(buf.toString('hex'));
      varint.toString().should.equal('05');
    });
  });

  describe('#fromBuffer', () => {
    it('should set a buffer', () => {
      const buf = new BufferWriter().writeVarintNum(5).concat();
      const varint = new Varint().fromBuffer(buf);
      varint.toNumber().should.equal(5);
    });
  });

  describe('#fromBufferReader', () => {
    it('should set a buffer reader', () => {
      const buf = new BufferWriter().writeVarintNum(5).concat();
      const br = new BufferReader(buf);
      const varint = new Varint().fromBufferReader(br);
      varint.toNumber().should.equal(5);
    });
  });

  describe('#fromBN', () => {
    it('should set a number', () => {
      const varint = new Varint().fromBN(new BN(5));
      varint.toNumber().should.equal(5);
    });
  });

  describe('#fromNumber', () => {
    it('should set a number', () => {
      const varint = new Varint().fromNumber(5);
      varint.toNumber().should.equal(5);
    });
  });

  describe('#toBuffer', () => {
    it('should return a buffer', () => {
      const buf = new BufferWriter().writeVarintNum(5).concat();
      const varint = new Varint(buf);
      varint
        .toBuffer()
        .toString('hex')
        .should.equal(buf.toString('hex'));
    });
  });

  describe('#toBN', () => {
    it('should return a buffer', () => {
      const varint = new Varint(5);
      varint
        .toBN()
        .toString()
        .should.equal(new BN(5).toString());
    });
  });

  describe('#toNumber', () => {
    it('should return a buffer', () => {
      const varint = new Varint(5);
      varint.toNumber().should.equal(5);
    });
  });
});
