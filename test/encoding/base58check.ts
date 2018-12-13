'use strict';
import * as chai from 'chai';
import { Buffer } from 'buffer';
import { BitcoreLib } from '../../src';

const Base58Check = BitcoreLib.encoding.Base58Check;
const Base58 = BitcoreLib.encoding.Base58;

describe('Base58Check', () => {
  const buf = Buffer.from([0, 1, 2, 3, 253, 254, 255]);
  const enc = '14HV44ipwoaqfg';

  it('should make an instance with "new"', () => {
    const b58 = new Base58Check();
    should.exist(b58);
  });

  it('can validate a serialized string', () => {
    let address = '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy';
    Base58Check.validChecksum(address).should.equal(true);
    address = address + 'a';
    Base58Check.validChecksum(address).should.equal(false);
  });

  it('should make an instance without "new"', () => {
    const b58 = new Base58Check();
    should.exist(b58);
  });

  it('should allow this handy syntax', () => {
    new Base58Check(buf).toString().should.equal(enc);
    new Base58Check(enc)
      .toBuffer()
      .toString('hex')
      .should.equal(buf.toString('hex'));
  });

  describe('#set', () => {
    it('should set a buf', () => {
      should.exist(new Base58Check().set({ buf }).buf);
    });
  });

  describe('@encode', () => {
    it('should encode the buffer accurately', () => {
      Base58Check.encode(buf).should.equal(enc);
    });

    it('should throw an error when the input is not a buffer', () => {
      (() => {
        Base58Check.encode('string');
      }).should.throw('Input must be a buffer');
    });
  });

  describe('@decode', () => {
    it('should decode this encoded value correctly', () => {
      Base58Check.decode(enc)
        .toString('hex')
        .should.equal(buf.toString('hex'));
    });

    it('should throw an error when input is not a string', () => {
      (() => {
        Base58Check.decode(5);
      }).should.throw('Input must be a string');
    });

    it('should throw an error when input is too short', () => {
      (() => {
        Base58Check.decode(enc.slice(0, 1));
      }).should.throw('Input string too short');
    });

    it('should throw an error when there is a checksum mismatch', () => {
      const buf2 = Base58.decode(enc);
      buf2[0] = buf2[0] + 1;
      const enc2 = Base58.encode(buf2);
      (() => {
        Base58Check.decode(enc2);
      }).should.throw('Checksum mismatch');
    });
  });

  describe('#fromBuffer', () => {
    it('should not fail', () => {
      should.exist(new Base58Check().fromBuffer(buf));
    });

    it('should set buffer', () => {
      const b58 = new Base58Check().fromBuffer(buf);
      b58.buf.toString('hex').should.equal(buf.toString('hex'));
    });
  });

  describe('#fromString', () => {
    it('should convert this known string to a buffer', () => {
      new Base58Check()
        .fromString(enc)
        .toBuffer()
        .toString('hex')
        .should.equal(buf.toString('hex'));
    });
  });

  describe('#toBuffer', () => {
    it('should return the buffer', () => {
      const b58 = new Base58Check({ buf });
      b58.buf.toString('hex').should.equal(buf.toString('hex'));
    });
  });

  describe('#toString', () => {
    it('should return the buffer', () => {
      const b58 = new Base58Check({ buf });
      b58.toString().should.equal(enc);
    });
  });
});
