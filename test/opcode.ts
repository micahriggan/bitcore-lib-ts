'use strict';

import * as _ from 'lodash';
import { should, expect } from 'chai';
import { BitcoreLib } from '../src';
const Opcode = BitcoreLib.Opcode;

describe('Opcode', () => {
  it('should create a new Opcode', () => {
    const opcode = new Opcode(5);
    should().exist(opcode);
  });

  it('should convert to a string with this handy syntax', () => {
    new Opcode(0).toString().should.equal('OP_0');
    new Opcode(96).toString().should.equal('OP_16');
    new Opcode(97).toString().should.equal('OP_NOP');
  });

  it('should convert to a number with this handy syntax', () => {
    new Opcode('OP_0').toNumber().should.equal(0);
    new Opcode('OP_16').toNumber().should.equal(96);
    new Opcode('OP_NOP').toNumber().should.equal(97);
  });

  describe('#fromNumber', () => {
    it('should work for 0', () => {
      Opcode.fromNumber(0).num.should.equal(0);
    });
    it('should fail for non-number', () => {
      Opcode.fromNumber.bind(null, 'a string').should.throw('Invalid Argument');
    });
  });

  describe('#set', () => {
    it('should work for object', () => {
      new Opcode(42).num.should.equal(42);
    });
    it('should fail for empty-object', () => {
      expect(() => {
        const x = new (Opcode as any)();
      }).to.throw(TypeError);
    });
  });

  describe('#toNumber', () => {
    it('should work for 0', () => {
      Opcode.fromNumber(0)
        .toNumber()
        .should.equal(0);
    });
  });

  describe('#buffer', () => {
    it('should correctly input/output a buffer', () => {
      const buf = new Buffer('a6', 'hex');
      Opcode.fromBuffer(buf)
        .toBuffer()
        .should.deep.equal(buf);
    });
  });

  describe('#fromString', () => {
    it('should work for OP_0', () => {
      Opcode.fromString('OP_0').num.should.equal(0);
    });
    it('should fail for invalid string', () => {
      Opcode.fromString
        .bind(null, 'OP_SATOSHI')
        .should.throw('Invalid opcodestr');
      Opcode.fromString.bind(null, 'BANANA').should.throw('Invalid opcodestr');
    });
    it('should fail for non-string', () => {
      Opcode.fromString.bind(null, 123).should.throw('Invalid Argument');
    });
  });

  describe('#toString', () => {
    it('should work for OP_0', () => {
      Opcode.fromString('OP_0')
        .toString()
        .should.equal('OP_0');
    });

    it('should not work for non-opcode', () => {
      expect(() => {
        new Opcode('OP_NOTACODE').toString();
      }).to.throw('Opcode does not have a string representation');
    });
  });

  describe('@map', () => {
    it('should have a map containing 117 elements', () => {
      _.size(Opcode.map).should.equal(117);
    });
  });

  describe('@reverseMap', () => {
    it('should exist and have op 185', () => {
      should().exist(Opcode.reverseMap);
      Opcode.reverseMap[185].should.equal('OP_NOP10');
    });
  });
  const smallints = [
    new Opcode('OP_0'),
    new Opcode('OP_1'),
    new Opcode('OP_2'),
    new Opcode('OP_3'),
    new Opcode('OP_4'),
    new Opcode('OP_5'),
    new Opcode('OP_6'),
    new Opcode('OP_7'),
    new Opcode('OP_8'),
    new Opcode('OP_9'),
    new Opcode('OP_10'),
    new Opcode('OP_11'),
    new Opcode('OP_12'),
    new Opcode('OP_13'),
    new Opcode('OP_14'),
    new Opcode('OP_15'),
    new Opcode('OP_16')
  ];

  describe('@smallInt', () => {
    const testSmallInt = (n, op) => {
      Opcode.smallInt(n)
        .toString()
        .should.equal(op.toString());
    };

    for (let i = 0; i < smallints.length; i++) {
      const op = smallints[i];
      it('should work for small int ' + op, testSmallInt.bind(null, i, op));
    }

    it('with not number', () => {
      Opcode.smallInt.bind(null, '2').should.throw('Invalid Argument');
    });

    it('with n equal -1', () => {
      Opcode.smallInt.bind(null, -1).should.throw('Invalid Argument');
    });

    it('with n equal 17', () => {
      Opcode.smallInt.bind(null, 17).should.throw('Invalid Argument');
    });
  });
  describe('@isSmallIntOp', () => {
    const testIsSmallInt = op => {
      Opcode.isSmallIntOp(op).should.equal(true);
    };
    for (const op of smallints) {
      it('should work for small int ' + op, testIsSmallInt.bind(null, op));
    }

    it('should work for non-small ints', () => {
      Opcode.isSmallIntOp(new Opcode('OP_RETURN')).should.equal(false);
      Opcode.isSmallIntOp(new Opcode('OP_CHECKSIG')).should.equal(false);
      Opcode.isSmallIntOp(new Opcode('OP_IF')).should.equal(false);
      Opcode.isSmallIntOp(new Opcode('OP_NOP')).should.equal(false);
    });
  });

  describe('#inspect', () => {
    it('should output opcode by name, hex, and decimal', () => {
      Opcode.fromString('OP_NOP')
        .inspect()
        .should.equal('<Opcode: OP_NOP, hex: 61, decimal: 97>');
    });
  });
});
