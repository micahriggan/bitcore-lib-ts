'use strict';

import * as _ from 'lodash';
import * as sinon from 'sinon';
import { BitcoreLib } from '../../src';
const Interpreter = BitcoreLib.Script.Interpreter;
const Transaction = BitcoreLib.Transaction;
const PrivateKey = BitcoreLib.PrivateKey;
const Script = BitcoreLib.Script;
const BN = BitcoreLib.crypto.BN;
const BufferWriter = BitcoreLib.encoding.BufferWriter;
const Opcode = BitcoreLib.Opcode;

const script_valid = require('../data/bitcoind/script_valid');
const script_invalid = require('../data/bitcoind/script_invalid');
const tx_valid = require('../data/bitcoind/tx_valid');
const tx_invalid = require('../data/bitcoind/tx_invalid');

// the script string format used in bitcoind data tests
Script.fromBitcoindString = str => {
  const bw = new BufferWriter();
  const tokens = str.split(' ');
  for (const token of tokens) {
    if (token === '') {
      continue;
    }

    let opstr;
    let opcodenum;
    let tbuf;
    if (token[0] === '0' && token[1] === 'x') {
      const hex = token.slice(2);
      bw.write(new Buffer(hex, 'hex'));
    } else if (token[0] === "'") {
      const tstr = token.slice(1, token.length - 1);
      const cbuf = new Buffer(tstr);
      tbuf = new Script().add(cbuf).toBuffer();
      bw.write(tbuf);
    } else if (typeof Opcode['OP_' + token] !== 'undefined') {
      opstr = 'OP_' + token;
      opcodenum = Opcode[opstr];
      bw.writeUInt8(opcodenum);
    } else if (typeof Opcode[token] === 'number') {
      opstr = token;
      opcodenum = Opcode[opstr];
      bw.writeUInt8(opcodenum);
    } else if (!isNaN(parseInt(token, 10))) {
      const script = new Script().add(new BN(token).toScriptNumBuffer());
      tbuf = script.toBuffer();
      bw.write(tbuf);
    } else {
      throw new Error('Could not determine type of script value');
    }
  }
  const buf = bw.concat();
  return this.fromBuffer(buf);
};

describe('Interpreter', () => {
  it('should make a new interp', () => {
    const interp = new Interpreter();
    (interp instanceof Interpreter).should.equal(true);
    interp.stack.length.should.equal(0);
    interp.altstack.length.should.equal(0);
    interp.pc.should.equal(0);
    interp.pbegincodehash.should.equal(0);
    interp.nOpCount.should.equal(0);
    interp.vfExec.length.should.equal(0);
    interp.errstr.should.equal('');
    interp.flags.should.equal(0);
  });

  describe('@castToBool', () => {
    it('should cast these bufs to bool correctly', () => {
      Interpreter.castToBool(
        new BN(0).toSM({
          endian: 'little'
        })
      ).should.equal(false);
      Interpreter.castToBool(new Buffer('0080', 'hex')).should.equal(false); // negative 0
      Interpreter.castToBool(
        new BN(1).toSM({
          endian: 'little'
        })
      ).should.equal(true);
      Interpreter.castToBool(
        new BN(-1).toSM({
          endian: 'little'
        })
      ).should.equal(true);

      const buf = new Buffer('00', 'hex');
      const bool =
        BN.fromSM(buf, {
          endian: 'little'
        }).cmp(BN.Zero) !== 0;
      Interpreter.castToBool(buf).should.equal(bool);
    });
  });

  describe('#verifyWitnessProgram', () => {
    it('will return true if witness program greater than 0', () => {
      const si = new Interpreter();
      const version = 1;
      const program = new Buffer(
        'bcbd1db07ce89d1f4050645c26c90ce78b67eff78460002a4d5c10410958e064',
        'hex'
      );
      const witness = [
        new Buffer(
          'bda0eeeb166c8bfeaee88dedc8efa82d3bea35aac5be253902f59d52908bfe25',
          'hex'
        )
      ];
      const satoshis = 1;
      const flags = 0;
      si.verifyWitnessProgram(
        version,
        program,
        witness,
        satoshis,
        flags
      ).should.equal(true);
    });
    it('will return false with error if witness length is 0', () => {
      const si = new Interpreter();
      const version = 0;
      const program = new Buffer(
        'bcbd1db07ce89d1f4050645c26c90ce78b67eff78460002a4d5c10410958e064',
        'hex'
      );
      const witness = [];
      const satoshis = 1;
      const flags = 0;
      si.verifyWitnessProgram(
        version,
        program,
        witness,
        satoshis,
        flags
      ).should.equal(false);
      si.errstr.should.equal('SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY');
    });
    it('will return false if program hash mismatch (version 0, 32 byte program)', () => {
      const si = new Interpreter();
      const version = 0;
      const program = new Buffer(
        '0000000000000000000000000000000000000000000000000000000000000000',
        'hex'
      );
      const witness = [
        new Buffer(
          '0000000000000000000000000000000000000000000000000000000000000000',
          'hex'
        ),
        new Buffer(
          '0000000000000000000000000000000000000000000000000000000000000000',
          'hex'
        )
      ];
      const satoshis = 1;
      const flags = 0;
      si.verifyWitnessProgram(
        version,
        program,
        witness,
        satoshis,
        flags
      ).should.equal(false);
      si.errstr.should.equal('SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH');
    });
    it("will return false if witness stack doesn't have two items (version 0, 20 byte program)", () => {
      const si = new Interpreter();
      const version = 0;
      const program = new Buffer(
        'b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc6',
        'hex'
      );
      const witness = [
        new Buffer(
          '0000000000000000000000000000000000000000000000000000000000000000',
          'hex'
        ),
        new Buffer(
          '0000000000000000000000000000000000000000000000000000000000000000',
          'hex'
        ),
        new Buffer(
          '0000000000000000000000000000000000000000000000000000000000000000',
          'hex'
        )
      ];
      const satoshis = 1;
      const flags = 0;
      si.verifyWitnessProgram(
        version,
        program,
        witness,
        satoshis,
        flags
      ).should.equal(false);
      si.errstr.should.equal('SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH');
    });
    it('will return false if program wrong length for version 0', () => {
      const si = new Interpreter();
      const version = 0;
      const program = new Buffer('b8bcb07f6344b42ab04250c86a6e8b75d3', 'hex');
      const witness = [
        new Buffer(
          '0000000000000000000000000000000000000000000000000000000000000000',
          'hex'
        )
      ];
      const satoshis = 1;
      const flags = 0;
      si.verifyWitnessProgram(
        version,
        program,
        witness,
        satoshis,
        flags
      ).should.equal(false);
      si.errstr.should.equal('SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH');
    });
    it('will return false with discourage upgradable witness program', () => {
      const si = new Interpreter();
      const version = 1;
      const program = new Buffer(
        'b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc6',
        'hex'
      );
      const witness = [
        new Buffer(
          '0000000000000000000000000000000000000000000000000000000000000000',
          'hex'
        ),
        new Buffer(
          '0000000000000000000000000000000000000000000000000000000000000000',
          'hex'
        )
      ];
      const satoshis = 1;
      const flags =
        Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;
      si.verifyWitnessProgram(
        version,
        program,
        witness,
        satoshis,
        flags
      ).should.equal(false);
      si.errstr.should.equal(
        'SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM'
      );
    });
    it("will return false with error if stack doesn't have exactly one item", () => {
      const si = new Interpreter();
      si.evaluate = sinon.stub().returns(true);
      const version = 0;
      const program = new Buffer(
        'b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc6',
        'hex'
      );
      const witness = [
        new Buffer(
          '0000000000000000000000000000000000000000000000000000000000000000',
          'hex'
        ),
        new Buffer(
          '0000000000000000000000000000000000000000000000000000000000000000',
          'hex'
        )
      ];
      const satoshis = 1;
      const flags = 0;
      si.verifyWitnessProgram(
        version,
        program,
        witness,
        satoshis,
        flags
      ).should.equal(false);
      si.errstr.should.equal('SCRIPT_ERR_EVAL_FALSE');
    });
    it('will return false if last item in stack casts to false', () => {
      const si = new Interpreter();
      si.evaluate = () => {
        si.stack = [new Buffer('00', 'hex')];
        return true;
      };
      const version = 0;
      const program = new Buffer(
        'b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc6',
        'hex'
      );
      const witness = [
        new Buffer(
          '0000000000000000000000000000000000000000000000000000000000000000',
          'hex'
        ),
        new Buffer(
          '0000000000000000000000000000000000000000000000000000000000000000',
          'hex'
        )
      ];
      const satoshis = 1;
      const flags = 0;
      si.verifyWitnessProgram(
        version,
        program,
        witness,
        satoshis,
        flags
      ).should.equal(false);
      si.errstr.should.equal('SCRIPT_ERR_EVAL_FALSE_IN_STACK');
    });
  });

  describe('#verify', () => {
    it('should verify these trivial scripts', () => {
      let verified;
      const si = new Interpreter();
      verified = si.verify(new Script('OP_1'), Script('OP_1'));
      verified.should.equal(true);
      verified = new Interpreter().verify(new Script('OP_1'), Script('OP_0'));
      verified.should.equal(false);
      verified = new Interpreter().verify(new Script('OP_0'), Script('OP_1'));
      verified.should.equal(true);
      verified = new Interpreter().verify(
        Script('OP_CODESEPARATOR'),
        Script('OP_1')
      );
      verified.should.equal(true);
      verified = Interpreter().verify(
        Script(''),
        Script('OP_DEPTH OP_0 OP_EQUAL')
      );
      verified.should.equal(true);
      verified = Interpreter().verify(
        Script('OP_1 OP_2'),
        Script('OP_2 OP_EQUALVERIFY OP_1 OP_EQUAL')
      );
      verified.should.equal(true);
      verified = Interpreter().verify(
        Script('9 0x000000000000000010'),
        Script('')
      );
      verified.should.equal(true);
      verified = Interpreter().verify(
        Script('OP_1'),
        Script('OP_15 OP_ADD OP_16 OP_EQUAL')
      );
      verified.should.equal(true);
      verified = Interpreter().verify(
        Script('OP_0'),
        Script('OP_IF OP_VER OP_ELSE OP_1 OP_ENDIF')
      );
      verified.should.equal(true);
    });

    it('should verify these simple transaction', () => {
      // first we create a transaction
      const privateKey = new PrivateKey(
        'cSBnVM4xvxarwGQuAfQFwqDg9k5tErHUHzgWsEfD4zdwUasvqRVY'
      );
      const publicKey = privateKey.publicKey;
      const fromAddress = publicKey.toAddress();
      const toAddress = 'mrU9pEmAx26HcbKVrABvgL7AwA5fjNFoDc';
      const scriptPubkey = Script.buildPublicKeyHashOut(fromAddress);
      const utxo = {
        address: fromAddress,
        txId:
          'a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458',
        outputIndex: 0,
        script: scriptPubkey,
        satoshis: 100000
      };
      const tx = new Transaction()
        .from(utxo)
        .to(toAddress, 100000)
        .sign(privateKey);

      // we then extract the signature from the first input
      const inputIndex = 0;
      const signature = tx.getSignatures(privateKey)[inputIndex].signature;

      const scriptSig = Script.buildPublicKeyHashIn(publicKey, signature);
      const flags =
        Interpreter.SCRIPT_VERIFY_P2SH | Interpreter.SCRIPT_VERIFY_STRICTENC;
      const verified = Interpreter().verify(
        scriptSig,
        scriptPubkey,
        tx,
        inputIndex,
        flags
      );
      verified.should.equal(true);
    });
  });

  function getFlags(flagstr) {
    let flags = 0;
    if (flagstr.indexOf('NONE') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_NONE;
    }
    if (flagstr.indexOf('P2SH') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_P2SH;
    }
    if (flagstr.indexOf('STRICTENC') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_STRICTENC;
    }
    if (flagstr.indexOf('DERSIG') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_DERSIG;
    }
    if (flagstr.indexOf('LOW_S') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_LOW_S;
    }
    if (flagstr.indexOf('NULLDUMMY') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_NULLDUMMY;
    }
    if (flagstr.indexOf('SIGPUSHONLY') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_SIGPUSHONLY;
    }
    if (flagstr.indexOf('MINIMALDATA') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_MINIMALDATA;
    }
    if (flagstr.indexOf('DISCOURAGE_UPGRADABLE_NOPS') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
    }
    if (flagstr.indexOf('CHECKLOCKTIMEVERIFY') !== -1) {
      flags = flags | Interpreter.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    }
    return flags;
  }

  const testToFromString = script => {
    const s = script.toString();
    Script.fromString(s)
      .toString()
      .should.equal(s);
  };

  const testFixture = (vector, expected) => {
    const scriptSig = Script.fromBitcoindString(vector[0]);
    const scriptPubkey = Script.fromBitcoindString(vector[1]);
    const flags = getFlags(vector[2]);

    const hashbuf = new Buffer(32);
    hashbuf.fill(0);
    const credtx = new Transaction();
    credtx.uncheckedAddInput(
      new Transaction.Input({
        prevTxId:
          '0000000000000000000000000000000000000000000000000000000000000000',
        outputIndex: 0xffffffff,
        sequenceNumber: 0xffffffff,
        script: Script('OP_0 OP_0')
      })
    );
    credtx.addOutput(
      new Transaction.Output({
        script: scriptPubkey,
        satoshis: 0
      })
    );
    const idbuf = credtx.id;

    const spendtx = new Transaction();
    spendtx.uncheckedAddInput(
      new Transaction.Input({
        prevTxId: idbuf.toString('hex'),
        outputIndex: 0,
        sequenceNumber: 0xffffffff,
        script: scriptSig
      })
    );
    spendtx.addOutput(
      new Transaction.Output({
        script: new Script(),
        satoshis: 0
      })
    );

    const interp = new Interpreter();
    const verified = interp.verify(scriptSig, scriptPubkey, spendtx, 0, flags);
    verified.should.equal(expected);
  };
  describe('bitcoind script evaluation fixtures', () => {
    const testAllFixtures = (set, expected) => {
      let c = 0;
      set.forEach(vector => {
        if (vector.length === 1) {
          return;
        }
        c++;
        const descstr = vector[3];
        const fullScriptString = vector[0] + ' ' + vector[1];
        const comment = descstr ? ' (' + descstr + ')' : '';
        it(
          'should pass script_' +
            (expected ? '' : 'in') +
            'valid ' +
            'vector #' +
            c +
            ': ' +
            fullScriptString +
            comment,
          () => {
            testFixture(vector, expected);
          }
        );
      });
    };
    testAllFixtures(script_valid, true);
    testAllFixtures(script_invalid, false);
  });
  describe('bitcoind transaction evaluation fixtures', () => {
    const test_txs = (set, expected) => {
      let c = 0;
      set.forEach(vector => {
        if (vector.length === 1) {
          return;
        }
        c++;
        const cc = c; // copy to local
        it(
          'should pass tx_' + (expected ? '' : 'in') + 'valid vector ' + cc,
          () => {
            const inputs = vector[0];
            const txhex = vector[1];
            const flags = getFlags(vector[2]);

            const map = {};
            inputs.forEach(input => {
              const txid = input[0];
              let txoutnum = input[1];
              const scriptPubKeyStr = input[2];
              if (txoutnum === -1) {
                txoutnum = 0xffffffff; // bitcoind casts -1 to an unsigned int
              }
              map[txid + ':' + txoutnum] = Script.fromBitcoindString(
                scriptPubKeyStr
              );
            });

            const tx = new Transaction(txhex);
            let allInputsVerified = true;
            tx.inputs.forEach((txin, j) => {
              if (txin.isNull()) {
                return;
              }
              const scriptSig = txin.script;
              const txidhex = txin.prevTxId.toString('hex');
              const txoutnum = txin.outputIndex;
              const scriptPubkey = map[txidhex + ':' + txoutnum];
              should.exist(scriptPubkey);
              (scriptSig !== undefined).should.equal(true);
              const interp = new Interpreter();
              const verified = interp.verify(
                scriptSig,
                scriptPubkey,
                tx,
                j,
                flags
              );
              if (!verified) {
                allInputsVerified = false;
              }
            });
            let txVerified = tx.verify();
            txVerified = txVerified === true ? true : false;
            allInputsVerified = allInputsVerified && txVerified;
            allInputsVerified.should.equal(expected);
          }
        );
      });
    };
    test_txs(tx_valid, true);
    test_txs(tx_invalid, false);
  });
});
