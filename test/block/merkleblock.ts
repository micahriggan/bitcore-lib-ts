import * as chai from 'chai';
const should = require('chai').should();

import { BitcoreLib } from '../../src';
const MerkleBlock = BitcoreLib.MerkleBlock;
const BufferReader = BitcoreLib.encoding.BufferReader;
const BufferWriter = BitcoreLib.encoding.BufferWriter;
const Transaction = BitcoreLib.Transaction;
const data = require('../data/merkleblocks.js');
const transactionVector = require('../data/tx_creation');

describe('MerkleBlock', () => {
  const blockhex = data.HEX[0];
  const blockbuf = new Buffer(blockhex, 'hex');
  const blockJSON = JSON.stringify(data.JSON[0]);
  const blockObject = JSON.parse(JSON.stringify(data.JSON[0]));

  describe('#constructor', () => {
    it('should make a new merkleblock from buffer', () => {
      const b = new MerkleBlock(blockbuf);
      b.toBuffer()
        .toString('hex')
        .should.equal(blockhex);
    });

    it('should make a new merkleblock from object', () => {
      const b = new MerkleBlock(blockObject);
      b.toObject().should.deep.equal(blockObject);
    });

    it('should make a new merkleblock from JSON', () => {
      const b = new MerkleBlock(JSON.parse(blockJSON));
      JSON.stringify(b).should.equal(blockJSON);
    });

    it('should not make an empty block', () => {
      (() => {
        return new MerkleBlock();
      }).should.throw('Unrecognized argument for MerkleBlock');
    });
  });

  describe('#fromObject', () => {
    it('should set these known values', () => {
      const block = MerkleBlock.fromObject(JSON.parse(blockJSON));
      should.exist(block.header);
      should.exist(block.numTransactions);
      should.exist(block.hashes);
      should.exist(block.flags);
    });

    it('should set these known values', () => {
      const block = new MerkleBlock(JSON.parse(blockJSON));
      should.exist(block.header);
      should.exist(block.numTransactions);
      should.exist(block.hashes);
      should.exist(block.flags);
    });

    it('accepts an object as argument', () => {
      const block = new MerkleBlock(blockbuf);
      should.exist(MerkleBlock.fromObject(block.toObject()));
    });
  });

  describe('#toJSON', () => {
    it('should recover these known values', () => {
      const block = new MerkleBlock(JSON.parse(blockJSON));
      const b = JSON.parse(JSON.stringify(block));
      should.exist(block.header);
      should.exist(block.numTransactions);
      should.exist(block.hashes);
      should.exist(block.flags);
      should.exist(b.header);
      should.exist(b.numTransactions);
      should.exist(b.hashes);
      should.exist(b.flags);
    });
  });

  describe('#fromBuffer', () => {
    it('should make a block from this known buffer', () => {
      const block = MerkleBlock.fromBuffer(blockbuf);
      block
        .toBuffer()
        .toString('hex')
        .should.equal(blockhex);
    });
  });

  describe('#fromBufferReader', () => {
    it('should make a block from this known buffer', () => {
      const block = MerkleBlock.fromBufferReader(new BufferReader(blockbuf));
      block
        .toBuffer()
        .toString('hex')
        .should.equal(blockhex);
    });
  });

  describe('#toBuffer', () => {
    it('should recover a block from this known buffer', () => {
      const block = MerkleBlock.fromBuffer(blockbuf);
      block
        .toBuffer()
        .toString('hex')
        .should.equal(blockhex);
    });
  });

  describe('#toBufferWriter', () => {
    it('should recover a block from this known buffer', () => {
      const block = MerkleBlock.fromBuffer(blockbuf);
      block
        .toBufferWriter()
        .concat()
        .toString('hex')
        .should.equal(blockhex);
    });

    it("doesn't create a bufferWriter if one provided", () => {
      const writer = new BufferWriter();
      const block = MerkleBlock.fromBuffer(blockbuf);
      block.toBufferWriter(writer).should.equal(writer);
    });
  });

  describe('#validMerkleTree', () => {
    it('should validate good merkleblocks', () => {
      data.JSON.forEach(blockData => {
        const b = new MerkleBlock(blockData);
        b.validMerkleTree().should.equal(true);
      });
    });

    it('should not validate merkleblocks with too many hashes', () => {
      const b = new MerkleBlock(data.JSON[0]);
      // Add too many hashes
      let i = 0;
      while (i <= b.numTransactions) {
        b.hashes.push('bad' + i++);
      }
      b.validMerkleTree().should.equal(false);
    });

    it('should not validate merkleblocks with too few bit flags', () => {
      const b = new MerkleBlock(JSON.parse(blockJSON));
      b.flags.pop();
      b.validMerkleTree().should.equal(false);
    });
  });

  describe('#filterdTxsHash', () => {
    it('should validate good merkleblocks', () => {
      const hashOfFilteredTx =
        '6f64fd5aa9dd01f74c03656d376625cf80328d83d9afebe60cc68b8f0e245bd9';
      const b = new MerkleBlock(data.JSON[3]);
      b.filterdTxsHash()[0].should.equal(hashOfFilteredTx);
    });

    it('should fail with merkleblocks with too many hashes', () => {
      const b = new MerkleBlock(data.JSON[0]);
      // Add too many hashes
      let i = 0;
      while (i <= b.numTransactions) {
        b.hashes.push('bad' + i++);
      }
      (() => {
        b.filterdTxsHash();
      }).should.throw('This MerkleBlock contain an invalid Merkle Tree');
    });

    it('should fail with merkleblocks with too few bit flags', () => {
      const b = new MerkleBlock(JSON.parse(blockJSON));
      b.flags.pop();
      (() => {
        b.filterdTxsHash();
      }).should.throw('This MerkleBlock contain an invalid Merkle Tree');
    });
  });

  describe('#hasTransaction', () => {
    it('should find transactions via hash string', () => {
      const jsonData = data.JSON[0];
      const txId = new Buffer(jsonData.hashes[1], 'hex').toString('hex');
      const b = new MerkleBlock(jsonData);
      b.hasTransaction(txId).should.equal(true);
      b.hasTransaction(txId + 'abcd').should.equal(false);
    });

    it('should find transactions via Transaction object', () => {
      const jsonData = data.JSON[0];
      const txBuf = new Buffer(data.TXHEX[0][0], 'hex');
      const tx = new Transaction().fromBuffer(txBuf);
      const b = new MerkleBlock(jsonData);
      b.hasTransaction(tx).should.equal(true);
    });

    it('should not find non-existant Transaction object', () => {
      // Reuse another transaction already in data/ dir
      const serialized = transactionVector[0][7];
      const tx = new Transaction().fromBuffer(new Buffer(serialized, 'hex'));
      const b = new MerkleBlock(data.JSON[0]);
      b.hasTransaction(tx).should.equal(false);
    });

    it('should not match with merkle nodes', () => {
      const b = new MerkleBlock(data.JSON[0]);

      const hashData = [
        [
          '3612262624047ee87660be1a707519a443b1c1ce3d248cbfc6c15870f6c5daa2',
          false
        ],
        [
          '019f5b01d4195ecbc9398fbf3c3b1fa9bb3183301d7a1fb3bd174fcfa40a2b65',
          true
        ],
        [
          '41ed70551dd7e841883ab8f0b16bf04176b7d1480e4f0af9f3d4c3595768d068',
          false
        ],
        [
          '20d2a7bc994987302e5b1ac80fc425fe25f8b63169ea78e68fbaaefa59379bbf',
          false
        ]
      ];

      hashData.forEach(function check(d) {
        b.hasTransaction(d[0]).should.equal(d[1]);
      });
    });
  });
});
