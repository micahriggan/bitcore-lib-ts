'use strict';

/* jshint maxstatements: 30 */

import { BitcoreLib } from '../src';
const PublicKey = BitcoreLib.PublicKey;
const Address = BitcoreLib.Address;
const Script = BitcoreLib.Script;
const Networks = BitcoreLib.Network;
const BitcoreError = BitcoreLib.errors;
const ErrorTypes = BitcoreLib.errors.Types;

const validbase58 = require('./data/bitcoind/base58_keys_valid.json');
const invalidbase58 = require('./data/bitcoind/base58_keys_invalid.json');

describe('Address', () => {
  const pubkeyhash = new Buffer(
    '3c3fa3d4adcaf8f52d5b1843975e122548269937',
    'hex'
  );
  const buf = Buffer.concat([new Buffer([0]), pubkeyhash]);
  const str = '16VZnHwRhwrExfeHFHGjwrgEMq8VcYPs9r';

  it("can't build without data", () => {
    (() => {
      return new Address();
    }).should.throw('First argument is required, please include address data.');
  });

  it('should throw an error because of bad network param', () => {
    (() => {
      return new Address(PKHLivenet[0], 'main', 'pubkeyhash');
    }).should.throw('Second argument must be "livenet" or "testnet".');
  });

  it('should throw an error because of bad type param', () => {
    (() => {
      return new Address(PKHLivenet[0], 'livenet', 'pubkey');
    }).should.throw('Third argument must be "pubkeyhash" or "scripthash"');
  });

  describe('bitcoind compliance', () => {
    validbase58.map(d => {
      if (!d[2].isPrivkey) {
        it('should describe address ' + d[0] + ' as valid', () => {
          let type;
          if (d[2].addrType === 'script') {
            type = 'scripthash';
          } else if (d[2].addrType === 'pubkey') {
            type = 'pubkeyhash';
          }
          let network = 'livenet';
          if (d[2].isTestnet) {
            network = 'testnet';
          }
          return new Address(d[0], network, type);
        });
      }
    });
    invalidbase58.map(d => {
      it(
        'should describe input ' + d[0].slice(0, 10) + '... as invalid',
        () => {
          expect(() => {
            return new Address(d[0]);
          }).to.throw(Error);
        }
      );
    });
  });

  // livenet valid
  const PKHLivenet = [
    '15vkcKf7gB23wLAnZLmbVuMiiVDc1Nm4a2',
    '1A6ut1tWnUq1SEQLMr4ttDh24wcbJ5o9TT',
    '1BpbpfLdY7oBS9gK7aDXgvMgr1DPvNhEB2',
    '1Jz2yCRd5ST1p2gUqFB5wsSQfdm3jaFfg7',
    '    1Jz2yCRd5ST1p2gUqFB5wsSQfdm3jaFfg7   \t\n'
  ];

  // livenet p2sh
  const P2SHLivenet = [
    '342ftSRCvFHfCeFFBuz4xwbeqnDw6BGUey',
    '33vt8ViH5jsr115AGkW6cEmEz9MpvJSwDk',
    '37Sp6Rv3y4kVd1nQ1JV5pfqXccHNyZm1x3',
    '3QjYXhTkvuj8qPaXHTTWb5wjXhdsLAAWVy',
    '\t \n3QjYXhTkvuj8qPaXHTTWb5wjXhdsLAAWVy \r'
  ];

  // testnet p2sh
  const P2SHTestnet = [
    '2N7FuwuUuoTBrDFdrAZ9KxBmtqMLxce9i1C',
    '2NEWDzHWwY5ZZp8CQWbB7ouNMLqCia6YRda',
    '2MxgPqX1iThW3oZVk9KoFcE5M4JpiETssVN',
    '2NB72XtkjpnATMggui83aEtPawyyKvnbX2o'
  ];

  // livenet bad checksums
  const badChecksums = [
    '15vkcKf7gB23wLAnZLmbVuMiiVDc3nq4a2',
    '1A6ut1tWnUq1SEQLMr4ttDh24wcbj4w2TT',
    '1BpbpfLdY7oBS9gK7aDXgvMgr1DpvNH3B2',
    '1Jz2yCRd5ST1p2gUqFB5wsSQfdmEJaffg7'
  ];

  // livenet non-base58
  const nonBase58 = [
    '15vkcKf7g#23wLAnZLmb$uMiiVDc3nq4a2',
    '1A601ttWnUq1SEQLMr4ttDh24wcbj4w2TT',
    '1BpbpfLdY7oBS9gK7aIXgvMgr1DpvNH3B2',
    '1Jz2yCRdOST1p2gUqFB5wsSQfdmEJaffg7'
  ];

  // testnet valid
  const PKHTestnet = [
    'n28S35tqEMbt6vNad7A5K3mZ7vdn8dZ86X',
    'n45x3R2w2jaSC62BMa9MeJCd3TXxgvDEmm',
    'mursDVxqNQmmwWHACpM9VHwVVSfTddGsEM',
    'mtX8nPZZdJ8d3QNLRJ1oJTiEi26Sj6LQXS'
  ];

  describe('validation', () => {
    it('getValidationError detects network mismatchs', () => {
      const error = Address.getValidationError(
        '37BahqRsFrAd3qLiNNwLNV3AWMRD7itxTo',
        'testnet'
      );
      should.exist(error);
    });

    it('isValid returns true on a valid address', () => {
      const valid = Address.isValid(
        '37BahqRsFrAd3qLiNNwLNV3AWMRD7itxTo',
        'livenet'
      );
      valid.should.equal(true);
    });

    it('isValid returns false on network mismatch', () => {
      const valid = Address.isValid(
        '37BahqRsFrAd3qLiNNwLNV3AWMRD7itxTo',
        'testnet'
      );
      valid.should.equal(false);
    });

    it('validates correctly the P2PKH test vector', () => {
      for (const PHK of PKHLivenet) {
        const error = Address.getValidationError(PHK);
        should.not.exist(error);
      }
    });

    it('validates correctly the P2SH test vector', () => {
      for (const P2SH of P2SHLivenet) {
        const error = Address.getValidationError(P2SH);
        should.not.exist(error);
      }
    });

    it('validates correctly the P2SH testnet test vector', () => {
      for (const P2SH of P2SHTestnet) {
        const error = Address.getValidationError(P2SH, 'testnet');
        should.not.exist(error);
      }
    });

    it('rejects correctly the P2PKH livenet test vector with "testnet" parameter', () => {
      for (const PKH of PKHLivenet) {
        const error = Address.getValidationError(PKH, 'testnet');
        should.exist(error);
      }
    });

    it('validates correctly the P2PKH livenet test vector with "livenet" parameter', () => {
      for (const PKH of PKHLivenet) {
        const error = Address.getValidationError(PKH, 'livenet');
        should.not.exist(error);
      }
    });

    it('should not validate if checksum is invalid', () => {
      for (const chksum of badChecksums) {
        const error = Address.getValidationError(
          chksum,
          'livenet',
          'pubkeyhash'
        );
        should.exist(error);
        error.message.should.equal('Checksum mismatch');
      }
    });

    it('should not validate on a network mismatch', () => {
      let error;
      let i;
      for (i = 0; i < PKHLivenet.length; i++) {
        error = Address.getValidationError(
          PKHLivenet[i],
          'testnet',
          'pubkeyhash'
        );
        should.exist(error);
        error.message.should.equal('Address has mismatched network type.');
      }
      for (i = 0; i < PKHTestnet.length; i++) {
        error = Address.getValidationError(
          PKHTestnet[i],
          'livenet',
          'pubkeyhash'
        );
        should.exist(error);
        error.message.should.equal('Address has mismatched network type.');
      }
    });

    it('should not validate on a type mismatch', () => {
      for (const PKH of PKHLivenet) {
        const error = Address.getValidationError(PKH, 'livenet', 'scripthash');
        should.exist(error);
        error.message.should.equal('Address has mismatched type.');
      }
    });

    it('should not validate on non-base58 characters', () => {
      for (const base58 of nonBase58) {
        const error = Address.getValidationError(
          base58,
          'livenet',
          'pubkeyhash'
        );
        should.exist(error);
        error.message.should.equal('Non-base58 character');
      }
    });

    it('testnet addresses are validated correctly', () => {
      for (const PKH of PKHTestnet) {
        const error = Address.getValidationError(PKH, 'testnet');
        should.not.exist(error);
      }
    });

    it('addresses with whitespace are validated correctly', () => {
      const ws =
        '  \r \t    \n 1A6ut1tWnUq1SEQLMr4ttDh24wcbJ5o9TT \t \n            \r';
      const error = Address.getValidationError(ws);
      should.not.exist(error);
      Address.fromString(ws)
        .toString()
        .should.equal('1A6ut1tWnUq1SEQLMr4ttDh24wcbJ5o9TT');
    });
  });

  describe('instantiation', () => {
    it('can be instantiated from another address', () => {
      const address = Address.fromBuffer(buf);
      const address2 = new Address({
        hashBuffer: address.hashBuffer,
        network: address.network,
        type: address.type
      });
      address.toString().should.equal(address2.toString());
    });
  });

  describe('encodings', () => {
    it('should make an address from a buffer', () => {
      Address.fromBuffer(buf)
        .toString()
        .should.equal(str);
      new Address(buf).toString().should.equal(str);
      new Address(buf).toString().should.equal(str);
    });

    it('should make an address from a string', () => {
      Address.fromString(str)
        .toString()
        .should.equal(str);
      new Address(str).toString().should.equal(str);
    });

    it('should make an address using a non-string network', () => {
      Address.fromString(str, Networks.livenet)
        .toString()
        .should.equal(str);
    });

    it('should throw with bad network param', () => {
      (() => {
        Address.fromString(str, 'somenet');
      }).should.throw('Unknown network');
    });

    it('should error because of unrecognized data format', () => {
      (() => {
        return new Address(new Error());
      }).should.throw(new BitcoreError(ErrorTypes.InvalidArgument));
    });

    it('should error because of incorrect format for pubkey hash', () => {
      (() => {
        return new Address.fromPublicKeyHash('notahash');
      }).should.throw('Address supplied is not a buffer.');
    });

    it('should error because of incorrect format for script hash', () => {
      (() => {
        return new Address.fromScriptHash('notascript');
      }).should.throw('Address supplied is not a buffer.');
    });

    it('should error because of incorrect type for transform buffer', () => {
      (() => {
        return Address._transformBuffer('notabuffer');
      }).should.throw('Address supplied is not a buffer.');
    });

    it('should error because of incorrect length buffer for transform buffer', () => {
      (() => {
        return Address._transformBuffer(new Buffer(20));
      }).should.throw('Address buffers must be exactly 21 bytes.');
    });

    it('should error because of incorrect type for pubkey transform', () => {
      (() => {
        return Address._transformPublicKey(new Buffer(20));
      }).should.throw('Address must be an instance of PublicKey.');
    });

    it('should error because of incorrect type for script transform', () => {
      (() => {
        return Address._transformScript(new Buffer(20));
      }).should.throw('Invalid Argument: script must be a Script instance');
    });

    it('should error because of incorrect type for string transform', () => {
      (() => {
        return Address._transformString(new Buffer(20));
      }).should.throw('data parameter supplied is not a string.');
    });

    it('should make an address from a pubkey hash buffer', () => {
      const hash = pubkeyhash; // use the same hash
      const a = Address.fromPublicKeyHash(hash, 'livenet');
      a.network.should.equal(Networks.livenet);
      a.toString().should.equal(str);
      const b = Address.fromPublicKeyHash(hash, 'testnet');
      b.network.should.equal(Networks.testnet);
      b.type.should.equal('pubkeyhash');
      new Address(hash, 'livenet').toString().should.equal(str);
    });

    it('should make an address using the default network', () => {
      const hash = pubkeyhash; // use the same hash
      const network = Networks.defaultNetwork;
      Networks.defaultNetwork = Networks.livenet;
      const a = Address.fromPublicKeyHash(hash);
      a.network.should.equal(Networks.livenet);
      // change the default
      Networks.defaultNetwork = Networks.testnet;
      const b = Address.fromPublicKeyHash(hash);
      b.network.should.equal(Networks.testnet);
      // restore the default
      Networks.defaultNetwork = network;
    });

    it('should throw an error for invalid length hashBuffer', () => {
      (() => {
        return Address.fromPublicKeyHash(buf);
      }).should.throw('Address hashbuffers must be exactly 20 bytes.');
    });

    it('should make this address from a compressed pubkey', () => {
      const pubkey = new PublicKey(
        '0285e9737a74c30a873f74df05124f2aa6f53042c2fc0a130d6cbd7d16b944b004'
      );
      const address = Address.fromPublicKey(pubkey, 'livenet');
      address.toString().should.equal('19gH5uhqY6DKrtkU66PsZPUZdzTd11Y7ke');
    });

    it('should use the default network for pubkey', () => {
      const pubkey = new PublicKey(
        '0285e9737a74c30a873f74df05124f2aa6f53042c2fc0a130d6cbd7d16b944b004'
      );
      const address = Address.fromPublicKey(pubkey);
      address.network.should.equal(Networks.defaultNetwork);
    });

    it('should make this address from an uncompressed pubkey', () => {
      const pubkey = new PublicKey(
        '0485e9737a74c30a873f74df05124f2aa6f53042c2fc0a130d6cbd7d16b944b00' +
          '4833fef26c8be4c4823754869ff4e46755b85d851077771c220e2610496a29d98'
      );
      const a = Address.fromPublicKey(pubkey, 'livenet');
      a.toString().should.equal('16JXnhxjJUhxfyx4y6H4sFcxrgt8kQ8ewX');
      const b = new Address(pubkey, 'livenet', 'pubkeyhash');
      b.toString().should.equal('16JXnhxjJUhxfyx4y6H4sFcxrgt8kQ8ewX');
    });

    it('should classify from a custom network', () => {
      const custom = {
        name: 'customnetwork',
        pubkeyhash: 0x1c,
        privatekey: 0x1e,
        scripthash: 0x28,
        xpubkey: 0x02e8de8f,
        xprivkey: 0x02e8da54,
        networkMagic: 0x0c110907,
        port: 7333
      };
      const addressString = 'CX4WePxBwq1Y6u7VyMJfmmitE7GiTgC9aE';
      Networks.addNetwork(custom);
      const network = Networks.get('customnetwork');
      const address = Address.fromString(addressString);
      address.type.should.equal(Address.PayToPublicKeyHash);
      address.network.should.equal(network);
      Networks.removeNetwork(network);
    });

    describe('from a script', () => {
      it('should fail to build address from a non p2sh,p2pkh script', () => {
        const s = new Script('OP_CHECKMULTISIG');
        (() => {
          return new Address(s);
        }).should.throw(
          'needs to be p2pkh in, p2pkh out, p2sh in, or p2sh out'
        );
      });
      it('should make this address from a p2pkh output script', () => {
        const s = new Script(
          'OP_DUP OP_HASH160 20 ' +
            '0xc8e11b0eb0d2ad5362d894f048908341fa61b6e1 OP_EQUALVERIFY OP_CHECKSIG'
        );
        const bufr = s.toBuffer();
        const a = Address.fromScript(s, 'livenet');
        a.toString().should.equal('1KK9oz4bFH8c1t6LmighHaoSEGx3P3FEmc');
        const b = new Address(s, 'livenet');
        b.toString().should.equal('1KK9oz4bFH8c1t6LmighHaoSEGx3P3FEmc');
      });

      it('should make this address from a p2sh input script', () => {
        const s = Script.fromString(
          'OP_HASH160 20 0xa6ed4af315271e657ee307828f54a4365fa5d20f OP_EQUAL'
        );
        const a = Address.fromScript(s, 'livenet');
        a.toString().should.equal('3GueMn6ruWVfQTN4XKBGEbCbGLwRSUhfnS');
        const b = new Address(s, 'livenet');
        b.toString().should.equal('3GueMn6ruWVfQTN4XKBGEbCbGLwRSUhfnS');
      });

      it('returns the same address if the script is a pay to public key hash out', () => {
        const address = '16JXnhxjJUhxfyx4y6H4sFcxrgt8kQ8ewX';
        const script = Script.buildPublicKeyHashOut(new Address(address));
        Address(script, Networks.livenet)
          .toString()
          .should.equal(address);
      });
      it('returns the same address if the script is a pay to script hash out', () => {
        const address = '3BYmEwgV2vANrmfRymr1mFnHXgLjD6gAWm';
        const script = Script.buildScriptHashOut(new Address(address));
        Address(script, Networks.livenet)
          .toString()
          .should.equal(address);
      });
    });

    it('should derive from this known address string livenet', () => {
      const address = new Address(str);
      const buffer = address.toBuffer();
      const slice = buffer.slice(1);
      const sliceString = slice.toString('hex');
      sliceString.should.equal(pubkeyhash.toString('hex'));
    });

    it('should derive from this known address string testnet', () => {
      const a = new Address(PKHTestnet[0], 'testnet');
      const b = new Address(a.toString());
      b.toString().should.equal(PKHTestnet[0]);
      b.network.should.equal(Networks.testnet);
    });

    it('should derive from this known address string livenet scripthash', () => {
      const a = new Address(P2SHLivenet[0], 'livenet', 'scripthash');
      const b = new Address(a.toString());
      b.toString().should.equal(P2SHLivenet[0]);
    });

    it('should derive from this known address string testnet scripthash', () => {
      let address = new Address(P2SHTestnet[0], 'testnet', 'scripthash');
      address = new Address(address.toString());
      address.toString().should.equal(P2SHTestnet[0]);
    });
  });

  describe('#toBuffer', () => {
    it('3c3fa3d4adcaf8f52d5b1843975e122548269937 corresponds to hash 16VZnHwRhwrExfeHFHGjwrgEMq8VcYPs9r', () => {
      const address = new Address(str);
      address
        .toBuffer()
        .slice(1)
        .toString('hex')
        .should.equal(pubkeyhash.toString('hex'));
    });
  });

  describe('#object', () => {
    it('roundtrip to-from-to', () => {
      const obj = new Address(str).toObject();
      const address = Address.fromObject(obj);
      address.toString().should.equal(str);
    });

    it('will fail with invalid state', () => {
      expect(() => {
        return Address.fromObject('¹');
      }).to.throw(new BitcoreError(ErrorTypes.InvalidState));
    });
  });

  describe('#toString', () => {
    it('livenet pubkeyhash address', () => {
      const address = new Address(str);
      address.toString().should.equal(str);
    });

    it('scripthash address', () => {
      const address = new Address(P2SHLivenet[0]);
      address.toString().should.equal(P2SHLivenet[0]);
    });

    it('testnet scripthash address', () => {
      const address = new Address(P2SHTestnet[0]);
      address.toString().should.equal(P2SHTestnet[0]);
    });

    it('testnet pubkeyhash address', () => {
      const address = new Address(PKHTestnet[0]);
      address.toString().should.equal(PKHTestnet[0]);
    });
  });

  describe('#inspect', () => {
    it('should output formatted output correctly', () => {
      const address = new Address(str);
      const output =
        '<Address: 16VZnHwRhwrExfeHFHGjwrgEMq8VcYPs9r, type: pubkeyhash, network: livenet>';
      address.inspect().should.equal(output);
    });
  });

  describe('questions about the address', () => {
    it('should detect a P2SH address', () => {
      new Address(P2SHLivenet[0]).isPayToScriptHash().should.equal(true);
      new Address(P2SHLivenet[0]).isPayToPublicKeyHash().should.equal(false);
      new Address(P2SHTestnet[0]).isPayToScriptHash().should.equal(true);
      new Address(P2SHTestnet[0]).isPayToPublicKeyHash().should.equal(false);
    });
    it('should detect a Pay To PubkeyHash address', () => {
      new Address(PKHLivenet[0]).isPayToPublicKeyHash().should.equal(true);
      new Address(PKHLivenet[0]).isPayToScriptHash().should.equal(false);
      new Address(PKHTestnet[0]).isPayToPublicKeyHash().should.equal(true);
      new Address(PKHTestnet[0]).isPayToScriptHash().should.equal(false);
    });
  });

  it("throws an error if it couldn't instantiate", () => {
    expect(() => {
      return new Address(1);
    }).to.throw(TypeError);
  });
  it('can roundtrip from/to a object', () => {
    const address = new Address(P2SHLivenet[0]);
    expect(new Address(address.toObject()).toString()).to.equal(P2SHLivenet[0]);
  });

  it('will use the default network for an object', () => {
    const obj = {
      hash: '19a7d869032368fd1f1e26e5e73a4ad0e474960e',
      type: 'scripthash'
    };
    const address = new Address(obj);
    address.network.should.equal(Networks.defaultNetwork);
  });

  describe('creating a P2SH address from public keys', () => {
    const public1 =
      '02da5798ed0c055e31339eb9b5cef0d3c0ccdec84a62e2e255eb5c006d4f3e7f5b';
    const public2 =
      '0272073bf0287c4469a2a011567361d42529cd1a72ab0d86aa104ecc89342ffeb0';
    const public3 =
      '02738a516a78355db138e8119e58934864ce222c553a5407cf92b9c1527e03c1a2';
    const publics = [public1, public2, public3];

    it('can create an address from a set of public keys', () => {
      let address = Address.createMultisig(publics, 2, Networks.livenet);
      address.toString().should.equal('3FtqPRirhPvrf7mVUSkygyZ5UuoAYrTW3y');
      address = new Address(publics, 2, Networks.livenet);
      address.toString().should.equal('3FtqPRirhPvrf7mVUSkygyZ5UuoAYrTW3y');
    });

    it('works on testnet also', () => {
      const address = Address.createMultisig(publics, 2, Networks.testnet);
      address.toString().should.equal('2N7T3TAetJrSCruQ39aNrJvYLhG1LJosujf');
    });

    it('can create an address from a set of public keys with a nested witness program', () => {
      const address = Address.createMultisig(
        publics,
        2,
        Networks.livenet,
        true
      );
      address.toString().should.equal('3PpK1bBqUmPK3Q6QPSUK7BQSZ1DMWL6aes');
    });

    it('can also be created by Address.createMultisig', () => {
      const address = Address.createMultisig(publics, 2);
      const address2 = Address.createMultisig(publics, 2);
      address.toString().should.equal(address2.toString());
    });

    it('fails if invalid array is provided', () => {
      expect(() => {
        return Address.createMultisig([], 3, 'testnet');
      }).to.throw(
        'Number of required signatures must be less than or equal to the number of public keys'
      );
    });
  });
});
