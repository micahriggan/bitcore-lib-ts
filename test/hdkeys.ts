'use strict';

import * as _ from 'lodash';
import sinon from 'sinon';
import { expect, should } from 'chai';
import { BitcoreLib } from '../src';
const Networks = BitcoreLib.Network;
const HDPrivateKey = BitcoreLib.HDPrivateKey;
const HDPublicKey = BitcoreLib.HDPublicKey;

describe('HDKeys building with static methods', () => {
  const classes = [HDPublicKey, HDPrivateKey];

  _.each(classes, clazz => {
    const expectStaticMethodFail = (staticMethod, argument, message) => {
      expect(clazz[staticMethod].bind(null, argument)).to.throw(message);
    };
    it(clazz.name + ' fromJSON checks that a valid JSON is provided', () => {
      const errorMessage = 'Invalid Argument: No valid argument was provided';
      const method = 'fromObject';
      expectStaticMethodFail(method, undefined, errorMessage);
      expectStaticMethodFail(method, null, errorMessage);
      expectStaticMethodFail(method, 'invalid JSON', errorMessage);
      expectStaticMethodFail(method, "{'singlequotes': true}", errorMessage);
    });
    it(clazz.name + ' fromString checks that a string is provided', () => {
      const errorMessage = 'No valid string was provided';
      const method = 'fromString';
      expectStaticMethodFail(method, undefined, errorMessage);
      expectStaticMethodFail(method, null, errorMessage);
      expectStaticMethodFail(method, {}, errorMessage);
    });
    it(clazz.name + ' fromObject checks that an object is provided', () => {
      const errorMessage = 'No valid argument was provided';
      const method = 'fromObject';
      expectStaticMethodFail(method, undefined, errorMessage);
      expectStaticMethodFail(method, null, errorMessage);
      expectStaticMethodFail(method, '', errorMessage);
    });
  });
});

describe('BIP32 compliance', () => {
  it('should initialize test vector 1 from the extended public key', () => {
    new HDPublicKey(vector1_m_public).xpubkey.should.equal(vector1_m_public);
  });

  it('should initialize test vector 1 from the extended private key', () => {
    new HDPrivateKey(vector1_m_private).xprivkey.should.equal(
      vector1_m_private
    );
  });

  it('can initialize a public key from an extended private key', () => {
    new HDPublicKey(vector1_m_private).xpubkey.should.equal(vector1_m_public);
  });

  it('toString should be equal to the `xpubkey` member', () => {
    const privateKey = new HDPrivateKey(vector1_m_private);
    privateKey.toString().should.equal(privateKey.xprivkey);
  });

  it('toString should be equal to the `xpubkey` member', () => {
    const publicKey = new HDPublicKey(vector1_m_public);
    publicKey.toString().should.equal(publicKey.xpubkey);
  });

  it('should get the extended public key from the extended private key for test vector 1', () => {
    new HDPrivateKey(vector1_m_private).xpubkey.should.equal(vector1_m_public);
  });

  it("should get m/0' ext. private key from test vector 1", () => {
    const privateKey = new HDPrivateKey(vector1_m_private).derive("m/0'");
    privateKey.xprivkey.should.equal(vector1_m0h_private);
  });

  it("should get m/0' ext. public key from test vector 1", () => {
    new HDPrivateKey(vector1_m_private)
      .derive("m/0'")
      .xpubkey.should.equal(vector1_m0h_public);
  });

  it("should get m/0'/1 ext. private key from test vector 1", () => {
    new HDPrivateKey(vector1_m_private)
      .derive("m/0'/1")
      .xprivkey.should.equal(vector1_m0h1_private);
  });

  it("should get m/0'/1 ext. public key from test vector 1", () => {
    new HDPrivateKey(vector1_m_private)
      .derive("m/0'/1")
      .xpubkey.should.equal(vector1_m0h1_public);
  });

  it("should get m/0'/1 ext. public key from m/0' public key from test vector 1", () => {
    const derivedPublic = new HDPrivateKey(vector1_m_private)
      .derive("m/0'")
      .hdPublicKey.derive('m/1');
    derivedPublic.xpubkey.should.equal(vector1_m0h1_public);
  });

  it("should get m/0'/1/2' ext. private key from test vector 1", () => {
    const privateKey = new HDPrivateKey(vector1_m_private);
    const derived = privateKey.derive("m/0'/1/2'");
    derived.xprivkey.should.equal(vector1_m0h12h_private);
  });

  it("should get m/0'/1/2' ext. public key from test vector 1", () => {
    new HDPrivateKey(vector1_m_private)
      .derive("m/0'/1/2'")
      .xpubkey.should.equal(vector1_m0h12h_public);
  });

  it("should get m/0'/1/2'/2 ext. private key from test vector 1", () => {
    new HDPrivateKey(vector1_m_private)
      .derive("m/0'/1/2'/2")
      .xprivkey.should.equal(vector1_m0h12h2_private);
  });

  it("should get m/0'/1/2'/2 ext. public key from m/0'/1/2' public key from test vector 1", () => {
    const derived = new HDPrivateKey(vector1_m_private).derive("m/0'/1/2'")
      .hdPublicKey;
    derived.derive('m/2').xpubkey.should.equal(vector1_m0h12h2_public);
  });

  it("should get m/0'/1/2h/2 ext. public key from test vector 1", () => {
    new HDPrivateKey(vector1_m_private)
      .derive("m/0'/1/2'/2")
      .xpubkey.should.equal(vector1_m0h12h2_public);
  });

  it("should get m/0'/1/2h/2/1000000000 ext. private key from test vector 1", () => {
    new HDPrivateKey(vector1_m_private)
      .derive("m/0'/1/2'/2/1000000000")
      .xprivkey.should.equal(vector1_m0h12h21000000000_private);
  });

  it("should get m/0'/1/2h/2/1000000000 ext. public key from test vector 1", () => {
    new HDPrivateKey(vector1_m_private)
      .derive("m/0'/1/2'/2/1000000000")
      .xpubkey.should.equal(vector1_m0h12h21000000000_public);
  });

  it("should get m/0'/1/2'/2/1000000000 ext. public key from m/0'/1/2'/2 public key from test vector 1", () => {
    const derived = new HDPrivateKey(vector1_m_private).derive("m/0'/1/2'/2")
      .hdPublicKey;
    derived
      .derive('m/1000000000')
      .xpubkey.should.equal(vector1_m0h12h21000000000_public);
  });

  it('should initialize test vector 2 from the extended public key', () => {
    new HDPublicKey(vector2_m_public).xpubkey.should.equal(vector2_m_public);
  });

  it('should initialize test vector 2 from the extended private key', () => {
    new HDPrivateKey(vector2_m_private).xprivkey.should.equal(
      vector2_m_private
    );
  });

  it('should get the extended public key from the extended private key for test vector 2', () => {
    new HDPrivateKey(vector2_m_private).xpubkey.should.equal(vector2_m_public);
  });

  it('should get m/0 ext. private key from test vector 2', () => {
    new HDPrivateKey(vector2_m_private)
      .derive(0)
      .xprivkey.should.equal(vector2_m0_private);
  });

  it('should get m/0 ext. public key from test vector 2', () => {
    new HDPrivateKey(vector2_m_private)
      .derive(0)
      .xpubkey.should.equal(vector2_m0_public);
  });

  it('should get m/0 ext. public key from m public key from test vector 2', () => {
    new HDPrivateKey(vector2_m_private).hdPublicKey
      .derive(0)
      .xpubkey.should.equal(vector2_m0_public);
  });

  it('should get m/0/2147483647h ext. private key from test vector 2', () => {
    new HDPrivateKey(vector2_m_private)
      .derive("m/0/2147483647'")
      .xprivkey.should.equal(vector2_m02147483647h_private);
  });

  it('should get m/0/2147483647h ext. public key from test vector 2', () => {
    new HDPrivateKey(vector2_m_private)
      .derive("m/0/2147483647'")
      .xpubkey.should.equal(vector2_m02147483647h_public);
  });

  it('should get m/0/2147483647h/1 ext. private key from test vector 2', () => {
    new HDPrivateKey(vector2_m_private)
      .derive("m/0/2147483647'/1")
      .xprivkey.should.equal(vector2_m02147483647h1_private);
  });

  it('should get m/0/2147483647h/1 ext. public key from test vector 2', () => {
    new HDPrivateKey(vector2_m_private)
      .derive("m/0/2147483647'/1")
      .xpubkey.should.equal(vector2_m02147483647h1_public);
  });

  it('should get m/0/2147483647h/1 ext. public key from m/0/2147483647h public key from test vector 2', () => {
    const derived = new HDPrivateKey(vector2_m_private).derive(
      "m/0/2147483647'"
    ).hdPublicKey;
    derived.derive(1).xpubkey.should.equal(vector2_m02147483647h1_public);
  });

  it('should get m/0/2147483647h/1/2147483646h ext. private key from test vector 2', () => {
    new HDPrivateKey(vector2_m_private)
      .derive("m/0/2147483647'/1/2147483646'")
      .xprivkey.should.equal(vector2_m02147483647h12147483646h_private);
  });

  it('should get m/0/2147483647h/1/2147483646h ext. public key from test vector 2', () => {
    new HDPrivateKey(vector2_m_private)
      .derive("m/0/2147483647'/1/2147483646'")
      .xpubkey.should.equal(vector2_m02147483647h12147483646h_public);
  });

  it('should get m/0/2147483647h/1/2147483646h/2 ext. private key from test vector 2', () => {
    new HDPrivateKey(vector2_m_private)
      .derive("m/0/2147483647'/1/2147483646'/2")
      .xprivkey.should.equal(vector2_m02147483647h12147483646h2_private);
  });

  it('should get m/0/2147483647h/1/2147483646h/2 ext. public key from test vector 2', () => {
    new HDPrivateKey(vector2_m_private)
      .derive("m/0/2147483647'/1/2147483646'/2")
      .xpubkey.should.equal(vector2_m02147483647h12147483646h2_public);
  });

  it('should get m/0/2147483647h/1/2147483646h/2 ext. public key from m/0/2147483647h/2147483646h public key from test vector 2', () => {
    const derivedPublic = new HDPrivateKey(vector2_m_private).derive(
      "m/0/2147483647'/1/2147483646'"
    ).hdPublicKey;
    derivedPublic
      .derive('m/2')
      .xpubkey.should.equal(vector2_m02147483647h12147483646h2_public);
  });

  it('should use full 32 bytes for private key data that is hashed (as per bip32)', () => {
    // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    const privateKeyBuffer = new Buffer(
      '00000055378cf5fafb56c711c674143f9b0ee82ab0ba2924f19b64f5ae7cdbfd',
      'hex'
    );
    const chainCodeBuffer = new Buffer(
      '9c8a5c863e5941f3d99453e6ba66b328bb17cf0b8dec89ed4fc5ace397a1c089',
      'hex'
    );
    const key = HDPrivateKey.fromObject({
      network: 'testnet',
      depth: 0,
      parentFingerPrint: 0,
      childIndex: 0,
      privateKey: privateKeyBuffer,
      chainCode: chainCodeBuffer
    });
    const derived = key.deriveChild("m/44'/0'/0'/0/0'");
    derived.privateKey
      .toString()
      .should.equal(
        '3348069561d2a0fb925e74bf198762acc47dce7db27372257d2d959a9e6f8aeb'
      );
  });

  it('should NOT use full 32 bytes for private key data that is hashed with nonCompliant flag', () => {
    // This is to test that the previously implemented non-compliant to BIP32
    const privateKeyBuffer = new Buffer(
      '00000055378cf5fafb56c711c674143f9b0ee82ab0ba2924f19b64f5ae7cdbfd',
      'hex'
    );
    const chainCodeBuffer = new Buffer(
      '9c8a5c863e5941f3d99453e6ba66b328bb17cf0b8dec89ed4fc5ace397a1c089',
      'hex'
    );
    const key = HDPrivateKey.fromObject({
      network: 'testnet',
      depth: 0,
      parentFingerPrint: 0,
      childIndex: 0,
      privateKey: privateKeyBuffer,
      chainCode: chainCodeBuffer
    });
    const derived = key.deriveNonCompliantChild("m/44'/0'/0'/0/0'");
    derived.privateKey
      .toString()
      .should.equal(
        '4811a079bab267bfdca855b3bddff20231ff7044e648514fa099158472df2836'
      );
  });

  it('should NOT use full 32 bytes for private key data that is hashed with the nonCompliant derive method', () => {
    // This is to test that the previously implemented non-compliant to BIP32
    const privateKeyBuffer = new Buffer(
      '00000055378cf5fafb56c711c674143f9b0ee82ab0ba2924f19b64f5ae7cdbfd',
      'hex'
    );
    const chainCodeBuffer = new Buffer(
      '9c8a5c863e5941f3d99453e6ba66b328bb17cf0b8dec89ed4fc5ace397a1c089',
      'hex'
    );
    const key = HDPrivateKey.fromObject({
      network: 'testnet',
      depth: 0,
      parentFingerPrint: 0,
      childIndex: 0,
      privateKey: privateKeyBuffer,
      chainCode: chainCodeBuffer
    });
    const derived = key.derive("m/44'/0'/0'/0/0'");
    derived.privateKey
      .toString()
      .should.equal(
        '4811a079bab267bfdca855b3bddff20231ff7044e648514fa099158472df2836'
      );
  });

  describe('edge cases', () => {
    const sandbox = sinon.sandbox.create();
    afterEach(() => {
      sandbox.restore();
    });
    it('will handle edge case that derived private key is invalid', () => {
      const invalid = new Buffer(
        '0000000000000000000000000000000000000000000000000000000000000000',
        'hex'
      );
      const privateKeyBuffer = new Buffer(
        '5f72914c48581fc7ddeb944a9616389200a9560177d24f458258e5b04527bcd1',
        'hex'
      );
      const chainCodeBuffer = new Buffer(
        '39816057bba9d952fe87fe998b7fd4d690a1bb58c2ff69141469e4d1dffb4b91',
        'hex'
      );
      const unstubbed = BitcoreLib.crypto.BN.prototype.toBuffer;
      let count = 0;
      const stub = sandbox.replace(
        BitcoreLib.crypto.BN.prototype,
        'toBuffer',
        args => {
          // On the fourth call to the function give back an invalid private key
          // otherwise use the normal behavior.
          count++;
          if (count === 4) {
            return invalid;
          }
          const ret = unstubbed.apply(this, arguments);
          return ret;
        }
      );
      sandbox.spy(BitcoreLib.PrivateKey, 'isValid');
      const key = HDPrivateKey.fromObject({
        network: 'testnet',
        depth: 0,
        parentFingerPrint: 0,
        childIndex: 0,
        privateKey: privateKeyBuffer,
        chainCode: chainCodeBuffer
      });
      const derived = key.derive("m/44'");
      derived.privateKey
        .toString()
        .should.equal(
          'b15bce3608d607ee3a49069197732c656bca942ee59f3e29b4d56914c1de6825'
        );
      (BitcoreLib.PrivateKey.isValid as sinon.SinonSpy).callCount.should.equal(
        2
      );
    });
    it('will handle edge case that a derive public key is invalid', () => {
      const publicKeyBuffer = new Buffer(
        '029e58b241790284ef56502667b15157b3fc58c567f044ddc35653860f9455d099',
        'hex'
      );
      const chainCodeBuffer = new Buffer(
        '39816057bba9d952fe87fe998b7fd4d690a1bb58c2ff69141469e4d1dffb4b91',
        'hex'
      );
      const key = new HDPublicKey({
        network: 'testnet',
        depth: 0,
        parentFingerPrint: 0,
        childIndex: 0,
        chainCode: chainCodeBuffer,
        publicKey: publicKeyBuffer
      });
      const unstubbed = BitcoreLib.PublicKey.fromPoint;
      BitcoreLib.PublicKey.fromPoint = () => {
        BitcoreLib.PublicKey.fromPoint = unstubbed;
        throw new Error('Point cannot be equal to Infinity');
      };
      sandbox.spy(key, '_deriveWithNumber');
      const derived = key.derive('m/44');
      (key._deriveWithNumber as sinon.SinonSpy).callCount.should.equal(2);
      key.publicKey
        .toString()
        .should.equal(
          '029e58b241790284ef56502667b15157b3fc58c567f044ddc35653860f9455d099'
        );
    });
  });

  describe('seed', () => {
    it('should initialize a new BIP32 correctly from test vector 1 seed', () => {
      const seededKey = HDPrivateKey.fromSeed(vector1_master, Networks.livenet);
      seededKey.xprivkey.should.equal(vector1_m_private);
      seededKey.xpubkey.should.equal(vector1_m_public);
    });

    it('should initialize a new BIP32 correctly from test vector 2 seed', () => {
      const seededKey = HDPrivateKey.fromSeed(vector2_master, Networks.livenet);
      seededKey.xprivkey.should.equal(vector2_m_private);
      seededKey.xpubkey.should.equal(vector2_m_public);
    });
  });
});

// test vectors: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
const vector1_master = '000102030405060708090a0b0c0d0e0f';
const vector1_m_public =
  'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8';
const vector1_m_private =
  'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi';
const vector1_m0h_public =
  'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw';
const vector1_m0h_private =
  'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7';
const vector1_m0h1_public =
  'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ';
const vector1_m0h1_private =
  'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs';
const vector1_m0h12h_public =
  'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5';
const vector1_m0h12h_private =
  'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM';
const vector1_m0h12h2_public =
  'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV';
const vector1_m0h12h2_private =
  'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334';
const vector1_m0h12h21000000000_public =
  'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy';
const vector1_m0h12h21000000000_private =
  'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76';
const vector2_master =
  'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542';
const vector2_m_public =
  'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB';
const vector2_m_private =
  'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U';
const vector2_m0_public =
  'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH';
const vector2_m0_private =
  'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt';
const vector2_m02147483647h_public =
  'xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a';
const vector2_m02147483647h_private =
  'xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9';
const vector2_m02147483647h1_public =
  'xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon';
const vector2_m02147483647h1_private =
  'xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef';
const vector2_m02147483647h12147483646h_public =
  'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL';
const vector2_m02147483647h12147483646h_private =
  'xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc';
const vector2_m02147483647h12147483646h2_public =
  'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt';
const vector2_m02147483647h12147483646h2_private =
  'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j';
