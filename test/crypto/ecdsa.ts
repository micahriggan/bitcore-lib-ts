import { should } from 'chai';
import { BitcoreLib } from '../../src';
import { ECDSA } from '../../src/crypto/ecdsa';
import { Hash } from '../../src/crypto/hash';
import { Signature } from '../../src/crypto/signature';
import { BitcoreBN } from '../../src/crypto/bn';
import { Point } from '../../src/crypto/point';
import { PrivateKey } from '../../src/privatekey';
import { PublicKey } from '../../src/publickey';

const vectors = require('../data/ecdsa');

describe('ECDSA', () => {
  it('instantiation', () => {
    const ec = new ECDSA();
    should().exist(ecdsa);
  });

  const ecdsa = new ECDSA();
  ecdsa.hashbuf = Hash.sha256(new Buffer('test data'));
  ecdsa.privkey = new PrivateKey(
    BitcoreBN.fromBuffer(
      new Buffer(
        'fee0a1f7afebf9d2a5a80c0c98a31c709681cce195cbcd06342b517970c0be1e',
        'hex'
      )
    )
  );
  ecdsa.privkey2pubkey();

  describe('#set', () => {
    it('sets hashbuf', () => {
      should().exist(
        new ECDSA().set({
          hashbuf: ecdsa.hashbuf
        }).hashbuf
      );
    });
  });

  describe('#calci', () => {
    it('calculates i correctly', () => {
      ecdsa.randomK();
      ecdsa.sign();
      ecdsa.calci();
      should().exist(ecdsa.sig.i);
    });

    it('calulates this known i', () => {
      const hashbuf = Hash.sha256(new Buffer('some data'));
      const r = new BitcoreBN(
        '71706645040721865894779025947914615666559616020894583599959600180037551395766',
        10
      );
      const s = new BitcoreBN(
        '109412465507152403114191008482955798903072313614214706891149785278625167723646',
        10
      );
      const ec = new ECDSA({
        privkey: new PrivateKey(
          BitcoreBN.fromBuffer(Hash.sha256(new Buffer('test')))
        ),
        hashbuf,
        sig: new Signature({
          r,
          s
        })
      });

      ec.calci();
      ec.sig.i.should.equal(1);
    });
  });

  describe('#fromString', () => {
    it('round trip with fromString', () => {
      const str = ecdsa.toString();
      const ecdsa2 = ECDSA.fromString(str);
      should().exist(ecdsa2.hashbuf);
      should().exist(ecdsa2.privkey);
    });
  });

  describe('#randomK', () => {
    it('should generate a new random k when called twice in a row', () => {
      ecdsa.randomK();
      const k1 = ecdsa.k;
      ecdsa.randomK();
      const k2 = ecdsa.k;
      (k1.cmp(k2) === 0).should.equal(false);
    });

    it('should generate a random k that is (almost always) greater than this relatively small number', () => {
      ecdsa.randomK();
      const k1 = ecdsa.k;
      const k2 = new BitcoreBN(Math.pow(2, 32))
        .mul(new BitcoreBN(Math.pow(2, 32)))
        .mul(new BitcoreBN(Math.pow(2, 32)));
      k2.gt(k1).should.equal(false);
    });
  });

  describe('#deterministicK', () => {
    it('should generate the same deterministic k', () => {
      ecdsa.deterministicK();
      ecdsa.k
        .toBuffer()
        .toString('hex')
        .should.equal(
          'fcce1de7a9bcd6b2d3defade6afa1913fb9229e3b7ddf4749b55c4848b2a196e'
        );
    });
    it('should generate the same deterministic k if badrs is set', () => {
      ecdsa.deterministicK(0);
      ecdsa.k
        .toBuffer()
        .toString('hex')
        .should.equal(
          'fcce1de7a9bcd6b2d3defade6afa1913fb9229e3b7ddf4749b55c4848b2a196e'
        );
      ecdsa.deterministicK(1);
      ecdsa.k
        .toBuffer()
        .toString('hex')
        .should.not.equal(
          'fcce1de7a9bcd6b2d3defade6afa1913fb9229e3b7ddf4749b55c4848b2a196e'
        );
      ecdsa.k
        .toBuffer()
        .toString('hex')
        .should.equal(
          '727fbcb59eb48b1d7d46f95a04991fc512eb9dbf9105628e3aec87428df28fd8'
        );
    });
    it('should compute this test vector correctly', () => {
      // test fixture from bitcoinjs
      // https://github.com/bitcoinjs/bitcoinjs-lib/blob/10630873ebaa42381c5871e20336fbfb46564ac8/test/fixtures/ecdsa.json#L6
      const ec = new ECDSA();
      ec.hashbuf = Hash.sha256(
        new Buffer(
          'Everything should be made as simple as possible, but not simpler.'
        )
      );
      ec.privkey = new PrivateKey(new BitcoreBN(1));
      ec.privkey2pubkey();
      ec.deterministicK();
      ec.k
        .toBuffer()
        .toString('hex')
        .should.equal(
          'ec633bd56a5774a0940cb97e27a9e4e51dc94af737596a0c5cbb3d30332d92a5'
        );
      ec.sign();
      ec.sig.r
        .toString()
        .should.equal(
          '23362334225185207751494092901091441011938859014081160902781146257181456271561'
        );
      ec.sig.s
        .toString()
        .should.equal(
          '50433721247292933944369538617440297985091596895097604618403996029256432099938'
        );
    });
  });

  describe('#toPublicKey', () => {
    it('should calculate the correct public key', () => {
      ecdsa.k = new BitcoreBN(
        '114860389168127852803919605627759231199925249596762615988727970217268189974335',
        10
      );
      ecdsa.sign();
      ecdsa.sig.i = 0;
      const pubkey = ecdsa.toPublicKey();
      pubkey.point.eq(ecdsa.pubkey.point).should.equal(true);
    });

    it('should calculate the correct public key for this signature with low s', () => {
      ecdsa.k = new BitcoreBN(
        '114860389168127852803919605627759231199925249596762615988727970217268189974335',
        10
      );
      ecdsa.sig = Signature.fromString(
        '3045022100ec3cfe0e335791ad278b4ec8eac93d0347' +
          'a97877bb1d54d35d189e225c15f6650220278cf15b05ce47fb37d2233802899d94c774d5480bba9f0f2d996baa13370c43'
      );
      ecdsa.sig.i = 0;
      const pubkey = ecdsa.toPublicKey();
      pubkey.point.eq(ecdsa.pubkey.point).should.equal(true);
    });

    it('should calculate the correct public key for this signature with high s', () => {
      ecdsa.k = new BitcoreBN(
        '114860389168127852803919605627759231199925249596762615988727970217268189974335',
        10
      );
      ecdsa.sign();
      ecdsa.sig = Signature.fromString(
        '3046022100ec3cfe0e335791ad278b4ec8eac93d0347' +
          'a97877bb1d54d35d189e225c15f665022100d8730ea4fa31b804c82ddcc7fd766269f33a079ea38e012c9238f2e2bcff34fe'
      );
      ecdsa.sig.i = 1;
      const pubkey = ecdsa.toPublicKey();
      pubkey.point.eq(ecdsa.pubkey.point).should.equal(true);
    });
  });

  describe('#sigError', () => {
    it('should return an error if the hash is invalid', () => {
      const ec = new ECDSA();
      ec.sigError().should.equal('hashbuf must be a 32 byte buffer');
    });

    it('should return an error if r, s are invalid', () => {
      const ec = new ECDSA();
      ecdsa.hashbuf = Hash.sha256(new Buffer('test'));
      const pk = PublicKey.fromDER(
        new Buffer(
          '041ff0fe0f7b15ffaa85ff9f4744d539139c252a49' +
            '710fb053bb9f2b933173ff9a7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341',
          'hex'
        )
      );
      ecdsa.pubkey = pk;
      ecdsa.sig = new Signature();
      ecdsa.sig.r = new BitcoreBN(0);
      ecdsa.sig.s = new BitcoreBN(0);
      ecdsa.sigError().should.equal('r and s not in range');
    });

    it('should return an error if the signature is incorrect', () => {
      ecdsa.sig = Signature.fromString(
        '3046022100e9915e6236695f093a4128ac2a956c40' +
          'ed971531de2f4f41ba05fac7e2bd019c02210094e6a4a769cc7f2a8ab3db696c7cd8d56bcdbfff860a8c81de4bc6a798b90827'
      );
      ecdsa.sig.r = new BitcoreBN(ecdsa.sig.r.add(new BitcoreBN(1)));
      ecdsa.sigError().should.equal('Invalid signature');
    });
  });

  describe('#sign', () => {
    it('should create a valid signature', () => {
      ecdsa.randomK();
      ecdsa.sign();
      ecdsa.verify().verified.should.equal(true);
    });

    it('should should throw an error if hashbuf is not 32 bytes', () => {
      const ecdsa2 = new ECDSA().set({
        hashbuf: ecdsa.hashbuf.slice(0, 31),
        privkey: ecdsa.privkey
      });
      ecdsa2.randomK();
      ecdsa2.sign.bind(ecdsa2).should.throw('hashbuf must be a 32 byte buffer');
    });

    it('should default to deterministicK', () => {
      const ecdsa2 = new ECDSA(ecdsa);
      ecdsa2.k = undefined;
      let called = 0;
      const deterministicK = ecdsa2.deterministicK.bind(ecdsa2);
      ecdsa2.deterministicK = (badrs: number) => {
        called++;
        return deterministicK();
      };
      ecdsa2.sign();
      called.should.equal(1);
    });

    it('should generate right K', () => {
      const msg1 = new Buffer(
        '52204d20fd0131ae1afd173fd80a3a746d2dcc0cddced8c9dc3d61cc7ab6e966',
        'hex'
      );
      const msg2 = [].reverse.call(new Buffer(msg1));
      const pk = new Buffer(
        '16f243e962c59e71e54189e67e66cf2440a1334514c09c00ddcc21632bac9808',
        'hex'
      );
      const signature1 = ECDSA.sign(msg1, PrivateKey.fromBuffer(pk))
        .toBuffer()
        .toString('hex');
      const signature2 = ECDSA.sign(msg2, PrivateKey.fromBuffer(pk), 'little')
        .toBuffer()
        .toString('hex');
      signature1.should.equal(signature2);
    });
  });

  describe('#toString', () => {
    it('should convert this to a string', () => {
      const str = ecdsa.toString();
      (typeof str === 'string').should.equal(true);
    });
  });

  describe('signing and verification', () => {
    describe('@sign', () => {
      it('should produce a signature', () => {
        const sig = ECDSA.sign(ecdsa.hashbuf, ecdsa.privkey);
        (sig instanceof Signature).should.equal(true);
      });
      it('should produce a signature, and be different when called twice', () => {
        ecdsa.signRandomK();
        should().exist(ecdsa.sig);
        const ecdsa2 = new ECDSA(ecdsa);
        ecdsa2.signRandomK();
        ecdsa.sig.toString().should.not.equal(ecdsa2.sig.toString());
      });
    });

    describe('#verify', () => {
      it('should verify a signature that was just signed', () => {
        ecdsa.sig = Signature.fromString(
          '3046022100e9915e6236695f093a4128ac2a956c' +
            '40ed971531de2f4f41ba05fac7e2bd019c02210094e6a4a769cc7f2a8ab3db696c7cd8d56bcdbfff860a8c81de4bc6a798b90827'
        );
        ecdsa.verify().verified.should.equal(true);
      });
      it('should verify this known good signature', () => {
        ecdsa.signRandomK();
        ecdsa.verify().verified.should.equal(true);
      });
      it('should verify a valid signature, and unverify an invalid signature', () => {
        const sig = ECDSA.sign(ecdsa.hashbuf, ecdsa.privkey);
        ECDSA.verify(ecdsa.hashbuf, sig, ecdsa.pubkey).should.equal(true);
        const fakesig = new Signature(sig.r.add(new BitcoreBN(1)), sig.s);
        ECDSA.verify(ecdsa.hashbuf, fakesig, ecdsa.pubkey).should.equal(false);
      });
      it('should work with big and little endian', () => {
        let sig = ECDSA.sign(ecdsa.hashbuf, ecdsa.privkey, 'big');
        ECDSA.verify(ecdsa.hashbuf, sig, ecdsa.pubkey, 'big').should.equal(
          true
        );
        ECDSA.verify(ecdsa.hashbuf, sig, ecdsa.pubkey, 'little').should.equal(
          false
        );
        sig = ECDSA.sign(ecdsa.hashbuf, ecdsa.privkey, 'little');
        ECDSA.verify(ecdsa.hashbuf, sig, ecdsa.pubkey, 'big').should.equal(
          false
        );
        ECDSA.verify(ecdsa.hashbuf, sig, ecdsa.pubkey, 'little').should.equal(
          true
        );
      });
    });

    describe('vectors', () => {
      vectors.valid.forEach((obj, i) => {
        it('should validate valid vector ' + i, () => {
          const ec = new ECDSA().set({
            privkey: new PrivateKey(
              BitcoreBN.fromBuffer(new Buffer(obj.d, 'hex'))
            ),
            k: BitcoreBN.fromBuffer(new Buffer(obj.k, 'hex')),
            hashbuf: Hash.sha256(new Buffer(obj.message)),
            sig: new Signature().set({
              r: new BitcoreBN(obj.signature.r),
              s: new BitcoreBN(obj.signature.s),
              i: obj.i
            })
          });
          const ecdsa2 = new ECDSA(ec);
          ecdsa2.k = undefined;
          ecdsa2.sign();
          ecdsa2.calci();
          ecdsa2.k.toString().should.equal(ec.k.toString());
          ecdsa2.sig.toString().should.equal(ec.sig.toString());
          ecdsa2.sig.i.should.equal(ec.sig.i);
          ec.verify().verified.should.equal(true);
        });
      });

      vectors.invalid.sigError.forEach((obj, i) => {
        it(
          'should validate invalid.sigError vector ' +
            i +
            ': ' +
            obj.description,
          () => {
            const ec = new ECDSA().set({
              pubkey: PublicKey.fromPoint(Point.fromX(true, 1)),
              sig: new Signature(
                new BitcoreBN(obj.signature.r),
                new BitcoreBN(obj.signature.s)
              ),
              hashbuf: Hash.sha256(new Buffer(obj.message))
            });
            ec.sigError().should.equal(obj.exception);
          }
        );
      });

      vectors.deterministicK.forEach((obj, i) => {
        it('should validate deterministicK vector ' + i, () => {
          const hashbuf = Hash.sha256(new Buffer(obj.message));
          const privkey = new PrivateKey(
            BitcoreBN.fromBuffer(new Buffer(obj.privkey, 'hex')),
            'mainnet'
          );
          const ec = new ECDSA({
            privkey,
            hashbuf
          });
          ec.deterministicK(0)
            .k.toString('hex')
            .should.equal(obj.k_bad00);
          ec.deterministicK(1)
            .k.toString('hex')
            .should.equal(obj.k_bad01);
          ec.deterministicK(15)
            .k.toString('hex')
            .should.equal(obj.k_bad15);
        });
      });
    });
  });
});
