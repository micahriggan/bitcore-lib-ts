import { UnspentOutput } from './transaction/unspentoutput';
import { URI } from './uri';
import { Block } from './block/block';
import { Crypto } from './crypto';
import { Encoding } from './encoding';
import { BitcoreError } from './errors';
import { Network } from './networks';
import { MerkleBlock } from './block/merkleblock';
import { Script } from './script/script';
import { Transaction } from './transaction/transaction';
import { Util } from './util';
import { HDPrivateKey } from './hdprivatekey';
import { HDPublicKey } from './hdpublickey';
import { Address } from './address';
import { Opcode } from './opcode';
import { PrivateKey } from './privatekey';
import { PublicKey } from './publickey';
import { Unit } from './unit';
export const BitcoreLib = {
  Address,
  Block,
  crypto: Crypto,
  encoding: Encoding,
  errors: BitcoreError,
  Script,
  UnspentOutput,
  Transaction,
  HDPrivateKey,
  HDPublicKey,
  Network,
  Opcode,
  PrivateKey,
  MerkleBlock,
  PublicKey,
  Unit,
  util: Util,
  URI,
  version: 'v' + require('./package.json').version,
  versionGuard(version) {
    if (version !== undefined) {
      const message =
        'More than one instance of bitcore-lib found. ' +
        'Please make sure to require bitcore-lib and check that submodules do' +
        ' not also include their own bitcore-lib dependency.';
      throw new Error(message);
    }
  }
};

(global as any)._bitcore = BitcoreLib.version;

export * from './address';
export * from './hdprivatekey';
export * from './hdpublickey';
export * from './networks';
export * from './opcode';
export * from './privatekey';
export * from './publickey';
export * from './unit';
export * from './uri';
export * from './transaction';
export * from './crypto';
export * from './networks';
export * from './encoding';
export * from './script';
