import { BitcoreLib } from '../src';
import { should } from 'chai';

declare global {
  export interface Global extends NodeJS.Global {
    _bitcore: string;
  }
}

const Global: Global = global as any;

describe('#versionGuard', () => {
  it('global._bitcore should be defined', () => {
    should().equal(Global._bitcore, BitcoreLib.version);
  });

  it('throw an error if version is already defined', () => {
    (() => {
      BitcoreLib.versionGuard('version');
    }).should.throw('More than one instance of bitcore');
  });
});
