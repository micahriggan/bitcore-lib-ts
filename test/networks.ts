'use strict';

import { BitcoreLib } from '../src';
import { expect, should } from 'chai';
const networks = BitcoreLib.Network;

describe('Networks', () => {
  let customnet;

  it('should contain all Networks', () => {
    should().exist(networks.livenet);
    should().exist(networks.testnet);
    should().exist(networks.defaultNetwork);
  });

  it('will get network based on string "regtest" value', () => {
    const network = networks.get('regtest');
    network.should.equal(networks.testnet);
  });

  it('should be able to define a custom Network', () => {
    const custom = {
      name: 'customnet',
      alias: 'mynet',
      pubkeyhash: 0x10,
      privatekey: 0x90,
      scripthash: 0x08,
      xpubkey: 0x0278b20e,
      xprivkey: 0x0278ade4,
      networkMagic: 0xe7beb4d4,
      port: 20001,
      dnsSeeds: ['localhost', 'mynet.localhost']
    };
    networks.addNetwork(custom);
    customnet = networks.get('customnet');
    for (const key in custom) {
      if (key !== 'networkMagic') {
        customnet[key].should.equal(custom[key]);
      } else {
        const expected = new Buffer('e7beb4d4', 'hex');
        customnet[key].should.deep.equal(expected);
      }
    }
  });

  it('can remove a custom network', () => {
    networks.removeNetwork(customnet);
    const net = networks.get('customnet');
    should().equal(net, undefined);
  });

  it('should not set a network map for an undefined value', () => {
    const custom = {
      name: 'somenet',
      pubkeyhash: 0x13,
      privatekey: 0x93,
      scripthash: 0x11,
      xpubkey: 0x0278b20f,
      xprivkey: 0x0278ade5,
      networkMagic: 0xe7beb4d5,
      port: 20008,
      dnsSeeds: ['somenet.localhost']
    };
    networks.addNetwork(custom);
    const network = networks.get(undefined);
    should().not.exist(network);
    const somenet = networks.get('somenet');
    should().exist(somenet);
    somenet.name.should.equal('somenet');
    networks.removeNetwork(somenet);
  });

  const constants = [
    'name',
    'alias',
    'pubkeyhash',
    'scripthash',
    'xpubkey',
    'xprivkey'
  ];

  constants.forEach(key => {
    it('should have constant ' + key + ' for livenet and testnet', () => {
      networks.testnet.hasOwnProperty(key).should.equal(true);
      networks.livenet.hasOwnProperty(key).should.equal(true);
    });
  });

  it('tests only for the specified key', () => {
    expect(networks.get(0x6f, 'pubkeyhash')).to.equal(networks.testnet);
    expect(networks.get(0x6f, 'privatekey')).to.equal(undefined);
  });

  it('can test for multiple keys', () => {
    expect(networks.get(0x6f, ['pubkeyhash', 'scripthash'])).to.equal(
      networks.testnet
    );
    expect(networks.get(0xc4, ['pubkeyhash', 'scripthash'])).to.equal(
      networks.testnet
    );
    expect(networks.get(0x6f, ['privatekey', 'port'])).to.equal(undefined);
  });

  it('converts to string using the "name" property', () => {
    networks.livenet.toString().should.equal('livenet');
  });

  it('network object should be immutable', () => {
    expect(networks.testnet.name).to.equal('testnet');
    const fn = () => {
      networks.testnet.name = 'livenet';
    };
    expect(fn).to.throw(TypeError);
  });
});
