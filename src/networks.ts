'use strict';
import * as _ from 'lodash';

import { BufferUtil } from './util/buffer';
import { JSUtil } from './util/js';
const networks = [];
const networkMaps = {};

export interface INetworkObject {
  name: string;
  alias: string;
  pubkeyhash: number;
  privatekey: number;
  scripthash: number;
  xpubkey: number;
  xprivkey: number;
  networkMagic: Buffer;
  port: number;
  dnsSeeds: Array<string>;

}
/**
 * A network is merely a map containing values that correspond to version
 * numbers for each bitcoin network. Currently only supporting "livenet"
 * (a.k.a. "mainnet") and "testnet".
 * @constructor
 */
export class Networks implements INetworkObject {
  public name: string;
  public alias: string;
  public pubkeyhash: number;
  public privatekey: number;
  public scripthash: number;
  public xpubkey: number;
  public xprivkey: number;
  public networkMagic: Buffer;
  public port: number;
  public dnsSeeds: Array<string>;

  constructor(obj?: INetworkObject) {
    const {
      name,
      alias,
      pubkeyhash,
      privatekey,
      scripthash,
      xpubkey,
      xprivkey,
      networkMagic,
      port,
      dnsSeeds
    } = obj;
    Object.assign(this, {
      name,
      alias,
      pubkeyhash,
      privatekey,
      scripthash,
      xpubkey,
      xprivkey,
      networkMagic,
      port,
      dnsSeeds
    });
  }

  public toString() {
    return this.name;
  }

  /**
   * @function
   * @member Networks#get
   * Retrieves the network associated with a magic number or string.
   * @param {string|number|Network} arg
   * @param {string|Array} keys - if set, only check if the magic number associated with this name matches
   * @return Network
   */
  public static get(arg, keys) {
    if (~networks.indexOf(arg)) {
      return arg;
    }
    if (keys) {
      if (!_.isArray(keys)) {
        keys = [keys];
      }
      for (const index in networks) {
        if (_.some(keys, (key) => networks[index][key] === arg)) {
          return networks[index];
        }
      }
      return undefined;
    }
    return networkMaps[arg];
  }

  /**
   * @function
   * @member Networks#add
   * Will add a custom Network
   * @param {Object} data
   * @param {string} data.name - The name of the network
   * @param {string} data.alias - The aliased name of the network
   * @param {Number} data.pubkeyhash - The publickey hash prefix
   * @param {Number} data.privatekey - The privatekey prefix
   * @param {Number} data.scripthash - The scripthash prefix
   * @param {Number} data.xpubkey - The extended public key magic
   * @param {Number} data.xprivkey - The extended private key magic
   * @param {Number} data.networkMagic - The network magic number
   * @param {Number} data.port - The network port
   * @param {Array}  data.dnsSeeds - An array of dns seeds
   * @return Network
   */
  public static addNetwork(data) {

    const network = new Network({
      name: data.name,
      alias: data.alias,
      pubkeyhash: data.pubkeyhash,
      privatekey: data.privatekey,
      scripthash: data.scripthash,
      xpubkey: data.xpubkey,
      xprivkey: data.xprivkey,
      networkMagic: BufferUtil.integerAsBuffer(data.networkMagic),
      dnsSeeds: data.dnsSeeds,
      port: data.port
    });

    _.each(network, (value) => {
      if (!_.isUndefined(value) && !_.isObject(value)) {
        networkMaps[value] = network;
      }
    });

    networks.push(network);

    return network;

  }

  /**
   * @function
   * @member Networks#remove
   * Will remove a custom network
   * @param {Network} network
   */
  public removeNetwork(network) {
    for (let i = 0; i < networks.length; i++) {
      if (networks[i] === network) {
        networks.splice(i, 1);
      }
    }
    for (const key in networkMaps) {
      if (networkMaps[key] === network) {
        delete networkMaps[key];
      }
    }
  }
}
  Network.addNetwork({
    name: 'livenet',
    alias: 'mainnet',
    pubkeyhash: 0x00,
    privatekey: 0x80,
    scripthash: 0x05,
    xpubkey: 0x0488b21e,
    xprivkey: 0x0488ade4,
    networkMagic: 0xf9beb4d9,
    port: 8333,
    dnsSeeds: [
      'seed.bitcoin.sipa.be',
      'dnsseed.bluematt.me',
      'dnsseed.bitcoin.dashjr.org',
      'seed.bitcoinstats.com',
      'seed.bitnodes.io',
      'bitseed.xf2.org'
    ]
  });

  Networks.addNetwork({
    name: 'testnet',
    alias: 'testnet',
    pubkeyhash: 0x6f,
    privatekey: 0xef,
    scripthash: 0xc4,
    xpubkey: 0x043587cf,
    xprivkey: 0x04358394,
    port: 18333,
    networkMagic: BufferUtil.integerAsBuffer(0x0b110907),
    dnsSeeds: [
      'testnet-seed.bitcoin.petertodd.org',
      'testnet-seed.bluematt.me',
      'testnet-seed.alexykot.me',
      'testnet-seed.bitcoin.schildbach.de'
    ]
  });

  Networks.addNetwork({
    name: 'testnet',
    alias: 'testnet',
    pubkeyhash: 0x6f,
    privatekey: 0xef,
    scripthash: 0xc4,
    xpubkey: 0x043587cf,
    xprivkey: 0x04358394,
    port: 18444,
    networkMagic: BufferUtil.integerAsBuffer(0xfabfb5da),
    dnsSeeds: []
  });

/**
 * @namespace Networks
 */
/*
 *module.exports = {
 *  add: addNetwork,
 *  remove: removeNetwork,
 *  defaultNetwork: livenet,
 *  livenet: livenet,
 *  mainnet: livenet,
 *  testnet: testnet,
 *  get: get,
 *  enableRegtest: enableRegtest,
 *  disableRegtest: disableRegtest
 *};
 */
