type CryptoLib = {
  getRandomValues: (bbuf: Uint8Array) => void;
};
declare global {
  interface Window {
    browser: boolean;
    msCrypto: CryptoLib;
    crypto: CryptoLib;
  }
}
declare namespace NodeJS {
  interface Process {
    browser: boolean;
  }
}

declare var window: Window;
declare var process: NodeJS.Process;



export class Random {
  public static getRandomBuffer(size) {
    if (process.browser) return Random.getRandomBufferBrowser(size);
    else return Random.getRandomBufferNode(size);
  }

  public static getRandomBufferNode(size) {
    var crypto = require('crypto');
    return crypto.randomBytes(size);
  }

  public static getRandomBufferBrowser(size) {
    if (window) {
      if (!window.crypto && !window.msCrypto)
        throw new Error('window.crypto not available');

      if (window.crypto && window.crypto.getRandomValues)
        var crypto = window.crypto;
      else if (window.msCrypto && window.msCrypto.getRandomValues)
        //internet explorer
        var crypto = window.msCrypto;
      else throw new Error('window.crypto.getRandomValues not available');

      var bbuf = new Uint8Array(size);
      crypto.getRandomValues(bbuf);
      var buf = Buffer.from(bbuf);

      return buf;
    }
  }

  /* insecure random bytes, but it never fails */
  public static getPseudoRandomBuffer(size) {
    var b32 = 0x100000000;
    var b = Buffer.alloc(size);
    var r;

    for (var i = 0; i <= size; i++) {
      var j = Math.floor(i / 4);
      var k = i - j * 4;
      if (k === 0) {
        r = Math.random() * b32;
        b[i] = r & 0xff;
      } else {
        b[i] = (r = r >>> 8) & 0xff;
      }
    }

    return b;
  }
}

/* secure random bytes that sometimes throws an error due to lack of entropy */
