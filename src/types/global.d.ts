import { BitcoreLib } from '..';

declare global {
  export interface Global extends NodeJS.Global {
    _bitcore: string;
  }
}

