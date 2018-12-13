import { BufferUtil } from './buffer';
export * from './buffer';
export * from './js';
export * from './preconditions';

import preconditions from './preconditions';
import { JSUtil } from './js';

export const Util = {
  buffer: BufferUtil,
  js: JSUtil,
  preconditions
};
