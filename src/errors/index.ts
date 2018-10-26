import * as _ from 'lodash';
import { ERROR_TYPES } from './spec';

function format(message, args) {
  return message
    .replace('{0}', args[0])
    .replace('{1}', args[1])
    .replace('{2}', args[2]);
}
export class BitcoreError {
  constructor(errType: keyof typeof ERROR_TYPES, ...args) {
  const message = ERROR_TYPES[errType].message;
    let formattedMessage = '';
    if (typeof message === 'function') {
      formattedMessage = format(message(args), args);
    } else {
      formattedMessage = format(message, args);
    }
    return Error(formattedMessage);
  }
}
