import * as _ from 'lodash';
import { ERROR_TYPES } from './spec';

type MessageType = ((args: any) => string) | string;
type ErrorParam = keyof typeof ERROR_TYPES | { message: MessageType };

function format(message, args) {
  return message
    .replace('{0}', args[0])
    .replace('{1}', args[1])
    .replace('{2}', args[2]);
}
export class BitcoreError {
  constructor(errType: ErrorParam, ...args) {
    const message =
      typeof errType === 'string'
        ? ERROR_TYPES[errType].message
        : errType.message;

    const formattedMessage =
      typeof message === 'function'
        ? format(message(args), args)
        : format(message, args);
    return Error(formattedMessage);
  }
}
