'use strict';

import { should } from 'chai';
import { BitcoreLib } from '../../src';

const errors = BitcoreLib.errors;
const ErrorTypes = errors.Types;
const $ = BitcoreLib.util.preconditions;
const PrivateKey = BitcoreLib.PrivateKey;

describe('preconditions', () => {
  it('can be used to assert state', () => {
    (() => {
      $.checkState(false, 'testing');
    }).should.throw(new errors(ErrorTypes.InvalidState));
  });
  it('throws no false negative', () => {
    (() => {
      $.checkState(true, 'testing');
    }).should.not.throw();
  });

  it('can be used to check an argument', () => {
    (() => {
      $.checkArgument(false, 'testing');
    }).should.throw(new errors(ErrorTypes.InvalidArgument));

    (() => {
      $.checkArgument(true, 'testing');
    }).should.not.throw(new errors(ErrorTypes.InvalidArgument));
  });

  it('can be used to check an argument type', () => {
    let error;
    try {
      $.checkArgumentType(1, 'string', 'argumentName');
    } catch (e) {
      error = e;
      e.message.should.equal(
        'Invalid Argument for argumentName, expected string but got number'
      );
    }
    should().exist(error);
  });
  it('has no false negatives when used to check an argument type', () => {
    (() => {
      $.checkArgumentType('a String', 'string', 'argumentName');
    }).should.not.throw();
  });

  it('can be used to check an argument type for a class', () => {
    let error;
    try {
      $.checkArgumentType(1, PrivateKey);
    } catch (e) {
      error = e;
      const fail = !~e.message.indexOf('Invalid Argument for (unknown name)');
      fail.should.equal(false);
    }
    should().exist(error);
  });
  it('has no false negatives when checking a type for a class', () => {
    (() => {
      $.checkArgumentType(new PrivateKey(), PrivateKey);
    }).should.not.throw();
  });

  it('formats correctly a message on InvalidArgument()', () => {
    const error = new errors(ErrorTypes.InvalidArgumentType);
    error.message.should.equal('Invalid Argument');
  });

  it('formats correctly a message on checkArgument', () => {
    let error;
    try {
      $.checkArgument(null, 'parameter must be provided');
    } catch (e) {
      error = e;
    }
    error.message.should.equal('Invalid Argument: parameter must be provided');
  });
});
