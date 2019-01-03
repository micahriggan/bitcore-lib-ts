import * as chai from 'chai';
import { BitcoreLib } from '../src';
import * as fs from 'fs';

describe('Documentation', () => {
  it('major and minor versions should match', () => {
    const versionRE = /v[0-9]+\.[0-9]+/;
    const docIndex = fs.readFileSync('./docs/index.md', 'ascii');
    const docVersion = docIndex.match(versionRE)[0];
    BitcoreLib.version.indexOf(docVersion).should.equal(0);
  });
});
