import test from 'node:test';
import assert from 'node:assert';

import * as schemas from './schemas';

import debug from 'debug';

debug.enable('*');

test.describe('Parse report', () => {
    schemas.Report.parse({
        age: 0,
        user_agent: '',
        url: '',
        report_format: 'report-to-buffered',
        type: 'coep',
        body: {
            disposition: 'reporting',
            type: 'corp',
            destination: 'close',   
        }
    } satisfies schemas.Report);
});
