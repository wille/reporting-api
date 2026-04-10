import { describe, it } from 'vitest';

import * as schemas from './schemas';

import debug from 'debug';

debug.enable('*');

describe('Parse report', () => {
    it('parses a valid report', () => {
        schemas.Report.parse({
            age: 0,
            user_agent: '',
            url: '',
            report_format: 'report-to',
            type: 'coep',
            body: {
                disposition: 'reporting',
                type: 'corp',
                destination: 'close',
            },
        } satisfies schemas.Report);
    });
});
