import { describe, it, expect } from 'vitest';

import { createRequest, createResponse } from 'node-mocks-http';

import { setupReportingHeaders } from './index';

import debug from 'debug';

debug.enable('*');

describe('Handles multiple headers and only updates the last occuring', () => {
    it('updates the last CSP header with report-uri and report-to', () => {
        const req = createRequest();
        const res = createResponse();
        const next = () => {};

        const inputCsp = [
            "script-src 'self'",
            "img-src 'self'",
            "frame-src 'self'",
        ];
        res.setHeader('Content-Security-Policy', inputCsp);
        res.setHeader(
            'Content-Security-Policy-Report-Only',
            "frame-src 'none'"
        );

        setupReportingHeaders('/endpoint')(req, res, next);

        const outputCsp = res.getHeader('content-security-policy') as string[];

        for (let i = 0; i < inputCsp.length - 1; i++) {
            expect(inputCsp[i]).toBe(outputCsp[i]);
        }

        expect(inputCsp.at(-1)).toBe(
            "frame-src 'self';report-uri /endpoint?disposition=enforce;report-to reporter"
        );
    });
});

it('Does not update headers if they already contain report-to or report-uri', () => {
    const req = createRequest();
    const res = createResponse();
    const next = () => {};

    const inputCsp = [
        "script-src 'self';report-uri /endpoint?src=csp;report-to csp",
        "img-src 'self'",
        "frame-src 'self'",
    ];
    res.setHeader('Content-Security-Policy', inputCsp);
    setupReportingHeaders('/endpoint')(req, res, next);
    expect(res.getHeader('content-security-policy')).toEqual(inputCsp);
});
