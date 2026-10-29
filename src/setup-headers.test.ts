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

describe('Headers with multiple list members', () => {
    it('adds report-to to every feature in Permissions-Policy', () => {
        const req = createRequest();
        const res = createResponse();

        res.setHeader(
            'Permissions-Policy',
            'camera=(), geolocation=(self "https://a.example")'
        );
        setupReportingHeaders('/endpoint')(req, res);

        expect(res.getHeader('permissions-policy')).toEqual([
            'camera=();report-to=reporter, geolocation=(self "https://a.example");report-to=reporter',
        ]);
    });

    it('keeps an existing per-feature reporter', () => {
        const req = createRequest();
        const res = createResponse();

        res.setHeader(
            'Permissions-Policy',
            'camera=();report-to=other, geolocation=()'
        );
        setupReportingHeaders('/endpoint')(req, res);

        expect(res.getHeader('permissions-policy')).toEqual([
            'camera=();report-to=other, geolocation=();report-to=reporter',
        ]);
    });

    it('adds reporting to every comma separated CSP policy', () => {
        const req = createRequest();
        const res = createResponse();

        res.setHeader(
            'Content-Security-Policy',
            "script-src 'self', img-src 'self'"
        );
        setupReportingHeaders('/endpoint')(req, res);

        const reporter =
            ';report-uri /endpoint?disposition=enforce;report-to reporter';
        expect(res.getHeader('content-security-policy')).toEqual([
            `script-src 'self'${reporter}, img-src 'self'${reporter}`,
        ]);
    });

    it('does not set Reporting-Endpoints when every member has a reporter', () => {
        const req = createRequest();
        const res = createResponse();

        res.setHeader(
            'Permissions-Policy',
            'camera=();report-to=a, geolocation=();report-to=b'
        );
        setupReportingHeaders('/endpoint')(req, res);

        expect(res.getHeader('reporting-endpoints')).toBeUndefined();
    });
});
