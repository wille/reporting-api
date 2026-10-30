import { describe, it, expect } from 'vitest';

import { createRequest, createResponse } from 'node-mocks-http';

import { setupReportingHeaders } from './index';

import debug from 'debug';

debug.enable('*');

const enforceReporter =
    ';report-uri /endpoint?disposition=enforce;report-to reporter';

describe('Handles multiple header values', () => {
    // setHeader is given copies since the middleware updates the array in place

    it('adds report-uri and report-to to every CSP header value', () => {
        const req = createRequest();
        const res = createResponse();
        const next = () => {};

        const inputCsp = [
            "script-src 'self'",
            "img-src 'self'",
            "frame-src 'self'",
        ];
        res.setHeader('Content-Security-Policy', [...inputCsp]);
        res.setHeader(
            'Content-Security-Policy-Report-Only',
            "frame-src 'none'"
        );

        setupReportingHeaders('/endpoint')(req, res, next);

        expect(res.getHeader('content-security-policy')).toEqual(
            inputCsp.map((value) => value + enforceReporter)
        );
        expect(res.getHeader('content-security-policy-report-only')).toEqual([
            "frame-src 'none';report-uri /endpoint?disposition=report;report-to reporter",
        ]);
        expect(res.getHeader('reporting-endpoints')).toBe(
            'reporter="/endpoint"'
        );
    });

    it('does not update header values that already contain report-to or report-uri', () => {
        const req = createRequest();
        const res = createResponse();
        const next = () => {};

        const inputCsp = [
            "script-src 'self';report-uri /endpoint?src=csp;report-to csp",
            "img-src 'self'",
            "frame-src 'self'",
        ];
        res.setHeader('Content-Security-Policy', [...inputCsp]);
        setupReportingHeaders('/endpoint')(req, res, next);

        expect(res.getHeader('content-security-policy')).toEqual([
            inputCsp[0],
            inputCsp[1] + enforceReporter,
            inputCsp[2] + enforceReporter,
        ]);
    });

    it('does not set Reporting-Endpoints when every value has a reporter', () => {
        const req = createRequest();
        const res = createResponse();
        const next = () => {};

        const inputCsp = [
            "script-src 'self';report-uri /csp",
            "img-src 'self';report-to csp",
        ];
        res.setHeader('Content-Security-Policy', [...inputCsp]);
        setupReportingHeaders('/endpoint')(req, res, next);

        expect(res.getHeader('content-security-policy')).toEqual(inputCsp);
        expect(res.getHeader('reporting-endpoints')).toBeUndefined();
    });
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
