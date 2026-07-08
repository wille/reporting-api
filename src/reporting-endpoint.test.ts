import { describe, expect, it, vi } from 'vitest';

import { createRequest, createResponse, RequestOptions } from 'node-mocks-http';
import type { RequestHandler } from 'express';

import { reportingEndpoint, ReportingEndpointConfig } from './index';
import { Report } from './schemas';

import debug from 'debug';

debug.enable('*');

/**
 * Calls the reporting endpoint handler directly, bypassing the express.json
 * body parser by presetting `body` on the mocked request
 */
function call(config: ReportingEndpointConfig, reqOpts: RequestOptions) {
    const handler = reportingEndpoint(config)[1] as RequestHandler;
    const req = createRequest(reqOpts);
    const res = createResponse();
    handler(req, res, () => {});
    return { req, res };
}

function validReport(overrides: Partial<Report> = {}) {
    return {
        type: 'deprecation',
        age: 10,
        url: 'https://example.com/',
        user_agent: 'Mozilla/5.0',
        body: {
            id: 'websql',
            message: 'WebSQL is deprecated',
        },
        ...overrides,
    };
}

function post(body: any, reqOpts: RequestOptions = {}): RequestOptions {
    return {
        method: 'POST',
        headers: { 'content-type': 'application/reports+json' },
        body,
        ...reqOpts,
    };
}

describe('method guard', () => {
    it('responds 405 with an Allow header to non-POST requests', () => {
        const onReport = vi.fn();
        const { res } = call({ onReport }, { method: 'GET' });

        expect(res.statusCode).toBe(405);
        expect(res.getHeader('allow')).toBe('POST, OPTIONS');
        expect(onReport).not.toHaveBeenCalled();
    });
});

describe('CSP Level 2 report-uri format', () => {
    const cspLevel2Body = {
        'csp-report': {
            'blocked-uri': 'https://evil.example/script.js',
            'column-number': 8,
            'document-uri': 'https://site.example/page',
            'effective-directive': 'script-src-elem',
            'line-number': 12,
            'original-policy': "script-src 'self'; report-uri /endpoint",
            referrer: '',
            'script-sample': '',
            'source-file': 'https://site.example/app.js',
            'status-code': 200,
            disposition: 'enforce',
        },
    };

    it('maps kebab-case fields to a csp-violation report', () => {
        const onReport = vi.fn();
        const { res } = call(
            { onReport },
            {
                method: 'POST',
                headers: { 'content-type': 'application/csp-report' },
                body: cspLevel2Body,
            }
        );

        expect(res.statusCode).toBe(200);
        expect(onReport).toHaveBeenCalledOnce();

        const report = onReport.mock.calls[0][0] as Report;
        expect(report.type).toBe('csp-violation');
        expect(report.report_format).toBe('report-uri');
        expect(report.age).toBe(0);
        expect(report.url).toBe('https://site.example/page');
        expect(report.body).toMatchObject({
            blockedURL: 'https://evil.example/script.js',
            documentURL: 'https://site.example/page',
            effectiveDirective: 'script-src-elem',
            sourceFile: 'https://site.example/app.js',
            lineNumber: 12,
            columnNumber: 8,
            statusCode: 200,
            disposition: 'enforce',
        });
    });

    it('falls back to the deprecated violated-directive field', () => {
        const onReport = vi.fn();
        const body = structuredClone(cspLevel2Body);
        delete (body['csp-report'] as any)['effective-directive'];
        (body['csp-report'] as any)['violated-directive'] = 'img-src';

        call(
            { onReport },
            {
                method: 'POST',
                headers: { 'content-type': 'application/csp-report' },
                body,
            }
        );

        expect(onReport).toHaveBeenCalledOnce();
        expect(onReport.mock.calls[0][0].body.effectiveDirective).toBe(
            'img-src'
        );
    });

    it('reads the disposition from the query param when missing in the body', () => {
        const onReport = vi.fn();
        const body = structuredClone(cspLevel2Body);
        delete (body['csp-report'] as any).disposition;

        call(
            { onReport },
            {
                method: 'POST',
                headers: { 'content-type': 'application/csp-report' },
                query: { disposition: 'report' },
                body,
            }
        );

        expect(onReport).toHaveBeenCalledOnce();
        expect(onReport.mock.calls[0][0].body.disposition).toBe('report');
    });

    it('responds 400 and calls onValidationError when csp-report is missing', () => {
        const onReport = vi.fn();
        const onValidationError = vi.fn();
        const { res } = call(
            { onReport, onValidationError },
            {
                method: 'POST',
                headers: { 'content-type': 'application/csp-report' },
                body: { unexpected: true },
            }
        );

        expect(res.statusCode).toBe(400);
        expect(onReport).not.toHaveBeenCalled();
        expect(onValidationError).toHaveBeenCalledOnce();
        expect(onValidationError.mock.calls[0][0]).toBeInstanceOf(Error);
    });
});

describe('Safari report-to format', () => {
    it('parses a report sent with application/csp-report and a body object', () => {
        const onReport = vi.fn();
        call(
            { onReport },
            {
                method: 'POST',
                headers: {
                    'content-type': 'application/csp-report',
                    'user-agent': 'Safari/605.1.15',
                },
                body: {
                    type: 'csp-violation',
                    url: 'https://site.example/page',
                    body: {
                        blockedURL: 'https://evil.example/script.js',
                        disposition: 'enforce',
                        documentURL: 'https://site.example/page',
                        effectiveDirective: 'script-src-elem',
                        originalPolicy: "script-src 'self'",
                    },
                },
            }
        );

        expect(onReport).toHaveBeenCalledOnce();
        const report = onReport.mock.calls[0][0] as Report;
        expect(report.report_format).toBe('report-to-safari');
        expect(report.age).toBe(0);
        expect(report.user_agent).toBe('Safari/605.1.15');
    });
});

describe('Reporting API format', () => {
    it('handles multiple buffered reports in one request', () => {
        const onReport = vi.fn();
        const { res } = call(
            { onReport },
            post([validReport({ age: 10 }), validReport({ age: 20 })])
        );

        expect(res.statusCode).toBe(200);
        expect(onReport).toHaveBeenCalledTimes(2);
        expect(onReport.mock.calls[0][0].report_format).toBe('report-to');
        expect(onReport.mock.calls[1][0].age).toBe(20);
    });

    it('delivers valid reports and reports invalid ones in a mixed batch', () => {
        const onReport = vi.fn();
        const onValidationError = vi.fn();
        const { res } = call(
            { onReport, onValidationError },
            post([
                validReport(),
                { type: 'unknown-report-type', age: 0, url: '', body: {} },
            ])
        );

        expect(res.statusCode).toBe(200);
        expect(onReport).toHaveBeenCalledOnce();
        expect(onValidationError).toHaveBeenCalledOnce();
    });

    it('ignores a non-array JSON body', () => {
        const onReport = vi.fn();
        const onValidationError = vi.fn();
        const { res } = call(
            { onReport, onValidationError },
            post({ not: 'an array' })
        );

        expect(res.statusCode).toBe(200);
        expect(onReport).not.toHaveBeenCalled();
        expect(onValidationError).not.toHaveBeenCalled();
    });

    it('attaches the version query param to the report', () => {
        const onReport = vi.fn();
        call({ onReport }, post([validReport()], { query: { version: '42' } }));

        expect(onReport).toHaveBeenCalledOnce();
        expect(onReport.mock.calls[0][0].version).toBe('42');
    });
});

describe('report filtering', () => {
    const extensionReport = validReport({
        type: 'csp-violation',
        body: {
            blockedURL: 'https://evil.example/script.js',
            disposition: 'enforce',
            documentURL: 'https://site.example/page',
            effectiveDirective: 'script-src-elem',
            originalPolicy: "script-src 'self'",
            sourceFile: 'chrome-extension://abcdefg/content.js',
        },
    });

    it.each([
        'chrome-extension://abcdefg/content.js',
        'moz-extension://abcdefg/content.js',
        'safari-web-extension://abcdefg/content.js',
    ])(
        'drops reports from %s when ignoreBrowserExtensions is set',
        (sourceFile) => {
            const onReport = vi.fn();
            const report = structuredClone(extensionReport);
            (report.body as any).sourceFile = sourceFile;

            const { res } = call(
                { onReport, ignoreBrowserExtensions: true },
                post([report])
            );

            expect(res.statusCode).toBe(200);
            expect(onReport).not.toHaveBeenCalled();
        }
    );

    it('delivers extension reports when ignoreBrowserExtensions is off', () => {
        const onReport = vi.fn();
        call({ onReport }, post([extensionReport]));

        expect(onReport).toHaveBeenCalledOnce();
    });

    it('drops reports older than maxAge seconds', () => {
        const onReport = vi.fn();
        call(
            { onReport, maxAge: 60 },
            post([validReport({ age: 61_000 }), validReport({ age: 59_000 })])
        );

        expect(onReport).toHaveBeenCalledOnce();
        expect(onReport.mock.calls[0][0].age).toBe(59_000);
    });

    it('drops deprecation reports with ignored ids', () => {
        const onReport = vi.fn();
        call(
            { onReport, ignoredDeprecationIds: ['websql'] },
            post([
                validReport(),
                validReport({
                    body: { id: 'other-feature', message: 'deprecated' },
                }),
            ])
        );

        expect(onReport).toHaveBeenCalledOnce();
        expect(onReport.mock.calls[0][0].body.id).toBe('other-feature');
    });
});

describe('CORS', () => {
    it('allows any origin with allowedOrigins: "*"', () => {
        const onReport = vi.fn();
        const { res } = call(
            { onReport, allowedOrigins: '*' },
            post([validReport()], {
                headers: {
                    'content-type': 'application/reports+json',
                    origin: 'https://any.example',
                },
            })
        );

        expect(res.getHeader('access-control-allow-origin')).toBe('*');
        expect(onReport).toHaveBeenCalledOnce();
    });

    it('echoes an allowed origin and sets Vary: Origin', () => {
        const { res } = call(
            { onReport: vi.fn(), allowedOrigins: 'https://app.example.com' },
            post([validReport()], {
                headers: {
                    'content-type': 'application/reports+json',
                    origin: 'https://app.example.com',
                },
            })
        );

        expect(res.getHeader('access-control-allow-origin')).toBe(
            'https://app.example.com'
        );
        expect(res.getHeader('vary')).toBe('Origin');
    });

    it('matches origins against RegExp and array matchers', () => {
        const { res } = call(
            {
                onReport: vi.fn(),
                allowedOrigins: [
                    'https://exact.example.com',
                    /^https:\/\/.*\.example\.com$/,
                ],
            },
            post([validReport()], {
                headers: {
                    'content-type': 'application/reports+json',
                    origin: 'https://sub.example.com',
                },
            })
        );

        expect(res.getHeader('access-control-allow-origin')).toBe(
            'https://sub.example.com'
        );
    });

    it('still processes reports from disallowed origins but sets no CORS headers', () => {
        const onReport = vi.fn();
        const { res } = call(
            { onReport, allowedOrigins: 'https://app.example.com' },
            post([validReport()], {
                headers: {
                    'content-type': 'application/reports+json',
                    origin: 'https://evil.example.com',
                },
            })
        );

        expect(res.getHeader('access-control-allow-origin')).toBeUndefined();
        expect(onReport).toHaveBeenCalledOnce();
    });

    it('answers preflight requests when allowedOrigins is set', () => {
        const onReport = vi.fn();
        const { res } = call(
            { onReport, allowedOrigins: '*' },
            {
                method: 'OPTIONS',
                headers: { origin: 'https://any.example' },
            }
        );

        expect(res.statusCode).toBe(200);
        expect(res.getHeader('access-control-allow-headers')).toBe(
            'Content-Type'
        );
        expect(res.getHeader('access-control-allow-methods')).toBe('POST');
        expect(res.getHeader('access-control-max-age')).toBe('7200');
        expect(onReport).not.toHaveBeenCalled();
    });

    it('sets no CORS headers when allowedOrigins is not configured', () => {
        const { res } = call(
            { onReport: vi.fn() },
            post([validReport()], {
                headers: {
                    'content-type': 'application/reports+json',
                    origin: 'https://any.example',
                },
            })
        );

        expect(res.getHeader('access-control-allow-origin')).toBeUndefined();
    });
});
