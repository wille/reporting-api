import { describe, expect, it } from 'vitest';

import * as schemas from './schemas';

import debug from 'debug';

debug.enable('*');

/**
 * The report payloads below are real-world examples taken from
 * browser documentation and specs:
 *
 * - https://developer.chrome.com/docs/capabilities/web-apis/reporting-api
 * - https://web.dev/articles/coop-coep
 * - https://developer.mozilla.org/en-US/docs/Web/API/PermissionsPolicyViolationReport
 * - https://w3c.github.io/network-error-logging/
 * - https://wicg.github.io/crash-reporting/
 * - https://github.com/W3C/reporting/blob/main/EXPLAINER.md
 */
describe('Parse report', () => {
    it('parses a csp-violation report', () => {
        schemas.Report.parse({
            age: 2,
            body: {
                blockedURL: 'https://site2.example/script.js',
                disposition: 'enforce',
                documentURL: 'https://site.example',
                effectiveDirective: 'script-src-elem',
                originalPolicy:
                    "script-src 'self'; object-src 'none'; report-to main-endpoint;",
                referrer: 'https://site.example',
                sample: '',
                statusCode: 200,
            },
            type: 'csp-violation',
            url: 'https://site.example',
            user_agent: 'Mozilla/5.0... Chrome/92.0.4504.0',
            report_format: 'report-to',
        } satisfies schemas.Report);
    });

    it('parses a coop navigation report', () => {
        schemas.Report.parse({
            age: 7,
            body: {
                disposition: 'enforce',
                effectivePolicy: 'same-origin',
                nextResponseURL:
                    'https://third-party-test.glitch.me/popup?report-only&coop=same-origin&',
                type: 'navigation-from-response',
            },
            type: 'coop',
            url: 'https://cross-origin-isolation.glitch.me/coop?coop=same-origin&',
            user_agent:
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4246.0 Safari/537.36',
            report_format: 'report-to',
        } satisfies schemas.Report);
    });

    it('parses a coop access report', () => {
        schemas.Report.parse({
            age: 51785,
            body: {
                columnNumber: 18,
                disposition: 'reporting',
                effectivePolicy: 'same-origin',
                lineNumber: 83,
                property: 'postMessage',
                sourceFile: 'https://cross-origin-isolation.glitch.me/popup.js',
                type: 'access-from-coop-page-to-openee',
            },
            type: 'coop',
            url: 'https://cross-origin-isolation.glitch.me/coop?report-only&coop=same-origin&',
            user_agent:
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4246.0 Safari/537.36',
            report_format: 'report-to',
        } satisfies schemas.Report);
    });

    it('parses a coep report', () => {
        schemas.Report.parse({
            age: 25101,
            body: {
                'blocked-url': 'https://third-party-test.glitch.me/check.svg?',
                blockedURL: 'https://third-party-test.glitch.me/check.svg?',
                destination: 'image',
                disposition: 'enforce',
                type: 'corp',
            },
            type: 'coep',
            url: 'https://cross-origin-isolation.glitch.me/?coep=require-corp&coop=same-origin&',
            user_agent:
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4249.0 Safari/537.36',
            report_format: 'report-to',
        } satisfies schemas.Report);
    });

    it('parses a network-error report', () => {
        schemas.Report.parse({
            age: 20,
            type: 'network-error',
            url: 'https://example.com/previous-page',
            user_agent:
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.0.0 Safari/537.36',
            report_format: 'report-to',
            body: {
                elapsed_time: 338,
                method: 'POST',
                phase: 'application',
                protocol: 'http/1.1',
                referrer: 'https://example.com/previous-page',
                sampling_fraction: 1,
                server_ip: '192.0.2.172',
                status_code: 400,
                type: 'http.error',
                url: 'https://example.com/bad-request',
            },
        } satisfies schemas.Report);
    });

    it('parses a deprecation report', () => {
        schemas.Report.parse({
            type: 'deprecation',
            age: 10,
            url: 'https://example.com/',
            user_agent: 'BarBrowser/98.0',
            report_format: 'report-to',
            body: {
                id: 'websql',
                anticipatedRemoval: '1/1/2020',
                message:
                    'WebSQL is deprecated and will be removed in Chrome 97 around January 2020',
                sourceFile: 'https://example.com/index.js',
                lineNumber: 1234,
                columnNumber: 42,
            },
        } satisfies schemas.Report);
    });

    it('parses an intervention report', () => {
        schemas.Report.parse({
            type: 'intervention',
            age: 27,
            url: 'https://example.com/',
            user_agent:
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.0.0 Safari/537.36',
            report_format: 'report-to',
            body: {
                id: 'audio-no-gesture',
                message:
                    'A request to play audio was blocked because it was not triggered by user activation (such as a click).',
                sourceFile: 'https://example.com/index.js',
                lineNumber: 1234,
                columnNumber: 42,
            },
        } satisfies schemas.Report);
    });

    it('parses a crash report', () => {
        schemas.Report.parse({
            type: 'crash',
            age: 42,
            url: 'https://example.com/',
            user_agent:
                'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0',
            report_format: 'report-to',
            body: {
                reason: 'oom',
            },
        } satisfies schemas.Report);
    });

    it('parses a permissions-policy-violation report from Chrome', () => {
        schemas.Report.parse({
            age: 48512,
            body: {
                columnNumber: 29,
                disposition: 'enforce',
                lineNumber: 44,
                message:
                    'Permissions policy violation: geolocation access has been blocked because of a permissions policy applied to the current document.',
                policyId: 'geolocation',
                sourceFile: 'https://example.com/',
            },
            type: 'permissions-policy-violation',
            url: 'https://example.com/',
            user_agent:
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
            report_format: 'report-to',
        } satisfies schemas.Report);
    });

    it('parses a document-policy-violation report', () => {
        schemas.Report.parse({
            age: 420,
            body: {
                columnNumber: 12,
                disposition: 'enforce',
                lineNumber: 11,
                message:
                    'Document policy violation: document-write is not allowed in this document.',
                policyId: 'document-write',
                sourceFile: 'https://site.example/script.js',
            },
            type: 'document-policy-violation',
            url: 'https://site.example/',
            user_agent: 'Mozilla/5.0... Chrome/92.0.4504.0',
            report_format: 'report-to',
        } satisfies schemas.Report);
    });

    it('parses a legacy feature-policy-violation report from Firefox', () => {
        schemas.Report.parse({
            age: 445,
            user_agent:
                'Mozilla/5.0 (Android 16; Mobile; rv:152.0) Gecko/152.0 Firefox/152.0',
            url: 'https://example.com/',
            report_format: 'report-to',
            type: 'feature-policy-violation',
            body: {
                featureId: 'serial',
                sourceFile: 'https://example.com/assets/app.js',
                lineNumber: 2,
                columnNumber: 329176,
                disposition: 'enforce',
            },
        } satisfies schemas.Report);
    });

    it('rejects a report with an unknown type', () => {
        expect(() =>
            schemas.Report.parse({
                age: 0,
                user_agent: '',
                url: '',
                report_format: 'report-to',
                type: 'unknown-report-type',
                body: {},
            })
        ).toThrow();
    });

    it('rejects a report with an invalid body', () => {
        expect(() =>
            schemas.Report.parse({
                age: 0,
                user_agent: '',
                url: '',
                report_format: 'report-to',
                type: 'feature-policy-violation',
                body: {
                    disposition: 'enforce',
                },
            })
        ).toThrow();
    });

    it('parses a coep report with minimal envelope fields', () => {
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
