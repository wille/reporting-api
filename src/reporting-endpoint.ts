import debug from 'debug';
import express, { Request, Response, NextFunction } from 'express';

import { Report, ContentSecurityPolicyReportBody } from './schemas';
import { ZodError } from 'zod';

const log = debug('reporting-api:endpoint');

export interface ReportingEndpointConfig {
    /**
     * Called when a report is received
     */
    onReport: (report: Report, req: Request) => any;

    onError?: (error: Error, req: Request) => any;

    /**
     * Ignore CSP violations from browser extensions
     */
    ignoreBrowserExtensions?: boolean;

    /**
     * The max age of reports in seconds. The reporting API is buffering
     * reports and can send more than one in a single report call
     */
    maxAge?: number;

    /**
     * Debug mode
     */
    debug?: boolean;
}

function filterReport(
    report: Report,
    { ignoreBrowserExtensions, maxAge }: ReportingEndpointConfig
): boolean {
    if (ignoreBrowserExtensions) {
        // if (
        //     report.sourceFile === 'chrome-extension' ||
        //     // Firefox enforces the CSP for all extension user scripts
        //     report.sourceFile === 'moz-extension'
        // ) {
        //     return false;
        // }
    }

    // Reporting API v1 `age` is in milliseconds but our settings is in seconds
    if (maxAge && report.age > maxAge * 1000) {
        log('report is too old %O', report);
        return false;
    }

    return true;
}

function logDebugReport(report: Report) {
    log('received report %O', report);
}

function reportingEndpointReporter(config: ReportingEndpointConfig) {
    const { onReport } = config;

    return (req: Request, res: Response, next: NextFunction) => {
        // CSP Level 2 Reports
        // See MDN docs: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only
        if (req.headers['content-type'] === 'application/csp-report') {
            const body = req.body['csp-report'];

            if (!body) {
                log(
                    'application/csp-report without csp-report in body: %O',
                    req.body
                );
                return res.sendStatus(400);
            }

            const csp = ContentSecurityPolicyReportBody.parse({
                blockedURL: body['blocked-uri'],
                columnNumber: body['column-number'],
                disposition: body['disposition'],
                documentURL: body['document-uri'],

                // `violated-directive` is deprecated in favor of `effective-directive`
                effectiveDirective:
                    body['effective-directive'] || body['violated-directive'],
                lineNumber: body['line-number'],
                originalPolicy: body['original-policy'],

                referrer: body['referrer'],
                sample: body['script-sample'],
                sourceFile: body['source-file'],
                statusCode: body['status-code'],
            } satisfies ContentSecurityPolicyReportBody);

            const report = {
                body: csp,

                type: 'csp-violation',
                url: body['document-uri'],

                // CSP Level 2 reports are sent off directly by the browser
                age: 0,

                user_agent: req.headers['user-agent'] || '',

                report_format: 'report-uri',
            } satisfies Report;

            if (filterReport(report, config)) {
                logDebugReport(report);
                onReport(report, req);
            }

            return res.sendStatus(200);
        }

        // Safari sends reports in the format `body: {...}` with no `age`
        if (typeof req.body.body === 'object') {
            const { body, type, url } = req.body;
            const report = Report.parse({
                body,
                type,
                url,
                age: 0,
                user_agent: req.headers['user-agent'] || '',
                report_format: 'report-to-single',
            } satisfies Report);

            if (filterReport(report, config)) {
                logDebugReport(report);
                onReport(report, req);
            }
            return res.sendStatus(200);
        }

        // Modern reporting API
        if (Array.isArray(req.body)) {
            for (const r of req.body) {
                const report = Report.parse({
                    body: r,
                    type: r.type,
                    age: r.age,
                    url: r.url,
                    user_agent: r.user_agent,
                    report_format: 'report-to-buffered',
                } satisfies Report);

                if (filterReport(report, config)) {
                    logDebugReport(report);
                    onReport(report, req);
                }
            }
        }

        return res.sendStatus(200);
    };
}

const bodyParser = express.json({
    type: [
        // Reporting API v0, Reporting API v1
        'application/reports+json',

        // CSP Level 2 reports
        // Does not rely on the reporting API and is set through the deprecated `report-uri` attribute on the CSP header
        // https://developer.chrome.com/blog/reporting-api-migration#migration_steps_for_csp_reporting
        'application/csp-report',
    ],
    strict: true,
    limit: '200kb',
});

function createErrorHandler(config: ReportingEndpointConfig) {
    return (err: Error, req: Request, res: Response, next: NextFunction) => {
        if (config.onError) {
            config.onError(err, req);
        }

        if (err instanceof ZodError) {
            log('parse error: %O body: %O', {
                err,
                body: req.body,
            });
        } else {
            log('error: %O, body: %O', err, req.body);
        }

        if (res.headersSent) {
            return next(err);
        }

        return res.sendStatus(err instanceof ZodError ? 400 : 500);
    };
}

/**
 * Express route to collect reports
 */
export const reportingEndpoint = (config: ReportingEndpointConfig) => [
    bodyParser,
    reportingEndpointReporter(config),
    createErrorHandler(config),
];
