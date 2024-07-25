import debug from 'debug';
import express, { Request, Response, NextFunction } from 'express';

import { Report, ContentSecurityPolicyReportBody } from './schemas';
import { SafeParseReturnType, ZodError } from 'zod';

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
        // safari-web-extension://*
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

function createReportingEndpoint(config: ReportingEndpointConfig) {
    const { onReport, onError } = config;

    if (config.debug) {
        debug.enable('reporting-api:*');
    }

    function handleReport<Input extends Report, Output extends Report>(
        result: SafeParseReturnType<Input, Output>,
        raw: any,
        req: Request
    ) {
        if (result.success) {
            const report = result.data;

            if (filterReport(report, config)) {
                onReport(report, req);
                log('received report %O', report);
            } else {
                log('filtered %j', report);
            }
        } else {
            log('parse error %j', {
                raw,
                err: result.error,
            });
            if (onError) {
                onError(result.error, req);
            }

            throw result.error;
        }
    }

    return (req: Request, res: Response, next: NextFunction) => {
        const version =
            typeof req.query.version === 'string'
                ? req.query.version
                : undefined;

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

            const v2body = {
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
            } satisfies ContentSecurityPolicyReport;

            const result = Report.safeParse({
                body: v2body,

                type: 'csp-violation',
                url: body['document-uri'],

                // CSP Level 2 reports are sent off directly by the browser
                age: 0,

                user_agent: req.headers['user-agent'] || '',

                report_format: 'report-uri',

                version,
            } satisfies Report);

            handleReport(result, req.body, req);

            return res.sendStatus(200);
        }

        if (req.headers['content-type'] !== 'application/reports+json') {
            log('bad request: Content-Type: %s', req.headers['content-type']);
            return res.sendStatus(400);
        }

        // Safari sends reports in the format `body: {...}` with no `age`
        if (typeof req.body.body === 'object') {
            const { body, type, url } = req.body;
            const result = Report.safeParse({
                body,
                type,
                url,
                age: 0,
                user_agent: req.headers['user-agent'] || '',
                report_format: 'report-to-single',
                version,
            } satisfies Report);

            handleReport(result, req.body, req);
            return res.sendStatus(200);
        }

        // Modern reporting API
        if (Array.isArray(req.body)) {
            for (const raw of req.body) {
                const result = Report.safeParse({
                    body: raw.body,
                    type: raw.type,
                    age: raw.age,
                    url: raw.url,
                    user_agent: raw.user_agent,
                    report_format: 'report-to-buffered',
                    version,
                } satisfies Report);

                handleReport(result, raw, req);
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

        // debug
        res.sendStatus(200);
        // return res.sendStatus(err instanceof ZodError ? 400 : 500);
    };
}

/**
 * Express route to collect reports
 */
export const reportingEndpoint = (config: ReportingEndpointConfig) => [
    bodyParser,
    createReportingEndpoint(config),
    createErrorHandler(config),
];
