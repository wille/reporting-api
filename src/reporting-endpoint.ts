import debug from 'debug';
import express, { Request, Response, NextFunction } from 'express';

import { Report, ContentSecurityPolicyReport } from './schemas';
import { SafeParseReturnType, ZodError } from 'zod';

const log = debug('reporting-api:endpoint');

export interface ReportingEndpointConfig {
    /**
     * Called when a report is received
     */
    onReport: (report: Report, req: Request) => any;

    /**
     * Called when a report validation error occured.
     *
     * This should not happen as the schemas are well relaxed but if a new type of
     * report is received then this function is used to track these reports so we
     * can take action on them.
     *
     * @param error The validation error (ZodError)
     * @param object The body of the report that failed the validation
     * @param req The request
     */
    onValidationError?: (error: ZodError, body: any, req: Request) => any;

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
    if (ignoreBrowserExtensions && report.type === 'csp-violation') {
        if (
            report.body.sourceFile === 'chrome-extension' ||
            report.body.sourceFile === 'moz-extension' ||
            report.body.sourceFile?.startsWith('safari-web-extension://')
        ) {
            return false;
        }
    }

    // Reporting API v1 `age` is in milliseconds but our settings is in seconds
    if (maxAge && report.age > maxAge * 1000) {
        log('report is too old %O', report);
        return false;
    }

    return true;
}

function createReportingEndpoint(config: ReportingEndpointConfig) {
    const { onReport, onValidationError } = config;

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
            if (onValidationError) {
                onValidationError(result.error, raw, req);
            }

            throw result.error;
        }
    }

    return (req: Request, res: Response, next: NextFunction) => {
        if (req.method !== 'POST') {
            return res.sendStatus(405);
        }

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

                // Older Firefox doesn't set the disposition so we track it in the query params
                disposition: body['disposition'] || req.query.disposition,

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
                report_format: 'report-to-safari',
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
                    report_format: 'report-to',
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

/**
 * Express route to collect reports
 */
export const reportingEndpoint = (config: ReportingEndpointConfig) => [
    bodyParser,
    createReportingEndpoint(config),
];
