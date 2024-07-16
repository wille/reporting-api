import express, { NextFunction, Request, Response } from 'express';
import debug from 'debug';

interface Report {
    // CSP 3
    age?: number;
    body: any;
    type: string;
    url: string;

    user_agent?: string;

    isEnforced: boolean;
}

interface ReporterConfig {
    /**
     * When a violation that is not enforced is received
     * 
     *      * https://developers.google.com/tag-platform/security/guides/csp

     */
    onReport: (report: Report) => any;

    onError?: (error: Error) => any;

    
    /**
     * Debug mode 
     */
    debug?: boolean;
}

function reportingEndpointReporter({
     onReport,
}: ReporterConfig) {
    return (req: Request, res: Response, next: NextFunction) => {
        const src = typeof req.query.src === 'string' ? req.query.src : '';

        const isEnforced = ['csp', 'document-policy'].includes(src);

        const body = req.body;

        if (req.body['csp-report']) {

        }

        // Reporting API is buffered, so it might send multiple reports in one request
        if (Array.isArray(body)) {
            for (const item of body) {
                const isEnforced = item.disposition === 'enforce';
                onReport({
                    age: item.age,
                    body: item.body,
                    type: item.type,
                    url: item.url,
                    user_agent: item.user_agent,
                    isEnforced,
                });
            }
        } else {
            onReport({
                age: 0,
                body: body.body,
                type: body.type,
                url: body.url,
                user_agent: '',
                isEnforced,
            });
        }

        debug.log('reporting-endpoint', src);

        return res.sendStatus(204);
    }
}

/**
 * Express route to collect reports
 */
export const reportingEndpoint = (config: ReporterConfig) => [
    express.json({
        type: [
            // CSP 3
            'application/reports+json',

            // Older CSP, Firefox
            'application/csp-report'
        ],
        limit: '200kb',
    }),
    reportingEndpointReporter(config),
]

interface ReportingEndpointConfig {
    //  Deprecation, Crash and Intervention reports
    reportingEndpointPath: string;

    /**
     * Add a `default` reporter group to send Deprecation, Crash and Intervention reports
     */
    includeDefault?: boolean;
}

/**
 * Headers that support the Reporting API `report-to` directive
 */
const headers = [
    'Content-Security-Policy',
    'Content-Security-Policy-Report-Only',

    'Document-Policy',
    'Document-Policy-Report-Only',

    'Cross-Origin-Opener-Policy',
    'Cross-Origin-Opener-Policy-Report-Only',

    'Cross-Origin-Embedder-Policy',
    'Cross-Origin-Embedder-Policy-Report-Only'
] as const;
 
/**
 * Adds reporting to all existing headers and sets the `Reporting-Endpoints` header
 * 
 * Headers that support the Reporting API `report-to` directive:
 *
 * - Content-Security-Policy
 * - Content-Security-Policy-Report-Only
 * - Document-Policy
 * - Document-Policy-Report-Only
 * - Cross-Origin-Opener-Policy
 * - Cross-Origin-Opener-Policy-Report-Only
 * - Cross-Origin-Embedder-Policy
 * - Cross-Origin-Embedder-Policy-Report-Only
 * 
 * @param reportingUrl The pathname or full URL for the reporting endpoint
 */
export function reportingEndpointHeader(reportingUrl: string, config: ReportingEndpointConfig) {
    function headerOk(value: any) {
        return typeof value === 'string' && !value.includes('report-to ') && !value.includes('report-uri ');
    }

    return (req: Request, res: Response, next: NextFunction) => {
        let setHeader = false;

        if (res.getHeader('Reporting-Endpoints')) {
            debug.log('Reporting-Endpoints already set, will set up reporting')
            return next();
        }

        // The 'default' reporting group always receives Deprecation, Crash and Intervention reports.
        // If we do not want to collect those,  always use 'reporter' as group name.
        const reportTo = config.includeDefault ? 'default' : 'reporter';

        for (const headerKey of headers) {
            const headers = res.getHeader(headerKey);
            const values = Array.isArray(headers) ? headers : [headers];

            // Do not set reporters on of the supported headers if it's already there
            if (!values.every(headerOk)) {
                debug.log(`Header ${headerKey} already contains reporter`);
                continue;
            }
 
            let append = '';

            switch (headerKey) {
                case 'Content-Security-Policy':
                case 'Content-Security-Policy-Report-Only':
                    // report-uri is deprecated in CSP 3 and ignored if the browser supports report-to, but Firefox does not and will use report-uri
                    append += `;report-uri ${reportingUrl}?src=report-uri`;
                    append += `;report-to ${reportTo}`;
                    break;
                default:
                    // All other headers than CSP needs the `=`
                    append += `;report-to=${reportTo}`;
                    break;
            }

            // Append report-uri and report-to the last header
            values[values.length - 1] += append;

            res.setHeader(headerKey, values as any);

            setHeader = true;
        }

        if (setHeader) {
            res.setHeader('Reporting-Endpoints', `${reportTo}="${reportingUrl}"`);
        }

        return next();
    }
}
