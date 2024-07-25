import debug from 'debug';

import { Request, Response, NextFunction } from 'express';

interface ReportingHeadersConfig {
    /**
     * The reporting group name to use. Set to avoid collision with existing Reporting API usage.
     *
     * If `enableDefaultReporters` is set, this group name will always be set to `default`
     * @default "reporter"
     */
    reportingGroup?: string;

    /**
     * Add a `default` reporter group to receive Deprecation, Crash and Intervention reports
     */
    enableDefaultReporters?: boolean;

    /**
     * Enable `NEL` (Network Error Logging)
     *
     * Uses Reporting API v0 `Report-To` header as the Reporting API v1 doesn't support
     * Network Error Logging. See https://developer.chrome.com/blog/reporting-api-migration#network_error_logging
     */
    enableNetworkErrorLogging?: boolean;

    /**
     * Report version
     */
    version?: string;
}

/**
 * Headers that support the Reporting API v1
 */
const headers = [
    'Content-Security-Policy',
    'Content-Security-Policy-Report-Only',

    'Permissions-Policy',
    'Permissions-Policy-Report-Only',

    'Cross-Origin-Opener-Policy',
    'Cross-Origin-Opener-Policy-Report-Only',

    'Cross-Origin-Embedder-Policy',
    'Cross-Origin-Embedder-Policy-Report-Only',
] as const;
type Header = (typeof headers)[number];

/**
 * Adds reporting to all existing headers and sets the `Reporting-Endpoints` header
 *
 * Headers that support the Reporting API `report-to` directive:
 *
 * - Content-Security-Policy
 * - Content-Security-Policy-Report-Only
 * - Permissions-Policy
 * - Permissions-Policy-Report-Only
 * - Cross-Origin-Opener-Policy
 * - Cross-Origin-Opener-Policy-Report-Only
 * - Cross-Origin-Embedder-Policy
 * - Cross-Origin-Embedder-Policy-Report-Only
 *
 * @param reportingUrl The pathname or full URL for the reporting endpoint
 */
export function setupReportingHeaders(
    reportingUrl: string,
    config: ReportingHeadersConfig = {}
) {
    return (req: Request, res: Response, next: NextFunction) => {
        let setHeader = false;

        if (res.getHeader('Reporting-Endpoints')) {
            debug.log(
                'Reporting-Endpoints already set, will not set up reporting'
            );
            return next();
        }

        // The 'default' reporting group always receives Deprecation, Crash and Intervention reports.
        // If we do not want to collect those,  always use 'reporter' as group name.
        const reportTo = config.enableDefaultReporters
            ? 'default'
            : config.reportingGroup || 'reporter';

        for (const headerKey of headers) {
            const headers = res.getHeader(headerKey);
            const values = Array.isArray(headers) ? headers : [headers];

            for (let i = 0; i < values.length; i++) {
                const value = values[i];

                if (typeof value !== 'string') {
                    continue;
                }

                const newHeader = addReporterToHeader(
                    headerKey,
                    value,
                    reportTo,
                    reportingUrl
                );

                if (newHeader) {
                    values[i] = newHeader;
                    setHeader = true;
                }
            }

            res.setHeader(headerKey, values as any);
        }

        // Only set Reporting-Endpoints if any existing header was modified with reporting
        if (setHeader) {
            res.append('Reporting-Endpoints', `${reportTo}="${reportingUrl}"`);
        }

        if (config.enableNetworkErrorLogging) {
            // Reporting API v1 does not support Network Error Logging
            // so we rely on the Reporting API v0 `Report-To` header
            // https://developer.chrome.com/blog/reporting-api-migration#network_error_logging
            res.append(
                'Report-To',
                JSON.stringify({
                    group: reportTo,
                    max_age: 60 * 60 * 24 * 1000, // 1 day, milliseconds
                    endpoints: [{ url: reportingUrl }],
                })
            );
            res.setHeader(
                'NEL',
                JSON.stringify({
                    report_to: reportTo,
                    max_age: 60 * 60 * 24, // 1 day
                })
            );
        }

        return next();
    };
}

/**
 * Adds a reporter to a header
 */
function addReporterToHeader(
    header: Header,
    value: string,
    reportingGroup: string,
    reportingUri: string
): string | null {
    if (
        typeof value !== 'string' ||
        value.includes('report-to') ||
        value.includes('report-uri ')
    ) {
        debug.log(`Header "${header}: ${value}" already contains reporter`);
        return null;
    }

    switch (header) {
        case 'Content-Security-Policy':
        case 'Content-Security-Policy-Report-Only':
            // report-uri is deprecated in CSP 3 and ignored if the browser supports report-to, but Firefox does not and will use report-uri
            value += `;report-uri ${reportingUri}?src=report-uri`;

            // CSP does not have a `=` between report-to and the group name
            value += `;report-to ${reportingGroup}`;
            break;
        case 'Permissions-Policy':
        case 'Permissions-Policy-Report-Only':
            // https://github.com/w3c/webappsec-permissions-policy/blob/main/reporting.md
            value += `;report-to=${reportingGroup}`;
            break;
        case 'Cross-Origin-Embedder-Policy':
        case 'Cross-Origin-Embedder-Policy-Report-Only':
        case 'Cross-Origin-Opener-Policy':
        case 'Cross-Origin-Opener-Policy-Report-Only':
            // All other headers than CSP needs the `=` and needs to be encapsulated with ""
            value += `;report-to="${reportingGroup}"`;
            break;
        default:
            debug.log(`Unknown header ${header}`);
            return null;
    }

    return value;
}
