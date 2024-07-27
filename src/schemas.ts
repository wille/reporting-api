import { z } from 'zod';

export const ContentSecurityPolicyReport = z
    .object({
        blockedURL: z.string(),
        columnNumber: z.number().optional(),
        disposition: z.enum(['enforce', 'report']),
        documentURL: z.string(), // url
        effectiveDirective: z.string(),
        lineNumber: z.number().optional(),
        originalPolicy: z.string(),
        referrer: z.string(),
        sample: z.string().optional(),
        sourceFile: z.string().optional(),
        statusCode: z.number().optional(),
    })
    .passthrough();
export type ContentSecurityPolicyReport = z.infer<
    typeof ContentSecurityPolicyReport
>;

export const CrossOriginOpenerPolicyReport = z
    .object({
        disposition: z.enum(['reporting', 'enforce']),
        effectivePolicy: z.enum([
            'unsafe-none',
            'same-origin',
            'same-origin-allow-popups',
            'same-origin-plus-coep',
        ]),
        type: z.enum([
            'navigate-to-document',
            'navigate-from-document',
            'navigation-from-response',
            'access-to-coop-page-from-opener',
            'access-from-coop-page-to-opener',
            'access-from-coop-page-to-other',
            'access-from-coop-page-to-openee',
            'access-to-coop-page-from-opener',
            'access-to-coop-page-from-openee',
            'access-to-coop-page-from-other',
        ]),
        columnNumber: z.number().optional(),
        initialPopupURL: z.string().optional(),
        lineNumber: z.number().optional(),
        openeeURL: z.string().optional(), // url
        property: z.string(), // closed, postMessage
        sourceFile: z.string().optional(), // url
    })
    .passthrough();
export type CrossOriginOpenerPolicyReport = z.infer<
    typeof CrossOriginOpenerPolicyReport
>;

export const CrossOriginEmbedderPolicyReport = z
    .object({
        disposition: z.enum(['reporting', 'enforce']),

        blockedURL: z.string().optional(), // url

        /**
         * - navigation
         * - worker initialization
         * - corp
         */
        type: z.string(), // navigation, 'worker initialization', corp

        /**
         * Set on `type: 'corp'`
         */
        destination: z.string().optional(), // script, iframe
    })
    .passthrough();
/**
 * https://github.com/camillelamy/explainers/blob/main/coop_reporting.md
 */
export type CrossOriginEmbedderPolicyReport = z.infer<
    typeof CrossOriginEmbedderPolicyReport
>;

export const NetworkErrorLogging = z
    .object({
        elapsed_time: z.number(),
        method: z.string(),
        phase: z.string(), // application
        protocol: z.string(),
        referrer: z.string(),
        sampling_fraction: z.number(),
        server_ip: z.string(),
        status_code: z.number(),
        type: z.string(), // http.error
    })
    .passthrough();
export type NetworkErrorLogging = z.infer<typeof NetworkErrorLogging>;

export const PermissionsPolicyViolation = z
    .object({
        message: z.string(),
        disposition: z.enum(['report', 'enforce']),

        /**
         * The voilated policy
         * `accelerometer`
         */
        policyId: z.string(),

        columnNumber: z.number().optional(),
        lineNumber: z.number().optional(),
        sourceFile: z.string(),
    })
    .passthrough();
export type PermissionsPolicyViolation = z.infer<
    typeof PermissionsPolicyViolation
>;

export const InterventionReport = z.object({
    id: z.string(),
    message: z.string(),

    columnNumber: z.number().optional(),
    lineNumber: z.number().optional(),
    sourceFile: z.string().optional(),
});
export type InterventionReport = z.infer<typeof InterventionReport>;

export const CrashReport = z.object({
    /**
     * Crash reason
     *
     * - `oom` Out of memory
     */
    reason: z.string().optional(), // oom
});
export type CrashReport = z.infer<typeof CrashReport>;

export const DeprecationReport = z.object({
    id: z.string(),
    message: z.string(),

    columnNumber: z.number().optional(),
    lineNumber: z.number().optional(),
    sourceFile: z.string().optional(),
});
export type DeprecationReport = z.infer<typeof DeprecationReport>;

export const Report = z
    .discriminatedUnion('type', [
        z.object({
            type: z.literal('csp-violation'),
            body: ContentSecurityPolicyReport,
        }),
        z.object({
            type: z.literal('coop'),
            body: CrossOriginOpenerPolicyReport,
        }),
        z.object({
            type: z.literal('coep'),
            body: CrossOriginEmbedderPolicyReport,
        }),
        z.object({
            type: z.literal('deprecation'),
            body: DeprecationReport,
        }),
        z.object({
            type: z.literal('crash'),
            body: CrashReport,
        }),
        z.object({
            type: z.literal('intervention'),
            body: InterventionReport,
        }),
        z.object({
            type: z.literal('network-error'),
            body: NetworkErrorLogging,
        }),
        z.object({
            type: z.literal('permissions-policy-violation'),
            body: PermissionsPolicyViolation,
        }),
    ])
    .and(
        z.object({
            /**
             * URL of the page where the violation occured
             */
            url: z.string(), // url

            /**
             * Age of the report in milliseconds
             */
            age: z.number(),
            user_agent: z.string(),

            /**
             * Your policy version
             */
            version: z.string().optional(),

            /**
             * The format the report was received in
             *
             * - `report-uri` - legacy csp report-uri attribute
             * - `report-to-buffered` Reporting API v2 report
             * - `report-to-single` Safari is not sending buffered reports
             */
            report_format: z.enum([
                'report-uri',
                'report-to',
                'report-to-safari',
            ]),
        })
    );
export type Report = z.infer<typeof Report>;
