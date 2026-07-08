import { z } from 'zod';

export const ContentSecurityPolicyReport = z
    .object({
        blockedURL: z.string(),
        columnNumber: z.number().nullish(),
        disposition: z.enum(['enforce', 'report']),
        documentURL: z.string(), // url
        effectiveDirective: z.string(),
        lineNumber: z.number().nullish(),
        originalPolicy: z.string(),
        referrer: z.string().nullish(),
        sample: z.string().nullish(),
        sourceFile: z.string().nullish(),
        statusCode: z.number().nullish(),
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
            'navigation-to-response',
            'access-to-coop-page-from-opener',
            'access-from-coop-page-to-opener',
            'access-from-coop-page-to-other',
            'access-from-coop-page-to-openee',
            'access-to-coop-page-from-opener',
            'access-to-coop-page-from-openee',
            'access-to-coop-page-from-other',
        ]),
        columnNumber: z.number().nullish(),
        initialPopupURL: z.string().nullish(),
        lineNumber: z.number().nullish(),
        openeeURL: z.string().nullish(), // url
        property: z.string().nullish(), // closed, postMessage
        sourceFile: z.string().nullish(), // url
    })
    .passthrough();
export type CrossOriginOpenerPolicyReport = z.infer<
    typeof CrossOriginOpenerPolicyReport
>;

export const CrossOriginEmbedderPolicyReport = z
    .object({
        disposition: z.enum(['reporting', 'enforce']),

        blockedURL: z.string().nullish(), // url

        /**
         * - navigation
         * - worker initialization
         * - corp
         */
        type: z.string(), // navigation, 'worker initialization', corp

        /**
         * Set on `type: 'corp'`
         */
        destination: z.string().nullish(), // script, iframe
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
         * `accelerometer`, `autoplay`, ...
         */
        policyId: z.string(),

        columnNumber: z.number().nullish(),
        lineNumber: z.number().nullish(),
        sourceFile: z.string(),
    })
    .passthrough();
export type PermissionsPolicyViolation = z.infer<
    typeof PermissionsPolicyViolation
>;

/**
 * Legacy report type sent by Firefox, which implemented reporting before
 * Feature Policy was renamed to Permissions Policy.
 * Same as `permissions-policy-violation` but with `featureId` instead of `policyId`
 */
export const FeaturePolicyViolation = z
    .object({
        message: z.string().nullish(),
        disposition: z.enum(['report', 'enforce']),

        /**
         * The violated feature
         * `serial`, `geolocation`, ...
         */
        featureId: z.string(),

        columnNumber: z.number().nullish(),
        lineNumber: z.number().nullish(),
        sourceFile: z.string().nullish(),
    })
    .passthrough();
export type FeaturePolicyViolation = z.infer<typeof FeaturePolicyViolation>;

/**
 * https://wicg.github.io/document-policy/
 */
export const DocumentPolicyViolation = z
    .object({
        message: z.string(),
        disposition: z.enum(['report', 'enforce']),

        /**
         * The violated policy
         * `document-write`, `force-load-at-top`, ...
         */
        policyId: z.string(),

        columnNumber: z.number().nullish(),
        lineNumber: z.number().nullish(),
        sourceFile: z.string().nullish(),
    })
    .passthrough();
export type DocumentPolicyViolation = z.infer<typeof DocumentPolicyViolation>;

export const PotentialPermissionsPolicyViolation = z
    .object({
        allowAttribute: z.string(),
        disposition: z.enum(['report', 'enforce']),
        message: z.string(),
        policyId: z.string(),
        srcAttribute: z.string(),
    })
    .passthrough();
export type PotentialPermissionsPolicyViolation = z.infer<
    typeof PotentialPermissionsPolicyViolation
>;

export const InterventionReport = z.object({
    id: z.string(),
    message: z.string(),

    columnNumber: z.number().nullish(),
    lineNumber: z.number().nullish(),
    sourceFile: z.string().nullish(),
});
export type InterventionReport = z.infer<typeof InterventionReport>;

export const CrashReport = z.object({
    /**
     * Crash reason
     *
     * - `oom` Out of memory
     */
    reason: z.string().nullish(), // oom
});
export type CrashReport = z.infer<typeof CrashReport>;

export const DeprecationReport = z.object({
    id: z.string(),
    message: z.string(),

    /**
     * Date when the browser version that removes the feature ships,
     * e.g. `2020-01-01`. Not always known
     */
    anticipatedRemoval: z.string().nullish(),

    columnNumber: z.number().nullish(),
    lineNumber: z.number().nullish(),
    sourceFile: z.string().nullish(),
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
        z.object({
            type: z.literal('potential-permissions-policy-violation'),
            body: PotentialPermissionsPolicyViolation,
        }),
        z.object({
            type: z.literal('feature-policy-violation'),
            body: FeaturePolicyViolation,
        }),
        z.object({
            type: z.literal('document-policy-violation'),
            body: DocumentPolicyViolation,
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
            version: z.string().nullish(),

            /**
             * The format the report was received in
             *
             * - `report-uri` legacy csp report-uri attribute
             * - `report-to` Reporting API report
             * - `report-to-safari` Safari is not sending buffered reports, fields in camelCase, body in `body` instead of `csp-report` etc
             */
            report_format: z.enum([
                'report-uri',
                'report-to',
                'report-to-safari',
            ]),
        })
    );
export type Report = z.infer<typeof Report>;
