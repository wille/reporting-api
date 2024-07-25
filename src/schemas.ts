import { z } from 'zod';

export const ContentSecurityPolicyReportBody = z
    .object({
        blockedURL: z.string(),
        columnNumber: z.number(),
        disposition: z.enum(['enforce', 'report']),
        documentURL: z.string(), // url
        effectiveDirective: z.string(),
        lineNumber: z.number(),
        originalPolicy: z.string(),
        referrer: z.string(),
        sample: z.string(),
        sourceFile: z.string(),
        statusCode: z.number(),
    })
    .passthrough();
export type ContentSecurityPolicyReportBody = z.infer<
    typeof ContentSecurityPolicyReportBody
>;

export const CrossOriginOpenerPolicyReportBody = z
    .object({
        disposition: z.enum(['reporting', 'enforce']),
        effectivePolicy: z.enum([
            'unsafe-none',
            'same-origin',
            'same-origin-allow-popups',
            'same-origin-plus-coep',
        ]),

        /*
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
     */
        type: z.string(),

        columnNumber: z.number().optional(),
        initialPopupURL: z.string().optional(),
        lineNumber: z.number().optional(),
        openeeURL: z.string().optional(), // url
        property: z.string(), // closed, postMessage
        sourceFile: z.string().optional(), // url
    })
    .passthrough();
export type CrossOriginOpenerPolicyReportBody = z.infer<
    typeof CrossOriginOpenerPolicyReportBody
>;

export const CrossOriginEmbedderPolicyReportBody = z
    .object({
        disposition: z.enum(['reporting', 'enforce']),

        blockedURL: z.string().optional(), // url

        type: z.string(), // navigation, 'worker initialization', corp

        destination: z.string(), // script, iframe
    })
    .passthrough();
/**
 * https://github.com/camillelamy/explainers/blob/main/coop_reporting.md
 */
export type CrossOriginEmbedderPolicyReportBody = z.infer<
    typeof CrossOriginEmbedderPolicyReportBody
>;

export const Report = z
    .discriminatedUnion('type', [
        z.object({
            type: z.literal('csp-violation'),
            body: ContentSecurityPolicyReportBody,
        }),
        z.object({
            type: z.literal('coop'),
            body: CrossOriginOpenerPolicyReportBody,
        }),
        z.object({
            type: z.literal('coep'),
            body: CrossOriginEmbedderPolicyReportBody,
        }),
        z.object({
            type: z.literal('deprecation'),
            body: z.object({}).passthrough(),
        }),
        z.object({
            type: z.literal('crash'),
            body: z.object({}).passthrough(),
        }),
        z.object({
            type: z.literal('intervention'),
            body: z.object({}).passthrough(),
        }),
        z.object({
            type: z.literal('network-error'),
            body: z.object({}).passthrough(),
        }),
        z.object({
            type: z.literal('permissions-policy-violation'),
            body: z.object({}).passthrough(),
        }),
    ])
    .and(
        z.object({
            url: z.string(), // url
            age: z.number(),
            user_agent: z.string(),

            version: z.string().optional(),
            report_format: z.enum([
                'report-uri',
                'report-to-buffered',
                'report-to-single',
            ]),
        })
    );
export type Report = z.infer<typeof Report>;
