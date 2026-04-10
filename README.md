# reporting-api

[![npm](https://img.shields.io/npm/v/reporting-api?style=flat-square)](https://www.npmjs.com/package/reporting-api)
[![license](https://img.shields.io/npm/l/reporting-api?style=flat-square)](https://github.com/wille/reporting-api/blob/master/LICENSE)

Express.js middleware for the [Reporting API](https://w3c.github.io/reporting/). Automatically wires up `report-to` / `report-uri` on your existing policy headers and gives you a ready-made endpoint to collect violation, deprecation, crash, and network error reports.

## Supported headers and report types

| Header | Shorthand |
|--------|-----------|
| [`Content-Security-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) | CSP |
| [`Content-Security-Policy-Report-Only`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only) | |
| [`Cross-Origin-Opener-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy) | COOP |
| [`Cross-Origin-Opener-Policy-Report-Only`](https://github.com/camillelamy/explainers/blob/main/coop_reporting.md) | |
| [`Cross-Origin-Embedder-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy) | COEP |
| [`Cross-Origin-Embedder-Policy-Report-Only`](https://gist.github.com/yutakahirano/f14f15bd1595e1e913b0870649000470) | |
| [`Permissions-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Permissions_Policy) | |
| [`Permissions-Policy-Report-Only`](https://github.com/w3c/webappsec-permissions-policy/blob/main/reporting.md) | |
| [`NEL` (Network Error Logging)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Network_Error_Logging) | NEL |

Plus [Deprecation](https://wicg.github.io/deprecation-reporting/), [Intervention](https://wicg.github.io/intervention-reporting/), and [Crash](https://wicg.github.io/crash-reporting/) reports.

Backwards-compatible with CSP Level 2 `report-uri` for browsers that don't yet support the Reporting API.

## Install

```bash
npm install reporting-api
```

Peer dependencies: `express`, `zod`, `debug`.

## Quick start

```ts
import express from 'express';
import { reportingEndpoint, setupReportingHeaders } from 'reporting-api';

const app = express();

// 1. Mount the reporting endpoint
app.use('/reporting-endpoint', reportingEndpoint({
  allowedOrigins: '*',
  onReport(report) {
    console.log(report.type, report.body);
  },
}));

// 2. Set your policy headers, then let the middleware attach reporters
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "script-src 'self'");
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  next();
});
app.use(setupReportingHeaders('/reporting-endpoint'));

app.listen(8080);
```

> [!NOTE]
> Policy headers must be set **before** `setupReportingHeaders` runs so the middleware can append `report-to` and `report-uri` directives to them.

The resulting response headers will look like this:

```
Reporting-Endpoints: reporter="/reporting-endpoint"
Content-Security-Policy: script-src 'self';report-uri /reporting-endpoint?disposition=enforce;report-to reporter
Cross-Origin-Opener-Policy: same-origin;report-to="reporter"
Cross-Origin-Embedder-Policy: require-corp;report-to="reporter"
```

## API

### `reportingEndpoint(config)`

Returns Express middleware that accepts incoming reports.

| Option | Type | Description |
|--------|------|-------------|
| `onReport` | `(report, req) => void` | Called for every valid report. |
| `onValidationError` | `(error, body, req) => void` | Called when a report fails Zod validation. |
| `allowedOrigins` | `string \| RegExp \| Array` | Enable CORS for cross-origin reports. Use `'*'` to allow any origin. |
| `ignoreBrowserExtensions` | `boolean` | Drop CSP violations originating from browser extensions. |
| `ignoredDeprecationIds` | `string[]` | Deprecation report IDs to ignore (e.g. `['AttributionReporting', 'Topics']`). |
| `maxAge` | `number` | Maximum report age in **seconds**. Older buffered reports are dropped. |
| `debug` | `boolean` | Enable `debug` logging for the `reporting-api:*` namespace. |

### `setupReportingHeaders(url, config?)`

Returns Express middleware that appends `report-to` / `report-uri` to every policy header already set on the response and adds the `Reporting-Endpoints` header.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `reportingGroup` | `string` | `"reporter"` | Reporting group name. |
| `enableDefaultReporters` | `boolean` | `false` | Use the `default` group so you also receive Deprecation, Crash, and Intervention reports. |
| `enableNetworkErrorLogging` | `boolean \| object` | `false` | Add `Report-To` + `NEL` headers (Reporting API v0, required for NEL). Accepts `{ success_fraction, failure_fraction, include_subdomains }`. |
| `version` | `string \| number` | — | Appended as a `?version=` query param so you can correlate reports with policy revisions. |

## Report schema

Every report delivered to `onReport` is validated with Zod and has the shape:

```ts
{
  type: 'csp-violation' | 'coop' | 'coep' | 'deprecation' | 'crash'
       | 'intervention' | 'network-error' | 'permissions-policy-violation'
       | 'potential-permissions-policy-violation';
  body: { /* type-specific fields */ };
  url: string;
  age: number;
  user_agent: string;
  report_format: 'report-uri' | 'report-to' | 'report-to-safari';
  version?: string;
}
```

Full type definitions are exported as `Report` and the individual body types (`ContentSecurityPolicyReport`, `CrossOriginOpenerPolicyReport`, etc.).

## Client-side observing

Reports can also be observed in the browser via [ReportingObserver](https://developer.mozilla.org/en-US/docs/Web/API/ReportingObserver):

```js
if (typeof ReportingObserver !== 'undefined') {
  new ReportingObserver((reports) => {
    reports.forEach(r => console.log(r.body));
  }).observe();
}
```

## Resources

- [Reporting API v1 spec (Reporting-Endpoints)](https://w3c.github.io/reporting/)
- [Reporting API v0 spec (Report-To)](https://www.w3.org/TR/reporting/)
- [Migrating from v0 to v1](https://developer.chrome.com/blog/reporting-api-migration)
- [v0 vs v1 differences (Chromium)](https://chromium.googlesource.com/chromium/src/+/HEAD/net/reporting/README.md#supporting-both-v0-and-v1-reporting-in-the-same-codebase)
- [Permissions-Policy reporting](https://github.com/w3c/webappsec-permissions-policy/blob/main/reporting.md)

### Notes

- `Permissions-Policy` reports to the `default` group when `report-to` is not set.
- COOP and COEP require `report-to` values wrapped in double quotes (e.g. `report-to="group"`).
- Safari sends reports as `{ body: { ... } }` instead of an array and omits `age`.
