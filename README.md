[![GitHub release](https://img.shields.io/npm/v/reporting-api.svg?style=flat-square)](https://github.com/wille/reporting-api/releases/latest)

# reporting-api

This package provides a middleware for Express.js that automatically configures the [Reporting API](https://w3c.github.io/reporting/) on existing policy headers and an endpoint to help you collect your own reports using the Reporting API.

Automatically sets up reporting for the following headers and features supporting the Reporting API
- [`Content-Security-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) (CSP)
- [`Content-Security-Policy-Report-Only`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only)
- [`Permissions-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Permissions_Policy)
- [`Permissions-Policy-Report-Only`](https://github.com/w3c/webappsec-permissions-policy/blob/main/reporting.md
)
- [`Cross-Origin-Opener-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy) (COOP)
- [`Cross-Origin-Opener-Policy-Report-Only`](https://github.com/camillelamy/explainers/blob/main/coop_reporting.md)
- `Cross-Origin-Embedder-Policy` (COEP)
- `Cross-Origin-Embedder-Policy-Report-Only`
- [`NEL` (Network Error Logging)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Network_Error_Logging)
- [Deprecation Reports](https://wicg.github.io/deprecation-reporting/)
- [Intervention Reports](https://wicg.github.io/intervention-reporting/)
- [Crash Reports](https://wicg.github.io/crash-reporting/)

Supports "CSP Level 2 Reports" in browsers browsers not supporting the Reporting API.

## Core concepts

Retrofitting a policy on a large website is hard to get right first. The solution is to use `-Report-Only` policies that will not enforce them and break your website. These headers and their enforcing equivalents supports reporting, which makes all policy violations gets sent to you so you can adjust your policies to not break functionality. 

### Setup a reporting endpoint and setup reporters on your policy headers
```ts
import { reportingEndpoint } from 'reporting-api';
import express from 'express';

const app = express();

// The reporting endpoint
app.post('/reporting-endpoint', reportingEndpoint({
  onReport(report) {
    // Collect the reports and do what you want with them
    console.log('Received report', report);

    console.log('Report received', {
      isEnforced: report.body.type === 'enforce';
      type: report.type,
      body: report.body,
    });
  }
}));

// Set the security headers
app.get('/*', (req, res, next) => {
  // Set a CSP that disallows inline scripts.
  res.setHeader('Content-Security-Policy', "script-src 'self'");

  // COOP policy that disallows link in new tab
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');

  // COEP policy that disallows external resources that does not use CORS or CORP (Cross-Origin-Resource-Policy)
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
});
// Setup the reporters on the headers
app.get('/*', setupReportingHeaders('/reporting-endpoint', {
  includeDefaultReporters: true,
  enableNetworkErrorLogging: true,
  version: '1',
}));
// 
app.get('/test', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/html; charset=utf8'
  });

  // The script will not run and instead generate a csp-violation report
  // Clicking the link will trigger a COOP report
  // Loading the image will trigger a COEP report
  res.end(`Hello World!
<script>alert(1)</script>
<a href="https://google.com" target="_blank">Trigger COOP</>
<img src="https://lh3.googleusercontent.com/wAPeTvxh_EwOisF8kMR2L2eOrIOzjfA5AjE28W5asyfGeH85glwrO6zyqL71dCC26R63chADTO7DLOjnqRoXXOAB8t2f4C3QnU6o0BA">
`);
});

app.listen(8080);
```

> [!NOTE]
> The policy headers must be set before the reportingEndpointHeader middleware so the middleware is able to append the reporter to the policy headers.
>
> If the reporting endpoint is on another origin, you need to setup CORS
> ```ts
> import cors from 'cors';
> const corsMiddleware = cors();
> app.options('/reporting-endpoint', cors());
> app.post('/reporting-endpoint', cors(), ...);
> ```

### Response with a `Reporting-Endpoints` header created and reporter setup on the Policy headers
```
$ curl -I localhost:8080/test
Reporting-Endpoints: default=/test-endpoint
Content-Security-Policy: default-src 'self'; report-to default; report-uri /reporting-endpoint?src=report-uri
Cross-Origin-Opener-Policy: same-origin; report-to="default"
Cross-Origin-Embedder-Policy: require-corp; report-to="default"

Hello World!
<script>alert(1)</script>
<a href="https://google.com" target="_blank">Trigger COOP</>
<img src="https://lh3.googleusercontent.com/wAPeTvxh_EwOisF8kMR2L2eOrIOzjfA5AjE28W5asyfGeH85glwrO6zyqL71dCC26R63chADTO7DLOjnqRoXXOAB8t2f4C3QnU6o0BA">
```

> [!TIP]
> 
> The Reporting API is also accessible in some browsers using the [ReportingObserver](https://developer.mozilla.org/en-US/docs/Web/API/ReportingObserver)
> ```js
> if (typeof ReportingObserver !== 'undefined') {
>   const myObserver = new ReportingObserver(reportList => {
>     reportList.forEach(report => {
>       console.log(report.body);
>     });
>   });
>   myObserver.observe();
> }
>```

## Configuration options

- [`reportingEndpoint`](./src/reporting-endpoint.ts)
- [`setupReportingHeaders`](./src/setup-headers.ts)

## Resources

- Permissions-Policy reporting https://github.com/w3c/webappsec-permissions-policy/blob/main/reporting.md
- Reporting API v0 and Reporting API v1 differences https://chromium.googlesource.com/chromium/src/+/HEAD/net/reporting/README.md#supporting-both-v0-and-v1-reporting-in-the-same-codebase
- https://developer.chrome.com/blog/reporting-api-migration
- `Report-To` header in reportingv0 https://www.w3.org/TR/reporting/
- `Reporting-Endpoints` header in reportingv1 https://w3c.github.io/reporting/
- https://www.tollmanz.com/content-security-policy-report-samples/ (2015)

### Notes

- `Permissions-Policy` reports to the `default` reporting group if `report-to` is not set.
- `report-to` group MUST be in double quotes (eg. `report-to="group"`) in COOP AND COEP headers to be used.
- [`Document-Policy`](https://wicg.github.io/document-policy/) and [`Document-Policy-Report-Only`](https://wicg.github.io/document-policy/) is doesn't look that supported or well documented, is it supersceded by Permissions-Policy?
- Safari sends reports in the format `body: { ... }` instead of an array of reports and it doesn't include an `age`
