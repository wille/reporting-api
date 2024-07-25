[![GitHub release](https://img.shields.io/npm/v/reporting-api.svg?style=flat-square)](https://github.com/wille/reporting-api/releases/latest)

# reporting-api

This package provides a middleware for Express.js that automatically configures the [Reporting API](https://w3c.github.io/reporting/) on existing policy headers and an endpoint to help you collect your own reports using the Reporting API.

Automatically sets up reporting for the following headers and features supporting the Reporting API
- `Content-Security-Policy` (CSP)
- `Content-Security-Policy-Report-Only`

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

Supports "CSP Level 2 Reports" in browsers browsers not supporting `report-to` yet but supports the `report-uri` attribute

## Core concepts

## Use cases

## Usage


### Setup a reporter and the header middleware
```ts
import { reportingEndpoint } from 'reporting-api';
import express from 'express';

const app = express();

// The reporting endpoint
app.post('/reporting-endpoint', reportingEndpoint({
  onReport(report) {
    // Collect the reports and do what you want with them
    console.log('Received report', report);

    if (report.disposition === 'enforce') {
      // This affects real clients on your site and needs to be fixed
      console.log('Enforced policy', report);
    }

    if (report.disposition === 'report') {
      // This is received from policies defined in XX-Policy-Report-Only headers and is not enforced by the browser
      console.log('Triggered policy', report);
    }

    // report.type = csp-violation,deprecation,coop,..
    // report.disposition = enforce,report
  }
}));

// A web page
app.get('/*', (req, res, next) => {
  // Set a CSP that disallows inline scripts.
  res.setHeader('Content-Security-Policy', "script-src 'self'");

  // COOP policy that disallows link in new tab
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');

  // COEP policy that disallows external resources that does not use CORS or CORP (Cross-Origin-Resource-Policy)
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
});
app.get('/*', reportingEndpointHeader('/reporting-endpoint', { includeDefault: true }));
app.get('/test', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/plain; charset=utf8'
  });

  // The script will not run and instead generate a csp-violation report
  // Clicking the link will trigger a COOP report
  // Loading the image will trigger a COEP report
  res.end(`Hello World!
<script>alert(1)</script>
<a href="https://google.com" target="_blank">Trigger COOP</>
<img src="">
`);
});

app.listen(8080);
```

> [!NOTE]
> The policy headers must be set before the reportingEndpointHeader middleware so the middleware is able to append the reporter to the policy headers.

### Response with a `Reporting-Endpoints` header created and reporter setup on the Policy header
```
$ curl -I localhost:8080/test
Reporting-Endpoints: default=/test-endpoint
Content-Security-Policy-Report-Only: default-src 'self'; report-to default; report-uri /reporting-endpoint?src=report-uri

Hello world! <script>alert(1)</script>
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

## Options

`reporter.reportingEndpoint` options

- ****

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
- [`Document-Policy`](https://wicg.github.io/document-policy/) and [`Document-Policy-Report-Only`](https://wicg.github.io/document-policy/) is not available in any browser yet.
- Safari sends reports in the format `body: { ... }` instead of an array of reports and it doesn't include an `age`

#### TODO

- README
- Versioning
- Fail safe Schemas for all supported types of reports
- Error handling
