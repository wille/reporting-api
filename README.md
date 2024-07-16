[![GitHub release](https://img.shields.io/npm/v/reporting-api.svg?style=flat-square)](https://github.com/wille/reporting-api/releases/latest)

# reporting-api

This package provides a middleware for Express.js that automatically configures the [Reporting API](https://w3c.github.io/reporting/) on existing policy headers and an endpoint to help you collect your own reports using the Reporting API.


Automatically sets up reporting for the following headers supporting the Reporting API
- `Content-Security-Policy` (CSP)
- `Content-Security-Policy-Report-Only`
- `Document-Policy`
- `Document-Policy-Report-Only`
- `Cross-Origin-Opener-Policy` (COOP)
- `Cross-Origin-Opener-Policy-Report-Only`
- `Cross-Origin-Embedder-Policy` (COEP)
- `Cross-Origin-Embedder-Policy-Report-Only`

Supports CSP 1, CSP 2 and Firefox Content-Security-Policy headers using the `report-uri` attribute

There is also support for collecting [Deprecation](https://wicg.github.io/deprecation-reporting/), [Intervention](https://wicg.github.io/intervention-reporting/) and [Crash reports](https://wicg.github.io/crash-reporting/)

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
});

// A web page
app.get('/*', (req, res, next) => {
  // Set a CSP that disallows inline scripts.
  res.setHeader('Content-Security-Policy-Report-Only', "script-src 'self'");
});
app.get('/*', reportingEndpointHeader('/reporting-endpoint', { includeDefault: true }));
app.get('/test', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/plain; charset=utf8'
  });

  // This script will not run and instead generate a csp-violation report
  res.end('Hello World! <script>alert(1)</script>');
});

app.listen(8080);
```

> [!NOTE]
> The policy headers must be set before the reportingEndpointHeader middleware so the middleware is able to append the reporter to the polic headers.

### Response with a `Reporting-Endpoints` header created and reporter setup on the Policy header
```
$ curl -I localhost:8080/test
Reporting-Endpoints: default=/test-endpoint
Content-Security-Policy-Report-Only: default-src 'self'; report-to default; report-uri /reporting-endpoint?src=report-uri

Hello world! <script>alert(1)</script>
```

> [!TIP]
> 
> The Reporting API is accessible in the browser using the [ReportingObserver](https://developer.mozilla.org/en-US/docs/Web/API/ReportingObserver)
> ```js
> const myObserver = new ReportingObserver(reportList => {
>  reportList.forEach(report => {
>    console.log(report.body);
>  });
> });
> myObserver.observe();
>```


## Read more about Reporting

https://github.com/w3c/webappsec-permissions-policy/blob/main/reporting.md
