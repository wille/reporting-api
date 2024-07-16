import test, { after, before, beforeEach } from 'node:test';
import assert from "node:assert"

import { createRequest, createResponse } from 'node-mocks-http'
import express from 'express';

import { reportingEndpoint, setReportingEndpointHeader } from './index'

test.describe('Handles multiple headers and only updates the last occuring', () => {
    const req = createRequest();
    const res = createResponse();
    const next = () => {};

    const inputCsp = [
        "script-src 'self'",
        "img-src 'self'",
        "frame-src 'self'",
    ]
    res.setHeader('Content-Security-Policy', inputCsp);
    res.setHeader('Content-Security-Report-Only', "frame-src 'none'")

    setReportingEndpointHeader('/endpoint')(req, res, next)

    const outputCsp = res.getHeader('content-security-policy') as string[];

    for (let i = 0; i < inputCsp.length - 1; i++) {
        assert.equal(inputCsp[i], outputCsp[i]);
    }

    // Check so last header is updated
    assert.equal(inputCsp.slice(-1), "frame-src 'self';report-uri /endpoint?src=csp;report-to csp");
 });

 test.it('Does not update headers if they already contain report-to or report-uri', () => {
    const req = createRequest();
    const res = createResponse();
    const next = () => {};

    const inputCsp = [
        "script-src 'self';report-uri /endpoint?src=csp;report-to csp",
        "img-src 'self'",
        "frame-src 'self'",
    ]
    res.setHeader('Content-Security-Policy', inputCsp);
    setReportingEndpointHeader('/endpoint')(req, res, next)
    assert.equal(res.getHeader('content-security-policy'), inputCsp);
 });