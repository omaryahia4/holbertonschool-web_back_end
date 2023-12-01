const chai = require('chai');
const request = require('request');

const { expect } = chai;

describe('basic integration testing', () => {
  it('should return a statuscode 200', (done) => {
    request('http://localhost:7865', (error, response) => {
      expect(response.statusCode).equal(200);
      done();
    });
  });

  it('should return the body', (done) => {
    request('http://localhost:7865', (error, response, body) => {
      expect(body).equal('Welcome to the payment system');
      done();
    });
  });

  it('should request the method GET', (done) => {
    request('http://localhost:7865', (error, response, body) => {
      expect(response.request.method).equal('GET');
      done();
    });
  });
});