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

describe('ID validation testing', () => {
  it('should return a 200 status code for a valid ID', (done) => {
    request.get('http://localhost:7865/cart/12', (error, response, body) => {
      expect(response.statusCode).equal(200);
      expect(body).equal('Payment methods for cart 12');
      done();
    });
  });

  it('should return a 404 status code for invalid ID', (done) => {
    request.get('http://localhost:7865/cart/hello', (error, response, body) => {
      expect(response.statusCode).equal(404);
      done();
    });
  });
});