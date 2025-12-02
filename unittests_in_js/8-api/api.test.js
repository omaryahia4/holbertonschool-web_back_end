const expect = require("chai").expect;
const request = require("request");

describe("Index page", function () {
  it("Status code is 200", function () {
    request("http://localhost:7865", function (error, response, body) {
      expect(response.statusCode).to.be.equal(200);
    });
  });
  it("Server response is 'Welcome to the payment system'", function (done) {
    request("http://localhost:7865", function (error, response, body) {
      expect(response.body).to.be.equal("Welcome to the payment system");
      done();
    });
  });
});
