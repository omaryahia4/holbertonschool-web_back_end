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

describe("Cart endpoint", function () {
  const url = "http://localhost:7865/cart";
  it("Status code is 404 when param 'id' is a string", function (done) {
    request(`${url}/string`, (error, response, body) => {
      expect(response.statusCode).to.be.equal(404);
    });
    done();
  });

  it("Body is empty when param 'id' is a string", function (done) {
    request(`${url}/string`, (error, response, body) => {
      expect(response.body).to.be.equal("");
    });
    done();
  });

  it("Code status is 200 when param id is a number", (done) => {
    request(`${url}/3`, (error, response, body) => {
      expect(response.statusCode).to.be.equal(200);
    });
    done();
  });

  it("Server response is 'Payment methods for cart :id'", (done) => {
    request(`${url}/20`, (error, response, body) => {
      expect(response.body).to.be.equal("Payment methods for cart 20");
    });
    done();
  });
});

describe("Tests for login endpoint", () => {
  const url = "http://localhost:7865/login";
  it("Returns Welcome :username", (done) => {
    payload = { userName: "Betty" };
    request.post(
      { url: url, json: true, body: payload },
      (error, response, body) => {
        expect(response.body).to.be.equal("Welcome Betty");
      }
    );
    done();
  });

  it("Code status is 200", (done) => {
    request.post(
      { url: url, json: true, body: payload },
      (error, response, body) => {
        expect(response.statusCode).to.be.equal(200);
      }
    );
    done();
  });
});

describe("Tests for 'available_payments' endpoint", () => {
  const url = "http://localhost:7865/available_payments";
  it("Returns '{payment_methods: {credit_cards: true,paypal: false }}'", (done) => {
    request(url, (error, response, body) => {
      expect(body).to.deep.equal(
        '{"payment_methods":{"credit_cards":true,"paypal":false}}'
      );
    });
    done();
  });
});
