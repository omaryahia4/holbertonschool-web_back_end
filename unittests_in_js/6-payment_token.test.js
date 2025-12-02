const assert = require("assert");
const getPaymentTokenFromAPI = require("./6-payment_token");

describe("Tests async ", function () {
  it("Tests for success = true", function (done) {
    getPaymentTokenFromAPI(true).then((result) => {
      assert.deepStrictEqual(result, {
        data: "Successful response from the API",
      });
      done();
    });
  });
});
