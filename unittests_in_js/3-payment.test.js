const sinon = require("sinon");
const sendPaymentRequestToApi = require("./3-payment");
const Utils = require("./utils");

describe("Test sendPaymentRequestToApi", function () {
  it("call the Utils.calculateNumber function", function () {
    const spy = sinon.spy(Utils, "calculateNumber");
    sendPaymentRequestToApi(100, 20);
    sinon.assert.calledOnce(spy);
    sinon.assert.calledWith(spy, "SUM", 100, 20);
    spy.restore();
  });
});
