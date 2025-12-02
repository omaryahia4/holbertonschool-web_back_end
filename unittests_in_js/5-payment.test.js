const sinon = require("sinon");
const sendPaymentRequestToApi = require("./5-payment");
const Utils = require("./utils");

describe("Testing with hooks", function () {
  let spy;
  let log;
  beforeEach(function () {
    spy = sinon.spy(Utils, "calculateNumber");
    log = sinon.spy(console, "log");
  });
  afterEach(function () {
    spy.restore();
    log.restore();
  });
  it("first test", function () {
    sendPaymentRequestToApi(100, 20);
    sinon.assert.calledOnce(spy);
    sinon.assert.calledWith(log, "The total is: 120");
  });
  it("second test", function () {
    sendPaymentRequestToApi(100, 20);
    sinon.assert.calledOnce(spy);
    sinon.assert.calledWith(log, "The total is: 120");
  });
});
