const sinon = require("sinon");
const sendPaymentRequestToApi = require("./4-payment");
const Utils = require("./utils");
const expect = require("chai").expect;

describe("Test sendPaymentRequestToApi", function () {
  it("stub the Utils.calculateNumber function", function () {
    const stub = sinon.stub(Utils, "calculateNumber");
    const log = sinon.spy(console, "log");
    stub.returns(10);
    sendPaymentRequestToApi(100, 20);
    sinon.assert.calledOnce(stub);
    sinon.assert.calledWith(stub, "SUM", 100, 20);
    sinon.assert.calledWith(log, "The total is: 10");
    stub.restore();
    log.restore();
  });
});
