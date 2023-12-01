const sinon = require('sinon');
const chai = require('chai');
const sendPaymentRequestToApi = require('./3-payment');
const Utils = require('./utils');

const { expect } = chai;

describe('sendPaymentRequestToApi', () => {
  it('should call the Utils.calculateNumber and result is equal to call sendPaymentRequestToApi', () => {
    const calculateNumberSpy = sinon.spy(Utils, 'calculateNumber');
    const expected = Utils.calculateNumber('SUM', 100, 20);
    const actual = sendPaymentRequestToApi(100, 20);

    expect(actual).equal(expected);
    expect(calculateNumberSpy.calledWith('SUM', 100, 20)).to.equal(true);

    calculateNumberSpy.restore();
  });

  let spyConsole;
  beforeEach(function () {
    
    spyConsole = sinon.spy(console, 'log');
  });

  afterEach(function () {
   
    spyConsole.restore();
  });

  it('logs correctly with 100, 20', () => {
    sendPaymentRequestToApi(100, 20);

    expect(spyConsole.calledOnceWithExactly('The total is: 120')).to.be.true;
    expect(spyConsole.calledOnce).to.be.true;
  });

  it('logs correctly with 10, 10', () => {
    sendPaymentRequestToApi(10, 10);

    expect(spyConsole.calledOnceWithExactly('The total is: 20')).to.be.true;
    expect(spyConsole.calledOnce).to.be.true;
  });
});