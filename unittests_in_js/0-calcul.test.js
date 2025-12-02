const assert = require("assert");
const calculateNumber = require("./0-calcul.js");

describe("calculateNumber", function () {
  it("add two positive integers", function () {
    assert.equal(calculateNumber(1, 2), 3);
  });

  it("add two positive floats", function () {
    assert.equal(calculateNumber(2.3, 4.6), 7);
  });

  it("add one positive integer and one negative integer", function () {
    assert.equal(calculateNumber(2, -1), 1);
  });

  it("add one positive integer and one negative float", function () {
    assert.equal(calculateNumber(1, -2.4), -1);
  });

  it("add one negative integer and one positive float", function () {
    assert.equal(calculateNumber(-1, 2.4), 1);
  });

  it("add two negative floats", function () {
    assert.equal(calculateNumber(-1.5, -2.4), -3);
  });

  it("round to the supp integer", function () {
    assert.equal(calculateNumber(1.5, 2.5), 5);
  });
});
