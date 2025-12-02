const assert = require("assert");
const calculateNumber = require("./1-calcul.js");

describe("Case type is 'SUM'", function () {
  it("add two positive integers", function () {
    assert.equal(calculateNumber("SUM", 1, 2), 3);
  });

  it("add two positive floats", function () {
    assert.equal(calculateNumber("SUM", 2.3, 4.6), 7);
  });

  it("add one positive integer and one negative integer", function () {
    assert.equal(calculateNumber("SUM", 2, -1), 1);
  });

  it("add one positive integer and one negative float", function () {
    assert.equal(calculateNumber("SUM", 1, -2.4), -1);
  });

  it("add one negative integer and one positive float", function () {
    assert.equal(calculateNumber("SUM", -1, 2.4), 1);
  });

  it("add two negative floats", function () {
    assert.equal(calculateNumber("SUM", -1.5, -2.4), -3);
  });

  it("round to the supp integer", function () {
    assert.equal(calculateNumber("SUM", 1.5, 2.5), 5);
  });
});

describe("Case type is 'SUBTRACT'", function () {
  it("subtract two positive integers", function () {
    assert.equal(calculateNumber("SUBTRACT", 1, 2), 1);
  });

  it("subtract two positive floats", function () {
    assert.equal(calculateNumber("SUBTRACT", 2.3, 4.6), 3);
  });

  it("subtract one positive integer and one negative integer", function () {
    assert.equal(calculateNumber("SUBTRACT", 2, -1), -3);
  });

  it("subtract one positive integer and one negative float", function () {
    assert.equal(calculateNumber("SUBTRACT", 1, -2.4), -3);
  });

  it("subtract one negative integer and one positive float", function () {
    assert.equal(calculateNumber("SUBTRACT", -1, 2.4), 3);
  });

  it("subtract two negative floats", function () {
    assert.equal(calculateNumber("SUBTRACT", -1.5, -2.4), -1);
  });

  it("subtract same number", function () {
    assert.equal(calculateNumber("SUBTRACT", 1.5, 1.5), 0);
  });

  it("round to the supp integer", function () {
    assert.equal(calculateNumber("SUBTRACT", 1.5, 2.5), 1);
  });
});

describe("Case type is 'DIVIDE'", function () {
  it("divide two positive integers", function () {
    assert.equal(calculateNumber("DIVIDE", 1, 2), 0.5);
  });

  it("divide two positive floats", function () {
    assert.equal(calculateNumber("DIVIDE", 4.3, 1.6), 2);
  });

  it("divide one positive integer and one negative integer", function () {
    assert.equal(calculateNumber("DIVIDE", 2, -1), -2);
  });

  it("divide one positive integer and one negative float", function () {
    assert.equal(calculateNumber("DIVIDE", 4, -2.4), -2);
  });

  it("divide one negative integer and one positive float", function () {
    assert.equal(calculateNumber("DIVIDE", -6, 2.7), -2);
  });

  it("divide two negative floats", function () {
    assert.equal(calculateNumber("DIVIDE", -1.5, -2.4), 0.5);
  });

  it("round to the supp integer", function () {
    assert.equal(calculateNumber("DIVIDE", 1.5, 1.5), 1);
  });

  it("divide when round b is equal to 0", function () {
    assert.equal(calculateNumber("DIVIDE", 4, 0.4), "Error");
  });

  it("divide when b is equal to 0", function () {
    assert.equal(calculateNumber("DIVIDE", 4, 0), "Error");
  });
});

describe("Case when type is not 'SUM', 'SUBTRACT', 'DIVIDE'", function () {
  it("case when argument type is 'SIM'", function () {
    assert.equal(calculateNumber("SIM", 2, 3), undefined);
  });
});
