const expect = require("chai").expect;
const calculateNumber = require("./2-calcul_chai");

describe("Case type is 'SUM'", function () {
  it("add two positive integers", function () {
    expect(calculateNumber("SUM", 1, 2)).to.equal(3);
  });

  it("add two positive floats", function () {
    expect(calculateNumber("SUM", 2.3, 4.6)).to.equal(7);
  });

  it("add one positive integer and one negative integer", function () {
    expect(calculateNumber("SUM", 2, -1)).to.equal(1);
  });

  it("add one positive integer and one negative float", function () {
    expect(calculateNumber("SUM", 1, -2.4)).to.equal(-1);
  });

  it("add one negative integer and one positive float", function () {
    expect(calculateNumber("SUM", -1, 2.4)).to.equal(1);
  });

  it("add two negative floats", function () {
    expect(calculateNumber("SUM", -1.5, -2.4)).to.equal(-3);
  });

  it("round to the supp integer", function () {
    expect(calculateNumber("SUM", 1.5, 2.5)).to.equal(5);
  });
});

describe("Case type is 'SUBTRACT'", function () {
  it("subtract two positive integers", function () {
    expect(calculateNumber("SUBTRACT", 1, 2)).to.equal(-1);
  });

  it("subtract two positive floats", function () {
    expect(calculateNumber("SUBTRACT", 2.3, 4.6)).to.equal(-3);
  });

  it("subtract one positive integer and one negative integer", function () {
    expect(calculateNumber("SUBTRACT", 2, -1)).to.equal(3);
  });

  it("subtract one positive integer and one negative float", function () {
    expect(calculateNumber("SUBTRACT", 1, -2.4)).to.equal(3);
  });

  it("subtract one negative integer and one positive float", function () {
    expect(calculateNumber("SUBTRACT", -1, 2.4)).to.equal(-3);
  });

  it("subtract two negative floats", function () {
    expect(calculateNumber("SUBTRACT", -1.5, -2.4)).to.equal(1);
  });

  it("subtract same number", function () {
    expect(calculateNumber("SUBTRACT", 1.5, 1.5)).to.equal(0);
  });

  it("round to the supp integer", function () {
    expect(calculateNumber("SUBTRACT", 1.5, 2.5)).to.equal(-1);
  });
});

describe("Case type is 'DIVIDE'", function () {
  it("divide two positive integers", function () {
    expect(calculateNumber("DIVIDE", 1, 2)).to.equal(0.5);
  });

  it("divide two positive floats", function () {
    expect(calculateNumber("DIVIDE", 4.3, 1.6)).to.equal(2);
  });

  it("divide one positive integer and one negative integer", function () {
    expect(calculateNumber("DIVIDE", 2, -1)).to.equal(-2);
  });

  it("divide one positive integer and one negative float", function () {
    expect(calculateNumber("DIVIDE", 4, -2.4)).to.equal(-2);
  });

  it("divide one negative integer and one positive float", function () {
    expect(calculateNumber("DIVIDE", -6, 2.7)).to.equal(-2);
  });

  it("divide two negative floats", function () {
    expect(calculateNumber("DIVIDE", -1.5, -2.4)).to.equal(0.5);
  });

  it("round to the supp integer", function () {
    expect(calculateNumber("DIVIDE", 1.5, 1.5)).to.equal(1);
  });

  it("divide when round b is equal to 0", function () {
    expect(calculateNumber("DIVIDE", 4, 0.4)).to.equal("Error");
  });

  it("divide when b is equal to 0", function () {
    expect(calculateNumber("DIVIDE", 4, 0)).to.equal("Error");
  });
});

describe("Case when type is not 'SUM', 'SUBTRACT', 'DIVIDE'", function () {
  it("case when argument type is 'SIM'", function () {
    expect(calculateNumber("SIM", 2, 3)).to.equal(undefined);
  });
});
