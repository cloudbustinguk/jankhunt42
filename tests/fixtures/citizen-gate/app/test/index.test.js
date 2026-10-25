const assert = require("node:assert");
const test = require("node:test");
const { workingDays } = require("../src/index.js");

test("a working week has five days", () => {
  assert.strictEqual(workingDays(new Date("2026-10-19"), new Date("2026-10-25")), 5);
});
