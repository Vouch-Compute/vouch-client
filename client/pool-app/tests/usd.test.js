// Money display test for app.js (contract 2.0.0 decimal strings, BigInt only). Run: node pool-app/tests/usd.test.js
const fs = require("fs");
const src = fs.readFileSync(require("path").join(__dirname, "..", "ui", "app.js"), "utf8");
const start = src.indexOf("const USD_RE");
const end = src.indexOf("const day =");
const { usd, nanos } = new Function(src.slice(start, end) + "; return { usd, nanos };")();
const cases = [
  ["12.345678901", "$12.35"], ["12.344999999", "$12.34"], ["0.004200000", "$0.0042"], ["0.000049999", "$0.0000"],
  ["0.009999999", "$0.0100"], ["0", "$0.00"], ["1234567.995", "$1,234,568.00"], ["-4.100000000", "-$4.10"],
  ["9.000000000", "$9.00"], [12.5, "—"], ["1e3", "—"], ["1.0000000001", "—"], [null, "—"], ["01", "—"],
];
let bad = 0;
for (const [i, want] of cases) {
  const got = usd(i);
  if (got !== want) { bad++; console.log("FAIL", i, got, want); }
}
if (nanos("0.1") + nanos("0.2") !== 300000000n) { bad++; console.log("FAIL sum"); }
console.log(bad ? `${bad} failures` : `all ${cases.length + 1} usd() cases pass`);
process.exit(bad ? 1 : 0);
