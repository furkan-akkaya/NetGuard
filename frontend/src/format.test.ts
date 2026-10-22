import { endpoint, formatBytes, formatDuration, formatNumber, formatTime, humanize, timeAgo } from "./format";
import { qs } from "./api";

test("formatBytes uses SI units and handles bad input", () => {
  expect(formatBytes(0)).toBe("0 B");
  expect(formatBytes(999)).toBe("999 B");
  expect(formatBytes(1500)).toBe("1.50 KB");
  expect(formatBytes(24_300_000)).toBe("24.3 MB");
  expect(formatBytes(-1)).toBe("–");
  expect(formatBytes(Number.NaN)).toBe("–");
});

test("formatDuration picks a readable unit", () => {
  expect(formatDuration(0.0005)).toBe("1 ms");
  expect(formatDuration(1.5)).toBe("1.50 s");
  expect(formatDuration(61.5)).toBe("1 min 2 s");
  expect(formatDuration(7260)).toBe("2 h 1 min");
});

test("formatTime shows UTC and tolerates garbage", () => {
  expect(formatTime("2025-10-09T08:53:20.000+00:00")).toBe("2025-10-09 08:53:20 UTC");
  expect(formatTime(null)).toBe("–");
  expect(formatTime("not a date")).toBe("not a date");
});

test("misc helpers", () => {
  expect(formatNumber(1234567)).toBe("1,234,567");
  expect(endpoint("10.0.0.1", 443)).toBe("10.0.0.1:443");
  expect(endpoint("fe80::1", 22)).toBe("[fe80::1]:22");
  expect(endpoint(null)).toBe("?");
  expect(humanize("distinct_ports")).toBe("Distinct ports");
  expect(timeAgo("2025-01-01T00:00:00Z", Date.parse("2025-01-01T02:00:00Z"))).toBe("2 h ago");
});

test("qs drops empty values and encodes the rest", () => {
  expect(qs({ a: "x y", b: "", c: undefined, d: null, e: 0 })).toBe("?a=x+y&e=0");
  expect(qs({})).toBe("");
});
