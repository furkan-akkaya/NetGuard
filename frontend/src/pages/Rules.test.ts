import { diffOverrides } from "./Rules";

const base = [
  { name: "portscan", rules: [], settings: { enabled: true, min_distinct_ports: 15, window_seconds: 60 } },
  { name: "arpspoof", rules: [], settings: { enabled: true, critical_ips: [] as string[] } },
];

test("only changed values are stored", () => {
  const values = {
    portscan: { enabled: true, min_distinct_ports: 30, window_seconds: 60 },
    arpspoof: { enabled: true, critical_ips: ["10.0.0.1"] },
  };
  expect(diffOverrides(base, values, [])).toEqual({
    portscan: { min_distinct_ports: 30 },
    arpspoof: { critical_ips: ["10.0.0.1"] },
  });
});

test("unchanged profile stores nothing but the allowlist", () => {
  const values = { portscan: { ...base[0]!.settings }, arpspoof: { ...base[1]!.settings } };
  expect(diffOverrides(base, values, ["10.0.0.5"])).toEqual({ allowlist: ["10.0.0.5"] });
});
