// Capture-derived strings (DNS names, evidence, filenames) are attacker-controlled.
// They must reach the DOM as text, never as markup.
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import type { Alert } from "./api";
import { AlertTable } from "./components/AlertTable";
import { BarList } from "./components/charts";

const HOSTILE = '"><script>window.pwned=1</script><img src=x onerror="window.pwned=2">';

const alert: Alert = {
  id: 1,
  analysis_id: "a".repeat(32),
  schema_version: "1.1",
  alert_id: "x",
  stage: "early",
  reported_at: "2025-01-01T00:00:30Z",
  rule_id: "NG-DNS-001",
  detector: "dnstunnel",
  title: HOSTILE,
  severity: "HIGH",
  first_seen: "2025-01-01T00:00:00Z",
  last_seen: "2025-01-01T00:01:00Z",
  src: "10.0.0.20",
  dst: HOSTILE,
  summary: HOSTILE,
  confidence: { score: 50, level: "medium", base: 50, factors: [{ reason: HOSTILE, weight: 5 }] },
  technique: null,
  evidence: { sample_names: [HOSTILE] },
};

test("alert fields render as inert text", () => {
  const { container } = render(
    <MemoryRouter>
      <AlertTable alerts={[alert]} />
      <BarList items={[{ label: HOSTILE, value: 3 }]} />
    </MemoryRouter>,
  );
  expect(container.querySelector("script")).toBeNull();
  expect(container.querySelector("img")).toBeNull();
  expect(screen.getAllByText(HOSTILE, { exact: false }).length).toBeGreaterThan(0);
  expect((window as unknown as { pwned?: number }).pwned).toBeUndefined();
});
