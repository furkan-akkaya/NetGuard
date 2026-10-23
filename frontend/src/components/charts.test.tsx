import { render } from "@testing-library/react";
import { TimeSeries } from "./charts";

test("TimeSeries drops to zero across empty buckets instead of interpolating", () => {
  // Two 1 s buckets 10 s apart: nothing was seen in between.
  const { container } = render(
    <TimeSeries
      bucketSeconds={1}
      points={[
        { t: "2025-01-01T00:00:00Z", value: 4 },
        { t: "2025-01-01T00:00:10Z", value: 8 },
      ]}
    />,
  );
  const line = container.querySelector("path.chart-line")?.getAttribute("d") ?? "";
  const ys = (x: string) => [...line.matchAll(new RegExp(`L${x},([\\d.]+)`, "g"))].map((m) => m[1]);
  // 640 px across 11 s: the first bucket ends at x=58.2 and the second starts at x=581.8.
  expect(ys("58.2")).toEqual(["82.0", "158.0"]); // its own level, then down to zero
  expect(ys("581.8")).toEqual(["158.0", "6.0"]); // up from zero to the peak
  expect(container.textContent).toContain("peak 8 per bucket");
});
