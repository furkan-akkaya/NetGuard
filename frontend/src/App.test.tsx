import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, vi } from "vitest";
import { App } from "./App";

function mockFetch(handler: (url: string) => { status?: number; body: unknown }) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      const { status = 200, body } = handler(url);
      return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
    }),
  );
}

afterEach(() => vi.unstubAllGlobals());

const emptySummary = {
  captures: 0,
  capture_bytes: 0,
  analyses: { queued: 0, running: 0, done: 0, failed: 0, cancelled: 0 },
  alerts: { HIGH: 0, MEDIUM: 0, LOW: 0 },
  alerts_by_rule: [],
  recent_alerts: [],
  recent_analyses: [],
};

test("overview shows an empty state on a fresh server", async () => {
  mockFetch(() => ({ body: emptySummary }));
  render(
    <MemoryRouter initialEntries={["/"]}>
      <App />
    </MemoryRouter>,
  );
  expect(await screen.findByText("No captures yet")).toBeTruthy();
  expect(screen.getByText("No alerts.")).toBeTruthy();
});

test("a 401 explains that a token is needed", async () => {
  mockFetch(() => ({ status: 401, body: { detail: "missing or invalid API token" } }));
  render(
    <MemoryRouter initialEntries={["/alerts"]}>
      <App />
    </MemoryRouter>,
  );
  expect(await screen.findAllByText("Authentication required")).not.toHaveLength(0);
});

test("server errors are shown with a retry button", async () => {
  mockFetch(() => ({ status: 500, body: { detail: "database is locked" } }));
  render(
    <MemoryRouter initialEntries={["/"]}>
      <App />
    </MemoryRouter>,
  );
  expect(await screen.findByText("database is locked")).toBeTruthy();
  expect(screen.getByRole("button", { name: "Retry" })).toBeTruthy();
});

test("unknown routes show not found", () => {
  mockFetch(() => ({ body: {} }));
  render(
    <MemoryRouter initialEntries={["/nope"]}>
      <App />
    </MemoryRouter>,
  );
  expect(screen.getByText("Page not found")).toBeTruthy();
});
