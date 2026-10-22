import { NavLink, Route, Routes } from "react-router";
import { AlertDetail } from "./pages/AlertDetail";
import { Alerts } from "./pages/Alerts";
import { AnalysisDetail } from "./pages/AnalysisDetail";
import { Captures } from "./pages/Captures";
import { Overview } from "./pages/Overview";
import { Rules } from "./pages/Rules";
import { Settings } from "./pages/Settings";

const NAV = [
  { to: "/", label: "Overview", end: true },
  { to: "/captures", label: "Captures" },
  { to: "/alerts", label: "Alerts" },
  { to: "/rules", label: "Rules" },
  { to: "/settings", label: "Settings" },
];

export function App() {
  return (
    <div className="shell">
      <header className="topbar">
        <NavLink to="/" className="brand" aria-label="NetGuard home">
          <svg viewBox="0 0 32 32" aria-hidden="true">
            <path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z" />
            <path d="m10 16 4 4 8-9" className="check" />
          </svg>
          NetGuard
        </NavLink>
        <nav aria-label="Main">
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.end ?? false} className="navlink">
              {n.label}
            </NavLink>
          ))}
        </nav>
      </header>
      <main className="content">
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/captures" element={<Captures />} />
          <Route path="/analyses/:id" element={<AnalysisDetail />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/alerts/:id" element={<AlertDetail />} />
          <Route path="/rules" element={<Rules />} />
          <Route path="/settings" element={<Settings />} />
          <Route
            path="*"
            element={
              <div className="state empty">
                <strong>Page not found</strong>
                <NavLink to="/">Back to the overview</NavLink>
              </div>
            }
          />
        </Routes>
      </main>
    </div>
  );
}
