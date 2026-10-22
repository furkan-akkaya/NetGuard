import { useState } from "react";
import { api, getToken, request, setToken } from "../api";
import { ErrorBox, Panel } from "../components/ui";
import { useAsync } from "../hooks";

interface Health {
  status: string;
  version: string;
  schema_version: number;
}

export function Settings() {
  const health = useAsync(() => request<Health>("/health"), []);
  const auth = useAsync(() => api.captures({ limit: 1 }).then(() => true), []);
  const [value, setValue] = useState("");
  const [hasToken, setHasToken] = useState(!!getToken());

  return (
    <>
      <h1>Settings</h1>
      <Panel title="Server">
        {health.error ? <ErrorBox error={health.error} retry={health.reload} /> : null}
        {health.data ? (
          <table className="kv">
            <tbody>
              <tr>
                <th scope="row">NetGuard</th>
                <td>{health.data.version}</td>
              </tr>
              <tr>
                <th scope="row">Database schema</th>
                <td>{health.data.schema_version}</td>
              </tr>
              <tr>
                <th scope="row">API access</th>
                <td>{auth.data ? "authorised" : auth.error ? "token required or invalid" : "checking…"}</td>
              </tr>
              <tr>
                <th scope="row">API reference</th>
                <td>
                  <a href="/api/v1/docs">/api/v1/docs</a>
                </td>
              </tr>
            </tbody>
          </table>
        ) : null}
      </Panel>
      <Panel title="API token">
        <p className="muted">
          Needed only when the server was started with <code>NETGUARD_API_TOKEN</code>. The token is kept for this
          browser tab only (session storage) and sent as a bearer header.
        </p>
        <form
          className="filters"
          onSubmit={(e) => {
            e.preventDefault();
            setToken(value.trim() || null);
            setHasToken(!!value.trim());
            setValue("");
            auth.reload();
          }}
        >
          <label className="grow">
            Token
            <input type="password" value={value} onChange={(e) => setValue(e.target.value)} autoComplete="off" />
          </label>
          <button type="submit" className="btn btn-primary">
            Save
          </button>
          {hasToken ? (
            <button
              type="button"
              className="btn"
              onClick={() => {
                setToken(null);
                setHasToken(false);
                auth.reload();
              }}
            >
              Forget token
            </button>
          ) : null}
        </form>
      </Panel>
    </>
  );
}
