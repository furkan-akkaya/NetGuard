import { useEffect, useMemo, useState } from "react";
import { type Profile, type Rule, api, download } from "../api";
import { ErrorBox, Loading, Panel } from "../components/ui";
import { humanize } from "../format";
import { useAsync } from "../hooks";

const RULE_DOCS = "https://github.com/furkan-akkaya/NetGuard/blob/main/docs/rules/";

type Section = Record<string, unknown>;
type Overrides = Record<string, Section | string[]>;

interface Detector {
  name: string;
  rules: Rule[];
  settings: Section; // base values from the server
}

function detectors(rules: Rule[]): Detector[] {
  const byName = new Map<string, Detector>();
  for (const r of rules) {
    const d = byName.get(r.detector) ?? { name: r.detector, rules: [], settings: r.settings };
    d.rules.push(r);
    byName.set(r.detector, d);
  }
  return [...byName.values()];
}

const asList = (text: string) =>
  text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);

/** Only the values that differ from the base configuration are stored in a profile. */
export function diffOverrides(base: Detector[], values: Record<string, Section>, allowlist: string[]): Overrides {
  const out: Overrides = {};
  for (const d of base) {
    const changed: Section = {};
    for (const [key, baseValue] of Object.entries(d.settings)) {
      const v = values[d.name]?.[key];
      if (v !== undefined && JSON.stringify(v) !== JSON.stringify(baseValue)) changed[key] = v;
    }
    if (Object.keys(changed).length) out[d.name] = changed;
  }
  if (allowlist.length) out.allowlist = allowlist;
  return out;
}

function Field({
  name,
  value,
  onChange,
}: {
  name: string;
  value: unknown;
  onChange: (v: unknown) => void;
}) {
  if (typeof value === "boolean") {
    return (
      <label className="check">
        <input type="checkbox" checked={value} onChange={(e) => onChange(e.target.checked)} />
        {humanize(name)}
      </label>
    );
  }
  if (Array.isArray(value)) {
    return (
      <label>
        {humanize(name)}
        <input
          defaultValue={value.join(", ")}
          onBlur={(e) => onChange(asList(e.target.value))}
          placeholder="comma-separated"
          spellCheck={false}
        />
      </label>
    );
  }
  return (
    <label>
      {humanize(name)}
      <input
        type="number"
        step="any"
        min="0"
        value={String(value)}
        onChange={(e) => onChange(e.target.value === "" ? value : Number(e.target.value))}
      />
    </label>
  );
}

function Editor({ base, profile, onSaved }: { base: Detector[]; profile: Profile | null; onSaved: (p: Profile | null) => void }) {
  const initial = useMemo(() => {
    const values: Record<string, Section> = {};
    for (const d of base) {
      const override = (profile?.config[d.name] ?? {}) as Section;
      values[d.name] = { ...d.settings, ...override };
    }
    return values;
  }, [base, profile]);
  const [values, setValues] = useState(initial);
  const [name, setName] = useState(profile?.name ?? "");
  const [description, setDescription] = useState(profile?.description ?? "");
  const [allowlist, setAllowlist] = useState(((profile?.config.allowlist as string[] | undefined) ?? []).join(", "));
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  useEffect(() => {
    setValues(initial);
    setName(profile?.name ?? "");
    setDescription(profile?.description ?? "");
    setAllowlist(((profile?.config.allowlist as string[] | undefined) ?? []).join(", "));
    setError(null);
  }, [initial, profile]);

  const overrides = diffOverrides(base, values, asList(allowlist));
  const set = (detector: string, key: string, v: unknown) =>
    setValues((prev) => ({ ...prev, [detector]: { ...prev[detector], [key]: v } }));

  async function save() {
    setError(null);
    setSaved(false);
    const body = { name: name.trim(), description, config: overrides };
    try {
      const result = profile ? await api.updateProfile(profile.id, body) : await api.createProfile(body);
      setSaved(true);
      onSaved(result);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <form
      className="editor"
      onSubmit={(e) => {
        e.preventDefault();
        void save();
      }}
    >
      <div className="filters">
        <label>
          Profile name
          <input value={name} onChange={(e) => setName(e.target.value)} required maxLength={64} pattern="[\w .\(\)\-]+" />
        </label>
        <label className="grow">
          Description
          <input value={description} onChange={(e) => setDescription(e.target.value)} maxLength={500} />
        </label>
        <label className="grow">
          Allowlist (IPs or CIDRs never treated as attackers)
          <input value={allowlist} onChange={(e) => setAllowlist(e.target.value)} placeholder="10.0.0.5, 192.168.10.0/24" />
        </label>
      </div>
      <div className="detectors">
        {base.map((d) => (
          <fieldset key={d.name} className={values[d.name]?.enabled === false ? "disabled-rule" : ""}>
            <legend>
              {d.rules.map((r) => r.rule_id).join(", ")} · {d.rules[0]?.title}
            </legend>
            {Object.entries(values[d.name] ?? {}).map(([key, v]) => (
              <Field key={key} name={key} value={v} onChange={(nv) => set(d.name, key, nv)} />
            ))}
          </fieldset>
        ))}
      </div>
      <details>
        <summary>Stored overrides ({Object.keys(overrides).length} sections differ from the server defaults)</summary>
        <pre className="json">{JSON.stringify(overrides, null, 2)}</pre>
      </details>
      <div className="button-row">
        <button type="submit" className="btn btn-primary">
          {profile ? "Save profile" : "Create profile"}
        </button>
        {profile ? (
          <button
            type="button"
            className="btn"
            onClick={() =>
              download(`/profiles/${profile.id}/export.toml`, `netguard-profile-${profile.name.replace(/\s+/g, "-")}.toml`).catch(
                (e: unknown) => setError(e instanceof Error ? e.message : String(e)),
              )
            }
          >
            Export TOML
          </button>
        ) : null}
        {profile ? (
          <button
            type="button"
            className="btn btn-danger"
            onClick={() => {
              if (window.confirm(`Delete profile ${profile.name}?`)) {
                api.deleteProfile(profile.id).then(
                  () => onSaved(null),
                  (e: unknown) => setError(e instanceof Error ? e.message : String(e)),
                );
              }
            }}
          >
            Delete
          </button>
        ) : null}
        {saved ? <span className="sev-text-low">Saved.</span> : null}
        {error ? (
          <span className="sev-text-high" role="alert">
            {error}
          </span>
        ) : null}
      </div>
    </form>
  );
}

function ImportProfile({ onImported }: { onImported: (p: Profile) => void }) {
  const [error, setError] = useState<string | null>(null);
  return (
    <div className="button-row">
      <label className="btn">
        Import TOML…
        <input
          type="file"
          accept=".toml,text/plain,application/toml"
          className="sr-only"
          onChange={(e) => {
            const file = e.target.files?.[0];
            e.target.value = "";
            if (!file) return;
            setError(null);
            const name = file.name.replace(/\.toml$/i, "").replace(/[^\w .()-]/g, "_").slice(0, 64) || "imported";
            file
              .text()
              .then((text) => api.importProfile(name, text))
              .then(onImported, (err: unknown) => setError(err instanceof Error ? err.message : String(err)));
          }}
        />
      </label>
      <span className="muted small">A profile exported here, or any netguard.toml (validated by the server).</span>
      {error ? (
        <span className="sev-text-high" role="alert">
          {error}
        </span>
      ) : null}
    </div>
  );
}

export function Rules() {
  const rules = useAsync(() => api.rules(), []);
  const profiles = useAsync(() => api.profiles(), []);
  const [selected, setSelected] = useState<string>("new");
  const base = useMemo(() => (rules.data ? detectors(rules.data) : []), [rules.data]);
  const profile = profiles.data?.find((p) => p.id === selected) ?? null;

  if (rules.error) return <ErrorBox error={rules.error} retry={rules.reload} />;
  if (!rules.data) return <Loading />;

  return (
    <>
      <h1>Rules</h1>
      <Panel title={`${rules.data.length} detection rules`}>
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Title</th>
                <th>Detector</th>
                <th>ATT&amp;CK</th>
                <th>Default</th>
              </tr>
            </thead>
            <tbody>
              {rules.data.map((r) => (
                <tr key={r.rule_id}>
                  <td>
                    <a href={`${RULE_DOCS}${r.rule_id}.md`} target="_blank" rel="noreferrer noopener" className="mono">
                      {r.rule_id}
                    </a>
                  </td>
                  <td>{r.title}</td>
                  <td className="mono">{r.detector}</td>
                  <td className="mono">{r.technique ?? "–"}</td>
                  <td>{r.enabled ? "on" : "off"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
      <Panel
        title="Rule profiles"
        actions={
          <label className="inline">
            Edit{" "}
            <select value={selected} onChange={(e) => setSelected(e.target.value)}>
              <option value="new">New profile…</option>
              {profiles.data?.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </label>
        }
      >
        <p className="muted">
          A profile is a named set of thresholds and switches. Choose one when analysing a capture to compare results
          under different settings. Only values that differ from the server defaults are stored.
        </p>
        <ImportProfile
          onImported={(p) => {
            profiles.reload();
            setSelected(p.id);
          }}
        />
        <Editor
          base={base}
          profile={profile}
          onSaved={(p) => {
            profiles.reload();
            setSelected(p ? p.id : "new");
          }}
        />
      </Panel>
    </>
  );
}
