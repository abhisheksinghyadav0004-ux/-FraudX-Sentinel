import { type FormEvent, useEffect, useMemo, useState } from "react";
import "./App.css";

const API = "http://127.0.0.1:8000";
const sessionHeaders = (json = false) => {
  const token = sessionStorage.getItem("fraudx_session");
  return { ...(json ? { "Content-Type": "application/json" } : {}), ...(token ? { "X-FraudX-Session": token } : {}) };
};
const nav = [
  "Command Center",
  "Alert Queue",
  "Incidents",
  "Threat Entities",
  "Campaigns",
  "Digital DNA",
  "Threat Intelligence",
  "Transactions",
  "Identity",
  "Investigations",
  "Detection Rules",
  "Access Control",
  "Audit Logs",
];
type Alert = {
  id: number;
  alertId: string;
  severity: string;
  riskScore: number;
  category: string;
  affectedEntity: string;
  ruleName: string;
  evidence: string;
  status: string;
  campaignId?: string;
};
type Dashboard = {
  metrics: Record<string, number>;
  severity: Record<string, number>;
  alerts: Alert[];
  events: any[];
};
const get = async (path: string) => {
  const response = await fetch(`${API}${path}`, { headers: sessionHeaders() });
  if (!response.ok) throw new Error("API request failed");
  return response.json();
};
const apiError = (detail: unknown) => {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((item) => `${item.loc?.at(-1) ?? "Field"}: ${item.msg ?? "Invalid value"}`).join(" ");
  return "Request could not be completed.";
};

export default function App() {
  const [active, setActive] = useState("Command Center"),
    [dashboard, setDashboard] = useState<Dashboard | null>(null),
    [records, setRecords] = useState<Record<string, any[]>>({}),
    [dna, setDna] = useState<any>(null),
    [investigation, setInvestigation] = useState<any>(null),
    [offline, setOffline] = useState(false),
    [authReady, setAuthReady] = useState(false),
    [hasUsers, setHasUsers] = useState(false),
    [user, setUser] = useState<any>(null);
  const refresh = async () => {
    try {
      setDashboard(await get("/api/dashboard"));
      setOffline(false);
    } catch {
      setOffline(true);
    }
  };
  const load = async () => {
    try {
      const [
        alerts,
        incidents,
        entities,
        campaigns,
        intelligence,
        transactions,
        identity,
        rules,
        audit,
        dnaData,
        summary,
      ] = await Promise.all([
        get("/api/alerts"),
        get("/api/incidents"),
        get("/api/entities"),
        get("/api/campaigns"),
        get("/api/intelligence"),
        get("/api/transactions"),
        get("/api/identity"),
        get("/api/detection-rules"),
        get("/api/audit-logs"),
        get("/api/digital-dna").catch(() => null),
        get("/api/investigations/summary"),
      ]);
      setRecords({
        alerts: alerts.items,
        incidents: incidents.items,
        entities: entities.items,
        campaigns: campaigns.items,
        intelligence: intelligence.items,
        transactions: transactions.items,
        identity: identity.items,
        rules: rules.items,
        audit: audit.items,
      });
      setDna(dnaData);
      setInvestigation(summary);
    } catch {
      setOffline(true);
    }
  };
  const allRefresh = async () => {
    await refresh();
    await load();
  };
  useEffect(() => { void (async () => { try { const bootstrap = await fetch(`${API}/api/auth/bootstrap`).then(response => response.json()); setHasUsers(bootstrap.hasUsers); if (bootstrap.hasUsers && sessionStorage.getItem("fraudx_session")) { const me = await get("/api/auth/me"); setUser(me.user); } } catch { sessionStorage.removeItem("fraudx_session"); } finally { setAuthReady(true); } })(); }, []);
  useEffect(() => { if (user) void allRefresh(); }, [user]);
  const action = async (
    kind: "alerts" | "incidents",
    id: number,
    status: string,
  ) => {
    await fetch(`${API}/api/${kind}/${id}`, {
      method: "PATCH",
      headers: sessionHeaders(true),
      body: JSON.stringify({ status }),
    });
    await allRefresh();
  };
  const toggleRule = async (ruleId: string, enabled: boolean) => {
    await fetch(`${API}/api/detection-rules/${ruleId}`, {
      method: "PATCH",
      headers: sessionHeaders(true),
      body: JSON.stringify({ enabled }),
    });
    await allRefresh();
  };
  const alerts =
    (records.alerts as Alert[] | undefined) ?? dashboard?.alerts ?? [];
  const highest = useMemo(
    () => alerts.find((x) => x.severity === "CRITICAL") ?? alerts[0],
    [alerts],
  );
  if (!authReady) return <div className="auth-shell"><p>Starting secure workspace...</p></div>;
  if (!user) return <AuthGate setup={!hasUsers} onExistingAccount={() => setHasUsers(true)} onAuthenticated={(result:any) => { sessionStorage.setItem("fraudx_session", result.token); setHasUsers(true); setUser(result.user); }} />;
  const signOut = async () => { await fetch(`${API}/api/auth/logout`, { method:"POST", headers:sessionHeaders() }); sessionStorage.removeItem("fraudx_session"); setUser(null); };
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">FX</span>
          <div>
            <strong>FraudX Sentinel</strong>
            <small>Fraud Intelligence SOC</small>
          </div>
        </div>
        <div className="workspace-label">OPERATIONAL WORKSPACE</div>
        <nav>
          {nav.map((item) => (
            <button
              className={active === item ? "nav active" : "nav"}
              onClick={() => setActive(item)}
              key={item}
            >
              <span>{item === "Command Center" ? "⌘" : "◦"}</span>
              {item}
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          <span className={offline ? "status-dot danger" : "status-dot"} />
          {offline ? "API disconnected" : "Protected local environment"}
          <small>Local analyst data only</small>
          <div className="developer-credit">
            <span>DESIGNED &amp; DEVELOPED BY</span>
            <strong>Abhishek Yadav</strong>
          </div>
        </div>
      </aside>
      <main>
        <header className="topbar">
          <div>
            <span className="eyebrow">
              FRAUD INTELLIGENCE / {active.toUpperCase()}
            </span>
            <h1>{active}</h1>
          </div>
          <div className="top-actions">
            <span className="signed-in">{user.username} / {user.role}</span>
            <span className={offline ? "connection offline" : "connection"}>
              <i />
              {offline ? "API offline" : "Live telemetry"}
            </span>
            <button
              className="icon-button"
              onClick={() => void allRefresh()}
              title="Refresh live data"
            >
              ↻
            </button>
            <button className="icon-button" onClick={() => void signOut()} title="Sign out">↗</button>
          </div>
        </header>
        {offline ? (
          <section className="offline-panel">
            <strong>Backend connection required</strong>
            <p>Start FastAPI on port 8000, then refresh this workspace.</p>
          </section>
        ) : (
          <Workspace
            active={active}
            dashboard={dashboard}
            records={records}
            highest={highest}
            dna={dna}
            investigation={investigation}
            onImported={allRefresh}
            action={action}
            toggleRule={toggleRule}
            user={user}
          />
        )}
      </main>
    </div>
  );
}

function AuthGate({ setup, onAuthenticated, onExistingAccount }: { setup: boolean; onAuthenticated: (result: any) => void; onExistingAccount: () => void }) {
  const [username, setUsername] = useState(""); const [password, setPassword] = useState(""); const [state, setState] = useState("");
  const submit = async (event: FormEvent) => { event.preventDefault(); const cleanUsername = username.trim().toLowerCase(); if (!/^[A-Za-z0-9_.-]{3,80}$/.test(cleanUsername)) { setState("Username can use only letters, numbers, dots, hyphens, or underscores."); return; } setUsername(cleanUsername); setState("Checking credentials..."); try { const response = await fetch(`${API}/api/auth/${setup ? "register" : "login"}`, { method:"POST", headers:sessionHeaders(true), body:JSON.stringify({ username: cleanUsername, password }) }); const result = await response.json(); if (!response.ok) { const message = apiError(result.detail); if (message === "Initial administrator already exists") { onExistingAccount(); setState(""); return; } throw new Error(message); } onAuthenticated(result); } catch (error) { setState(error instanceof Error ? error.message : "Authentication failed"); } };
  return <main className="auth-shell"><section className="auth-panel"><div className="brand"><span className="brand-mark">FX</span><div><strong>FraudX Sentinel</strong><small>Fraud Intelligence SOC</small></div></div><span className="eyebrow">LOCAL ACCESS CONTROL</span><h1>{setup ? "Create administrator account" : "Sign in to workspace"}</h1><p>{setup ? "The first account becomes the local administrator. Use a unique password of at least 12 characters." : "Use your local FraudX credentials to access analyst data."}</p><form onSubmit={submit} noValidate><label>Username<input required minLength={3} maxLength={80} value={username} onChange={event => setUsername(event.target.value.trim())} autoComplete="username" /><small>Use letters, numbers, dots, hyphens, or underscores only.</small></label><label>Password<PasswordField value={password} onChange={setPassword} autoComplete={setup ? "new-password" : "current-password"} /></label><button className="scenario-button" type="submit">{setup ? "Create secure account" : "Sign in"}</button></form>{state && <p className="auth-state">{state}</p>}</section></main>;
}

function PasswordField({ value, onChange, autoComplete }: { value: string; onChange: (value: string) => void; autoComplete?: string }) {
  const [visible, setVisible] = useState(false);
  return (
    <span className="password-wrap">
      <input required minLength={12} type={visible ? "text" : "password"} value={value} onChange={event => onChange(event.target.value)} autoComplete={autoComplete} />
      <button type="button" className="password-eye" onClick={() => setVisible(current => !current)} aria-label={visible ? "Hide password" : "Show password"} title={visible ? "Hide password" : "Show password"}>
        {visible ? "◉" : "◎"}
      </button>
    </span>
  );
}

function Workspace({
  active,
  dashboard,
  records,
  highest,
  dna,
  investigation,
  onImported,
  action,
  toggleRule,
  user,
}: any) {
  if (active === "Command Center")
    return (
      <>
        <section className="command-strip">
          <div>
            <span className="eyebrow">ANALYST EVENT INTAKE</span>
            <h2>Ingest verified local telemetry, then investigate evidence.</h2>
            <p>
              FraudX stores only events submitted by the analyst or imported
              from your approved local log export.
            </p>
          </div>
        </section>
        <EventIntake onImported={onImported} />
        <section className="metric-grid">
          <Metric
            label="Events processed"
            value={dashboard?.metrics.eventsProcessed ?? 0}
            tone="emerald"
          />
          <Metric
            label="Active alerts"
            value={dashboard?.metrics.activeAlerts ?? 0}
            tone="ochre"
          />
          <Metric
            label="Critical alerts"
            value={dashboard?.metrics.criticalAlerts ?? 0}
            tone="vermilion"
          />
          <Metric
            label="Suspected entities"
            value={dashboard?.metrics.suspiciousEntities ?? 0}
            tone="violet"
          />
          <Metric
            label="Campaigns"
            value={dashboard?.metrics.activeCampaigns ?? 0}
            tone="emerald"
          />
          <Metric
            label="Detection rate"
            value={`${dashboard?.metrics.detectionRate ?? 0}%`}
            tone="ochre"
          />
        </section>
        <section className="grid-two">
          <article className="panel threat-panel">
            <Title
              tag="PRIORITY SIGNAL"
              title={highest?.category ?? "No active escalation"}
              right={<Severity value={highest?.severity ?? "INFO"} />}
            />
            {highest ? (
              <>
                <p className="evidence">{highest.evidence}</p>
                <Signal label="Rule" value={highest.ruleName} />
                <Signal label="Entity" value={highest.affectedEntity} />
                <Signal
                  label="Case"
                  value={highest.campaignId ?? "Awaiting correlation"}
                />
              </>
            ) : (
              <Empty text="Submit verified telemetry to begin evidence correlation." />
            )}
          </article>
          <article className="panel">
            <Title
              tag="RISK POSTURE"
              title="Severity distribution"
              right={<span className="subtle">Live</span>}
            />
            <div className="severity-bars">
              {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((level) => (
                <div className="bar-row" key={level}>
                  <span>{level}</span>
                  <div className="bar">
                    <i
                      className={level.toLowerCase()}
                      style={{
                        width: `${Math.min((dashboard?.severity[level] ?? 0) * 16, 100)}%`,
                      }}
                    />
                  </div>
                  <strong>{dashboard?.severity[level] ?? 0}</strong>
                </div>
              ))}
            </div>
          </article>
        </section>
        <section className="panel stream-panel">
          <Title
            tag="NORMALIZED TELEMETRY"
            title="Recent event stream"
            right={
              <span className="subtle">
                {dashboard?.events.length ?? 0} visible
              </span>
            }
          />
          <DataTable
            columns={[
              "Timestamp",
              "Event",
              "Account",
              "Device",
              "Source IP",
              "Context",
            ]}
            rows={(dashboard?.events ?? []).map((e: any) => [
              new Date(e.timestamp).toLocaleTimeString(),
              e.eventType,
              e.userId,
              e.deviceId,
              e.sourceIp,
              e.riskContext || "Normal telemetry",
            ])}
          />
        </section>
      </>
    );
  if (active === "Alert Queue")
    return (
      <Box
        tag="SOC TRIAGE"
        title="Evidence-backed alert queue"
        right={`${records.alerts?.length ?? 0} records`}
      >
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Alert</th>
                <th>Severity</th>
                <th>Risk</th>
                <th>Category</th>
                <th>Entity</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {(records.alerts ?? []).length === 0 ? (
                <tr><td className="empty-cell" colSpan={7}>No alerts yet. Matching events will appear here for analyst review.</td></tr>
              ) : (records.alerts ?? []).map((a: any) => (
                <tr key={a.id}>
                  <td className="mono">{a.alertId}</td>
                  <td>
                    <Severity value={a.severity} />
                  </td>
                  <td>{a.riskScore}/100</td>
                  <td>{a.category}</td>
                  <td>{a.affectedEntity}</td>
                  <td>
                    <span className="status-pill">{a.status}</span>
                  </td>
                  <td>
                    {a.status === "NEW" ? (
                      <button
                        className="table-action"
                        onClick={() =>
                          void action("alerts", a.id, "ACKNOWLEDGED")
                        }
                      >
                        Acknowledge
                      </button>
                    ) : a.status !== "CONTAINED" ? (
                      <button
                        className="table-action contain"
                        onClick={() => void action("alerts", a.id, "CONTAINED")}
                      >
                        Contain
                      </button>
                    ) : (
                      <span className="contained">Contained</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Box>
    );
  if (active === "Incidents")
    return (
      <Box
        tag="CASE MANAGEMENT"
        title="Open investigation cases"
        right={`${records.incidents?.length ?? 0} cases`}
      >
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Case</th>
                <th>Severity</th>
                <th>Campaign</th>
                <th>Owner</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {(records.incidents ?? []).length === 0 ? (
                <tr><td className="empty-cell" colSpan={6}>No investigation cases have been opened.</td></tr>
              ) : (records.incidents ?? []).map((i: any) => (
                <tr key={i.id}>
                  <td>
                    <strong>{i.title}</strong>
                    <small className="cell-note">{i.incidentId}</small>
                  </td>
                  <td>
                    <Severity value={i.severity} />
                  </td>
                  <td className="mono">{i.campaignId}</td>
                  <td><strong>{i.owner}</strong><small className={`cell-note sla-${String(i.slaState ?? "UNSET").toLowerCase()}`}>{i.dueAt ? `${i.slaState.replace("_", " ")} / ${new Date(i.dueAt).toLocaleString()}` : "Due time not set"}</small></td>
                  <td>
                    <span className="status-pill">{i.status}</span>
                  </td>
                  <td>
                    <div className="case-actions">
                      {i.status === "OPEN" ? (
                        <button className="table-action" onClick={() => void action("incidents", i.id, "INVESTIGATING")}>Start review</button>
                      ) : i.status === "INVESTIGATING" ? (
                        <button className="table-action contain" onClick={() => void action("incidents", i.id, "CONTAINED")}>Contain</button>
                      ) : (
                        <span className="contained">{i.status}</span>
                      )}
                      <ReportButton incidentId={i.id} />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <IncidentAssignment incident={records.incidents?.[0]} user={user} onChanged={onImported} />
        <IncidentNotes incident={records.incidents?.[0]} user={user} />
        <EvidenceRegister incident={records.incidents?.[0]} />
      </Box>
    );
  if (active === "Digital DNA") return <Dna data={dna} />;
  if (active === "Investigations")
    return <Investigation data={investigation} />;
  if (active === "Detection Rules")
    return <RuleControl rules={records.rules ?? []} toggleRule={toggleRule} />;
  if (active === "Access Control")
    return <AccessControl user={user} />;
  const config: any = {
    "Threat Entities": [
      "ENTITY CORRELATION",
      "Observed behaviour clusters",
      "Risk-ranked",
      ["Entity", "Type", "Risk", "Confidence", "Disposition"],
      (x: any) => [
        x.label,
        x.entityType,
        `${x.riskScore}/100`,
        `${x.confidence}%`,
        x.disposition,
      ],
      "entities",
    ],
    Campaigns: [
      "CAMPAIGN DETECTION",
      "Correlated analyst data",
      "Evidence-linked",
      ["Campaign", "Severity", "Confidence", "Status", "Summary"],
      (x: any) => [
        x.title,
        x.severity,
        `${x.confidence}%`,
        x.status,
        x.summary,
      ],
      "campaigns",
    ],
    "Threat Intelligence": [
      "INDICATOR INTELLIGENCE",
      "Observed local indicators",
      "Local sources only",
      ["Indicator", "Type", "Risk", "Confidence", "Source"],
      (x: any) => [
        x.value,
        x.type,
        `${x.riskScore}/100`,
        `${x.confidence}%`,
        x.source,
      ],
      "intelligence",
    ],
    Transactions: [
      "PAYMENT TELEMETRY",
      "Transaction events under review",
      "Normalized",
      ["Time", "Account", "Amount", "Target", "Context"],
      (x: any) => [
        new Date(x.timestamp).toLocaleTimeString(),
        x.userId,
        `INR ${x.metadata?.amount ?? 0}`,
        x.target,
        x.riskContext,
      ],
      "transactions",
    ],
    Identity: [
      "IDENTITY RISK",
      "Account and device correlation",
      "Observed only",
      ["Identity", "Events", "Devices", "IPs", "Risk"],
      (x: any) => [x.identity, x.events, x.devices, x.ips, `${x.risk}/100`],
      "identity",
    ],
    "Detection Rules": [
      "DETECTION ENGINE",
      "Active correlation rules",
      "4 enabled",
      ["Rule", "Category", "Severity", "State", "Detection logic"],
      (x: any) => [x.name, x.category, x.severity, x.status, x.logic],
      "rules",
    ],
    "Audit Logs": [
      "AUDIT TRAIL",
      "Analyst and system activity",
      "Append-only",
      ["Timestamp", "Actor", "Action", "Target", "Result"],
      (x: any) => [
        new Date(x.timestamp).toLocaleString(),
        x.actor,
        x.action,
        x.target,
        x.result,
      ],
      "audit",
    ],
  };
  const [tag, title, right, columns, formatter, key] = config[active];
  return (
    <Box tag={tag} title={title} right={right}>
      <DataTable columns={columns} rows={(records[key] ?? []).map(formatter)} />
    </Box>
  );
}
function RuleControl({ rules, toggleRule }: { rules: any[]; toggleRule: (ruleId: string, enabled: boolean) => Promise<void> }) {
  const enabledCount = rules.filter((rule) => rule.enabled).length;
  return <Box tag="DETECTION ENGINE" title="Active correlation rules" right={`${enabledCount} enabled`}>
    <div className="rule-list">
      {rules.length === 0 ? <Empty text="No detection rules are available." /> : rules.map((rule) => <article className="rule-row" key={rule.ruleId}>
        <div><span className="eyebrow">{rule.ruleId} / {rule.category}</span><h3>{rule.name}</h3><p>{rule.logic}</p></div>
        <div className="rule-control"><Severity value={rule.severity} /><button className={rule.enabled ? "rule-toggle enabled" : "rule-toggle"} onClick={() => void toggleRule(rule.ruleId, !rule.enabled)}>{rule.enabled ? "Enabled" : "Disabled"}</button></div>
      </article>)}
    </div>
  </Box>;
}

function AccessControl({ user }: { user: any }) {
  const [users, setUsers] = useState<any[]>([]); const [username, setUsername] = useState(""); const [password, setPassword] = useState(""); const [role, setRole] = useState("ANALYST"); const [state, setState] = useState("");
  const loadUsers = async () => { if (user.role !== "ADMIN") return; const result = await get("/api/users"); setUsers(result.items); };
  useEffect(() => { void loadUsers(); }, [user.role]);
  if (user.role !== "ADMIN") return <Box tag="ACCESS CONTROL" title="Restricted workspace" right="Analyst role"><Empty text="Only an administrator can create or review local user accounts." /></Box>;
  const submit = async (event: FormEvent) => { event.preventDefault(); const cleanUsername = username.trim().toLowerCase(); if (!/^[A-Za-z0-9_.-]{3,80}$/.test(cleanUsername)) { setState("Username can use only letters, numbers, dots, hyphens, or underscores."); return; } setState("Creating account..."); try { const response = await fetch(`${API}/api/users`, { method:"POST", headers:sessionHeaders(true), body:JSON.stringify({ username: cleanUsername, password, role }) }); const result = await response.json(); if (!response.ok) throw new Error(result.detail ?? "Account was not created"); setUsername(""); setPassword(""); setState(`${result.user.username} was created as ${result.user.role}.`); await loadUsers(); } catch (error) { setState(error instanceof Error ? error.message : "Account was not created"); } };
  return <Box tag="ACCESS CONTROL" title="Local user administration" right={`${users.length} accounts`}><form className="account-form" onSubmit={submit}><label>Username<input required minLength={3} value={username} onChange={event=>setUsername(event.target.value)} /></label><label>Temporary password<PasswordField value={password} onChange={setPassword} autoComplete="new-password" /></label><label>Role<select value={role} onChange={event=>setRole(event.target.value)}><option value="ANALYST">Analyst</option><option value="ADMIN">Administrator</option></select></label><button className="scenario-button" type="submit">Create account</button></form>{state&&<p className="intake-state">{state}</p>}<DataTable columns={["Username","Role","Created"]} rows={users.map(item=>[item.username,item.role,new Date(item.createdAt).toLocaleString()])}/></Box>;
}

function Dna({ data }: { data: any }) {
  return (
    <section className="panel dna-panel">
      <Title
        tag="DIGITAL DNA"
        title={data?.entity?.label ?? "No correlated entity yet"}
        right={<span className="subtle">Evidence graph</span>}
      />
      {data?.entity ? (
        <>
          <p className="evidence">
            Each relationship is persisted by the API with an explicit
            confidence score and evidence note.
          </p>
          <div className="dna-map">
            <div className="dna-center">
              {data.entity.label}
              <small>Behaviour cluster</small>
            </div>
            {data.nodes
              .filter((n: any) => n.id !== data.entity.entityId)
              .map((n: any) => (
                <div className="dna-node" key={n.id}>
                  <strong>{n.label}</strong>
                  <span>{n.type.replace("_", " ")}</span>
                  <small>{n.riskScore}/100 risk</small>
                </div>
              ))}
          </div>
          <div className="relation-list">
            {data.edges.map((e: any) => (
              <div key={`${e.source}-${e.target}`}>
                <strong>{e.relation.replaceAll("_", " ")}</strong>
                <span>{e.confidence}% confidence</span>
                <p>{e.evidence}</p>
              </div>
            ))}
          </div>
        </>
      ) : (
        <Empty text="A Digital DNA graph appears after a submitted event creates an alert." />
      )}
    </section>
  );
}
function Investigation({ data }: { data: any }) {
  return (
    <section className="grid-two investigation">
      <article className="panel">
        <Title
          tag="EVIDENCE-GROUNDED REVIEW"
          title={data?.available ? data.incident.title : "No investigation yet"}
          right={<span className="subtle">Analyst support</span>}
        />
        <p className="evidence">{data?.summary}</p>
        {data?.evidence?.map((x: string) => (
          <div className="evidence-line" key={x}>
            {x}
          </div>
        ))}
      </article>
      <article className="panel">
        <Title
          tag="RECOMMENDED NEXT STEPS"
          title="Controlled response path"
          right={<span className="subtle">Human approved</span>}
        />
        {data?.recommendedActions?.map((x: string, i: number) => (
          <Signal key={x} label={`0${i + 1}`} value={x} />
        )) ?? (
          <Empty text="A response plan appears after an incident is generated." />
        )}
      </article>
    </section>
  );
}
function Box({ tag, title, right, children }: any) {
  return (
    <section className="panel full-panel">
      <Title
        tag={tag}
        title={title}
        right={<span className="subtle">{right}</span>}
      />
      {children}
    </section>
  );
}
function Title({ tag, title, right }: any) {
  return (
    <div className="panel-heading">
      <div>
        <span className="eyebrow">{tag}</span>
        <h2>{title}</h2>
      </div>
      {right}
    </div>
  );
}
function Metric({ label, value, tone }: any) {
  return (
    <article className={`metric ${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      <small>Derived from local API</small>
    </article>
  );
}
function Severity({ value }: { value: string }) {
  return <span className={`severity ${value.toLowerCase()}`}>{value}</span>;
}
function Signal({ label, value }: any) {
  return (
    <div className="signal-row">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
function Empty({ text }: { text: string }) {
  return <p className="empty">{text}</p>;
}
function DataTable({ columns, rows }: any) {
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const pageSize = 10;
  const filteredRows = rows.filter((row: any[]) => row.some((cell) => String(cell ?? "").toLowerCase().includes(query.trim().toLowerCase())));
  const pages = Math.max(1, Math.ceil(filteredRows.length / pageSize));
  const safePage = Math.min(page, pages - 1);
  const visibleRows = filteredRows.slice(safePage * pageSize, safePage * pageSize + pageSize);
  return (
    <>
      <div className="table-tools">
        <input value={query} onChange={(event) => { setQuery(event.target.value); setPage(0); }} placeholder="Search visible records" aria-label="Search records" />
        <span>{filteredRows.length} records</span>
      </div>
      <div className="table-wrap"><table><thead><tr>{columns.map((x: string) => <th key={x}>{x}</th>)}</tr></thead><tbody>
          {visibleRows.length ? (
            visibleRows.map((row: any[], i: number) => (
              <tr key={i}>
                {row.map((cell: any, j: number) => (
                  <td key={j}>{cell}</td>
                ))}
              </tr>
            ))
          ) : (
            <tr>
              <td className="empty-cell" colSpan={columns.length}>{query ? "No records match this search." : "No records available yet. Submit or import verified telemetry first."}</td>
            </tr>
          )}
        </tbody></table></div>
      {filteredRows.length > pageSize && <div className="pagination"><button className="table-action" disabled={safePage === 0} onClick={() => setPage(safePage - 1)}>Previous</button><span>Page {safePage + 1} of {pages}</span><button className="table-action" disabled={safePage >= pages - 1} onClick={() => setPage(safePage + 1)}>Next</button></div>}
    </>
  );
}

function ReportButton({ incidentId }: { incidentId: number }) {
  const download = async () => {
    const response = await fetch(`${API}/api/incidents/${incidentId}/report`, { headers: sessionHeaders() });
    if (!response.ok) return;
    const report = await response.json();
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob); const anchor = document.createElement("a");
    anchor.href = url; anchor.download = `fraudx-incident-${report.incident.incidentId}.json`; anchor.click(); URL.revokeObjectURL(url);
  };
  return <button className="report-link" onClick={() => void download()}>Report</button>;
}

function IncidentAssignment({ incident, user, onChanged }: { incident?: any; user: any; onChanged: () => Promise<void> }) {
  const [owner, setOwner] = useState(incident?.owner === "Unassigned" ? user.username : incident?.owner ?? user.username);
  const [dueAt, setDueAt] = useState(incident?.dueAt ? new Date(incident.dueAt).toISOString().slice(0, 16) : "");
  const [users, setUsers] = useState<any[]>([]); const [state, setState] = useState("");
  useEffect(() => { setOwner(incident?.owner === "Unassigned" ? user.username : incident?.owner ?? user.username); setDueAt(incident?.dueAt ? new Date(incident.dueAt).toISOString().slice(0, 16) : ""); }, [incident?.id, incident?.owner, incident?.dueAt, user.username]);
  useEffect(() => { if (user.role === "ADMIN") void get("/api/users").then(result => setUsers(result.items)).catch(() => setUsers([])); }, [user.role]);
  if (!incident) return null;
  const save = async (event: FormEvent) => { event.preventDefault(); setState("Updating case ownership..."); try { const response = await fetch(`${API}/api/incidents/${incident.id}/assignment`, { method:"PATCH", headers:sessionHeaders(true), body:JSON.stringify({ owner, due_at: dueAt }) }); const result = await response.json(); if (!response.ok) throw new Error(result.detail ?? "Case assignment was not updated"); setState(`Assigned to ${result.incident.owner}.`); await onChanged(); } catch (error) { setState(error instanceof Error ? error.message : "Case assignment was not updated"); } };
  return <section className="assignment-panel"><Title tag="CASE OWNERSHIP & SLA" title={incident.incidentId} right={<span className={`sla-badge sla-${String(incident.slaState ?? "UNSET").toLowerCase()}`}>{String(incident.slaState ?? "UNSET").replace("_", " ")}</span>}/><form className="assignment-form" onSubmit={save}><label>Case owner{user.role === "ADMIN" ? <select required value={owner} onChange={event=>setOwner(event.target.value)}><option value="">Choose a local user</option>{users.map(item=><option value={item.username} key={item.username}>{item.username} / {item.role}</option>)}</select> : <input value={user.username} readOnly />}</label><label>Review due time<input required type="datetime-local" value={dueAt} onChange={event=>setDueAt(event.target.value)} /></label><button className="table-action" type="submit">Save assignment</button></form>{state && <p className="note-state">{state}</p>}</section>;
}

function IncidentNotes({ incident, user }: { incident?: any; user: any }) {
  const [notes, setNotes] = useState<any[]>([]);
  const [content, setContent] = useState("");
  const [state, setState] = useState("");
  const loadNotes = async () => {
    if (!incident) { setNotes([]); return; }
    const result = await get(`/api/incidents/${incident.id}/notes`);
    setNotes(result.items);
  };
  useEffect(() => { void loadNotes(); }, [incident?.id]);
  if (!incident) return null;
  const save = async (event: FormEvent) => {
    event.preventDefault();
    if (!content.trim()) return;
    setState("Saving note...");
    try {
      const response = await fetch(`${API}/api/incidents/${incident.id}/notes`, { method: "POST", headers: sessionHeaders(true), body: JSON.stringify({ content, author: user.username }) });
      if (!response.ok) throw new Error("Note was not saved");
      setContent(""); setState("Note saved to the incident timeline."); await loadNotes();
    } catch (error) { setState(error instanceof Error ? error.message : "Note was not saved"); }
  };
  return <section className="notes-panel"><Title tag="ANALYST NOTES" title={incident.incidentId} right={<span className="subtle">Persistent timeline</span>}/><form className="note-form" onSubmit={save}><input value={content} onChange={event=>setContent(event.target.value)} placeholder="Add an evidence-based analyst note" maxLength={4000}/><button className="table-action" type="submit">Save note</button></form>{state&&<p className="note-state">{state}</p>}{notes.map(note=><article className="note-entry" key={note.id}><strong>{note.author}</strong><span>{new Date(note.createdAt).toLocaleString()}</span><p>{note.content}</p></article>)}</section>;
}

function EvidenceRegister({ incident }: { incident?: any }) {
  const [items, setItems] = useState<any[]>([]); const [title, setTitle] = useState(""); const [reference, setReference] = useState(""); const [sha256, setSha256] = useState(""); const [source, setSource] = useState(""); const [state, setState] = useState("");
  const loadEvidence = async () => { if (!incident) { setItems([]); return; } const result = await get(`/api/incidents/${incident.id}/evidence`); setItems(result.items); };
  useEffect(() => { void loadEvidence(); }, [incident?.id]);
  if (!incident) return null;
  const submit = async (event: FormEvent) => { event.preventDefault(); setState("Registering evidence..."); try { const response = await fetch(`${API}/api/incidents/${incident.id}/evidence`, { method:"POST", headers:sessionHeaders(true), body:JSON.stringify({ title, reference, sha256, source }) }); const result = await response.json(); if (!response.ok) throw new Error(result.detail ?? "Evidence was not registered"); setTitle(""); setReference(""); setSha256(""); setSource(""); setState("Evidence registered in the incident record."); await loadEvidence(); } catch (error) { setState(error instanceof Error ? error.message : "Evidence was not registered"); } };
  return <section className="evidence-register"><Title tag="EVIDENCE REGISTER" title="Artifact references" right={<span className="subtle">Hash verified by analyst</span>}/><form className="evidence-form" onSubmit={submit}><label>Artifact title<input required value={title} onChange={event=>setTitle(event.target.value)} placeholder="Log archive, report, screenshot" /></label><label>Reference / location<input required value={reference} onChange={event=>setReference(event.target.value)} placeholder="Secure path or ticket reference" /></label><label>SHA-256<input required value={sha256} onChange={event=>setSha256(event.target.value)} placeholder="64 hexadecimal characters" pattern="[A-Fa-f0-9]{64}" /></label><label>Source<input required value={source} onChange={event=>setSource(event.target.value)} placeholder="Collection system or analyst" /></label><button className="table-action" type="submit">Register evidence</button></form>{state&&<p className="note-state">{state}</p>}{items.map(item=><article className="evidence-entry" key={item.id}><strong>{item.title}</strong><span>{item.source} / {new Date(item.createdAt).toLocaleString()}</span><code>{item.sha256}</code><p>{item.reference}</p></article>)}</section>;
}

function EventIntake({ onImported }: { onImported: () => Promise<void> }) {
  const [event, setEvent] = useState({ event_type: "LOGIN", user_id: "", device_id: "", source_ip: "", target: "", risk_context: "", amount: "", new_beneficiary: false });
  const [state, setState] = useState("");
  const submit = async (submitEvent: FormEvent) => {
    submitEvent.preventDefault();
    setState("Submitting...");
    const metadata = event.amount ? { amount: Number(event.amount), new_beneficiary: event.new_beneficiary } : {};
    try {
      const response = await fetch(`${API}/api/events`, { method: "POST", headers: sessionHeaders(true), body: JSON.stringify({ ...event, metadata }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail ?? "Event was rejected");
      setState(result.alert ? `Event accepted. ${result.alert.alertId} was opened for analyst review.` : "Event accepted. No rule matched this record.");
      await onImported();
    } catch (error) { setState(error instanceof Error ? error.message : "Import failed"); }
  };
  const importFile = async (file?: File) => {
    if (!file) return;
    setState("Reading import file...");
    try {
      const text = await file.text();
      const parsed = file.name.toLowerCase().endsWith(".csv") ? csvEvents(text) : JSON.parse(text);
      const events = Array.isArray(parsed) ? parsed : parsed.events;
      if (!Array.isArray(events)) throw new Error("JSON must be an array or an object containing an events array.");
      const response = await fetch(`${API}/api/events/batch`, { method: "POST", headers: sessionHeaders(true), body: JSON.stringify({ events }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail ?? "Import failed");
      setState(`${result.eventsAccepted} verified events accepted; ${result.alertsCreated} alerts created.`);
      await onImported();
    } catch (error) { setState(error instanceof Error ? error.message : "Import failed"); }
  };
  const change = (key:string, value:string|boolean) => setEvent(current => ({ ...current, [key]: value }));
  return <section className="panel intake-panel"><Title tag="LIVE INTAKE" title="Add a verified event" right={<label className="file-import">Import JSON / CSV<input type="file" accept="application/json,.json,text/csv,.csv" onChange={e => void importFile(e.target.files?.[0])}/></label>}/><form className="intake-form" onSubmit={submit}><label>Event type<select value={event.event_type} onChange={e=>change("event_type",e.target.value)}><option>LOGIN</option><option>BOOKING_REQUEST</option><option>TRANSACTION</option><option>URL_CLICK</option><option>MFA</option><option>DEVICE_REGISTERED</option></select></label><label>Account / subject<input required value={event.user_id} onChange={e=>change("user_id",e.target.value)} placeholder="Account or case ID"/></label><label>Device identifier<input required value={event.device_id} onChange={e=>change("device_id",e.target.value)} placeholder="Observed device ID"/></label><label>Source IP<input required value={event.source_ip} onChange={e=>change("source_ip",e.target.value)} placeholder="Source IP from log"/></label><label>Target / resource<input value={event.target} onChange={e=>change("target",e.target.value)} placeholder="Application, URL, or resource"/></label><label>Analyst context<input value={event.risk_context} onChange={e=>change("risk_context",e.target.value)} placeholder="Observed facts only"/></label>{event.event_type==='TRANSACTION'&&<><label>Amount<input type="number" min="0" value={event.amount} onChange={e=>change("amount",e.target.value)} placeholder="Transaction amount"/></label><label className="check-label"><input type="checkbox" checked={event.new_beneficiary} onChange={e=>change("new_beneficiary",e.target.checked)}/> New beneficiary verified</label></>}<button className="scenario-button" type="submit">Submit verified event</button></form>{state&&<p className="intake-state">{state}</p>}</section>
}

function csvEvents(text: string) {
  const lines = text.trim().split(/\r?\n/).filter(Boolean);
  if (lines.length < 2) throw new Error("CSV needs a header row and at least one event row.");
  const headers = lines[0].split(",").map(item => item.trim());
  const required = ["event_type", "user_id", "device_id", "source_ip"];
  if (required.some(item => !headers.includes(item))) throw new Error("CSV requires event_type, user_id, device_id, and source_ip columns.");
  return lines.slice(1).map(line => {
    const values = line.split(",").map(item => item.trim());
    const row = Object.fromEntries(headers.map((header, index) => [header, values[index] ?? ""]));
    const amount = Number(row.amount || 0);
    return { event_type: row.event_type, user_id: row.user_id, device_id: row.device_id, source_ip: row.source_ip, target: row.target || "", risk_context: row.risk_context || "", metadata: amount ? { amount, new_beneficiary: String(row.new_beneficiary).toLowerCase() === "true" } : {} };
  });
}
