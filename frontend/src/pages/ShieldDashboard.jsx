import { useState, useEffect, useRef } from "react";
import client from "../api/client";
import AlertCard from "../components/AlertCard";

function StatCard({ label, value, sub, accent, icon }) {
  return (
    <div className="bg-[#1C1C1E] border border-[#2C2C2E] rounded-xl p-4">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs text-gray-500 mb-1">{label}</p>
          <p className={`text-2xl font-black ${accent || "text-white"}`}>{value}</p>
          {sub && <p className="text-xs text-gray-600 mt-0.5">{sub}</p>}
        </div>
        {icon && <span className="text-2xl opacity-60">{icon}</span>}
      </div>
    </div>
  );
}

function RegisterOrgModal({ onClose, onRegistered }) {
  const [form, setForm] = useState({
    org_name: "", sector_tag: "banking",
    org_domain: "", webhook_url: "",
    registered_domains: "", known_executives: "",
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const submit = async () => {
    if (!form.org_name) { setError("Organisation name is required"); return; }
    setLoading(true); setError("");
    try {
      const res = await client.post("/shield/org/register", {
        org_name: form.org_name,
        sector_tag: form.sector_tag,
        org_domain: form.org_domain,
        webhook_url: form.webhook_url,
        registered_domains: form.registered_domains.split(",").map(d => d.trim()).filter(Boolean),
        known_executives: form.known_executives.split(",").map(e => e.trim()).filter(Boolean),
      });
      onRegistered(res.data);
      onClose();
    } catch (err) {
      setError(err.response?.data?.detail || "Registration failed");
    } finally { setLoading(false); }
  };

  const field = (label, key, placeholder) => (
    <div>
      <label className="block text-xs text-gray-400 mb-1">{label}</label>
      <input
        placeholder={placeholder}
        value={form[key]}
        onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
        className="w-full bg-[#141414] border border-[#2C2C2E] rounded-lg px-3 py-2
                   text-sm text-white placeholder-gray-600 focus:border-[#E8470A] outline-none"
      />
    </div>
  );

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <div className="bg-[#1C1C1E] border border-[#2C2C2E] rounded-2xl p-6 w-full max-w-md space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-bold">Register Organisation</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-white text-xl">×</button>
        </div>
        {field("Organisation Name *", "org_name", "e.g. Bank of Ceylon")}
        <div>
          <label className="block text-xs text-gray-400 mb-1">Sector</label>
          <select
            value={form.sector_tag}
            onChange={e => setForm(f => ({ ...f, sector_tag: e.target.value }))}
            className="w-full bg-[#141414] border border-[#2C2C2E] rounded-lg px-3 py-2
                       text-sm text-white focus:border-[#E8470A] outline-none"
          >
            {["banking","government","telco","healthcare","general"].map(s => (
              <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
            ))}
          </select>
        </div>
        {field("Primary Email Domain", "org_domain", "e.g. boc.lk")}
        {field("Official Domains (comma-separated)", "registered_domains", "boc.lk, bankofceylon.lk")}
        {field("Known Executives (comma-separated)", "known_executives", "Kanchana Ratwatte, Siddhika Senarath")}
        {field("Webhook URL (optional)", "webhook_url", "https://your-siem.example.com/hook")}
        {error && <p className="text-xs text-red-400">{error}</p>}
        <div className="flex gap-3 pt-2">
          <button onClick={onClose} className="flex-1 py-2 rounded-lg border border-[#2C2C2E] text-sm text-gray-400 hover:bg-[#2C2C2E]">
            Cancel
          </button>
          <button
            onClick={submit}
            disabled={loading}
            className="flex-1 py-2 rounded-lg bg-[#E8470A] text-white text-sm font-semibold
                       hover:bg-[#C03A08] disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? "Registering…" : "Register"}
          </button>
        </div>
      </div>
    </div>
  );
}

function ScanEmailModal({ orgId, onClose }) {
  const [rawEmail, setRawEmail] = useState("");
  const [senderIp, setSenderIp] = useState("0.0.0.0");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const scan = async () => {
    if (!rawEmail.trim()) { setError("Paste the raw email headers + body"); return; }
    setLoading(true); setError(""); setResult(null);
    try {
      const b64 = btoa(unescape(encodeURIComponent(rawEmail)));
      const res = await client.post("/shield/scan-email", {
        raw_email: b64,
        sender_ip: senderIp,
        org_id: orgId,
      });
      setResult(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || "Scan failed");
    } finally { setLoading(false); }
  };

  const riskColor = (r) =>
    r >= 70 ? "text-red-400" : r >= 40 ? "text-yellow-400" : "text-green-400";

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <div className="bg-[#1C1C1E] border border-[#2C2C2E] rounded-2xl p-6 w-full max-w-2xl space-y-4 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-bold">Scan Email for BEC / Spoofing</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-white text-xl">×</button>
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Paste Raw Email (headers + body)</label>
          <textarea
            rows={8}
            value={rawEmail}
            onChange={e => setRawEmail(e.target.value)}
            placeholder={"From: CFO John Smith <cfo@evil-domain.xyz>\nTo: accounts@boc.lk\nSubject: URGENT – Update Bank Details\n\nDear Team,\nPlease update payment to IBAN LK..."}
            className="w-full bg-[#141414] border border-[#2C2C2E] rounded-lg px-3 py-2
                       text-xs font-mono text-gray-300 placeholder-gray-700
                       focus:border-[#E8470A] outline-none resize-none"
          />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Sender IP (optional)</label>
          <input
            value={senderIp}
            onChange={e => setSenderIp(e.target.value)}
            className="w-48 bg-[#141414] border border-[#2C2C2E] rounded-lg px-3 py-2
                       text-sm text-white focus:border-[#E8470A] outline-none"
          />
        </div>
        {error && <p className="text-xs text-red-400">{error}</p>}
        {result && (
          <div className="bg-[#141414] border border-[#2C2C2E] rounded-xl p-4 space-y-3">
            <div className="flex items-center gap-3">
              <span className={`text-3xl font-black ${riskColor(result.combined_risk)}`}>
                {result.combined_risk}
              </span>
              <div>
                <p className="text-sm font-semibold">Risk Score / 100</p>
                <p className="text-xs text-gray-500">
                  Action: <span className="text-[#E8470A]">{result.recommended_action?.toUpperCase()}</span>
                </p>
              </div>
            </div>
            <div className="grid grid-cols-3 gap-2 text-xs text-center">
              {["spf_result","dkim_result","dmarc_result"].map(k => (
                <div key={k} className="bg-[#1C1C1E] rounded-lg py-2">
                  <p className="text-gray-500 mb-0.5">{k.split("_")[0].toUpperCase()}</p>
                  <p className={result.email_auth?.[k] === "pass" ? "text-green-400" : "text-red-400"}>
                    {result.email_auth?.[k] || "—"}
                  </p>
                </div>
              ))}
            </div>
            {result.email_auth?.signals?.length > 0 && (
              <ul className="text-xs text-gray-300 space-y-1">
                {result.email_auth.signals.map((s, i) => (
                  <li key={i} className="flex gap-1"><span className="text-[#E8470A]">›</span>{s}</li>
                ))}
              </ul>
            )}
            {result.bec_analysis && result.bec_analysis.bec_probability > 0.3 && (
              <div className="bg-red-900/20 border border-red-700 rounded-lg p-3 text-xs">
                <p className="text-red-300 font-semibold mb-1">
                  BEC Payment Threat — {(result.bec_analysis.bec_probability * 100).toFixed(0)}% confidence
                </p>
                <p className="text-gray-400">{result.bec_analysis.explanation}</p>
              </div>
            )}
          </div>
        )}
        <div className="flex gap-3">
          <button onClick={onClose} className="flex-1 py-2 rounded-lg border border-[#2C2C2E] text-sm text-gray-400">
            Close
          </button>
          <button
            onClick={scan}
            disabled={loading}
            className="flex-1 py-2 rounded-lg bg-[#E8470A] text-white text-sm font-semibold
                       hover:bg-[#C03A08] disabled:opacity-50"
          >
            {loading ? "Scanning…" : "Scan Email"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function ShieldDashboard() {
  const [orgs, setOrgs]                     = useState([]);
  const [selectedOrg, setSelectedOrg]       = useState(null);
  const [alerts, setAlerts]                 = useState([]);
  const [holdQueue, setHoldQueue]           = useState([]);
  const [stats, setStats]                   = useState({ total: 0, critical: 0, high: 0, domains: 0 });
  const [showRegister, setShowRegister]     = useState(false);
  const [showScanEmail, setShowScanEmail]   = useState(false);
  const [liveConnected, setLiveConnected]   = useState(false);
  const esRef = useRef(null);

  useEffect(() => {
    const stored = JSON.parse(localStorage.getItem("shield_orgs") || "[]");
    setOrgs(stored);
    if (stored.length > 0) setSelectedOrg(stored[0]);
  }, []);

  useEffect(() => {
    if (!selectedOrg?.org_id) return;
    if (esRef.current) esRef.current.close();

    const es = new EventSource(`/api/v1/shield/alerts/${selectedOrg.org_id}`);
    esRef.current = es;

    es.onopen    = () => setLiveConnected(true);
    es.onerror   = () => setLiveConnected(false);
    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        if (data.event === "shield_alert" || data.event === "domain_alert") {
          setAlerts(prev => [data, ...prev.slice(0, 49)]);
          setStats(s => ({
            ...s,
            total:    s.total + 1,
            critical: s.critical + (data.severity === "critical" ? 1 : 0),
          }));
        }
      } catch (_) {}
    };

    client.get(`/shield/alerts/${selectedOrg.org_id}/history?limit=30`)
      .then(r => {
        setAlerts(r.data.alerts || []);
        const all = r.data.alerts || [];
        setStats({
          total:    r.data.total || all.length,
          critical: all.filter(a => a.severity === "critical").length,
          high:     all.filter(a => a.severity === "high").length,
          domains:  all.filter(a => a.alert_type === "domain_lookalike").length,
        });
      })
      .catch(() => {});

    client.get(`/shield/payment/queue/${selectedOrg.org_id}`)
      .then(r => setHoldQueue(r.data.holds || []))
      .catch(() => {});

    return () => es.close();
  }, [selectedOrg]);

  const handleRegistered = (data) => {
    const newOrg = { org_id: data.org_id, org_name: data.org_name || "New Organisation", api_key: data.api_key };
    const updated = [newOrg, ...orgs];
    setOrgs(updated);
    localStorage.setItem("shield_orgs", JSON.stringify(updated));
    setSelectedOrg(newOrg);
  };

  const markReviewed = (alertId) => {
    setAlerts(prev => prev.map(a => a.alert_id === alertId ? { ...a, resolved: true } : a));
  };

  const initiateTakedown = (domain) => {
    if (window.confirm(`Submit takedown request for: ${domain}?`)) {
      client.post("/shield/domain/takedown", { domain, org_id: selectedOrg?.org_id }).catch(() => {});
    }
  };

  return (
    <div className="min-h-screen bg-[#141414] text-white p-6 space-y-6">
      {showRegister && (
        <RegisterOrgModal onClose={() => setShowRegister(false)} onRegistered={handleRegistered} />
      )}
      {showScanEmail && selectedOrg && (
        <ScanEmailModal orgId={selectedOrg.org_id} onClose={() => setShowScanEmail(false)} />
      )}

      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <p className="text-xs text-[#E8470A] font-bold tracking-widest uppercase mb-1">NovaGuard</p>
          <h1 className="text-2xl font-black">Shield Dashboard</h1>
          <p className="text-sm text-gray-400">
            Business-level spoofing prevention ·{" "}
            {liveConnected
              ? <span className="text-green-400">● Live</span>
              : <span className="text-gray-600">○ Connecting…</span>}
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setShowScanEmail(true)}
            disabled={!selectedOrg}
            className="px-4 py-2 rounded-xl bg-[#1C1C1E] border border-[#2C2C2E]
                       text-sm text-gray-300 hover:border-[#E8470A] disabled:opacity-40"
          >
            Scan Email
          </button>
          <button
            onClick={() => setShowRegister(true)}
            className="px-4 py-2 rounded-xl bg-[#E8470A] text-white text-sm font-semibold hover:bg-[#C03A08]"
          >
            + Register Org
          </button>
        </div>
      </div>

      {orgs.length > 0 && (
        <div className="flex gap-2 flex-wrap">
          {orgs.map((org) => (
            <button
              key={org.org_id}
              onClick={() => setSelectedOrg(org)}
              className={`px-4 py-1.5 rounded-full text-sm border transition-colors ${
                selectedOrg?.org_id === org.org_id
                  ? "bg-[#E8470A] border-[#E8470A] text-white"
                  : "border-[#2C2C2E] text-gray-400 hover:border-gray-500"
              }`}
            >
              {org.org_name || org.org_id?.slice(0, 8)}
            </button>
          ))}
        </div>
      )}

      {!selectedOrg ? (
        <div className="flex flex-col items-center justify-center py-24 space-y-4">
          <div className="w-16 h-16 rounded-full bg-[#1C1C1E] border border-[#2C2C2E] flex items-center justify-center text-3xl">
            🛡️
          </div>
          <p className="text-gray-400 text-sm">No organisations registered yet.</p>
          <button
            onClick={() => setShowRegister(true)}
            className="px-6 py-2.5 rounded-xl bg-[#E8470A] text-white font-semibold text-sm hover:bg-[#C03A08]"
          >
            Register Your First Organisation
          </button>
        </div>
      ) : (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <StatCard label="Total Alerts"      value={stats.total}    sub="since activation"      icon="🔔" />
            <StatCard label="Critical"          value={stats.critical} sub="immediate action"       icon="🚨" accent="text-red-400"    />
            <StatCard label="High Severity"     value={stats.high}     sub="needs review"           icon="⚠️"  accent="text-orange-400" />
            <StatCard label="Domain Lookalikes" value={stats.domains}  sub="spoofed brand domains"  icon="🌐" accent="text-yellow-400" />
          </div>

          <div className="grid md:grid-cols-3 gap-6">
            <div className="md:col-span-2 space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-semibold text-gray-300">Live Alert Feed</h2>
                <span className="text-xs text-gray-500">{alerts.length} events</span>
              </div>
              {alerts.length === 0 ? (
                <div className="bg-[#1C1C1E] border border-[#2C2C2E] rounded-xl p-8 text-center">
                  <p className="text-gray-500 text-sm">No alerts yet — system is monitoring.</p>
                </div>
              ) : (
                <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
                  {alerts.map((alert, i) => (
                    <AlertCard
                      key={alert.alert_id || i}
                      alert={alert}
                      onMarkReviewed={markReviewed}
                      onTakedown={initiateTakedown}
                    />
                  ))}
                </div>
              )}
            </div>

            <div className="space-y-3">
              <h2 className="text-sm font-semibold text-gray-300">
                Payment Hold Queue
                {holdQueue.length > 0 && (
                  <span className="ml-2 bg-red-600 text-white text-xs rounded-full px-1.5 py-0.5">
                    {holdQueue.length}
                  </span>
                )}
              </h2>
              {holdQueue.length === 0 ? (
                <div className="bg-[#1C1C1E] border border-[#2C2C2E] rounded-xl p-6 text-center">
                  <p className="text-gray-500 text-xs">No payments on hold</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {holdQueue.map((hold) => (
                    <div key={hold.alert_id}
                      className="bg-red-900/20 border border-red-700 rounded-xl p-3 space-y-2">
                      <p className="text-xs text-red-300 font-semibold">⏸ Payment Held</p>
                      <p className="text-xs text-gray-400 break-all">
                        {hold.detail?.reason || "BEC threat detected"}
                      </p>
                      <p className="text-xs text-gray-600">{new Date(hold.created_at).toLocaleString()}</p>
                      <div className="flex gap-2">
                        <button className="flex-1 py-1 rounded-lg bg-green-900/30 border border-green-700 text-xs text-green-300 hover:bg-green-900/50">
                          Approve
                        </button>
                        <button className="flex-1 py-1 rounded-lg bg-red-900/30 border border-red-700 text-xs text-red-300 hover:bg-red-900/50">
                          Reject
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
