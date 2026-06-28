import { useState, useEffect } from "react";
import client from "../api/client";
import QRDropzone from "../components/QRDropzone";

const LEVEL_COLOR = {
  green:  { ring: "#16a34a", bg: "bg-green-900/30",  text: "text-green-300",  border: "border-green-600",  label: "SAFE",    emoji: "🟢" },
  yellow: { ring: "#ca8a04", bg: "bg-yellow-900/30", text: "text-yellow-300", border: "border-yellow-600", label: "CAUTION", emoji: "🟡" },
  red:    { ring: "#dc2626", bg: "bg-red-900/30",    text: "text-red-300",    border: "border-red-600",    label: "DANGER",  emoji: "🔴" },
};

function TrafficLight({ level, score }) {
  const lv = LEVEL_COLOR[level] || LEVEL_COLOR.green;
  return (
    <div className="flex flex-col items-center gap-2">
      <div
        className="w-24 h-24 rounded-full flex items-center justify-center text-3xl font-black text-white shadow-lg"
        style={{ background: lv.ring, boxShadow: `0 0 32px ${lv.ring}88` }}
      >
        {score}
      </div>
      <span className={`text-xs font-bold tracking-widest ${lv.text}`}>{lv.label}</span>
    </div>
  );
}

function ResultCard({ result, index }) {
  const [open, setOpen] = useState(false);
  const lv = LEVEL_COLOR[result.risk_level] || LEVEL_COLOR.green;

  return (
    <div className={`rounded-xl border ${lv.border} ${lv.bg} p-4 space-y-3`}>
      <div className="flex items-start gap-4">
        <TrafficLight level={result.risk_level} score={result.risk_score ?? 0} />
        <div className="flex-1 min-w-0">
          <p className="text-xs text-gray-400 mb-1">
            QR Code {index + 1}{result.page_number ? ` · Page ${result.page_number}` : ""}
          </p>
          <p className="text-sm font-mono text-gray-200 break-all">
            {result.decoded_url?.length > 80
              ? result.decoded_url.slice(0, 80) + "…"
              : result.decoded_url}
          </p>
          <p className="text-xs text-gray-400 mt-1">
            Quishing probability: {((result.quishing_probability || 0) * 100).toFixed(0)}%
          </p>
        </div>
      </div>

      {result.explanation && (
        <p className="text-sm text-gray-300 bg-black/20 rounded-lg px-3 py-2">{result.explanation}</p>
      )}

      {result.signals?.length > 0 && (
        <div>
          <p className="text-xs text-gray-500 mb-1">Detection signals</p>
          <ul className="space-y-1">
            {result.signals.slice(0, 5).map((s, i) => (
              <li key={i} className={`text-xs flex gap-1.5 ${lv.text}`}>
                <span>›</span><span>{s}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <button
        onClick={() => setOpen(!open)}
        className="text-xs text-gray-500 hover:text-gray-300 underline"
      >
        {open ? "Hide details" : "Show redirect chain + screenshot"}
      </button>

      {open && (
        <div className="space-y-3">
          {result.redirect_chain?.length > 0 && (
            <div>
              <p className="text-xs text-gray-500 mb-1">Redirect chain</p>
              {result.redirect_chain.map((url, i) => (
                <p key={i} className="text-xs font-mono text-gray-400 truncate">{i + 1}. {url}</p>
              ))}
            </div>
          )}
          {result.screenshot_url && (
            <div>
              <p className="text-xs text-gray-500 mb-1">URLScan.io screenshot</p>
              <img
                src={result.screenshot_url}
                alt="Page screenshot"
                className="rounded-lg max-h-40 object-cover border border-[#2C2C2E]"
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, sub, accent }) {
  return (
    <div className="bg-[#1C1C1E] border border-[#2C2C2E] rounded-xl p-4 space-y-1">
      <p className="text-xs text-gray-500">{label}</p>
      <p className={`text-2xl font-black ${accent || "text-white"}`}>{value}</p>
      {sub && <p className="text-xs text-gray-600">{sub}</p>}
    </div>
  );
}

export default function QRScanner() {
  const [results, setResults]           = useState([]);
  const [totalFound, setTotalFound]     = useState(null);
  const [scannedCount, setScannedCount] = useState(0);
  const [redCount, setRedCount]         = useState(0);
  const [history, setHistory]           = useState([]);
  const [activeTab, setActiveTab]       = useState(0);

  useEffect(() => {
    client.get("/qr/history?limit=10")
      .then(r => setHistory(r.data.scans || []))
      .catch(() => {});
  }, []);

  const handleResults = (data) => {
    const res = data.results || [];
    setResults(res);
    setTotalFound(data.total_qr_found);
    setScannedCount(c => c + 1);
    setRedCount(c => c + res.filter(r => r.risk_level === "red").length);
    setActiveTab(0);
    client.get("/qr/history?limit=10")
      .then(r => setHistory(r.data.scans || []))
      .catch(() => {});
  };

  const avgRisk = results.length > 0
    ? Math.round(results.reduce((s, r) => s + (r.risk_score || 0), 0) / results.length)
    : 0;

  return (
    <div className="min-h-screen bg-[#141414] text-white p-6 space-y-6">
      <div>
        <p className="text-xs text-[#E8470A] font-bold tracking-widest uppercase mb-1">NovaGuard</p>
        <h1 className="text-2xl font-black">QR Scanner</h1>
        <p className="text-sm text-gray-400">
          Detect quishing attacks hidden inside QR codes — images and PDFs
        </p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Scans This Session"   value={scannedCount}      sub="images + PDFs"   />
        <StatCard label="Red Threats Caught"   value={redCount}          sub="dangerous QRs"   accent="text-red-400"  />
        <StatCard label="Last Scan Risk Score" value={avgRisk || "—"}    sub="0–100 combined"  />
        <StatCard label="QR Codes Decoded"     value={totalFound ?? "—"} sub="in last upload"  />
      </div>

      <div className="grid md:grid-cols-2 gap-6">
        <div className="space-y-4">
          <h2 className="text-sm font-semibold text-gray-300">Upload Image or PDF</h2>
          <QRDropzone onResults={handleResults} />

          {history.length > 0 && (
            <div>
              <h3 className="text-xs text-gray-500 mb-2">Recent Scans</h3>
              <div className="space-y-1.5">
                {history.map((h) => (
                  <div key={h.investigation_id}
                    className="flex items-center gap-3 bg-[#1C1C1E] border border-[#2C2C2E] rounded-lg px-3 py-2 text-xs">
                    <span className="text-base">
                      {h.risk_level === "red" ? "🔴" : h.risk_level === "yellow" ? "🟡" : "🟢"}
                    </span>
                    <span className="font-mono text-gray-300 truncate flex-1">{h.decoded_url}</span>
                    <span className="text-gray-600 shrink-0">
                      {new Date(h.scanned_at).toLocaleDateString()}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="space-y-4">
          {results.length === 0 && totalFound === null && (
            <div className="flex items-center justify-center h-64 rounded-xl border border-dashed border-[#2C2C2E]">
              <p className="text-sm text-gray-500">Scan results will appear here</p>
            </div>
          )}

          {totalFound === 0 && (
            <div className="bg-green-900/20 border border-green-700 rounded-xl px-4 py-6 text-center">
              <p className="text-green-300 font-semibold">No QR codes detected</p>
              <p className="text-sm text-gray-400 mt-1">No QR codes were found in the uploaded file.</p>
            </div>
          )}

          {results.length > 0 && (
            <>
              {results.length > 1 && (
                <div className="flex gap-2 flex-wrap">
                  {results.map((r, i) => {
                    const lv = LEVEL_COLOR[r.risk_level] || LEVEL_COLOR.green;
                    return (
                      <button
                        key={i}
                        onClick={() => setActiveTab(i)}
                        className={`text-xs px-3 py-1.5 rounded-lg border transition-colors
                          ${activeTab === i
                            ? `${lv.border} ${lv.bg} ${lv.text}`
                            : "border-[#2C2C2E] text-gray-400 hover:border-gray-600"}`}
                      >
                        {lv.emoji} QR Code {i + 1}
                      </button>
                    );
                  })}
                </div>
              )}
              <ResultCard result={results[activeTab]} index={activeTab} />
            </>
          )}
        </div>
      </div>
    </div>
  );
}
