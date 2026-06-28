/**
 * AlertCard — displays a single Shield alert.
 * Props:
 *   alert: { alert_id, alert_type, severity, detail, action_taken, created_at }
 *   onMarkReviewed: function(alert_id)
 *   onTakedown: function(domain)
 */
const SEVERITY_STYLE = {
  critical: "border-red-600    bg-red-900/20    text-red-300",
  high:     "border-orange-500 bg-orange-900/20 text-orange-300",
  medium:   "border-yellow-600 bg-yellow-900/20 text-yellow-300",
  low:      "border-gray-600   bg-gray-800/40   text-gray-300",
};

const ALERT_TYPE_LABEL = {
  email_auth_fail: "Email Auth Failure",
  bec_payment:     "BEC Payment Threat",
  domain_lookalike:"Domain Lookalike",
  qr_quishing:     "QR Quishing",
};

const SEVERITY_DOT = {
  critical: "bg-red-500",
  high:     "bg-orange-500",
  medium:   "bg-yellow-500",
  low:      "bg-gray-500",
};

function timeAgo(iso) {
  if (!iso) return "";
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 60)  return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24)  return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export default function AlertCard({ alert, onMarkReviewed, onTakedown }) {
  const sv     = alert.severity || "medium";
  const detail = alert.detail || {};
  const sig    = detail.email_auth?.signals || detail.signals || [];
  const dom    = detail.suspicious_domain || "";

  return (
    <div className={`rounded-xl border px-4 py-3 ${SEVERITY_STYLE[sv]} space-y-2`}>
      {/* Header row */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${SEVERITY_DOT[sv]}`} />
          <span className="text-xs font-bold uppercase tracking-wide">{sv}</span>
          <span className="text-xs text-gray-400 ml-1">
            {ALERT_TYPE_LABEL[alert.alert_type] || alert.alert_type}
          </span>
        </div>
        <span className="text-xs text-gray-500">{timeAgo(alert.created_at)}</span>
      </div>

      {/* Signal list */}
      {sig.length > 0 && (
        <ul className="text-xs text-gray-300 space-y-0.5 pl-1">
          {sig.slice(0, 3).map((s, i) => (
            <li key={i} className="flex gap-1">
              <span className="text-[#E8470A] mt-0.5">›</span>
              <span>{s}</span>
            </li>
          ))}
        </ul>
      )}

      {/* Domain for lookalike alerts */}
      {dom && (
        <p className="text-xs font-mono text-yellow-300 bg-yellow-900/20 rounded px-2 py-1">
          {dom}
        </p>
      )}

      {/* Action buttons */}
      <div className="flex gap-2 pt-1">
        {!alert.resolved && (
          <button
            onClick={() => onMarkReviewed?.(alert.alert_id)}
            className="text-xs px-3 py-1 rounded-lg bg-[#2C2C2E] text-gray-300
                       hover:bg-[#3C3C3E] transition-colors"
          >
            Mark Reviewed
          </button>
        )}
        {dom && onTakedown && (
          <button
            onClick={() => onTakedown(dom)}
            className="text-xs px-3 py-1 rounded-lg bg-red-900/40 text-red-300
                       border border-red-700 hover:bg-red-800/40 transition-colors"
          >
            Initiate Takedown
          </button>
        )}
        {alert.resolved && (
          <span className="text-xs text-green-400 py-1">✓ Reviewed</span>
        )}
      </div>
    </div>
  );
}
