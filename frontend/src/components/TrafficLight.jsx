const CONFIG = {
  red: {
    label: 'DANGEROUS',
    icon: '🔴',
    className: 'badge-red',
    bg: 'bg-red-500/10',
    border: 'border-red-500/30',
    text: 'text-red-400',
  },
  yellow: {
    label: 'SUSPICIOUS',
    icon: '🟡',
    className: 'badge-yellow',
    bg: 'bg-yellow-500/10',
    border: 'border-yellow-500/30',
    text: 'text-yellow-400',
  },
  green: {
    label: 'SAFE',
    icon: '🟢',
    className: 'badge-green',
    bg: 'bg-green-500/10',
    border: 'border-green-500/30',
    text: 'text-green-400',
  },
}

export default function TrafficLight({ color = 'yellow', label, large = false }) {
  const cfg = CONFIG[color] || CONFIG.yellow
  const displayLabel = label || cfg.label

  if (large) {
    return (
      <div className={`flex items-center gap-4 p-4 rounded-xl border ${cfg.bg} ${cfg.border}`}>
        <span className="text-4xl">{cfg.icon}</span>
        <div>
          <p className="text-xs text-nova-muted uppercase tracking-widest font-medium">Verdict</p>
          <p className={`text-2xl font-bold ${cfg.text}`}>{displayLabel}</p>
        </div>
      </div>
    )
  }

  return (
    <span className={cfg.className}>
      {cfg.icon} {displayLabel}
    </span>
  )
}
