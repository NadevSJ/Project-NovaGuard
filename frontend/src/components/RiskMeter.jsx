export default function RiskMeter({ score = 50 }) {
  const pct = Math.min(100, Math.max(0, score))

  let barColor
  if (pct >= 70) barColor = 'bg-red-500'
  else if (pct >= 40) barColor = 'bg-yellow-500'
  else barColor = 'bg-green-500'

  return (
    <div>
      <div className="flex justify-between items-center mb-1.5">
        <span className="text-xs text-nova-muted font-medium uppercase tracking-wider">Risk Score</span>
        <span className="text-sm font-bold text-nova-light">{pct}/100</span>
      </div>
      <div className="h-2.5 w-full bg-nova-border rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-700 ${barColor}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <div className="flex justify-between mt-1">
        <span className="text-[10px] text-green-500">Safe</span>
        <span className="text-[10px] text-yellow-500">Suspicious</span>
        <span className="text-[10px] text-red-500">Danger</span>
      </div>
    </div>
  )
}
