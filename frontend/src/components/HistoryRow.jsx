import { Trash2 } from 'lucide-react'
import TrafficLight from './TrafficLight'

export default function HistoryRow({ item, onDelete, onClick }) {
  const date = new Date(item.created_at)
  const dateStr = date.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
  const timeStr = date.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })

  const typeIcon = { url: '🔗', text: '💬', email: '📧', screenshot: '📷' }

  return (
    <div
      className="flex items-center gap-4 p-4 rounded-xl border border-nova-border bg-nova-slate
                 hover:border-nova-orange/40 transition-colors duration-200 cursor-pointer group"
      onClick={() => onClick(item)}
    >
      {/* Type icon */}
      <span className="text-xl shrink-0">{typeIcon[item.input_type] || '🔍'}</span>

      {/* Main content */}
      <div className="flex-1 min-w-0">
        <p className="text-sm text-nova-light truncate font-medium">{item.input_preview}</p>
        <p className="text-xs text-nova-muted mt-0.5">
          {dateStr} at {timeStr}
        </p>
      </div>

      {/* Traffic light */}
      <div className="shrink-0">
        <TrafficLight color={item.traffic_light} />
      </div>

      {/* Score */}
      <div className="shrink-0 w-10 text-center">
        <span className="text-xs font-bold text-nova-muted">{item.predicted_score}</span>
        <p className="text-[9px] text-nova-muted/60">risk</p>
      </div>

      {/* Delete */}
      <button
        className="shrink-0 p-1.5 rounded-lg text-nova-muted hover:text-red-400 hover:bg-red-500/10
                   opacity-0 group-hover:opacity-100 transition-all duration-200"
        onClick={(e) => {
          e.stopPropagation()
          onDelete(item.id)
        }}
        title="Delete"
      >
        <Trash2 size={14} />
      </button>
    </div>
  )
}
