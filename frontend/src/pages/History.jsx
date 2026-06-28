import { useCallback, useEffect, useRef, useState } from 'react'
import { History as HistoryIcon, ChevronLeft, ChevronRight, X, AlertTriangle, Globe } from 'lucide-react'
import { deleteHistoryItem, getHistory, getHistoryItem } from '../api/history'
import { openLiveBrowser } from '../api/live'
import HistoryRow from '../components/HistoryRow'
import ReportCard from '../components/ReportCard'
import TrafficLight from '../components/TrafficLight'
import RiskMeter from '../components/RiskMeter'
import LiveBrowserFrame from '../components/LiveBrowserFrame'
import Spinner from '../components/Spinner'

// Extract all unique http/https URLs from a string
function extractAllUrls(text) {
  const re     = /https?:\/\/[^\s<>"']+/gi
  const seen   = new Set()
  const result = []
  let m
  while ((m = re.exec(text || '')) !== null) {
    if (!seen.has(m[0])) { seen.add(m[0]); result.push(m[0]) }
  }
  return result
}

export default function History() {
  const [page, setPage] = useState(1)
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [deleteConfirm, setDeleteConfirm] = useState(null)

  // Live browser — one entry per URL tab: { url, shot, status, done, error }
  const [liveTabs, setLiveTabs] = useState([])
  const esRefs = useRef([])

  // Cleanup all SSE connections on unmount
  useEffect(() => () => { esRefs.current.forEach(es => es?.close()) }, [])

  function closeLive() {
    esRefs.current.forEach(es => es?.close())
    esRefs.current = []
    setLiveTabs([])
  }

  const load = useCallback(async (p = 1) => {
    setLoading(true)
    try {
      const res = await getHistory(p, 20)
      setData(res)
      setPage(p)
    } catch {
      setData(null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load(1) }, [load])

  const handleClick = async (item) => {
    closeLive()
    setDetailLoading(true)
    try {
      const detail = await getHistoryItem(item.id)
      setSelected(detail)
    } catch {
      setSelected(null)
    } finally {
      setDetailLoading(false)
    }
  }

  const handleDelete = async (id) => {
    try {
      await deleteHistoryItem(id)
      setDeleteConfirm(null)
      if (selected?.id === id) { setSelected(null); closeLive() }
      load(page)
    } catch { /* ignore */ }
  }

  // Open one SSE connection per URL; only first URL runs the AI investigation
  const handleOpenLive = (urls, inputText) => {
    closeLive()

    const initTabs = urls.map(url => ({
      url, shot: null, status: 'Launching browser…', done: false, error: null,
    }))
    setLiveTabs(initTabs)
    const refs = new Array(urls.length).fill(null)
    esRefs.current = refs

    urls.forEach((url, i) => {
      const isFirst = i === 0
      const es = openLiveBrowser(
        url,
        isFirst ? inputText : url,
        {
          visualOnly: !isFirst,

          onStatus:     (msg) => setLiveTabs(prev => prev.map((t, idx) => idx === i ? { ...t, status: msg } : t)),
          onScreenshot: (b64) => setLiveTabs(prev => prev.map((t, idx) => idx === i ? { ...t, shot: b64 } : t)),
          onResult:     () => {},    // result already shown in the detail card
          onError:      (msg) => setLiveTabs(prev => prev.map((t, idx) => idx === i ? { ...t, error: msg } : t)),
          onDone:       ()    => setLiveTabs(prev => prev.map((t, idx) => idx === i ? { ...t, done: true } : t)),
        },
      )
      esRefs.current[i] = es
    })
  }

  // All URLs found in the selected investigation's preview text
  const detailUrls = selected ? extractAllUrls(selected.input_preview) : []
  const liveLoading = liveTabs.length > 0 && !liveTabs.every(t => t.done)

  return (
    <div className="max-w-6xl mx-auto px-4 py-8">
      <div className="flex items-center gap-3 mb-8">
        <HistoryIcon size={22} className="text-nova-orange" />
        <h1 className="text-2xl font-bold text-nova-light">Investigation History</h1>
      </div>

      <div className="grid lg:grid-cols-2 gap-8">
        {/* LEFT — list */}
        <div>
          {loading && (
            <div className="flex justify-center py-16"><Spinner size="lg" /></div>
          )}

          {!loading && data?.items?.length === 0 && (
            <div className="card flex flex-col items-center justify-center min-h-[300px] gap-4 border-dashed text-center">
              <HistoryIcon size={40} className="text-nova-muted/40" />
              <p className="text-nova-muted">No investigations yet</p>
              <p className="text-xs text-nova-muted/60">Go to the dashboard and run your first scan</p>
            </div>
          )}

          {!loading && data?.items?.length > 0 && (
            <>
              <div className="space-y-2 mb-6">
                {data.items.map((item) => (
                  <HistoryRow
                    key={item.id}
                    item={item}
                    onClick={handleClick}
                    onDelete={(id) => setDeleteConfirm(id)}
                  />
                ))}
              </div>

              {data.pages > 1 && (
                <div className="flex items-center justify-between">
                  <p className="text-xs text-nova-muted">
                    {data.total} total · page {page} of {data.pages}
                  </p>
                  <div className="flex gap-2">
                    <button disabled={page <= 1} onClick={() => load(page - 1)} className="btn-ghost p-2 disabled:opacity-30">
                      <ChevronLeft size={16} />
                    </button>
                    <button disabled={page >= data.pages} onClick={() => load(page + 1)} className="btn-ghost p-2 disabled:opacity-30">
                      <ChevronRight size={16} />
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* RIGHT — detail */}
        <div className="space-y-4">
          {detailLoading && (
            <div className="card flex items-center justify-center min-h-[300px]">
              <Spinner size="lg" />
            </div>
          )}

          {selected && !detailLoading && (
            <>
              {/* Header card */}
              <div className="card">
                <div className="flex items-start justify-between mb-4">
                  <p className="text-xs text-nova-muted">
                    {new Date(selected.created_at).toLocaleString('en-GB')}
                  </p>
                  <button
                    onClick={() => { setSelected(null); closeLive() }}
                    className="text-nova-muted hover:text-nova-light"
                  >
                    <X size={16} />
                  </button>
                </div>
                <TrafficLight color={selected.traffic_light} label={selected.predicted_label} large />
              </div>

              {/* URL(s) card — shown whenever at least one URL is in the preview */}
              {detailUrls.length > 0 && (
                <div className="card border-nova-orange/20 bg-nova-orange/5">
                  <div className="flex items-start justify-between gap-4">
                    <div className="min-w-0 flex-1">
                      <p className="text-xs text-nova-orange font-semibold uppercase tracking-wider mb-1">
                        {detailUrls.length === 1 ? 'URL Investigation' : `${detailUrls.length} URLs Detected`}
                      </p>
                      {detailUrls.map((u, i) => (
                        <p key={i} className="text-xs text-nova-muted truncate font-mono leading-5">{u}</p>
                      ))}
                    </div>
                    <button
                      onClick={() => handleOpenLive(detailUrls, selected.input_preview)}
                      disabled={liveLoading}
                      className="btn-primary shrink-0 flex items-center gap-2 text-xs px-4 py-2"
                    >
                      {liveLoading ? <Spinner size="sm" /> : <Globe size={14} />}
                      {liveLoading
                        ? 'Opening…'
                        : detailUrls.length > 1
                          ? `Open ${detailUrls.length} Tabs`
                          : 'Open in Browser'}
                    </button>
                  </div>
                </div>
              )}

              {/* Live browser frame (multi-tab) */}
              {liveTabs.length > 0 && (
                <LiveBrowserFrame tabs={liveTabs} />
              )}

              {/* Metrics */}
              <div className="card">
                <RiskMeter score={selected.predicted_score} />
                <div className="mt-3 pt-3 border-t border-nova-border">
                  <p className="text-xs text-nova-muted">Input</p>
                  <p className="text-sm text-nova-light mt-1 break-words">{selected.input_preview}</p>
                </div>
              </div>

              {selected.recommended_action && (
                <div className="card border-nova-orange/20 bg-nova-orange/5">
                  <p className="text-xs text-nova-orange font-semibold uppercase tracking-wider mb-2">Recommended Action</p>
                  <p className="text-sm text-nova-light">{selected.recommended_action}</p>
                </div>
              )}

              <div className="card">
                <p className="text-xs font-semibold text-nova-muted uppercase tracking-wider mb-4">Report</p>
                <ReportCard report={selected.report} />
              </div>
            </>
          )}

          {!selected && !detailLoading && (
            <div className="card flex flex-col items-center justify-center min-h-[300px] gap-4 border-dashed">
              <p className="text-nova-muted text-sm">Select an investigation to view the full report</p>
              <p className="text-xs text-nova-muted/60">Multiple URLs open in separate live Chrome tabs</p>
            </div>
          )}
        </div>
      </div>

      {/* Delete confirm modal */}
      {deleteConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="card max-w-sm w-full mx-4">
            <div className="flex items-start gap-3 mb-4">
              <AlertTriangle size={20} className="text-red-400 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold text-nova-light">Delete investigation?</p>
                <p className="text-sm text-nova-muted mt-1">This cannot be undone.</p>
              </div>
            </div>
            <div className="flex gap-3">
              <button onClick={() => setDeleteConfirm(null)} className="btn-ghost flex-1">Cancel</button>
              <button
                onClick={() => handleDelete(deleteConfirm)}
                className="flex-1 bg-red-500 hover:bg-red-600 text-white font-semibold px-4 py-2 rounded-lg transition-colors"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
