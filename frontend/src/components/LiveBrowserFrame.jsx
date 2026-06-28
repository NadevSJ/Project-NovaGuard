import { useEffect, useRef, useState } from 'react'
import { X, Minus, Maximize2, Shield, Wifi, Lock } from 'lucide-react'
import Spinner from './Spinner'

/**
 * LiveBrowserFrame — macOS-style laptop with a multi-tab browser.
 *
 * Props:
 *   tabs  — array of { url, shot, status, done, error }
 *           One entry per URL being investigated concurrently.
 */
export default function LiveBrowserFrame({ tabs = [] }) {
  const [activeIdx, setActiveIdx] = useState(0)

  // Crossfade state for the viewport
  const [prevShot, setPrevShot]   = useState(null)
  const [curShot,  setCurShot]    = useState(null)
  const [fadein,   setFadein]     = useState(false)
  const timerRef        = useRef(null)
  const prevActiveRef   = useRef(0)

  // When tabs are (re-)populated after being empty, reset to tab 0
  const prevLenRef = useRef(0)
  useEffect(() => {
    if (tabs.length > 0 && prevLenRef.current === 0) {
      setActiveIdx(0)
      prevActiveRef.current = 0
      setPrevShot(null)
      setCurShot(null)
      setFadein(false)
    }
    prevLenRef.current = tabs.length
  }, [tabs.length])

  // Crossfade: fires on tab switch OR new screenshot for the active tab
  const safeIdx  = tabs.length > 0 ? Math.min(activeIdx, tabs.length - 1) : 0
  const activeShot = tabs[safeIdx]?.shot ?? null

  useEffect(() => {
    clearTimeout(timerRef.current)

    // Tab switch → immediately show that tab's current screenshot
    if (prevActiveRef.current !== safeIdx) {
      prevActiveRef.current = safeIdx
      setPrevShot(null)
      setCurShot(activeShot)
      setFadein(true)
      return
    }

    // New screenshot for this tab → crossfade
    if (!activeShot) return
    setPrevShot(curShot)
    setCurShot(activeShot)
    setFadein(false)
    timerRef.current = setTimeout(() => setFadein(true), 30)
    return () => clearTimeout(timerRef.current)
  }, [activeShot, safeIdx]) // eslint-disable-line react-hooks/exhaustive-deps

  if (tabs.length === 0) return null

  const active   = tabs[safeIdx]
  const { url, status, done, error } = active || {}
  const allDone  = tabs.every(t => t.done)

  const displayUrl = url ? (url.length > 55 ? url.slice(0, 55) + '…' : url) : ''
  const isHttps    = url?.startsWith('https')

  return (
    <div className="w-full select-none">

      {/* ── Laptop lid (screen) ── */}
      <div
        className="relative rounded-t-2xl overflow-hidden border border-nova-border shadow-2xl shadow-black/60"
        style={{ background: '#1a1a1a' }}
      >

        {/* Browser chrome bar */}
        <div
          className="flex items-center gap-3 px-4 py-2.5 border-b border-white/10"
          style={{ background: 'linear-gradient(180deg, #2d2d2f 0%, #252527 100%)' }}
        >
          {/* macOS traffic lights */}
          <div className="flex items-center gap-1.5 shrink-0">
            <div className="h-3 w-3 rounded-full bg-red-500/80 hover:bg-red-500 transition-colors flex items-center justify-center group">
              <X size={7} className="text-red-900 opacity-0 group-hover:opacity-100" />
            </div>
            <div className="h-3 w-3 rounded-full bg-yellow-500/80 hover:bg-yellow-500 transition-colors flex items-center justify-center group">
              <Minus size={7} className="text-yellow-900 opacity-0 group-hover:opacity-100" />
            </div>
            <div className="h-3 w-3 rounded-full bg-green-500/80 hover:bg-green-500 transition-colors flex items-center justify-center group">
              <Maximize2 size={7} className="text-green-900 opacity-0 group-hover:opacity-100" />
            </div>
          </div>

          {/* Address bar — shows active tab's URL */}
          <div className="flex-1 flex items-center gap-2 bg-black/30 border border-white/10 rounded-md px-3 py-1 min-w-0">
            {isHttps
              ? <Lock size={11} className="shrink-0 text-green-400" />
              : <Wifi size={11} className="shrink-0 text-nova-muted" />
            }
            <span className="text-xs text-nova-muted truncate font-mono tracking-tight">
              {displayUrl || 'about:blank'}
            </span>
            {!done && !error && (
              <span className="ml-auto shrink-0 h-1.5 w-1.5 rounded-full bg-nova-orange animate-pulse" />
            )}
          </div>

          {/* NovaGuard badge */}
          <div className="shrink-0 flex items-center gap-1 text-[10px] text-nova-orange font-semibold">
            <Shield size={11} />
            <span className="hidden sm:inline">NovaGuard</span>
          </div>
        </div>

        {/* ── Tab bar — one clickable tab per URL ── */}
        <div
          className="flex items-end border-b border-white/5 text-[11px] overflow-x-auto"
          style={{ background: '#1e1e20' }}
        >
          {tabs.map((tab, i) => {
            const isActive = i === safeIdx
            const short    = tab.url.length > 30 ? tab.url.slice(0, 30) + '…' : tab.url
            return (
              <button
                key={tab.url + i}
                onClick={() => setActiveIdx(i)}
                className={`flex items-center gap-1.5 px-3 py-1.5 border-r border-white/5 transition-colors whitespace-nowrap shrink-0 ${
                  isActive
                    ? 'border-b-2 border-nova-orange text-nova-light bg-nova-dark/60'
                    : 'text-nova-muted hover:text-nova-light hover:bg-white/5'
                }`}
              >
                <Shield size={9} className={isActive ? 'text-nova-orange' : 'text-nova-muted/60'} />
                <span className="max-w-[140px] truncate">{short}</span>
                {/* Per-tab status dot */}
                {!tab.done && !tab.error && (
                  <span className="h-1.5 w-1.5 rounded-full bg-nova-orange animate-pulse shrink-0" />
                )}
                {tab.done && !tab.error && (
                  <span className="h-1.5 w-1.5 rounded-full bg-green-400 shrink-0" />
                )}
                {tab.error && (
                  <span className="h-1.5 w-1.5 rounded-full bg-red-400 shrink-0" />
                )}
              </button>
            )
          })}
        </div>

        {/* ── Viewport ── */}
        <div
          className="relative overflow-hidden bg-gray-900"
          style={{ aspectRatio: '16/9', maxHeight: '420px' }}
        >
          {/* Previous screenshot (fades out) */}
          {prevShot && (
            <img
              src={`data:image/png;base64,${prevShot}`}
              alt=""
              className="absolute inset-0 w-full h-full object-cover object-top transition-opacity duration-500"
              style={{ opacity: fadein ? 0 : 1 }}
            />
          )}

          {/* Current screenshot (fades in) */}
          {curShot && (
            <img
              src={`data:image/png;base64,${curShot}`}
              alt="Live browser view"
              className="absolute inset-0 w-full h-full object-cover object-top transition-opacity duration-500"
              style={{ opacity: fadein ? 1 : 0 }}
            />
          )}

          {/* Placeholder before first screenshot */}
          {!curShot && !error && (
            <div className="absolute inset-0 flex flex-col items-center justify-center gap-4">
              <div className="relative">
                <Shield size={48} className="text-nova-orange/20" />
                <div className="absolute inset-0 flex items-center justify-center">
                  <Spinner size="sm" />
                </div>
              </div>
              <p className="text-nova-muted text-sm animate-pulse">Launching browser…</p>
            </div>
          )}

          {/* Error overlay */}
          {error && (
            <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 bg-red-950/80">
              <p className="text-red-400 text-sm font-medium">Browser error</p>
              <p className="text-red-300/70 text-xs max-w-xs text-center">{error}</p>
            </div>
          )}

          {/* CRT scan-line overlay (cosmetic) */}
          <div
            className="absolute inset-0 pointer-events-none"
            style={{
              background:
                'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px)',
            }}
          />

          {/* Indeterminate progress bar — visible while any tab is still loading */}
          {!allDone && !error && (
            <div className="absolute top-0 left-0 right-0 h-0.5 bg-nova-border overflow-hidden">
              <div
                className="h-full bg-nova-orange"
                style={{ animation: 'indeterminate 1.5s ease-in-out infinite', width: '40%' }}
              />
            </div>
          )}
        </div>

        {/* Status bar — shows the active tab's status */}
        <div
          className="flex items-center justify-between px-4 py-1.5 border-t border-white/5 text-[10px]"
          style={{ background: '#1a1a1c' }}
        >
          <span className={`truncate transition-colors ${done ? 'text-green-400' : 'text-nova-muted'}`}>
            {done
              ? '✓ Done'
              : error
              ? `⚠ ${error}`
              : status || 'Waiting…'}
          </span>
          <div className="flex items-center gap-2 shrink-0 ml-2">
            {/* Per-tab completion count */}
            {tabs.length > 1 && (
              <span className="text-nova-muted/60">
                {tabs.filter(t => t.done).length}/{tabs.length} tabs
              </span>
            )}
            {!allDone && !error && <Spinner size="sm" />}
            {allDone && <Shield size={10} className="text-nova-orange" />}
          </div>
        </div>
      </div>

      {/* ── Laptop hinge + base ── */}
      <div className="relative flex flex-col items-center">
        <div
          className="w-full h-2 border-x border-b border-nova-border/60"
          style={{ background: 'linear-gradient(180deg, #252527 0%, #1a1a1c 100%)' }}
        />
        <div
          className="w-full h-3 rounded-b-xl border-x border-b border-nova-border/40"
          style={{
            background: 'linear-gradient(180deg, #1a1a1c 0%, #141416 100%)',
            clipPath: 'polygon(0 0, 100% 0, 96% 100%, 4% 100%)',
          }}
        />
        <div className="absolute bottom-0.5 flex items-center gap-1 text-[9px] text-nova-border">
          <Shield size={8} />
          <span>NovaGuard</span>
        </div>
      </div>

      {/* Inline keyframes for the indeterminate progress bar */}
      <style>{`
        @keyframes indeterminate {
          0%   { transform: translateX(-100%); }
          50%  { transform: translateX(150%); }
          100% { transform: translateX(350%); }
        }
      `}</style>
    </div>
  )
}
