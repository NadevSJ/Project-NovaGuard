import { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Search, Mail, Camera, Clock,
  CheckCircle, XCircle, Upload, Globe, MessageSquare,
} from 'lucide-react'
import { openLiveBrowser } from '../api/live'
import { investigate, investigateEmail, investigateScreenshot } from '../api/investigate'
import { getHistory } from '../api/history'
import { useAuth } from '../context/AuthContext'
import TrafficLight from '../components/TrafficLight'
import RiskMeter from '../components/RiskMeter'
import ReportCard from '../components/ReportCard'
import LiveBrowserFrame from '../components/LiveBrowserFrame'
import Spinner from '../components/Spinner'

// ---- helpers ----------------------------------------------------------------
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

/** Build the email blob the agent expects */
function composeEmail({ sender, subject, body }) {
  let s = 'EMAIL INPUT\n'
  if (sender?.trim())  s += `Sender: ${sender.trim()}\n`
  if (subject?.trim()) s += `Subject: ${subject.trim()}\n`
  s += `Body:\n${body.trim()}`
  return s
}

const TABS = [
  { id: 'text',       label: 'Text / URL',  icon: <MessageSquare size={15} /> },
  { id: 'email',      label: 'Email',       icon: <Mail size={15} /> },
  { id: 'screenshot', label: 'Screenshot',  icon: <Camera size={15} /> },
]

// ---- component --------------------------------------------------------------
export default function Dashboard() {
  const { user } = useAuth()
  const [activeTab, setActiveTab] = useState('text')

  const [loading,  setLoading]  = useState(false)
  const [result,   setResult]   = useState(null)
  const [error,    setError]    = useState('')

  // Live browser — one entry per URL tab: { url, shot, status, done, error }
  const [liveTabs, setLiveTabs] = useState([])
  const esRefs = useRef([])                   // one EventSource per URL

  // Forms
  const [textInput,         setTextInput]         = useState('')
  const [emailForm,         setEmailForm]         = useState({ sender: '', subject: '', body: '' })
  const [screenshot,        setScreenshot]        = useState(null)
  const [screenshotPreview, setScreenshotPreview] = useState(null)
  const fileInputRef = useRef(null)

  const [recentHistory, setRecentHistory] = useState([])

  const loadHistory = useCallback(async () => {
    try { setRecentHistory((await getHistory(1, 5)).items) } catch { /* ignore */ }
  }, [])

  useEffect(() => { loadHistory() }, [loadHistory])

  // Cleanup all open SSE connections on unmount
  useEffect(() => () => { esRefs.current.forEach(es => es?.close()) }, [])

  // ---- close all live connections & reset tab state -------------------------
  function closeLive() {
    esRefs.current.forEach(es => es?.close())
    esRefs.current = []
    setLiveTabs([])
  }

  // ---- shared multi-URL live-browser launcher --------------------------------
  /**
   * Opens one SSE connection per URL in `urls`.
   *   - First URL: uses `inputText` for the AI investigation (shows full-message verdict)
   *   - Other URLs: visual_only=true — navigate + screenshot only (no AI call, much faster)
   * @param {string[]} urls
   * @param {string}   inputText   — full message the agent investigates
   * @param {boolean}  updateResult — if false, don't update the result card (screenshot tab)
   * @param {boolean}  holdLoading  — if false, don't manipulate loading state
   */
  function startLiveBrowserMulti(urls, inputText, { updateResult = true, holdLoading = true } = {}) {
    closeLive()

    // Initialise tab slots
    const initTabs = urls.map(url => ({ url, shot: null, status: 'Launching browser…', done: false, error: null }))
    setLiveTabs(initTabs)
    if (holdLoading) setLoading(true)

    const refs = new Array(urls.length).fill(null)
    esRefs.current = refs

    urls.forEach((url, i) => {
      const isFirst = i === 0

      const es = openLiveBrowser(
        url,
        isFirst ? inputText : url,   // only first tab gets full message context
        {
          visualOnly: !isFirst,      // subsequent tabs skip AI (screenshots only)

          onStatus: (msg) =>
            setLiveTabs(prev => prev.map((t, idx) => idx === i ? { ...t, status: msg } : t)),

          onScreenshot: (b64) =>
            setLiveTabs(prev => prev.map((t, idx) => idx === i ? { ...t, shot: b64 } : t)),

          onResult: (isFirst && updateResult)
            ? (data) => { setResult(_normaliseResult(data, 'url')); loadHistory() }
            : () => {},

          onError: (msg) =>
            setLiveTabs(prev => prev.map((t, idx) => idx === i ? { ...t, error: msg } : t)),

          onDone: () => setLiveTabs(prev => {
            const next = prev.map((t, idx) => idx === i ? { ...t, done: true } : t)
            if (holdLoading && next.every(t => t.done)) setLoading(false)
            return next
          }),
        },
      )
      esRefs.current[i] = es
    })
  }

  // ---- regular (non-URL) investigation -------------------------------------
  async function runRegularInvestigation(fn, fallbackType) {
    closeLive()
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const data = await fn()
      setResult(_normaliseResult(data, fallbackType))
      loadHistory()
    } catch (err) {
      setError(err.response?.data?.detail || 'Investigation failed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  // ---- form handlers -------------------------------------------------------
  const handleTextSubmit = (e) => {
    e.preventDefault()
    const trimmed = textInput.trim()
    if (!trimmed) return
    const urls = extractAllUrls(trimmed)
    if (urls.length > 0) {
      setResult(null); setError('')
      startLiveBrowserMulti(urls, trimmed)
    } else {
      runRegularInvestigation(() => investigate(trimmed), 'text')
    }
  }

  const handleEmailSubmit = (e) => {
    e.preventDefault()
    if (!emailForm.body.trim()) return
    // Deduplicate URLs found across body + subject
    const urls = [
      ...new Set([
        ...extractAllUrls(emailForm.body),
        ...extractAllUrls(emailForm.subject),
      ]),
    ]
    if (urls.length > 0) {
      const emailText = composeEmail(emailForm)
      setResult(null); setError('')
      startLiveBrowserMulti(urls, emailText)
    } else {
      runRegularInvestigation(() => investigateEmail(emailForm), 'email')
    }
  }

  const handleScreenshotSubmit = async (e) => {
    e.preventDefault()
    if (!screenshot) return
    closeLive()
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const data = await investigateScreenshot(screenshot)
      if (data.investigation) {
        const inv = _normaliseResult(data.investigation, 'screenshot')
        setResult(inv)
        loadHistory()
        // Auto-open live tabs for any URLs found in the screenshot text
        const urlsFound    = (data.extraction?.urls_found || []).filter(u => /^https?:\/\//i.test(u))
        const extractedTxt = data.extraction?.message_text || ''
        const urls         = urlsFound.length > 0 ? urlsFound : extractAllUrls(extractedTxt)
        if (urls.length > 0) {
          startLiveBrowserMulti(urls, extractedTxt || urls[0], { updateResult: false, holdLoading: false })
        }
      } else {
        setError(data.user_message || 'Could not read the screenshot clearly.')
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'Screenshot analysis failed.')
    } finally {
      setLoading(false)
    }
  }

  const handleFileChange = (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    setScreenshot(file)
    setScreenshotPreview(URL.createObjectURL(file))
  }

  // ---- derived state -------------------------------------------------------
  const showLiveFrame = liveTabs.length > 0
  const showSpinner   = loading && !showLiveFrame
  const showResult    = Boolean(result)

  // Pre-compute URL lists for hints & button labels
  const textUrls  = extractAllUrls(textInput)
  const textHasUrl = textUrls.length > 0

  const emailUrls = [
    ...new Set([
      ...extractAllUrls(emailForm.body),
      ...extractAllUrls(emailForm.subject),
    ]),
  ]
  const emailHasUrl = emailUrls.length > 0

  // ---- render ---------------------------------------------------------------
  return (
    <div className="max-w-6xl mx-auto px-4 py-8">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-nova-light">
          Welcome back, <span className="text-nova-orange">{user?.username}</span>
        </h1>
        <p className="text-sm text-nova-muted mt-1">
          Submit a message, URL, email, or screenshot.{' '}
          <span className="text-nova-orange">
            Every URL detected opens in its own live Chrome tab.
          </span>
        </p>
      </div>

      <div className="grid lg:grid-cols-2 gap-8">
        {/* ── LEFT: input panel ── */}
        <div>
          <div className="card">
            {/* Tabs */}
            <div className="flex gap-1 mb-6 bg-nova-dark rounded-lg p-1">
              {TABS.map((t) => (
                <button
                  key={t.id}
                  onClick={() => {
                    setActiveTab(t.id)
                    setResult(null); setError('')
                    closeLive()
                  }}
                  className={`flex-1 flex items-center justify-center gap-1.5 py-2 rounded-md text-xs font-medium transition-all duration-200 ${
                    activeTab === t.id
                      ? 'bg-nova-orange text-white shadow-sm'
                      : 'text-nova-muted hover:text-nova-light'
                  }`}
                >
                  {t.icon} {t.label}
                </button>
              ))}
            </div>

            {/* ── Text / URL tab ── */}
            {activeTab === 'text' && (
              <form onSubmit={handleTextSubmit} className="space-y-4">
                <div>
                  <label className="label">Message, URL, or suspicious text</label>
                  <textarea
                    value={textInput}
                    onChange={(e) => setTextInput(e.target.value)}
                    className="input-field min-h-[160px] resize-y"
                    placeholder={'Paste a suspicious SMS, link, or message…\n\nTip: every URL found opens in its own Chrome tab.'}
                    required
                  />
                </div>
                {textHasUrl && (
                  <div className="flex items-center gap-2 text-xs text-nova-orange bg-nova-orange/10 border border-nova-orange/20 rounded-lg px-3 py-2">
                    <Globe size={13} />
                    {textUrls.length === 1
                      ? 'URL detected — Chrome will open it live while AI analyses the full message'
                      : `${textUrls.length} URLs detected — Chrome will open each in its own tab`}
                  </div>
                )}
                <button type="submit" disabled={loading} className="btn-primary w-full flex items-center justify-center gap-2">
                  {loading ? <Spinner size="sm" /> : (textHasUrl ? <Globe size={16} /> : <Search size={16} />)}
                  {loading
                    ? (textHasUrl ? 'Browser investigating…' : 'Investigating…')
                    : textHasUrl
                      ? (textUrls.length > 1 ? `Open ${textUrls.length} Live Tabs` : 'Open Live Browser')
                      : 'Investigate'}
                </button>
              </form>
            )}

            {/* ── Email tab ── */}
            {activeTab === 'email' && (
              <form onSubmit={handleEmailSubmit} className="space-y-4">
                <div>
                  <label className="label">From (sender)</label>
                  <input type="text" value={emailForm.sender}
                    onChange={(e) => setEmailForm({ ...emailForm, sender: e.target.value })}
                    className="input-field" placeholder="sender@suspicious-domain.com" />
                </div>
                <div>
                  <label className="label">Subject</label>
                  <input type="text" value={emailForm.subject}
                    onChange={(e) => setEmailForm({ ...emailForm, subject: e.target.value })}
                    className="input-field" placeholder="URGENT — Your account has been suspended" />
                </div>
                <div>
                  <label className="label">Email body *</label>
                  <textarea value={emailForm.body}
                    onChange={(e) => setEmailForm({ ...emailForm, body: e.target.value })}
                    className="input-field min-h-[120px] resize-y"
                    placeholder="Paste the full email body here…" required />
                </div>
                {emailHasUrl && (
                  <div className="flex items-center gap-2 text-xs text-nova-orange bg-nova-orange/10 border border-nova-orange/20 rounded-lg px-3 py-2">
                    <Globe size={13} />
                    {emailUrls.length === 1
                      ? 'URL detected in email — Chrome will open it live'
                      : `${emailUrls.length} URLs detected — Chrome will open each in its own tab`}
                  </div>
                )}
                <button type="submit" disabled={loading} className="btn-primary w-full flex items-center justify-center gap-2">
                  {loading ? <Spinner size="sm" /> : (emailHasUrl ? <Globe size={16} /> : <Mail size={16} />)}
                  {loading
                    ? (emailHasUrl ? 'Browser investigating…' : 'Analysing email…')
                    : emailHasUrl
                      ? (emailUrls.length > 1 ? `Open ${emailUrls.length} Live Tabs` : 'Open Live Browser')
                      : 'Analyse Email'}
                </button>
              </form>
            )}

            {/* ── Screenshot tab ── */}
            {activeTab === 'screenshot' && (
              <form onSubmit={handleScreenshotSubmit} className="space-y-4">
                <div
                  className="border-2 border-dashed border-nova-border rounded-xl p-8 text-center cursor-pointer hover:border-nova-orange/50 transition-colors duration-200"
                  onClick={() => fileInputRef.current?.click()}
                >
                  {screenshotPreview ? (
                    <img src={screenshotPreview} alt="preview" className="max-h-48 mx-auto rounded-lg object-contain" />
                  ) : (
                    <>
                      <Upload size={32} className="text-nova-muted mx-auto mb-3" />
                      <p className="text-sm text-nova-muted">Click to upload a screenshot</p>
                      <p className="text-xs text-nova-muted/60 mt-1">PNG, JPG, WEBP up to 10 MB</p>
                    </>
                  )}
                  <input ref={fileInputRef} type="file" accept="image/*" className="hidden" onChange={handleFileChange} />
                </div>
                {screenshot && <p className="text-xs text-nova-muted text-center">{screenshot.name}</p>}
                <p className="text-xs text-nova-muted/60 text-center">
                  If URLs are found in the screenshot, Chrome opens each in its own tab automatically
                </p>
                <button type="submit" disabled={loading || !screenshot} className="btn-primary w-full flex items-center justify-center gap-2">
                  {loading ? <Spinner size="sm" /> : <Camera size={16} />}
                  {loading ? 'Analysing screenshot…' : 'Analyse Screenshot'}
                </button>
              </form>
            )}
          </div>

          {/* Recent history */}
          {recentHistory.length > 0 && (
            <div className="mt-6">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold text-nova-muted flex items-center gap-1.5">
                  <Clock size={14} /> Recent Investigations
                </h3>
                <Link to="/history" className="text-xs text-nova-orange hover:text-nova-orange-light">View all</Link>
              </div>
              <div className="space-y-2">
                {recentHistory.map((item) => (
                  <div key={item.id} className="flex items-center gap-3 p-3 rounded-lg border border-nova-border bg-nova-slate/50 text-sm">
                    <TrafficLight color={item.traffic_light} />
                    <span className="flex-1 text-nova-muted truncate text-xs">{item.input_preview}</span>
                    <span className="text-xs text-nova-muted/60 shrink-0">{new Date(item.created_at).toLocaleDateString()}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* ── RIGHT: results panel ── */}
        <div className="space-y-4">
          {/* Live browser frame (multi-tab) */}
          {showLiveFrame && (
            <LiveBrowserFrame tabs={liveTabs} />
          )}

          {/* Regular loading spinner */}
          {showSpinner && (
            <div className="card flex flex-col items-center justify-center min-h-[300px] gap-4">
              <Spinner size="lg" />
              <p className="text-nova-muted text-sm animate-pulse">NovaGuard is investigating…</p>
            </div>
          )}

          {/* Error */}
          {error && !loading && (
            <div className="card border-red-500/30 bg-red-500/5">
              <div className="flex items-start gap-3">
                <XCircle size={20} className="text-red-400 shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm font-semibold text-red-400">Investigation failed</p>
                  <p className="text-sm text-nova-muted mt-1">{error}</p>
                </div>
              </div>
            </div>
          )}

          {/* Investigation result */}
          {showResult && (
            <>
              <div className="card">
                <TrafficLight color={result.traffic_light} label={result.predicted_label} large />
              </div>
              <div className="card space-y-4">
                <RiskMeter score={result.predicted_score} />
                <div className="grid grid-cols-2 gap-3 pt-2 border-t border-nova-border">
                  <div>
                    <p className="text-xs text-nova-muted">Input type</p>
                    <p className="text-sm font-medium text-nova-light capitalize mt-0.5">{result.input_type}</p>
                  </div>
                  <div>
                    <p className="text-xs text-nova-muted">Analysis time</p>
                    <p className="text-sm font-medium text-nova-light mt-0.5">{result.latency_seconds?.toFixed(1)}s</p>
                  </div>
                </div>
              </div>
              {result.recommended_action && (
                <div className="card border-nova-orange/20 bg-nova-orange/5">
                  <p className="text-xs text-nova-orange font-semibold uppercase tracking-wider mb-2">Recommended Action</p>
                  <p className="text-sm text-nova-light">{result.recommended_action}</p>
                </div>
              )}
              <div className="card">
                <p className="text-xs font-semibold text-nova-muted uppercase tracking-wider mb-4 flex items-center gap-1.5">
                  <CheckCircle size={13} className="text-nova-orange" /> Full Investigation Report
                </p>
                <ReportCard report={result.report} />
              </div>
            </>
          )}

          {/* Empty state */}
          {!showLiveFrame && !showSpinner && !result && !error && (
            <div className="card flex flex-col items-center justify-center min-h-[300px] gap-4 border-dashed">
              <div className="p-4 rounded-full bg-nova-orange/10">
                <Search size={32} className="text-nova-orange" />
              </div>
              <div className="text-center">
                <p className="text-nova-muted font-medium">Results will appear here</p>
                <p className="text-xs text-nova-muted/60 mt-1">Multiple URLs each open in their own live Chrome tab</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ---- util -------------------------------------------------------------------
function _normaliseResult(data, fallbackType) {
  if (data.predicted_label && data.traffic_light) return data
  const label = (data.predicted_label || 'SUSPICIOUS').toUpperCase()
  return {
    predicted_label:    label,
    predicted_score:    data.predicted_score ?? 50,
    input_type:         data.input_type ?? fallbackType,
    latency_seconds:    data.latency_seconds ?? 0,
    report:             data.response ?? data.report ?? '',
    traffic_light:      _labelToLight(label),
    recommended_action: data.recommended_action ?? '',
  }
}

function _labelToLight(label) {
  if (label === 'SCAM')       return 'red'
  if (label === 'SUSPICIOUS') return 'yellow'
  return 'green'
}
