/**
 * openLiveBrowser — opens an SSE connection to the /investigate/browse endpoint.
 *
 * @param {string} url        — the URL Chrome will navigate to (extracted from message)
 * @param {string} inputText  — the full message/text the agent will investigate
 * @param {object} callbacks
 *   .onStatus(msg)       — status string update
 *   .onScreenshot(b64)   — base64 PNG string
 *   .onResult(obj)       — full investigation result JSON
 *   .onError(msg)        — error string (non-fatal)
 *   .onDone()            — stream finished
 * @returns {EventSource} — call .close() to abort early
 */
export function openLiveBrowser(url, inputText, { onStatus, onScreenshot, onResult, onError, onDone, visualOnly = false }) {
  const token = localStorage.getItem('novaguard_token')
  const params = new URLSearchParams({ url })

  // If the full text differs from the bare URL, pass it so the agent gets the context
  if (inputText && inputText.trim() !== url.trim()) {
    params.set('input', inputText.trim())
  }

  if (token) params.set('token', token)
  if (visualOnly) params.set('visual_only', 'true')

  const es = new EventSource(`/api/v1/investigate/browse?${params.toString()}`)

  es.addEventListener('status', (e) => onStatus?.(e.data))
  es.addEventListener('screenshot', (e) => onScreenshot?.(e.data))
  es.addEventListener('result', (e) => {
    try { onResult?.(JSON.parse(e.data)) } catch { /* ignore */ }
  })
  es.addEventListener('error', (e) => {
    // Non-fatal — backend now never sends a fatal "error" event, only status updates
    try { onError?.(JSON.parse(e.data)) } catch { onError?.(e.data) }
  })
  es.addEventListener('done', () => {
    onDone?.()
    es.close()
  })

  // Network-level failure
  es.onerror = () => {
    onError?.('Connection lost')
    onDone?.()
    es.close()
  }

  return es
}
