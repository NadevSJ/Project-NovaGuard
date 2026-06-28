import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

export default function ReportCard({ report }) {
  if (!report) return null

  return (
    <div className="prose prose-invert prose-sm max-w-none">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          h1: ({ children }) => (
            <h1 className="text-lg font-bold text-nova-light mt-4 mb-2 border-b border-nova-border pb-1">
              {children}
            </h1>
          ),
          h2: ({ children }) => (
            <h2 className="text-base font-semibold text-nova-light mt-3 mb-2">{children}</h2>
          ),
          h3: ({ children }) => (
            <h3 className="text-sm font-semibold text-nova-orange mt-2 mb-1">{children}</h3>
          ),
          p: ({ children }) => (
            <p className="text-sm text-nova-muted leading-relaxed mb-2">{children}</p>
          ),
          strong: ({ children }) => (
            <strong className="text-nova-light font-semibold">{children}</strong>
          ),
          li: ({ children }) => (
            <li className="text-sm text-nova-muted mb-1 ml-4 list-disc">{children}</li>
          ),
          ul: ({ children }) => <ul className="my-2 space-y-0.5">{children}</ul>,
          ol: ({ children }) => (
            <ol className="my-2 space-y-0.5 list-decimal ml-4">{children}</ol>
          ),
          code: ({ inline, children }) =>
            inline ? (
              <code className="bg-nova-border/60 text-nova-orange text-xs px-1.5 py-0.5 rounded font-mono">
                {children}
              </code>
            ) : (
              <pre className="bg-nova-black rounded-lg p-3 overflow-x-auto my-2">
                <code className="text-xs text-green-400 font-mono">{children}</code>
              </pre>
            ),
          blockquote: ({ children }) => (
            <blockquote className="border-l-2 border-nova-orange pl-4 my-2 text-nova-muted italic">
              {children}
            </blockquote>
          ),
          hr: () => <hr className="border-nova-border my-4" />,
          a: ({ href, children }) => (
            <a
              href={href}
              target="_blank"
              rel="noopener noreferrer"
              className="text-nova-orange underline hover:text-nova-orange-light"
            >
              {children}
            </a>
          ),
        }}
      >
        {report}
      </ReactMarkdown>
    </div>
  )
}
