import { Link } from 'react-router-dom'
import { Home } from 'lucide-react'

export default function NotFound() {
  return (
    <div className="min-h-[70vh] flex flex-col items-center justify-center text-center px-4">
      <p className="text-8xl font-black text-nova-orange mb-4">404</p>
      <h1 className="text-2xl font-bold text-nova-light mb-2">Page not found</h1>
      <p className="text-nova-muted mb-8 max-w-sm">
        The page you're looking for doesn't exist or has been moved.
      </p>
      <Link to="/" className="btn-primary flex items-center gap-2">
        <Home size={16} /> Back to Home
      </Link>
    </div>
  )
}
