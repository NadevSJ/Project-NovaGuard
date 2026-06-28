import { LogOut, History, Shield, LayoutDashboard, QrCode } from 'lucide-react'
import { Link, NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

export default function Navbar() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  const handleLogout = () => {
    logout()
    navigate('/')
  }

  const linkClass = ({ isActive }) =>
    `flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors duration-200 ${
      isActive
        ? 'text-nova-orange bg-nova-orange/10'
        : 'text-nova-muted hover:text-nova-light hover:bg-nova-slate'
    }`

  return (
    <nav className="sticky top-0 z-50 bg-nova-dark/90 backdrop-blur-md border-b border-nova-border">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <Link to="/" className="flex items-center gap-3">
            <img src="/favicon.png" alt="NovaGuard Shield" className="h-8 w-8 object-contain" />
            <span className="font-bold text-lg tracking-tight">
              <span className="text-nova-light">NOVA</span>
              <span className="text-nova-orange">guard</span>
            </span>
          </Link>

          {/* Nav links */}
          {user && (
            <div className="flex items-center gap-1">
              <NavLink to="/dashboard" className={linkClass}>
                <LayoutDashboard size={16} />
                <span className="hidden sm:inline">Dashboard</span>
              </NavLink>
              <NavLink to="/history" className={linkClass}>
                <History size={16} />
                <span className="hidden sm:inline">History</span>
              </NavLink>
              <NavLink to="/qr" className={linkClass}>
                <QrCode size={16} />
                <span className="hidden sm:inline">QR Scan</span>
              </NavLink>
              <NavLink to="/shield" className={linkClass}>
                <Shield size={16} />
                <span className="hidden sm:inline">Shield</span>
              </NavLink>
            </div>
          )}

          {/* User menu */}
          <div className="flex items-center gap-3">
            {user ? (
              <>
                <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-nova-slate border border-nova-border">
                  <div className="h-6 w-6 rounded-full bg-nova-orange/20 flex items-center justify-center">
                    <span className="text-nova-orange text-xs font-bold">
                      {user.username?.[0]?.toUpperCase() || 'U'}
                    </span>
                  </div>
                  <span className="text-sm text-nova-light font-medium">{user.username}</span>
                </div>
                <button
                  onClick={handleLogout}
                  className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium
                             text-nova-muted hover:text-red-400 hover:bg-red-500/10 transition-all duration-200"
                >
                  <LogOut size={16} />
                  <span className="hidden sm:inline">Sign out</span>
                </button>
              </>
            ) : (
              <>
                <Link to="/login" className="btn-ghost text-sm">
                  Sign in
                </Link>
                <Link to="/register" className="btn-primary text-sm px-4 py-2">
                  Get Started
                </Link>
              </>
            )}
          </div>
        </div>
      </div>
    </nav>
  )
}
