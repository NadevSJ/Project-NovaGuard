export default function Spinner({ size = 'md', className = '' }) {
  const sizes = { sm: 'h-4 w-4', md: 'h-8 w-8', lg: 'h-12 w-12' }
  return (
    <div className={`${sizes[size]} ${className}`}>
      <div className="h-full w-full rounded-full border-2 border-nova-border border-t-nova-orange animate-spin" />
    </div>
  )
}
