// src/components/Modal.jsx
import { useEffect } from 'react'

export default function Modal({ title, children, onClose }) {
  useEffect(() => {
    const handler = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose])

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <div className="modal-title">
          <span>{title}</span>
          <span className="close-btn" onClick={onClose}>✕</span>
        </div>
        {children}
      </div>
    </div>
  )
}
