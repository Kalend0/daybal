import { useState, useEffect } from 'react'

const API_BASE = '/api'

function App() {
  const [status, setStatus] = useState('idle')
  const [message, setMessage] = useState('')
  const [accounts, setAccounts] = useState([])
  const [balances, setBalances] = useState({})

  // Check if we're returning from bank auth callback
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const code = params.get('code')
    const error = params.get('error')

    if (code) {
      handleCallback(code)
    } else if (error) {
      setStatus('error')
      setMessage(`Bank auth error: ${error}`)
    }
  }, [])

  const handleCallback = async (code) => {
    setStatus('processing')
    setMessage('Processing bank authorization...')

    try {
      const res = await fetch(`${API_BASE}/callback?code=${code}`)
      const data = await res.json()

      if (data.error) {
        setStatus('error')
        setMessage(data.detail || 'Failed to complete authorization')
      } else {
        setStatus('connected')
        setMessage('Bank connected successfully!')
        setAccounts(data.accounts || [])
        // Clear URL params
        window.history.replaceState({}, '', '/')
      }
    } catch (err) {
      setStatus('error')
      setMessage(err.message)
    }
  }

  const startBankAuth = async () => {
    setStatus('loading')
    setMessage('Starting bank authorization...')

    try {
      const res = await fetch(`${API_BASE}/start-auth`)
      const data = await res.json()

      if (data.error) {
        setStatus('error')
        setMessage(`API Error (${data.status}): ${data.detail}`)
      } else if (data.auth_url) {
        setMessage('Redirecting to bank...')
        window.location.href = data.auth_url
      } else {
        setStatus('error')
        setMessage('No auth URL received')
      }
    } catch (err) {
      setStatus('error')
      setMessage(err.message)
    }
  }

  const fetchBalance = async (accountId) => {
    try {
      const res = await fetch(`${API_BASE}/balance/${accountId}`)
      const data = await res.json()

      if (data.error) {
        setBalances(prev => ({ ...prev, [accountId]: { error: data.detail } }))
      } else {
        setBalances(prev => ({ ...prev, [accountId]: data }))
      }
    } catch (err) {
      setBalances(prev => ({ ...prev, [accountId]: { error: err.message } }))
    }
  }

  return (
    <div style={{ maxWidth: 500, margin: '0 auto' }}>
      <h1 style={{ marginBottom: 20 }}>DayBal</h1>
      <p style={{ color: '#888', marginBottom: 30 }}>Bank Connection Test</p>

      {status === 'idle' && (
        <button
          onClick={startBankAuth}
          style={{
            background: '#4a90d9',
            color: 'white',
            border: 'none',
            padding: '16px 32px',
            fontSize: 18,
            borderRadius: 8,
            cursor: 'pointer',
            width: '100%'
          }}
        >
          Connect ABN AMRO
        </button>
      )}

      {status === 'loading' && (
        <div style={{ textAlign: 'center', padding: 20 }}>
          <p>{message}</p>
        </div>
      )}

      {status === 'processing' && (
        <div style={{ textAlign: 'center', padding: 20 }}>
          <p>{message}</p>
        </div>
      )}

      {status === 'error' && (
        <div style={{ background: '#4a1a1a', padding: 20, borderRadius: 8 }}>
          <p style={{ color: '#ff6b6b', marginBottom: 15 }}>{message}</p>
          <button
            onClick={() => { setStatus('idle'); setMessage(''); }}
            style={{
              background: '#333',
              color: 'white',
              border: 'none',
              padding: '12px 24px',
              borderRadius: 6,
              cursor: 'pointer'
            }}
          >
            Try Again
          </button>
        </div>
      )}

      {status === 'connected' && (
        <div>
          <div style={{ background: '#1a4a1a', padding: 15, borderRadius: 8, marginBottom: 20 }}>
            <p style={{ color: '#6bff6b' }}>{message}</p>
          </div>

          <h3 style={{ marginBottom: 15 }}>Linked Accounts</h3>
          {accounts.length === 0 ? (
            <p style={{ color: '#888' }}>No accounts found</p>
          ) : (
            accounts.map((account, idx) => (
              <div
                key={account.account_id || idx}
                style={{
                  background: '#2a2a4e',
                  padding: 15,
                  borderRadius: 8,
                  marginBottom: 10
                }}
              >
                <p><strong>Account:</strong> {account.account_id || account.iban || 'N/A'}</p>
                <button
                  onClick={() => fetchBalance(account.account_id)}
                  style={{
                    background: '#4a90d9',
                    color: 'white',
                    border: 'none',
                    padding: '8px 16px',
                    borderRadius: 4,
                    cursor: 'pointer',
                    marginTop: 10
                  }}
                >
                  Fetch Balance
                </button>

                {balances[account.account_id] && (
                  <div style={{ marginTop: 10, padding: 10, background: '#1a1a2e', borderRadius: 4 }}>
                    {balances[account.account_id].error ? (
                      <p style={{ color: '#ff6b6b' }}>{balances[account.account_id].error}</p>
                    ) : (
                      <pre style={{ fontSize: 12, overflow: 'auto' }}>
                        {JSON.stringify(balances[account.account_id], null, 2)}
                      </pre>
                    )}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}

      <div style={{ marginTop: 40, padding: 15, background: '#2a2a3e', borderRadius: 8 }}>
        <p style={{ fontSize: 12, color: '#666' }}>
          Debug: Status = {status}
        </p>
      </div>
    </div>
  )
}

export default App
