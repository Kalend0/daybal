import { useState, useEffect } from 'react'

const API_BASE = '/api'

// PIN Keypad Component
function PinKeypad({ onSubmit, error, locked, lockoutSeconds }) {
  const [pin, setPin] = useState('')
  const [countdown, setCountdown] = useState(lockoutSeconds || 0)

  useEffect(() => {
    if (countdown > 0) {
      const timer = setTimeout(() => setCountdown(countdown - 1), 1000)
      return () => clearTimeout(timer)
    }
  }, [countdown])

  useEffect(() => {
    if (lockoutSeconds) setCountdown(lockoutSeconds)
  }, [lockoutSeconds])

  const handleDigit = (digit) => {
    if (pin.length < 4 && countdown === 0) {
      const newPin = pin + digit
      setPin(newPin)
      if (newPin.length === 4) {
        onSubmit(newPin)
        setPin('')
      }
    }
  }

  const handleDelete = () => {
    setPin(pin.slice(0, -1))
  }

  const digits = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '', '0', 'DEL']

  return (
    <div style={styles.pinContainer}>
      <h1 style={styles.title}>DayBal</h1>
      <p style={styles.subtitle}>Enter PIN to continue</p>

      <div style={styles.pinDots}>
        {[0, 1, 2, 3].map(i => (
          <div
            key={i}
            style={{
              ...styles.pinDot,
              backgroundColor: i < pin.length ? '#4a90d9' : '#333'
            }}
          />
        ))}
      </div>

      {error && !locked && (
        <p style={styles.error}>{error}</p>
      )}

      {locked && countdown > 0 && (
        <p style={styles.error}>Locked. Try again in {countdown}s</p>
      )}

      <div style={styles.keypad}>
        {digits.map((digit, i) => (
          <button
            key={i}
            style={{
              ...styles.keypadButton,
              visibility: digit === '' ? 'hidden' : 'visible',
              backgroundColor: digit === 'DEL' ? '#333' : '#2a2a4e'
            }}
            onClick={() => digit === 'DEL' ? handleDelete() : handleDigit(digit)}
            disabled={countdown > 0}
          >
            {digit}
          </button>
        ))}
      </div>
    </div>
  )
}

// Balance Display Component
function BalanceDisplay({ data, onRefresh }) {
  const formatCurrency = (amount, currency = 'EUR') => {
    return new Intl.NumberFormat('nl-NL', {
      style: 'currency',
      currency: currency
    }).format(amount)
  }

  const getComparisonColor = (current, comparison) => {
    if (comparison === null) return '#888'
    return current >= comparison ? '#4ade80' : '#f87171'
  }

  return (
    <div style={styles.balanceContainer}>
      <h1 style={styles.title}>DayBal</h1>
      <p style={styles.date}>
        {new Date().toLocaleDateString('nl-NL', {
          weekday: 'long',
          day: 'numeric',
          month: 'long'
        })}
      </p>

      <div style={styles.currentBalance}>
        <p style={styles.balanceLabel}>Current Balance</p>
        <p style={styles.balanceAmount}>
          {formatCurrency(data.current_balance, data.currency)}
        </p>
      </div>

      <div style={styles.comparisons}>
        <div style={styles.comparisonCard}>
          <p style={styles.comparisonLabel}>12-Month Median</p>
          <p style={{
            ...styles.comparisonValue,
            color: getComparisonColor(data.current_balance, data.median_12m)
          }}>
            {data.median_12m !== null
              ? formatCurrency(data.median_12m, data.currency)
              : '—'}
          </p>
          {data.median_12m !== null && (
            <p style={{
              ...styles.comparisonDiff,
              color: getComparisonColor(data.current_balance, data.median_12m)
            }}>
              {data.current_balance >= data.median_12m ? '+' : ''}
              {formatCurrency(data.current_balance - data.median_12m, data.currency)}
            </p>
          )}
        </div>

        <div style={styles.comparisonCard}>
          <p style={styles.comparisonLabel}>24-Month Average</p>
          <p style={{
            ...styles.comparisonValue,
            color: getComparisonColor(data.current_balance, data.average_24m)
          }}>
            {data.average_24m !== null
              ? formatCurrency(data.average_24m, data.currency)
              : '—'}
          </p>
          {data.average_24m !== null && (
            <p style={{
              ...styles.comparisonDiff,
              color: getComparisonColor(data.current_balance, data.average_24m)
            }}>
              {data.current_balance >= data.average_24m ? '+' : ''}
              {formatCurrency(data.current_balance - data.average_24m, data.currency)}
            </p>
          )}
        </div>
      </div>

      {!data.historical_data_available && (
        <p style={styles.infoMessage}>
          Historical data collection in progress. Comparison values will appear once enough data is collected.
        </p>
      )}

      <button onClick={onRefresh} style={styles.refreshButton}>
        Refresh Balance
      </button>
    </div>
  )
}

// Bank Connection Component
function BankConnection({ onConnected }) {
  const [status, setStatus] = useState('idle')
  const [message, setMessage] = useState('')

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

  return (
    <div style={styles.connectionContainer}>
      <h1 style={styles.title}>DayBal</h1>
      <p style={styles.subtitle}>Connect your bank account</p>

      {status === 'idle' && (
        <button onClick={startBankAuth} style={styles.connectButton}>
          Connect ABN AMRO
        </button>
      )}

      {status === 'loading' && (
        <p style={styles.loadingText}>{message}</p>
      )}

      {status === 'error' && (
        <div style={styles.errorContainer}>
          <p style={styles.error}>{message}</p>
          <button onClick={() => setStatus('idle')} style={styles.retryButton}>
            Try Again
          </button>
        </div>
      )}
    </div>
  )
}

// Main App Component
function App() {
  const [appState, setAppState] = useState('loading') // loading, pin, connect, callback, dashboard
  const [pinError, setPinError] = useState('')
  const [pinLocked, setPinLocked] = useState(false)
  const [lockoutSeconds, setLockoutSeconds] = useState(0)
  const [balanceData, setBalanceData] = useState(null)
  const [callbackMessage, setCallbackMessage] = useState('')

  useEffect(() => {
    console.log('App mounted, checking initial state...')
    console.log('Current URL:', window.location.href)
    checkInitialState()
  }, [])

  const checkInitialState = async () => {
    const params = new URLSearchParams(window.location.search)
    const code = params.get('code')
    const error = params.get('error')

    console.log('URL params - code:', code ? 'present' : 'none', 'error:', error)

    if (code) {
      // Handle OAuth callback
      console.log('Processing OAuth callback...')
      setAppState('callback')
      setCallbackMessage('Processing bank authorization...')
      await handleCallback(code)
    } else if (error) {
      console.log('OAuth error:', error)
      setAppState('connect')
      setPinError(`Bank auth error: ${error}`)
    } else {
      console.log('No code, showing PIN screen')
      setAppState('pin')
    }
  }

  const handleCallback = async (code) => {
    try {
      console.log('Calling /api/callback...')
      const res = await fetch(`${API_BASE}/callback?code=${code}`)
      console.log('Response status:', res.status)
      const data = await res.json()
      console.log('Response data:', data)

      // Clear URL params
      window.history.replaceState({}, '', '/')

      if (data.error) {
        console.log('Callback error:', data.detail)
        setCallbackMessage(`Error: ${data.detail}`)
        setTimeout(() => setAppState('connect'), 2000)
      } else {
        // Store account_uid in localStorage for subsequent requests
        if (data.account_uids && data.account_uids.length > 0) {
          localStorage.setItem('daybal_account_uid', data.account_uids[0])
          console.log('Stored account_uid:', data.account_uids[0])
        }
        console.log('Bank connected, fetching balance...')
        setCallbackMessage('Bank connected! Loading balance...')
        // Fetch balance data
        await fetchBalanceData()
        setAppState('dashboard')
      }
    } catch (err) {
      console.error('Callback exception:', err)
      setCallbackMessage(`Error: ${err.message}`)
      setTimeout(() => setAppState('connect'), 2000)
    }
  }

  const handlePinSubmit = async (pin) => {
    try {
      const res = await fetch(`${API_BASE}/verify-pin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pin })
      })
      const data = await res.json()

      if (data.success) {
        setPinError('')
        // Check if bank is connected
        const statusRes = await fetch(`${API_BASE}/session-status`)
        const statusData = await statusRes.json()

        if (statusData.bank_connected) {
          // Store account_uid returned from DB session so fetchBalanceData can use it
          if (statusData.account_uid) {
            localStorage.setItem('daybal_account_uid', statusData.account_uid)
          }
          await fetchBalanceData()
          setAppState('dashboard')
        } else {
          setAppState('connect')
        }
      } else if (data.locked) {
        setPinLocked(true)
        setLockoutSeconds(data.remaining_seconds)
        setPinError(data.detail)
      } else {
        setPinError(`${data.detail} (${data.attempts_left} attempts left)`)
      }
    } catch (err) {
      setPinError(err.message)
    }
  }

  const fetchBalanceData = async () => {
    try {
      const accountUid = localStorage.getItem('daybal_account_uid')
      console.log('Fetching comparison data with account_uid:', accountUid)

      const url = accountUid
        ? `${API_BASE}/comparison-data?account_uid=${accountUid}`
        : `${API_BASE}/comparison-data`

      const res = await fetch(url)
      console.log('Comparison data status:', res.status)
      const data = await res.json()
      console.log('Comparison data:', data)

      if (!data.error) {
        setBalanceData(data)
        return true
      } else {
        console.error('Balance API error:', data.detail)
        setBalanceData({ error: true, detail: data.detail })
        return false
      }
    } catch (err) {
      console.error('Failed to fetch balance:', err)
      setBalanceData({ error: true, detail: err.message })
      return false
    }
  }

  const handleRefresh = async () => {
    await fetchBalanceData()
  }

  const handleBankConnected = () => {
    fetchBalanceData()
    setAppState('dashboard')
  }

  // Render based on app state
  if (appState === 'loading') {
    return (
      <div style={styles.container}>
        <p style={styles.loadingText}>Loading...</p>
      </div>
    )
  }

  if (appState === 'callback') {
    return (
      <div style={styles.container}>
        <h1 style={styles.title}>DayBal</h1>
        <p style={styles.loadingText}>{callbackMessage}</p>
      </div>
    )
  }

  if (appState === 'pin') {
    return (
      <div style={styles.container}>
        <PinKeypad
          onSubmit={handlePinSubmit}
          error={pinError}
          locked={pinLocked}
          lockoutSeconds={lockoutSeconds}
        />
      </div>
    )
  }

  if (appState === 'connect') {
    return (
      <div style={styles.container}>
        <BankConnection onConnected={handleBankConnected} />
      </div>
    )
  }

  if (appState === 'dashboard') {
    if (balanceData?.error) {
      return (
        <div style={styles.container}>
          <h1 style={styles.title}>DayBal</h1>
          <p style={styles.error}>Failed to load balance: {balanceData.detail}</p>
          <button onClick={handleRefresh} style={styles.refreshButton}>
            Retry
          </button>
        </div>
      )
    }
    if (balanceData) {
      return (
        <div style={styles.container}>
          <BalanceDisplay data={balanceData} onRefresh={handleRefresh} />
        </div>
      )
    }
    return (
      <div style={styles.container}>
        <h1 style={styles.title}>DayBal</h1>
        <p style={styles.loadingText}>Loading balance...</p>
      </div>
    )
  }

  return (
    <div style={styles.container}>
      <p style={styles.loadingText}>Loading...</p>
    </div>
  )
}

// Styles
const styles = {
  container: {
    minHeight: '100vh',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 20,
    boxSizing: 'border-box'
  },
  title: {
    fontSize: 32,
    fontWeight: 'bold',
    marginBottom: 8,
    color: '#fff'
  },
  subtitle: {
    fontSize: 16,
    color: '#888',
    marginBottom: 30
  },
  date: {
    fontSize: 14,
    color: '#888',
    marginBottom: 30,
    textTransform: 'capitalize'
  },

  // PIN Keypad
  pinContainer: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    width: '100%',
    maxWidth: 320
  },
  pinDots: {
    display: 'flex',
    gap: 16,
    marginBottom: 20
  },
  pinDot: {
    width: 16,
    height: 16,
    borderRadius: '50%',
    border: '2px solid #4a90d9'
  },
  keypad: {
    display: 'grid',
    gridTemplateColumns: 'repeat(3, 1fr)',
    gap: 12,
    width: '100%',
    maxWidth: 280
  },
  keypadButton: {
    width: '100%',
    aspectRatio: '1.5',
    minHeight: 56,
    fontSize: 24,
    fontWeight: 'bold',
    border: 'none',
    borderRadius: 12,
    color: '#fff',
    cursor: 'pointer',
    transition: 'transform 0.1s, opacity 0.1s'
  },

  // Balance Display
  balanceContainer: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    width: '100%',
    maxWidth: 400
  },
  currentBalance: {
    textAlign: 'center',
    marginBottom: 30,
    padding: 24,
    background: '#2a2a4e',
    borderRadius: 16,
    width: '100%'
  },
  balanceLabel: {
    fontSize: 14,
    color: '#888',
    marginBottom: 8
  },
  balanceAmount: {
    fontSize: 36,
    fontWeight: 'bold',
    color: '#fff'
  },
  comparisons: {
    display: 'flex',
    gap: 12,
    width: '100%',
    marginBottom: 20
  },
  comparisonCard: {
    flex: 1,
    padding: 16,
    background: '#1e1e3a',
    borderRadius: 12,
    textAlign: 'center'
  },
  comparisonLabel: {
    fontSize: 12,
    color: '#888',
    marginBottom: 8
  },
  comparisonValue: {
    fontSize: 18,
    fontWeight: 'bold'
  },
  comparisonDiff: {
    fontSize: 12,
    marginTop: 4
  },
  infoMessage: {
    fontSize: 12,
    color: '#666',
    textAlign: 'center',
    marginBottom: 20,
    padding: '0 20px'
  },
  refreshButton: {
    padding: '14px 28px',
    fontSize: 16,
    background: '#4a90d9',
    color: '#fff',
    border: 'none',
    borderRadius: 8,
    cursor: 'pointer',
    marginTop: 10
  },

  // Bank Connection
  connectionContainer: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    width: '100%',
    maxWidth: 320
  },
  connectButton: {
    padding: '16px 32px',
    fontSize: 18,
    background: '#4a90d9',
    color: '#fff',
    border: 'none',
    borderRadius: 8,
    cursor: 'pointer',
    width: '100%'
  },
  retryButton: {
    padding: '12px 24px',
    fontSize: 14,
    background: '#333',
    color: '#fff',
    border: 'none',
    borderRadius: 6,
    cursor: 'pointer',
    marginTop: 12
  },

  // Common
  error: {
    color: '#f87171',
    fontSize: 14,
    marginBottom: 16,
    textAlign: 'center'
  },
  errorContainer: {
    textAlign: 'center',
    padding: 20,
    background: '#2a1a1a',
    borderRadius: 8
  },
  loadingText: {
    color: '#888',
    fontSize: 16
  }
}

export default App
