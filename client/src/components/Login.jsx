import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate, Link } from 'react-router-dom';

function Login({ setToken }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [otp, setOtp] = useState('');
  const [step, setStep] = useState(1); // 1: Login, 2: MFA
  const [mfaToken, setMfaToken] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const res = await axios.post('http://localhost:5000/api/auth/login', { username, password });
      setMfaToken(res.data.mfaToken);
      setStep(2);
    } catch (err) {
      setError(err.response?.data?.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const handleMfa = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const res = await axios.post('http://localhost:5000/api/auth/verify-mfa', { mfaToken, otp });
      setToken(res.data.token, res.data.role);
      navigate('/dashboard');
    } catch (err) {
      setError(err.response?.data?.message || 'MFA verification failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        {/* Logo / Brand */}
        <div className="text-center mb-6">
          <div style={{ 
            width: '48px', 
            height: '48px', 
            margin: '0 auto 1rem',
            backgroundColor: 'hsl(0 0% 98%)',
            borderRadius: '12px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="hsl(240 10% 10%)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
          </div>
          <h2>{step === 1 ? 'Welcome back' : 'Two-factor authentication'}</h2>
          <p className="subtitle">
            {step === 1 
              ? 'Enter your credentials to access your account' 
              : 'Enter the verification code from your authenticator app'}
          </p>
        </div>

        {/* Error Message */}
        {error && (
          <div style={{
            padding: '0.75rem 1rem',
            marginBottom: '1rem',
            backgroundColor: 'hsl(0 62.8% 15%)',
            border: '1px solid hsl(0 62.8% 25%)',
            borderRadius: '0.5rem',
            color: 'hsl(0 62.8% 70%)',
            fontSize: '0.875rem'
          }}>
            {error}
          </div>
        )}

        {step === 1 ? (
          <form onSubmit={handleLogin}>
            <div className="form-group">
              <label className="form-label">Username</label>
              <input 
                type="text" 
                className="form-input"
                value={username} 
                onChange={(e) => setUsername(e.target.value)} 
                required 
                placeholder="Enter your username"
                autoComplete="username"
              />
            </div>
            <div className="form-group">
              <label className="form-label">Password</label>
              <input 
                type="password" 
                className="form-input"
                value={password} 
                onChange={(e) => setPassword(e.target.value)} 
                required 
                placeholder="Enter your password"
                autoComplete="current-password"
              />
            </div>
            <button 
              type="submit" 
              className="btn btn-primary btn-full mt-4"
              disabled={loading}
            >
              {loading ? (
                <>
                  <span className="spinner" style={{ width: '1rem', height: '1rem' }}></span>
                  Signing in...
                </>
              ) : 'Sign in'}
            </button>
          </form>
        ) : (
          <>
            <form onSubmit={handleMfa}>
              <div className="form-group">
                <label className="form-label">Verification Code</label>
                <input 
                  type="text" 
                  className="form-input"
                  value={otp} 
                  onChange={(e) => setOtp(e.target.value)} 
                  required 
                  placeholder="Enter 6-digit code"
                  maxLength="6"
                  pattern="[0-9]*"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  style={{ 
                    letterSpacing: '0.5em', 
                    textAlign: 'center',
                    fontSize: '1.25rem',
                    fontWeight: '600'
                  }}
                />
              </div>
              <button 
                type="submit" 
                className="btn btn-primary btn-full mt-4"
                disabled={loading}
              >
                {loading ? (
                  <>
                    <span className="spinner" style={{ width: '1rem', height: '1rem' }}></span>
                    Verifying...
                  </>
                ) : 'Verify'}
              </button>
            </form>
            
             <button 
                type="button" 
                className="btn btn-ghost btn-full mt-2"
                onClick={() => { 
                  setStep(1); 
                  setError('');
                  setOtp('');
                  setMfaToken('');
                }}
              >
                Back to login
              </button>
           </>
        )}

        <p className="auth-link">
          Don't have an account? <Link to="/register">Create account</Link>
        </p>
      </div>
    </div>
  );
}

export default Login;
