import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate, Link } from 'react-router-dom';

function Register() {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('Viewer');
  const [qrCode, setQrCode] = useState(null);
  const [secret, setSecret] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleRegister = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const res = await axios.post('http://localhost:5000/api/auth/register', { username, email, password, role });
      setQrCode(res.data.qrCodeUrl);
      setSecret(res.data.secret);
    } catch (err) {
      setError(err.response?.data?.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  // QR Code Setup Screen
  if (qrCode) {
    return (
      <div className="auth-container">
        <div className="auth-card" style={{ maxWidth: '450px' }}>
          <div className="text-center mb-4">
            <div style={{ 
              width: '48px', 
              height: '48px', 
              margin: '0 auto 1rem',
              backgroundColor: 'hsl(142 76% 36%)',
              borderRadius: '12px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}>
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="20 6 9 17 4 12"/>
              </svg>
            </div>
            <h2>Setup Authenticator</h2>
            <p className="subtitle">Scan the QR code with your authenticator app</p>
          </div>

          {/* QR Code Display */}
          <div style={{
            padding: '1.5rem',
            backgroundColor: 'white',
            borderRadius: '0.75rem',
            margin: '1.5rem 0',
            textAlign: 'center'
          }}>
            <img 
              src={qrCode} 
              alt="MFA QR Code" 
              style={{ 
                width: '180px', 
                height: '180px',
                borderRadius: '8px'
              }} 
            />
          </div>

          {/* Manual Entry */}
          <div style={{
            padding: '1rem',
            backgroundColor: 'hsl(240 3.7% 10%)',
            border: '1px solid hsl(240 3.7% 15.9%)',
            borderRadius: '0.5rem',
            marginBottom: '1.5rem'
          }}>
            <p style={{ 
              fontSize: '0.75rem', 
              color: 'hsl(240 5% 64.9%)', 
              marginBottom: '0.5rem' 
            }}>
              Can't scan? Enter this code manually:
            </p>
            <code style={{
              display: 'block',
              padding: '0.5rem',
              backgroundColor: 'hsl(240 10% 3.9%)',
              borderRadius: '0.25rem',
              fontSize: '0.875rem',
              fontFamily: 'monospace',
              color: 'hsl(0 0% 98%)',
              wordBreak: 'break-all',
              letterSpacing: '0.05em'
            }}>
              {secret}
            </code>
          </div>

          <button 
            onClick={() => navigate('/login')} 
            className="btn btn-primary btn-full"
          >
            I've scanned it — Continue to login
          </button>

          <p style={{ 
            fontSize: '0.75rem', 
            color: 'hsl(240 5% 50%)', 
            textAlign: 'center',
            marginTop: '1rem'
          }}>
            Use Google Authenticator, Authy, or any TOTP-compatible app
          </p>
        </div>
      </div>
    );
  }

  // Registration Form
  return (
    <div className="auth-container">
      <div className="auth-card">
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
              <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/>
              <circle cx="9" cy="7" r="4"/>
              <line x1="19" y1="8" x2="19" y2="14"/>
              <line x1="22" y1="11" x2="16" y2="11"/>
            </svg>
          </div>
          <h2>Create an account</h2>
          <p className="subtitle">Enter your details to get started</p>
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

        <form onSubmit={handleRegister}>
          <div className="form-group">
            <label className="form-label">Username</label>
            <input 
              type="text" 
              className="form-input"
              value={username} 
              onChange={(e) => setUsername(e.target.value)} 
              required 
              placeholder="Choose a username"
              autoComplete="username"
            />
          </div>

          <div className="form-group">
            <label className="form-label">Email</label>
            <input 
              type="email" 
              className="form-input"
              value={email} 
              onChange={(e) => setEmail(e.target.value)} 
              required 
              placeholder="Enter your email"
              autoComplete="email"
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
              placeholder="Create a password"
              autoComplete="new-password"
            />
          </div>

          <div className="form-group">
            <label className="form-label">Role</label>
            <select 
              className="form-select"
              value={role} 
              onChange={(e) => setRole(e.target.value)}
            >
              <option value="Viewer">Viewer</option>
              <option value="Owner">Owner</option>
              <option value="Admin">Admin</option>
            </select>
          </div>

          <button 
            type="submit" 
            className="btn btn-primary btn-full mt-4"
            disabled={loading}
          >
            {loading ? (
              <>
                <span className="spinner" style={{ width: '1rem', height: '1rem' }}></span>
                Creating account...
              </>
            ) : 'Create account'}
          </button>
        </form>

        <p className="auth-link">
          Already have an account? <Link to="/login">Sign in</Link>
        </p>
      </div>
    </div>
  );
}

export default Register;
