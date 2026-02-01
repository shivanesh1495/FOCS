import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate, Link } from 'react-router-dom';

function Login({ setToken }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [otp, setOtp] = useState('');
  const [step, setStep] = useState(1); // 1: Login, 2: MFA
  const [mfaToken, setMfaToken] = useState('');
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post('http://localhost:5000/api/auth/login', { username, password });
      setMfaToken(res.data.mfaToken);
      setStep(2);
      // No alert needed, or a simple one
    } catch (err) {
      alert(err.response?.data?.message || 'Login failed');
    }
  };

  const handleMfa = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post('http://localhost:5000/api/auth/verify-mfa', { mfaToken, otp });
      setToken(res.data.token, res.data.role);
      navigate('/dashboard');
    } catch (err) {
      alert(err.response?.data?.message || 'MFA failed');
    }
  };

  return (
    <div style={{ maxWidth: '400px', margin: '50px auto', padding: '20px', border: '1px solid #ccc', borderRadius: '5px' }}>
      <h2>{step === 1 ? 'Login' : 'Authenticator Verification'}</h2>
      {step === 1 ? (
        <form onSubmit={handleLogin}>
          <div style={{ marginBottom: '10px' }}>
            <label>Username</label>
            <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} required style={{ width: '100%' }} />
          </div>
          <div style={{ marginBottom: '10px' }}>
            <label>Password</label>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required style={{ width: '100%' }} />
          </div>
          <button type="submit" style={{ width: '100%', padding: '10px' }}>Login</button>
        </form>
      ) : (
        <form onSubmit={handleMfa}>
          <div style={{ marginBottom: '10px' }}>
            <label>Enter Code from Authenticator App</label>
            <input type="text" value={otp} onChange={(e) => setOtp(e.target.value)} required style={{ width: '100%' }} placeholder="6-digit code" />
          </div>
          <button type="submit" style={{ width: '100%', padding: '10px' }}>Verify</button>
        </form>
      )}
      <p>Don't have an account? <Link to="/register">Register</Link></p>
    </div>
  );
}

export default Login;
