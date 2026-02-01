import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate, Link } from 'react-router-dom';

function Register() {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('Viewer');
  const [qrCode, setQrCode] = useState(null); // URL for QR image
  const [secret, setSecret] = useState(null); // Base32 secret text
  const navigate = useNavigate();

  const handleRegister = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post('http://localhost:5000/api/auth/register', { username, email, password, role });
      
      // Instead of navigating immediately, show the QR Code
      setQrCode(res.data.qrCodeUrl);
      setSecret(res.data.secret);
      alert('Registration Successful! Please scan the QR Code.');
      
    } catch (err) {
      alert(err.response?.data?.message || 'Registration failed');
    }
  };

  if (qrCode) {
    return (
      <div style={{ maxWidth: '400px', margin: '50px auto', padding: '20px', border: '1px solid #ccc', borderRadius: '5px', textAlign: 'center' }}>
        <h2>Setup Authenticator</h2>
        <p>Scan this QR code with Google Authenticator or Authy:</p>
        <img src={qrCode} alt="MFA QR Code" style={{ width: '200px', height: '200px' }} />
        <p>Or enter this code manually: <strong>{secret}</strong></p>
        <button 
          onClick={() => navigate('/login')} 
          style={{ width: '100%', padding: '10px', marginTop: '20px', backgroundColor: '#007bff', color: 'white', border: 'none' }}
        >
          I have scanned it, Go to Login
        </button>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: '400px', margin: '50px auto', padding: '20px', border: '1px solid #ccc', borderRadius: '5px' }}>
      <h2>Register</h2>
      <form onSubmit={handleRegister}>
        <div style={{ marginBottom: '10px' }}>
          <label>Username</label>
          <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} required style={{ width: '100%' }} />
        </div>
        <div style={{ marginBottom: '10px' }}>
          <label>Email</label>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required style={{ width: '100%' }} />
        </div>
        <div style={{ marginBottom: '10px' }}>
          <label>Password</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required style={{ width: '100%' }} />
        </div>
        <div style={{ marginBottom: '10px' }}>
          <label>Role</label>
          <select value={role} onChange={(e) => setRole(e.target.value)} style={{ width: '100%' }}>
            <option value="Viewer">Viewer</option>
            <option value="Owner">Owner</option>
            <option value="Admin">Admin</option>
          </select>
        </div>
        <button type="submit" style={{ width: '100%', padding: '10px' }}>Register</button>
      </form>
      <p>Already have an account? <Link to="/login">Login</Link></p>
    </div>
  );
}

export default Register;
