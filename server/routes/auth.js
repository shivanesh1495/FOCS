const express = require('express');
const router = express.Router();
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

// Helper to generate RSA Keys
function generateRSAKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { publicKey, privateKey };
}

// REGISTER
router.post('/register', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    // Check existing user
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    // Step 2.2: Password Hashing with Salt
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Step 5.1: Key Generation (RSA)
    const { publicKey, privateKey } = generateRSAKeys();

    // NEW: Generate TOTP Secret
    const secret = speakeasy.generateSecret({ length: 20, name: `SecureFileShare (${email})` });

    // NEW: Generate QR Code
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      salt: salt, 
      role: role || 'Viewer',
      publicKey,
      privateKey,
      mfaSecret: secret // Store the secret object
    });

    await newUser.save();
    
    // Send back the QR Code so the user can scan it
    res.status(201).json({ 
      message: 'User registered successfully.', 
      qrCodeUrl, // Frontend should display this
      secret: secret.base32 // Optional: show manual entry code
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
});

// LOGIN (Step 1 of MFA)
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Step 3.1: Username & Password Verification
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ message: 'Invalid Credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid Credentials' });

    // Step 3.2: MFA - Request Authenticator Code
    // We do NOT generate a random OTP anymore. 
    // We just tell the client "Password good, now give me the Code from your App".
    
    // We sign a temporary token so we know WHO is trying to verify.
    const mfaToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '5m' });

    res.json({ message: 'Please enter code from Authenticator App', mfaToken }); 

  } catch (error) {
    res.status(500).json({ message: 'Server Error', error: error.message });
  }
});

// VERIFY MFA (Step 2 of MFA)
router.post('/verify-mfa', async (req, res) => {
  try {
    const { mfaToken, otp } = req.body;
    if (!mfaToken || !otp) return res.status(400).json({ message: 'Missing Data' });

    let decoded;
    try {
      decoded = jwt.verify(mfaToken, process.env.JWT_SECRET);
    } catch(e) {
      return res.status(401).json({ message: 'Session expired. Login again.' });
    }

    const user = await User.findById(decoded.userId);
    if (!user) return res.status(404).json({ message: 'User not found' });
    
    // Verify TOTP
    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret.base32,
      encoding: 'base32',
      token: otp,
      window: 1 // Allow 30sec slack
    });

    if (!verified) {
      return res.status(400).json({ message: 'Invalid Authenticator Code' });
    }

    // Generate Final Session JWT
    const token = jwt.sign(
      { userId: user._id, role: user.role, username: user.username }, 
      process.env.JWT_SECRET, 
      { expiresIn: '1h' }
    );

    res.json({ token, role: user.role, username: user.username });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Verification failed', error: error.message });
  }
});

module.exports = router;
