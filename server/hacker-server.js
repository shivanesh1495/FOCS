/**
 * HACKER SIMULATOR SERVER
 * Runs on port 5001 - Connects to same MongoDB database
 * For demonstrating security attacks (CIA Triad)
 */

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// Connect to same MongoDB database
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/secure-file-share')
  .then(() => console.log('[HACKER] Connected to target database'))
  .catch(err => console.error('DB Error:', err));

// Import models from main server
const File = require('./models/File');
const User = require('./models/User');

// Serve static hacker panel
app.use(express.static(path.join(__dirname, 'hacker-panel')));

// ==================== RECONNAISSANCE ====================

// Get all files (spy on what's available)
app.get('/api/spy/files', async (req, res) => {
  try {
    const files = await File.find().populate('uploadedBy', 'username');
    console.log('[HACKER] Spying on files list...');
    res.json(files);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get all users (spy on user data)
app.get('/api/spy/users', async (req, res) => {
  try {
    const users = await User.find().select('-password'); // Still hiding password hash
    console.log('[HACKER] Spying on user list...');
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== CONFIDENTIALITY ATTACK ====================

// View encrypted file contents (raw bytes)
app.get('/api/attack/view-encrypted/:id', async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ error: 'File not found' });

    const encryptedData = fs.readFileSync(file.path);
    
    console.log(`[HACKER] Viewing encrypted file: ${file.originalName}`);
    
    res.json({
      attack: 'CONFIDENTIALITY',
      message: 'Accessed encrypted file data - but cannot read without key!',
      filename: file.originalName,
      encryptedPath: file.path,
      encryptedSize: encryptedData.length,
      encryptedHex: encryptedData.toString('hex').substring(0, 200) + '...',
      encryptedAESKey: file.encryptedAESKey,
      iv: file.iv,
      note: 'Data is AES-256 encrypted. Key is RSA encrypted. Cannot decrypt without private key!'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== INTEGRITY ATTACK ====================

// Tamper with file hash (corrupt integrity)
app.post('/api/attack/tamper-hash/:id', async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ error: 'File not found' });

    const originalHash = file.originalFileHash;
    
    // Create a fake hash (simulating tampering)
    const tamperedHash = crypto.randomBytes(32).toString('hex');
    
    // Update the database with tampered hash
    file.originalFileHash = tamperedHash;
    await file.save();

    console.log(`[HACKER] TAMPERED hash for: ${file.originalName}`);
    
    res.json({
      attack: 'INTEGRITY',
      message: 'Successfully tampered with file hash!',
      filename: file.originalName,
      originalHash: originalHash,
      tamperedHash: tamperedHash,
      result: 'Integrity verification will now FAIL on the legitimate system!'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Tamper with digital signature
app.post('/api/attack/tamper-signature/:id', async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ error: 'File not found' });

    const originalSig = file.digitalSignature;
    
    // Create a fake signature
    const tamperedSig = crypto.randomBytes(256).toString('base64');
    
    file.digitalSignature = tamperedSig;
    await file.save();

    console.log(`[HACKER] TAMPERED signature for: ${file.originalName}`);
    
    res.json({
      attack: 'INTEGRITY',
      message: 'Successfully tampered with digital signature!',
      filename: file.originalName,
      originalSignature: originalSig.substring(0, 50) + '...',
      tamperedSignature: tamperedSig.substring(0, 50) + '...',
      result: 'Signature verification will now FAIL on the legitimate system!'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Tamper with encrypted file contents
app.post('/api/attack/tamper-file/:id', async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ error: 'File not found' });

    // Read and corrupt the encrypted file
    const originalData = fs.readFileSync(file.path);
    const tamperedData = Buffer.from(originalData);
    
    // Flip some bytes to corrupt
    for (let i = 0; i < 10; i++) {
      tamperedData[i] = tamperedData[i] ^ 0xFF;
    }
    
    fs.writeFileSync(file.path, tamperedData);

    console.log(`[HACKER] CORRUPTED file data for: ${file.originalName}`);
    
    res.json({
      attack: 'INTEGRITY',
      message: 'Successfully corrupted encrypted file data!',
      filename: file.originalName,
      bytesCorrupted: 10,
      result: 'Decryption will fail or produce garbage on the legitimate system!'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== AVAILABILITY ATTACK ====================

// Delete a file (denial of service)
app.delete('/api/attack/delete-file/:id', async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ error: 'File not found' });

    const filename = file.originalName;

    // Delete from filesystem
    if (fs.existsSync(file.path)) {
      fs.unlinkSync(file.path);
    }

    // Delete from database
    await File.findByIdAndDelete(req.params.id);

    console.log(`[HACKER] DELETED file: ${filename}`);
    
    res.json({
      attack: 'AVAILABILITY',
      message: 'Successfully deleted file!',
      filename: filename,
      result: 'File is no longer available to legitimate users!'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete encrypted file only (keep DB record - causes 404 on download)
app.delete('/api/attack/delete-encrypted/:id', async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ error: 'File not found' });

    // Delete only the encrypted file, keep DB record
    if (fs.existsSync(file.path)) {
      fs.unlinkSync(file.path);
    }

    console.log(`[HACKER] DELETED encrypted file (kept record): ${file.originalName}`);
    
    res.json({
      attack: 'AVAILABILITY',
      message: 'Deleted encrypted file but kept database record!',
      filename: file.originalName,
      result: 'File appears in list but download will fail!'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== RESTORE (for demo reset) ====================

// This would require backup - simplified version
app.post('/api/restore/hash/:id', async (req, res) => {
  try {
    const { originalHash } = req.body;
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ error: 'File not found' });

    file.originalFileHash = originalHash;
    await file.save();

    res.json({ message: 'Hash restored', hash: originalHash });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== START SERVER ====================

const PORT = 5001;
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════════╗
║           🔓 HACKER SIMULATOR PANEL 🔓                  ║
║           Running on http://localhost:${PORT}              ║
║                                                          ║
║  ⚠️  FOR EDUCATIONAL PURPOSES ONLY                      ║
║  Demonstrates CIA Triad Security Concepts                ║
╚══════════════════════════════════════════════════════════╝
  `);
});
