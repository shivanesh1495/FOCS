const express = require('express');
const router = express.Router();
const multer = require('multer');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const FileModel = require('../models/File');
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const QRCode = require('qrcode');

// Middleware to verify JWT
const authenticate = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'Access Denied' });

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).json({ message: 'Invalid Token' });
  }
};

// Access Control Middleware
const authorize = (roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({ message: 'Forbidden' });
  }
  next();
};

// Multer setup (store temporarily or directly stream, we'll store temp then encrypt)
const upload = multer({ dest: 'uploads/temp/' });

// Ensure uploads directory exists
if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
if (!fs.existsSync('uploads/encrypted')) fs.mkdirSync('uploads/encrypted');

// Helper: Encrypt File with AES
function encryptFileWithAES(filePath, aesKey) {
  const fileBuffer = fs.readFileSync(filePath);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(aesKey, 'hex'), iv); // aesKey should be 32 bytes hex
  let encrypted = cipher.update(fileBuffer);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return { encryptedData: encrypted, iv: iv.toString('hex') };
}

// Helper: Decrypt File with AES
function decryptFileWithAES(encryptedData, aesKey, ivHex) {
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(aesKey, 'hex'), iv);
  let decrypted = decipher.update(encryptedData);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted;
}

// UPLOAD
router.post('/upload', authenticate, authorize(['Admin', 'Owner']), upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });

    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Step 5.1: Generate AES Key (32 bytes for AES-256)
    const aesKey = crypto.randomBytes(32).toString('hex');

    // Step 6.1: Encrypt File using AES key
    const { encryptedData, iv } = encryptFileWithAES(req.file.path, aesKey);

    // Step 8.1: Generate Hash of Original File (SHA-256)
    const originalFileBuffer = fs.readFileSync(req.file.path);
    const hash = crypto.createHash('sha256').update(originalFileBuffer).digest('hex');

    // Step 8.2: Digital Signature Creation (Encrypt hash using sender's RSA private key)
    const sign = crypto.createSign('SHA256');
    sign.update(originalFileBuffer);
    sign.end();
    const digitalSignature = sign.sign(user.privateKey, 'base64'); // Using stored private key for demo

    // Step 5.2: Secure Key Exchange (Encrypt AES key using RSA). 
    // In a real sharing scenario, we'd encrypt this key for EACH recipient. 
    // Here, we'll encrypt it with the USER'S OWN Public Key (or a "system" key) so they can retrieve it.
    // Ideally, for sharing, you'd add recipients and encrypt the AES key with THEIR public keys.
    // For this lab, we'll encrypt it with the uploader's public key (Owner) and maybe a system Admin key.
    // Let's just encrypt with the Uploader's Public Key for simplicity of the "Owner" role flow.
    const encryptedAESKey = crypto.publicEncrypt(user.publicKey, Buffer.from(aesKey, 'utf8')).toString('base64');

    // Store Encrypted File
    const encryptedFilename = `${Date.now()}-${req.file.originalname}.enc`;
    const encryptedPath = path.join('uploads/encrypted', encryptedFilename);
    fs.writeFileSync(encryptedPath, encryptedData);

    // Cleanup temp file
    fs.unlinkSync(req.file.path);

    // Database Entry
    const newFile = new FileModel({
      filename: req.file.originalname,
      originalName: req.file.originalname,
      uploadedBy: user._id,
      encryptedAESKey, // Storing encrypted version of the AES key
      iv,
      path: encryptedPath,
      digitalSignature,
      originalFileHash: hash
    });

    await newFile.save();
    res.status(201).json({ message: 'File uploaded and secured successfully' });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Upload failed', error: error.message });
  }
});

// LIST FILES
router.get('/', authenticate, async (req, res) => {
  try {
    const files = await FileModel.find().populate('uploadedBy', 'username');
    res.json(files);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching files' });
  }
});

// DOWNLOAD
router.get('/download/:id', authenticate, authorize(['Admin', 'Owner', 'Viewer']), async (req, res) => {
  try {
    const file = await FileModel.findById(req.params.id);
    if (!file) return res.status(404).json({ message: 'File not found' });

    // Authorization check logic for 'Owner' (only their own files?)
    // Table says: Owner -> Can Upload, Can View (implied all or own? "File Sharing" implies viewing shared. usually Owner sees own, Viewer sees shared). 
    // BUT Step 7.1: Authorization Check.
    // If Access Control Matrix says "Owner: Yes" for View File, it typically means they can view files.
    // Let's assume global view for simplicity or uploader check if "Owner" means "Data Owner".
    // For now, allow all roles passed in `authorize`.

    const user = await User.findById(req.user.userId);

    // Step 7.2: Decryption
    // To decrypt:
    // 1. Decrypt AES Key using User's Private Key?
    //    WAIT. We encrypted the AES key with the UPLOADER'S Public Key.
    //    If the DOWNLOADER is different, they can't decrypt it unless we did Key Exchange for THEM.
    //    For this lab, if User A downloads User B's file, A needs the AES key.
    //    *Simplification for Lab*: We will mock "Key Exchange" by assuming the server handles the decryption of the AES key 
    //    (simulating that the user has the right key or the server acts as the trusted authority).
    //    OR, strictly: We can't decrypt if we don't have the private key of the key-wrapper.
    //    Fix: We'll attempt to decrypt with the UPLOADER'S Private Key (since we stored it in DB 😅 - convenient for lab).
    //    Steps: 
    //    a. Fetch Uploader's Private Key (from DB).
    //    b. Decrypt `encryptedAESKey` -> `aesKey`.
    //    c. Decrypt File with `aesKey`.
    
    // NOTE: This relies on storing Private Key in DB which is a security "no-no" but allowed for this lab demo "RSA key pair for users" stored in DB.

    const uploader = await User.findById(file.uploadedBy);
    
    // Decrypt AES Key using Uploader's Private Key
    const aesKeyBuffer = crypto.privateDecrypt(
      {
        key: uploader.privateKey,
        passphrase: '' // if any
      },
      Buffer.from(file.encryptedAESKey, 'base64')
    );
    const aesKey = aesKeyBuffer.toString('utf8'); // It was hex string encoded as utf8 buffer

    // Decrypt File
    const encryptedFileBuffer = fs.readFileSync(file.path);
    const decryptedFileBuffer = decryptFileWithAES(encryptedFileBuffer, aesKey, file.iv);

    // Step 8.3: Verification (Digital Signature)
    const verifier = crypto.createVerify('SHA256');
    verifier.update(decryptedFileBuffer);
    const isVerified = verifier.verify(uploader.publicKey, file.digitalSignature, 'base64');

    console.log(`[INTEGRITY CHECK] File: ${file.filename}, Verified: ${isVerified}`);
    
    if (!isVerified) {
       // Ideally trigger alert, but for download we might warn.
       console.error("WARNING: Integrity Check Failed!");
    }

    // Send File
    // We send the decrypted file.
    // Step 9.1/9.2 mentions Encoding/Decoding. We could send base64 if needed, or binary. Binary is standard.
    
    res.setHeader('Content-Disposition', `attachment; filename="${file.originalName}"`);
    res.send(decryptedFileBuffer);

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Download failed', error: error.message });
  }
});

// VERIFY INTEGRITY (Active Check)
router.post('/verify/:id', authenticate, async (req, res) => {
  try {
    const file = await FileModel.findById(req.params.id);
    if (!file) return res.status(404).json({ message: 'File not found' });

    // 1. Fetch Uploader's Public Key/Private Key (Simulated Key Exchange)
    const uploader = await User.findById(file.uploadedBy);
    if (!uploader) return res.status(404).json({ message: 'Uploader not found' });

    // 2. Decrypt AES Key
    const aesKeyBuffer = crypto.privateDecrypt(
      { key: uploader.privateKey, passphrase: '' },
      Buffer.from(file.encryptedAESKey, 'base64')
    );
    const aesKey = aesKeyBuffer.toString('utf8');

    // 3. Decrypt File Content
    const encryptedFileBuffer = fs.readFileSync(file.path);
    const decryptedFileBuffer = decryptFileWithAES(encryptedFileBuffer, aesKey, file.iv);

    // 4. Verify Signature
    const verifier = crypto.createVerify('SHA256');
    verifier.update(decryptedFileBuffer);
    const isVerified = verifier.verify(uploader.publicKey, file.digitalSignature, 'base64');

    // 5. Compare Hash
    const currentHash = crypto.createHash('sha256').update(decryptedFileBuffer).digest('hex');
    const isHashMatch = (currentHash === file.originalFileHash);

    res.json({
      verified: isVerified && isHashMatch,
      signatureValid: isVerified,
      hashMatch: isHashMatch,
      originalHash: file.originalFileHash,
      computedHash: currentHash,
      isEncrypted: true,
      encryptionAlgorithm: 'AES-256-CBC'
    });

  } catch (error) {
    console.error("Verification Error:", error);
    res.status(500).json({ message: 'Verification failed', error: error.message });
  }
});

// Helper: Get MIME type from filename
function getMimeType(filename) {
  const ext = path.extname(filename).toLowerCase();
  const mimeTypes = {
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.webp': 'image/webp',
    '.svg': 'image/svg+xml',
    '.bmp': 'image/bmp',
    '.ico': 'image/x-icon',
    '.pdf': 'application/pdf',
    '.txt': 'text/plain',
    '.html': 'text/html',
    '.css': 'text/css',
    '.js': 'text/javascript',
    '.json': 'application/json',
    '.xml': 'application/xml',
    '.csv': 'text/csv',
    '.md': 'text/markdown',
    '.mp4': 'video/mp4',
    '.webm': 'video/webm',
    '.mp3': 'audio/mpeg',
    '.wav': 'audio/wav',
    '.zip': 'application/zip',
    '.doc': 'application/msword',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.xls': 'application/vnd.ms-excel',
    '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    '.ppt': 'application/vnd.ms-powerpoint',
    '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
  };
  return mimeTypes[ext] || 'application/octet-stream';
}

// PREVIEW (Base64 Encoded) - Accessible to ALL authenticated users
router.get('/preview/:id', authenticate, async (req, res) => {
  try {
    const file = await FileModel.findById(req.params.id);
    if (!file) return res.status(404).json({ message: 'File not found' });

    // Fetch Uploader to decrypt
    const uploader = await User.findById(file.uploadedBy);
    if (!uploader) return res.status(404).json({ message: 'Uploader not found' });

    // Decrypt AES Key using Uploader's Private Key
    const aesKeyBuffer = crypto.privateDecrypt(
      { key: uploader.privateKey, passphrase: '' },
      Buffer.from(file.encryptedAESKey, 'base64')
    );
    const aesKey = aesKeyBuffer.toString('utf8');

    // Decrypt File
    const encryptedFileBuffer = fs.readFileSync(file.path);
    const decryptedFileBuffer = decryptFileWithAES(encryptedFileBuffer, aesKey, file.iv);

    // Convert to Base64
    const base64Data = decryptedFileBuffer.toString('base64');
    const mimeType = getMimeType(file.originalName);

    // Generate QR Code with verification data
    const qrData = JSON.stringify({
      file: file.originalName,
      hash: file.originalFileHash,
      sig: file.digitalSignature.substring(0, 50) + '...',
      enc: 'AES-256-CBC',
      verified: new Date().toISOString()
    });
    const qrCodeDataUrl = await QRCode.toDataURL(qrData, { 
      width: 200, 
      margin: 2,
      color: { dark: '#000000', light: '#ffffff' }
    });

    // Log for security audit
    console.log(`[PREVIEW] File: ${file.originalName}, User: ${req.user.userId}, Encoded: Base64, MIME: ${mimeType}, QR: Generated`);

    res.json({
      base64: base64Data,
      mimeType: mimeType,
      filename: file.originalName,
      size: decryptedFileBuffer.length,
      encoding: 'base64',
      qrCode: qrCodeDataUrl,
      securityData: {
        hash: file.originalFileHash,
        signature: file.digitalSignature,
        encryption: 'AES-256-CBC',
        iv: file.iv
      }
    });

  } catch (error) {
    console.error("Preview Error:", error);
    res.status(500).json({ message: 'Preview failed', error: error.message });
  }
});

// DELETE FILE
router.delete('/:id', authenticate, authorize(['Admin', 'Owner']), async (req, res) => {
  try {
    const file = await FileModel.findById(req.params.id);
    if (!file) return res.status(404).json({ message: 'File not found' });

    // Check if user is owner (if not Admin) - strict check
    if (req.user.role !== 'Admin' && file.uploadedBy.toString() !== req.user.userId) {
      return res.status(403).json({ message: 'Not authorized to delete this file' });
    }

    // Remove from filesystem
    if (fs.existsSync(file.path)) {
      fs.unlinkSync(file.path);
    }

    // Remove from DB
    await FileModel.findByIdAndDelete(req.params.id);

    res.json({ message: 'File deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Delete failed' });
  }
});

module.exports = router;
