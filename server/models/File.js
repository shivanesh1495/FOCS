const mongoose = require('mongoose');

const FileSchema = new mongoose.Schema({
  filename: { type: String, required: true },
  originalName: { type: String, required: true }, // To restore name
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  encryptedAESKey: { type: String, required: true }, // Encrypted with Server/Admin Key for storage
  iv: { type: String, required: true }, // Hex string
  path: { type: String, required: true }, // Path to encrypted file on disk
  digitalSignature: { type: String, required: true }, // Signed hash of the original file
  originalFileHash: { type: String, required: true }, // SHA-256 hash of original file
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('File', FileSchema);
