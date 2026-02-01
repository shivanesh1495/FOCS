const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }, // Hashed password
  salt: { type: String, required: true }, // Stored explicitly as requested
  role: { type: String, enum: ['Admin', 'Owner', 'Viewer'], default: 'Viewer' },
  publicKey: { type: String, required: true },
  privateKey: { type: String, required: true }, // In a real app, this should be encrypted!
  mfaSecret: { type: Object, required: true } // Stores the TOTP secret (base32, etc.)
});

module.exports = mongoose.model('User', UserSchema);
