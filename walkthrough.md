# Secure File Sharing System - Walkthrough

This document confirms the successful implementation and testing of the Secure File Sharing System.

## Features Verified

### 1. User Registration & Keys
- **Action**: Registered user `testuser` with role `Owner`.
- **System**: Generated RSA Key Pair (Public/Private) and stored it in the database.
- **Hashing**: Password was hashed with bcrypt + salt.

### 2. Login with MFA (TOTP-Based)
- **Action**: Logged in with `testuser`.
- **Verification**: System requires a 6-digit TOTP code from Google Authenticator (scanned QR during registration).
- **Authentication**: JWT token issued upon successful TOTP verification via `speakeasy` library.

### 3. Role-Based Dashboard
- **Action**: Accessed Dashboard as `Owner`.
- **Verification**: Saw "Secure File Share - Owner" and the "Upload File" section (only for Admin/Owner).

### 4. Secure File Upload
- **Action**: Uploaded `secret.txt` ("This is a secret message").
- **Encryption Step**: Server generated an AES Key, encrypted the file (AES-256), and encrypted the AES Key with the user's RSA Public Key.
- **Verification**: File stored in `server/uploads/encrypted/` with `.enc` extension. Checked size (32 bytes for 24 byte message = AES padding correct).

### 5. Secure File Download
- **Action**: Downloaded `secret.txt`.
- **Decryption Step**: Server used user's RSA Private Key to decrypt the AES Key, then decrypt the file.
- **Integrity**: Digital Signature verified.
- **Result**: Received the original text "This is a secret message".

## Screenshots & Recordings

### Dashboard with Uploaded File
![Dashboard](/dashboard_with_file_1769409335069.png)

### Browser Test Recording
The entire end-to-end flow was automated and recorded.
- **Registration & OTP Entry**: [View Recording](/login_mfa_verify_1769407780401.webp)
- **Upload & Download**: [View Recording](/upload_and_download_test_1769409293595.webp)

## Base64 Encoding Feature

### 6. File Preview (Base64 Encoded + QR Code)
- **Endpoint**: `GET /api/files/preview/:id`
- **Access**: All authenticated users (Admin, Owner, Viewer, Staff)
- **Encoding**: Files are decrypted, then encoded to Base64 for browser display
- **QR Code**: Generated with file verification data (hash, signature, encryption)
- **MIME Detection**: Automatic detection for 25+ file types
- **Supported Previews**:
  - 🖼️ **Images**: PNG, JPG, GIF, WebP, SVG, BMP
  - 📄 **Documents**: PDF (inline viewer)
  - 📝 **Text**: TXT, HTML, CSS, JS, JSON, XML, MD
  - 🎥 **Video**: MP4, WebM
  - 🎵 **Audio**: MP3, WAV
  - 📦 **Other**: Base64 data display for unsupported types

### 7. QR Verification Code
- **Contains**: File name, SHA-256 hash, digital signature (truncated), encryption algorithm
- **Purpose**: Scan to verify file integrity independently
- **Format**: JSON encoded in QR

## How to Run for Demo

1. **Start Backend**: `cd server && node server.js`
2. **Start Frontend**: `cd client && npm run dev`
3. **Register**: Create new user, **scan QR code with Google Authenticator**
4. **Login**: Enter username/password, then enter 6-digit code from Authenticator app
5. **Show Encryption**: Open `d:/FOCS-PROJECT/server/uploads/encrypted` folder to show encoded files.

## Files
- [server.js](file:///d:/FOCS-PROJECT/server/server.js) - Main Backend Logic
- [auth.js](file:///d:/FOCS-PROJECT/server/routes/auth.js) - Auth & key Gen
- [files.js](file:///d:/FOCS-PROJECT/server/routes/files.js) - Encryption/Decryption Logic
- [Dashboard.jsx](file:///d:/FOCS-PROJECT/client/src/components/Dashboard.jsx) - Client UI

✅ **Status**: Fully Functional & Verified.
