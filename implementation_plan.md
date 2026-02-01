# Secure File Sharing System Implementation Plan

This plan follows the user's specific workflow for the "Secure File Sharing System" lab project.

## Project Structure
- `server/`: Node.js + Express Backend
- `client/`: React Frontend

## User Review Required
- **Database**: Ensure MongoDB is running locally or provide a connection string. I will assume a local instance at `mongodb://localhost:27017/secure-file-share` for now.
- **MFA**: Will be simulated via console logs as permitted in the requirements.

## Proposed Changes

### Backend (`/server`)

#### Dependencies
- `express`: Web server framework
- `mongoose`: MongoDB ODM
- `bcryptjs`: Password hashing
- `jsonwebtoken`: Authentication
- `multer`: File handling
- `crypto`: Built-in Node.js module for AES/RSA/Hashing
- `cors`, `dotenv`: Utilities
- `speakeasy`: TOTP generation and verification
- `qrcode`: QR code generation

#### [NEW] [server.js](file:///d:/FOCS-PROJECT/server/server.js)
- Main entry point.
- Connect to MongoDB.
- Middleware setup (CORS, JSON).

#### [MODIFY] [models/User.js](file:///d:/FOCS-PROJECT/server/models/User.js)
- Schema: username, email, password (hashed), salt, role, public_key, encrypted_private_key.
- **Add**: `mfaSecret` (Object with ascii, hex, base32, otpauth_url).

#### [NEW] [models/File.js](file:///d:/FOCS-PROJECT/server/models/File.js)
- Schema: filename, owner_id, encrypted_aes_key, file_path, digital_signature, original_file_hash, iv (initialization vector).

#### [MODIFY] [routes/auth.js](file:///d:/FOCS-PROJECT/server/routes/auth.js)
- `POST /register`: Hash password, generate RSA keys, **generate TOTP secret**, **generate QR code**, store user. Return QR code.
- `POST /login`: Verify password. **(No longer send OTP)**.
- `POST /verify-mfa`: Validate OTP using **speakeasy**.

#### [NEW] [routes/files.js](file:///d:/FOCS-PROJECT/server/routes/files.js)
- `POST /upload`: Auth check (Admin/Owner). Generate AES key, encrypt file, encrypt AES key with user's Public Key. Sign file hash. Store.
- `GET /download/:id`: Auth check (Admin/Owner/Viewer). Decrypt AES key with user's Private Key, Decrypt file.

### Frontend (`/client`)

#### Dependencies
- `react`, `react-router-dom`: UI & Routing
- `axios`: API calls

#### [NEW] [src/App.js](file:///d:/FOCS-PROJECT/client/src/App.js)
- Routing for Login, Register, Dashboard.

#### [NEW] [src/components/Register.js](file:///d:/FOCS-PROJECT/client/src/components/Register.js)
- Form: Username, Email, Password, Role.

#### [NEW] [src/components/Login.js](file:///d:/FOCS-PROJECT/client/src/components/Login.js)
- Username/Password form.
- OTP entry form.

#### [NEW] [src/components/Dashboard.js](file:///d:/FOCS-PROJECT/client/src/components/Dashboard.js)
- List files.
- Upload button (Admin/Owner).
- Download button (permissions based).
- Delete button (Admin).

## Verification Plan

### Automated Tests
- I will run the server and client.
- I will perform a full flow test:
    1. Register User A (Owner).
    2. Register User B (Viewer).
    3. User A uploads file.
    4. User B logs in and downloads file.
    5. Check server logs for Encryption/Decryption steps.

### Manual Verification
- Verify the "Audit Logs" or console outputs show the step-by-step security operations (Hashing, Salt, Key Gen, etc.) as required for the Viva explanation.
