import React, { useState, useEffect } from 'react';
import axios from 'axios';

function Dashboard({ token, role, logout }) {
  const [files, setFiles] = useState([]);
  const [selectedFile, setSelectedFile] = useState(null);
  const [showSecurityModal, setShowSecurityModal] = useState(false);
  const [fileToVerify, setFileToVerify] = useState(null);
  const [verificationStatus, setVerificationStatus] = useState(null);
  const [verificationResult, setVerificationResult] = useState(null);
  const [verificationError, setVerificationError] = useState(null);
  const [showPreviewModal, setShowPreviewModal] = useState(false);
  const [previewData, setPreviewData] = useState(null);
  const [previewError, setPreviewError] = useState(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [uploading, setUploading] = useState(false);

  const fetchFiles = async () => {
    try {
      const res = await axios.get('http://localhost:5000/api/files', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setFiles(res.data);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchFiles();
    const interval = setInterval(() => fetchFiles(), 3000);
    return () => clearInterval(interval);
  }, []);

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!selectedFile) return;

    const formData = new FormData();
    formData.append('file', selectedFile);
    setUploading(true);

    try {
      await axios.post('http://localhost:5000/api/files/upload', formData, {
        headers: { 
          'Content-Type': 'multipart/form-data',
          Authorization: `Bearer ${token}` 
        }
      });
      setSelectedFile(null);
      // Reset file input
      const fileInput = document.getElementById('file-upload');
      if (fileInput) fileInput.value = '';
      fetchFiles();
    } catch (err) {
      alert('Upload Failed: ' + (err.response?.data?.message || err.message));
    } finally {
      setUploading(false);
    }
  };

  const handleDownload = async (fileId, fileName) => {
    try {
      const res = await axios.get(`http://localhost:5000/api/files/download/${fileId}`, {
        headers: { Authorization: `Bearer ${token}` },
        responseType: 'blob'
      });

      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', fileName);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      alert('Download Failed: ' + (err.response?.data?.message || err.message));
    }
  };

  const handleDelete = async (fileId) => {
    if (!window.confirm('Are you sure you want to delete this file? This action cannot be undone.')) return;

    try {
      await axios.delete(`http://localhost:5000/api/files/${fileId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      fetchFiles();
    } catch (err) {
      alert('Delete Failed: ' + (err.response?.data?.message || err.message));
    }
  };

  const openSecurityModal = (file) => {
    setFileToVerify(file);
    setVerificationStatus(null);
    setVerificationResult(null);
    setVerificationError(null);
    setShowSecurityModal(true);
  };

  const closeSecurityModal = () => {
    setShowSecurityModal(false);
    setFileToVerify(null);
  };

  const verifyIntegrity = async () => {
    if (!fileToVerify) return;
    setVerificationStatus('verifying');
    try {
      const res = await axios.post(`http://localhost:5000/api/files/verify/${fileToVerify._id}`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setVerificationResult(res.data);
      setVerificationStatus('verified');
    } catch (err) {
      console.error(err);
      setVerificationStatus('failed');
      setVerificationError(err.response?.data?.message || 'Verification request failed. The server might be compromised or unreachable.');
    }
  };

  const handlePreview = async (fileId) => {
    setPreviewLoading(true);
    setShowPreviewModal(true);
    setPreviewData(null);
    try {
      const res = await axios.get(`http://localhost:5000/api/files/preview/${fileId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setPreviewData(res.data);
    } catch (err) {
      console.error(err);
      setPreviewError(err.response?.data?.message || 'Failed to generate preview. The file might be corrupted or deleted.');
    } finally {
      setPreviewLoading(false);
    }
  };

  const closePreviewModal = () => {
    setShowPreviewModal(false);
    setPreviewData(null);
  };

  const renderPreviewContent = () => {
    if (!previewData) return null;
    const { base64, mimeType, filename } = previewData;
    const dataUrl = `data:${mimeType};base64,${base64}`;

    if (mimeType.startsWith('image/')) {
      return <img src={dataUrl} alt={filename} style={{ maxWidth: '100%', maxHeight: '60vh', display: 'block', margin: '0 auto' }} />;
    }
    if (mimeType === 'application/pdf') {
      return <iframe src={dataUrl} title={filename} style={{ width: '100%', height: '60vh', border: 'none' }} />;
    }
    if (mimeType.startsWith('text/') || mimeType === 'application/json') {
      const textContent = atob(base64);
      return <pre className="preview-content">{textContent}</pre>;
    }
    if (mimeType.startsWith('video/')) {
      return <video src={dataUrl} controls style={{ maxWidth: '100%', maxHeight: '60vh', display: 'block', margin: '0 auto' }} />;
    }
    if (mimeType.startsWith('audio/')) {
      return <audio src={dataUrl} controls style={{ width: '100%' }} />;
    }
    return (
      <div className="text-center p-6">
        <p className="text-muted">Preview not available for this file type ({mimeType})</p>
      </div>
    );
  };

  return (
    <div className="dashboard-container">
      {/* Navbar */}
      <nav className="navbar">
        <div className="navbar-brand">
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/>
            <polyline points="13 2 13 9 20 9"/>
          </svg>
          <h1>Secure File Share</h1>
          <span className="badge">{role}</span>
        </div>
        <div className="navbar-actions">
          <button onClick={logout} className="btn btn-outline btn-sm">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
              <polyline points="16 17 21 12 16 7"/>
              <line x1="21" y1="12" x2="9" y2="12"/>
            </svg>
            Logout
          </button>
        </div>
      </nav>

      <main style={{ padding: '1.5rem' }}>
        {/* Upload Section */}
        {(role === 'Admin' || role === 'Owner') && (
          <div className="upload-card">
            <h3>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ marginRight: '0.5rem', verticalAlign: 'middle' }}>
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                <polyline points="17 8 12 3 7 8"/>
                <line x1="12" y1="3" x2="12" y2="15"/>
              </svg>
              Upload File
            </h3>
            <form onSubmit={handleUpload} className="upload-form">
              <div className="file-input-wrapper">
                <input 
                  id="file-upload"
                  type="file" 
                  className="file-input"
                  onChange={(e) => setSelectedFile(e.target.files[0])} 
                />
              </div>
              <button 
                type="submit" 
                className="btn btn-primary"
                disabled={!selectedFile || uploading}
              >
                {uploading ? (
                  <>
                    <span className="spinner" style={{ width: '1rem', height: '1rem' }}></span>
                    Encrypting...
                  </>
                ) : (
                  <>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <polyline points="17 8 12 3 7 8"/>
                      <line x1="12" y1="3" x2="12" y2="15"/>
                    </svg>
                    Upload
                  </>
                )}
              </button>
            </form>
          </div>
        )}

        {/* Files Table */}
        <div style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <h2 style={{ fontSize: '1.25rem', fontWeight: '600' }}>Files</h2>
          <span className="badge">{files.length} items</span>
        </div>

        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Filename</th>
                <th>Uploaded By</th>
                <th>Security</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {files.length === 0 ? (
                <tr>
                  <td colSpan="4">
                    <div className="empty-state">
                      <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round" style={{ margin: '0 auto 1rem', opacity: 0.5 }}>
                        <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/>
                        <polyline points="13 2 13 9 20 9"/>
                      </svg>
                      <p>No files uploaded yet</p>
                    </div>
                  </td>
                </tr>
              ) : (
                files.map(file => (
                  <tr key={file._id}>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ opacity: 0.5 }}>
                          <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/>
                          <polyline points="13 2 13 9 20 9"/>
                        </svg>
                        <span style={{ fontWeight: '500' }}>{file.originalName}</span>
                      </div>
                    </td>
                    <td>
                      <span className="text-muted">{file.uploadedBy?.username || 'Unknown'}</span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                        <code className="text-xs font-mono" style={{ color: 'hsl(142 76% 50%)' }}>
                          Sig: {file.digitalSignature?.substring(0, 12)}...
                        </code>
                        <code className="text-xs font-mono" style={{ color: 'hsl(38 92% 50%)' }}>
                          Hash: {file.originalFileHash?.substring(0, 12)}...
                        </code>
                        <button 
                          onClick={() => openSecurityModal(file)} 
                          className="btn btn-ghost btn-sm"
                          style={{ marginTop: '0.25rem', justifyContent: 'flex-start', padding: '0.25rem 0.5rem', height: 'auto' }}
                        >
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                          </svg>
                          View Details
                        </button>
                      </div>
                    </td>
                    <td>
                      <div className="action-buttons">
                        <button 
                          onClick={() => handlePreview(file._id)} 
                          className="btn btn-info btn-sm"
                        >
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                            <circle cx="12" cy="12" r="3"/>
                          </svg>
                          Preview
                        </button>
                        <button 
                          onClick={() => handleDownload(file._id, file.originalName)} 
                          className="btn btn-secondary btn-sm"
                        >
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                            <polyline points="7 10 12 15 17 10"/>
                            <line x1="12" y1="15" x2="12" y2="3"/>
                          </svg>
                          Download
                        </button>
                        {(role === 'Admin' || (role === 'Owner' && file.uploadedBy?._id === token.userId)) && (
                          <button 
                            onClick={() => handleDelete(file._id)} 
                            className="btn btn-destructive btn-sm"
                          >
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                              <polyline points="3 6 5 6 21 6"/>
                              <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                            </svg>
                            Delete
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </main>

      {/* Security Modal */}
      {showSecurityModal && fileToVerify && (
        <div className="modal-overlay" onClick={closeSecurityModal}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div>
                <h3 className="modal-title">Security Details</h3>
                <p className="text-sm text-muted mt-1">{fileToVerify.originalName}</p>
              </div>
              <button className="modal-close" onClick={closeSecurityModal}>×</button>
            </div>
            
            <div className="modal-body">
              <div className="security-data">
                <div className="security-item">
                  <div className="security-label">Digital Signature (RSA-SHA256)</div>
                  <div className="security-value">{fileToVerify.digitalSignature}</div>
                </div>

                <div className="security-item">
                  <div className="security-label">Original File Hash (SHA-256)</div>
                  <div className="security-value">{fileToVerify.originalFileHash}</div>
                </div>
              </div>

              <div style={{ marginTop: '1.5rem', paddingTop: '1.5rem', borderTop: '1px solid hsl(240 3.7% 15.9%)' }}>
                <h4 style={{ fontSize: '0.9rem', marginBottom: '0.75rem' }}>Integrity Verification</h4>
                <p className="text-sm text-muted mb-4">
                  Verify that the file on the server matches the original signature and hash.
                </p>

                {verificationStatus === 'failed' && (
                  <div style={{ 
                    padding: '1rem', 
                    backgroundColor: 'hsl(0 62.8% 10%)', 
                    border: '1px solid hsl(0 62.8% 25%)', 
                    borderRadius: '0.5rem',
                    marginBottom: '1rem',
                    color: 'hsl(0 62.8% 80%)'
                  }}>
                    <strong style={{ display: 'block', marginBottom: '0.25rem' }}>Error:</strong>
                    {verificationError}
                  </div>
                )}
                
                <button 
                  onClick={verifyIntegrity} 
                  disabled={verificationStatus === 'verifying'}
                  className="btn btn-primary"
                >
                  {verificationStatus === 'verifying' ? (
                    <>
                      <span className="spinner" style={{ width: '1rem', height: '1rem' }}></span>
                      Verifying...
                    </>
                  ) : (
                    <>
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                      </svg>
                      Verify Integrity
                    </>
                  )}
                </button>

                {verificationStatus === 'verified' && verificationResult && (
                  <div className={`verification-result ${verificationResult.verified ? 'verification-success' : 'verification-failed'}`}>
                    <h4>
                      {verificationResult.verified ? '✓ Verified Secure' : '✗ Verification Failed'}
                    </h4>
                    <ul className="verification-list">
                      <li>
                        <span className={verificationResult.isEncrypted ? 'check' : 'cross'}>
                          {verificationResult.isEncrypted ? '✓' : '✗'}
                        </span>
                        <strong>Confidentiality:</strong> {verificationResult.isEncrypted ? 'AES-256 Encrypted' : 'Not Encrypted'}
                      </li>
                      <li>
                        <span className={verificationResult.signatureValid ? 'check' : 'cross'}>
                          {verificationResult.signatureValid ? '✓' : '✗'}
                        </span>
                        <strong>Signature:</strong> {verificationResult.signatureValid ? 'Valid' : 'Invalid'}
                      </li>
                      <li>
                        <span className={verificationResult.hashMatch ? 'check' : 'cross'}>
                          {verificationResult.hashMatch ? '✓' : '✗'}
                        </span>
                        <strong>Hash:</strong> {verificationResult.hashMatch ? 'Match' : 'Mismatch'}
                      </li>
                      {verificationResult.encryptionAlgorithm && (
                        <li>
                          <span className="check">✓</span>
                          <strong>Algorithm:</strong> {verificationResult.encryptionAlgorithm}
                        </li>
                      )}
                    </ul>
                  </div>
                )}
              </div>
            </div>

            <div className="modal-footer">
              <button onClick={closeSecurityModal} className="btn btn-secondary">
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Preview Modal */}
      {showPreviewModal && (
        <div className="modal-overlay" onClick={closePreviewModal}>
          <div className="modal-content modal-lg" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div>
                <h3 className="modal-title">File Preview</h3>
                {previewData && <p className="text-sm text-muted mt-1">{previewData.filename}</p>}
              </div>
              <button className="modal-close" onClick={closePreviewModal}>×</button>
            </div>
            
            <div className="modal-body">
              {previewLoading ? (
                <div className="loading-overlay">
                  <div className="spinner"></div>
                  <p>Decrypting and loading preview...</p>
                </div>
              ) : previewError ? (
                <div className="empty-state">
                  <div style={{ 
                    width: '64px', 
                    height: '64px', 
                    backgroundColor: 'hsl(0 62.8% 10%)', 
                    borderRadius: '50%', 
                    display: 'flex', 
                    alignItems: 'center', 
                    justifyContent: 'center',
                    margin: '0 auto 1rem',
                    color: 'hsl(0 62.8% 60%)'
                  }}>
                     <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/>
                        <line x1="12" y1="8" x2="12" y2="12"/>
                        <line x1="12" y1="16" x2="12.01" y2="16"/>
                     </svg>
                  </div>
                  <h3 className="text-destructive mb-2">Preview Failed</h3>
                  <p className="text-muted" style={{ maxWidth: '400px', margin: '0 auto' }}>
                    {previewError}
                  </p>
                  <button onClick={closePreviewModal} className="btn btn-secondary mt-4">
                    Close Preview
                  </button>
                </div>
              ) : previewData ? (
                <>
                  {/* Info Bar */}
                  <div className="preview-info-bar">
                    <span><strong>Encoding:</strong> {previewData.encoding?.toUpperCase()}</span>
                    <span><strong>Type:</strong> {previewData.mimeType}</span>
                    <span><strong>Size:</strong> {(previewData.size / 1024).toFixed(2)} KB</span>
                  </div>

                  {/* Security Grid */}
                  <div className="preview-security-grid">
                    {/* QR Code */}
                    {previewData.qrCode && (
                      <div className="qr-section">
                        <h4>Verification QR</h4>
                        <img src={previewData.qrCode} alt="Verification QR" width="120" />
                        <p>Scan to verify integrity</p>
                      </div>
                    )}

                    {/* Security Data */}
                    <div className="security-data">
                      <div className="security-item" style={{ padding: '0.75rem' }}>
                        <div className="security-label">SHA-256 Hash</div>
                        <div className="security-value" style={{ maxHeight: '50px' }}>{previewData.securityData?.hash}</div>
                      </div>
                      <div className="security-item" style={{ padding: '0.75rem' }}>
                        <div className="security-label">Digital Signature</div>
                        <div className="security-value" style={{ maxHeight: '50px' }}>{previewData.securityData?.signature?.substring(0, 100)}...</div>
                      </div>
                      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', marginTop: '0.5rem' }}>
                        <span className="badge badge-success">
                          {previewData.securityData?.encryption}
                        </span>
                        <span className="text-xs text-muted font-mono">
                          IV: {previewData.securityData?.iv?.substring(0, 16)}...
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Content Preview */}
                  <h4 style={{ marginBottom: '0.75rem', fontSize: '0.9rem' }}>Content Preview</h4>
                  <div className="preview-content" style={{ padding: '1rem' }}>
                    {renderPreviewContent()}
                  </div>
                </>
              ) : null}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default Dashboard;
