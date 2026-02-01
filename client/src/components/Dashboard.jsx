import React, { useState, useEffect } from 'react';
import axios from 'axios';

function Dashboard({ token, role, logout }) {
  const [files, setFiles] = useState([]);
  const [selectedFile, setSelectedFile] = useState(null);
  const [showSecurityModal, setShowSecurityModal] = useState(false);
  const [fileToVerify, setFileToVerify] = useState(null);
  const [verificationStatus, setVerificationStatus] = useState(null); // null, 'verifying', 'verified', 'failed'
  const [verificationResult, setVerificationResult] = useState(null);
  
  // Preview state
  const [showPreviewModal, setShowPreviewModal] = useState(false);
  const [previewData, setPreviewData] = useState(null);
  const [previewLoading, setPreviewLoading] = useState(false);

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
  }, []);

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!selectedFile) return;

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      await axios.post('http://localhost:5000/api/files/upload', formData, {
        headers: { 
          'Content-Type': 'multipart/form-data',
          Authorization: `Bearer ${token}` 
        }
      });
      alert('File Uploaded!');
      setSelectedFile(null);
      fetchFiles();
    } catch (err) {
      alert('Upload Failed: ' + (err.response?.data?.message || err.message));
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
      alert('File Deleted Successfully');
      fetchFiles();
    } catch (err) {
      alert('Delete Failed: ' + (err.response?.data?.message || err.message));
    }
  };

  const openSecurityModal = (file) => {
    setFileToVerify(file);
    setVerificationStatus(null);
    setVerificationResult(null);
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
      alert('Verification Request Failed');
    }
  };

  // Preview file (Base64 encoded)
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
      alert('Preview Failed: ' + (err.response?.data?.message || err.message));
      setShowPreviewModal(false);
    } finally {
      setPreviewLoading(false);
    }
  };

  const closePreviewModal = () => {
    setShowPreviewModal(false);
    setPreviewData(null);
  };

  // Render preview content based on MIME type
  const renderPreviewContent = () => {
    if (!previewData) return null;
    const { base64, mimeType, filename } = previewData;
    const dataUrl = `data:${mimeType};base64,${base64}`;

    if (mimeType.startsWith('image/')) {
      return <img src={dataUrl} alt={filename} style={{ maxWidth: '100%', maxHeight: '70vh' }} />;
    }
    if (mimeType === 'application/pdf') {
      return <iframe src={dataUrl} title={filename} style={{ width: '100%', height: '70vh', border: 'none' }} />;
    }
    if (mimeType.startsWith('text/') || mimeType === 'application/json') {
      const textContent = atob(base64);
      return (
        <pre style={{ 
          backgroundColor: '#1e1e1e', color: '#d4d4d4', padding: '15px', 
          borderRadius: '6px', overflow: 'auto', maxHeight: '70vh', whiteSpace: 'pre-wrap' 
        }}>
          {textContent}
        </pre>
      );
    }
    if (mimeType.startsWith('video/')) {
      return <video src={dataUrl} controls style={{ maxWidth: '100%', maxHeight: '70vh' }} />;
    }
    if (mimeType.startsWith('audio/')) {
      return <audio src={dataUrl} controls style={{ width: '100%' }} />;
    }
    // Fallback for unsupported types
    return (
      <div style={{ textAlign: 'center', padding: '20px' }}>
        <p>Preview not available for this file type ({mimeType})</p>
        <p><strong>Base64 Encoded Data:</strong></p>
        <textarea 
          readOnly 
          value={base64.substring(0, 500) + '...'} 
          style={{ width: '100%', height: '200px', fontFamily: 'monospace', fontSize: '0.8em' }} 
        />
      </div>
    );
  };

  return (
    <div style={{ padding: '20px' }}>
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h1>Secure File Share - {role}</h1>
        <button onClick={logout}>Logout</button>
      </header>

      {(role === 'Admin' || role === 'Owner') && (
        <div style={{ margin: '20px 0', border: '1px solid #ddd', padding: '15px' }}>
          <h3>Upload File (Encrypted)</h3>
          <form onSubmit={handleUpload}>
            <input type="file" onChange={(e) => setSelectedFile(e.target.files[0])} />
            <button type="submit" disabled={!selectedFile}>Upload</button>
          </form>
        </div>
      )}

      <h3>Files</h3>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid #ddd', textAlign: 'left' }}>
            <th>Filename</th>
            <th>Uploaded By</th>
            <th>Security Info</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {files.map(file => (
            <tr key={file._id} style={{ borderBottom: '1px solid #eee' }}>
              <td>{file.originalName}</td>
              <td>{file.uploadedBy?.username}</td>
              <td style={{ fontSize: '0.8em', fontFamily: 'monospace' }}>
                <span title={`Full Signature (Base64): ${file.digitalSignature}`}>
                  Sig: {file.digitalSignature?.substring(0, 12)}...
                </span>
                <br />
                <span title={`SHA-256 Hash: ${file.originalFileHash}`}>
                  Hash: {file.originalFileHash?.substring(0, 12)}...
                </span>
                <br/>
                <button onClick={() => openSecurityModal(file)} style={{marginTop: '5px', fontSize: '0.9em', cursor: 'pointer'}}>
                   View Security Details
                </button>
              </td>
              <td>
                <button onClick={() => handlePreview(file._id)} style={{marginRight: '5px', backgroundColor: '#17a2b8', color: 'white', border: 'none', padding: '4px 8px', borderRadius: '3px'}}>Preview</button>
                <button onClick={() => handleDownload(file._id, file.originalName)} style={{marginRight: '5px'}}>Download</button>
                {(role === 'Admin' || (role === 'Owner' && file.uploadedBy?._id === token.userId)) && ( 
                  <button onClick={() => handleDelete(file._id)} style={{backgroundColor: '#dc3545', color: 'white', border: 'none', padding: '2px 5px'}}>Delete</button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      
      {showSecurityModal && fileToVerify && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          backgroundColor: 'rgba(0,0,0,0.5)', display: 'flex', justifyContent: 'center', alignItems: 'center'
        }}>
          <div style={{
            backgroundColor: 'white', padding: '20px', borderRadius: '8px', width: '600px', maxWidth: '90%',
            maxHeight: '90vh', overflowY: 'auto'
          }}>
            <h2>Security Details: {fileToVerify.originalName}</h2>
            
            <div style={{ marginBottom: '15px' }}>
              <strong>Digital Signature (RSA-SHA256):</strong>
              <div style={{ 
                wordBreak: 'break-all', backgroundColor: '#f5f5f5', padding: '10px', 
                borderRadius: '4px', fontSize: '0.8em', fontFamily: 'monospace', maxHeight: '100px', overflowY: 'auto' 
              }}>
                {fileToVerify.digitalSignature}
              </div>
            </div>

            <div style={{ marginBottom: '15px' }}>
              <strong>Original File Hash (SHA-256):</strong>
              <div style={{ 
                wordBreak: 'break-all', backgroundColor: '#f5f5f5', padding: '10px', 
                borderRadius: '4px', fontSize: '0.9em', fontFamily: 'monospace' 
              }}>
                {fileToVerify.originalFileHash}
              </div>
            </div>

            <div style={{ borderTop: '1px solid #ddd', paddingTop: '15px', marginTop: '15px' }}>
              <h3>Integrity Verification</h3>
              <p>Click below to verify that the file on the server matches the original signature and hash.</p>
              
              <button 
                onClick={verifyIntegrity} 
                disabled={verificationStatus === 'verifying'}
                style={{
                  padding: '10px 20px', backgroundColor: '#007bff', color: 'white', 
                  border: 'none', borderRadius: '4px', cursor: 'pointer'
                }}
              >
                {verificationStatus === 'verifying' ? 'Verifying...' : 'Verify Integrity Now'}
              </button>

              {verificationStatus === 'verified' && verificationResult && (
                <div style={{ marginTop: '15px', padding: '10px', borderRadius: '4px', backgroundColor: verificationResult.verified ? '#d4edda' : '#f8d7da', color: verificationResult.verified ? '#155724' : '#721c24' }}>
                  <h4>Result: {verificationResult.verified ? 'Verified Secure' : 'Verification Failed'}</h4>
                  <ul style={{ listStyle: 'none', paddingLeft: 0 }}>
                    <li><strong>Signature Check:</strong> {verificationResult.signatureValid ? 'Valid' : 'Invalid'}</li>
                    <li><strong>Hash Check:</strong> {verificationResult.hashMatch ? 'Match' : 'Mismatch'}</li>
                    {verificationResult.isEncrypted && (
                       <li><strong>Encryption:</strong> Verified ({verificationResult.encryptionAlgorithm})</li>
                    )}
                  </ul>
                </div>
              )}
            </div>

            <div style={{ marginTop: '20px', textAlign: 'right' }}>
              <button onClick={closeSecurityModal} style={{ padding: '8px 16px' }}>Close</button>
            </div>
          </div>
        </div>
      )}

      {/* Preview Modal */}
      {showPreviewModal && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          backgroundColor: 'rgba(0,0,0,0.7)', display: 'flex', justifyContent: 'center', alignItems: 'center',
          zIndex: 1000
        }}>
          <div style={{
            backgroundColor: 'white', padding: '20px', borderRadius: '12px', width: '80%', maxWidth: '900px',
            maxHeight: '90vh', overflowY: 'auto', position: 'relative'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
              <h2 style={{ margin: 0 }}>
                File Preview {previewData && `- ${previewData.filename}`}
              </h2>
              <button 
                onClick={closePreviewModal} 
                style={{ 
                  background: 'none', border: 'none', fontSize: '24px', cursor: 'pointer', 
                  padding: '5px 10px' 
                }}
              >
                ✕
              </button>
            </div>

            {previewLoading ? (
              <div style={{ textAlign: 'center', padding: '50px' }}>
                <div style={{ fontSize: '24px', marginBottom: '10px' }}>Loading...</div>
                <p>Decrypting and encoding file...</p>
              </div>
            ) : previewData ? (
              <div>
                {/* Encoding Info Bar */}
                <div style={{ 
                  backgroundColor: '#f8f9fa', padding: '10px', borderRadius: '6px', 
                  marginBottom: '15px', fontSize: '0.85em' 
                }}>
                  <strong>Encoding:</strong> {previewData.encoding.toUpperCase()} | 
                  <strong> MIME Type:</strong> {previewData.mimeType} | 
                  <strong> Size:</strong> {(previewData.size / 1024).toFixed(2)} KB
                </div>

                {/* QR Code & Security Data Section */}
                <div style={{ 
                  display: 'flex', gap: '20px', marginBottom: '15px', 
                  flexWrap: 'wrap', backgroundColor: '#ffffff', padding: '15px', 
                  borderRadius: '8px', color: '#000', border: '1px solid #000' 
                }}>
                  {/* QR Code */}
                  <div style={{ textAlign: 'center', flex: '0 0 auto' }}>
                    <h4 style={{ margin: '0 0 10px 0', color: '#000' }}>Verification QR</h4>
                    {previewData.qrCode && (
                      <img 
                        src={previewData.qrCode} 
                        alt="Verification QR Code" 
                        style={{ borderRadius: '4px', border: '2px solid #000' }}
                      />
                    )}
                    <p style={{ fontSize: '0.75em', marginTop: '8px', color: '#333' }}>
                      Scan to verify file integrity
                    </p>
                  </div>

                  {/* Encoded Security Data */}
                  <div style={{ flex: 1, minWidth: '300px' }}>
                    <h4 style={{ margin: '0 0 10px 0', color: '#000' }}>Encoded Security Data</h4>
                    
                    <div style={{ marginBottom: '10px' }}>
                      <strong style={{ color: '#000' }}>SHA-256 Hash:</strong>
                      <div style={{ 
                        fontFamily: 'monospace', fontSize: '0.7em', backgroundColor: '#f5f5f5', 
                        padding: '8px', borderRadius: '4px', wordBreak: 'break-all', marginTop: '4px',
                        border: '1px solid #ccc', color: '#000'
                      }}>
                        {previewData.securityData?.hash}
                      </div>
                    </div>

                    <div style={{ marginBottom: '10px' }}>
                      <strong style={{ color: '#000' }}>Digital Signature (Base64):</strong>
                      <div style={{ 
                        fontFamily: 'monospace', fontSize: '0.65em', backgroundColor: '#f5f5f5', 
                        padding: '8px', borderRadius: '4px', wordBreak: 'break-all', marginTop: '4px',
                        maxHeight: '60px', overflow: 'auto', border: '1px solid #ccc', color: '#000'
                      }}>
                        {previewData.securityData?.signature}
                      </div>
                    </div>

                    <div style={{ display: 'flex', gap: '15px', fontSize: '0.8em' }}>
                      <span><strong style={{ color: '#000' }}>Encryption:</strong> {previewData.securityData?.encryption}</span>
                      <span><strong style={{ color: '#000' }}>IV:</strong> {previewData.securityData?.iv?.substring(0, 16)}...</span>
                    </div>
                  </div>
                </div>

                {/* File Preview */}
                <h4 style={{ margin: '10px 0' }}>File Content Preview</h4>
                <div style={{ border: '1px solid #ddd', borderRadius: '6px', padding: '10px', backgroundColor: '#fff' }}>
                  {renderPreviewContent()}
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
}

export default Dashboard;
