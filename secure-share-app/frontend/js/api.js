/**
 * api.js — HTTP client for SecureShare backend
 *
 * All requests include Bearer JWT automatically.
 * Token and username are persisted in sessionStorage.
 */

const API = (() => {
  const BASE = '/api';

  // -----------------------------------------------------------------------
  // Token management
  // -----------------------------------------------------------------------

  function getToken()       { return sessionStorage.getItem('ss_token'); }
  function setToken(t)      { sessionStorage.setItem('ss_token', t); }
  function getUser()        { return JSON.parse(sessionStorage.getItem('ss_user') || 'null'); }
  function setUser(u)       { sessionStorage.setItem('ss_user', JSON.stringify(u)); }
  function clearSession()   { sessionStorage.removeItem('ss_token'); sessionStorage.removeItem('ss_user'); }
  function isLoggedIn()     { return !!getToken(); }

  // -----------------------------------------------------------------------
  // Core fetch helper
  // -----------------------------------------------------------------------

  async function request(method, path, body = null, isFormData = false) {
    const headers = {};
    const token = getToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    if (!isFormData && body) headers['Content-Type'] = 'application/json';

    const opts = { method, headers };
    if (body) opts.body = isFormData ? body : JSON.stringify(body);

    const res = await fetch(`${BASE}${path}`, opts);
    const data = await res.json().catch(() => ({}));

    if (!res.ok) throw { status: res.status, message: data.error || 'Erreur serveur' };
    return data;
  }

  const get    = (path)        => request('GET',    path);
  const post   = (path, body)  => request('POST',   path, body);
  const del    = (path)        => request('DELETE', path);
  const upload = (path, fd)    => request('POST',   path, fd, true);

  // -----------------------------------------------------------------------
  // Auth
  // -----------------------------------------------------------------------

  async function register(username, password) {
    const data = await post('/auth/register', { username, password });
    setToken(data.token);
    setUser(data.user);
    return data;
  }

  async function login(username, password) {
    const data = await post('/auth/login', { username, password });
    setToken(data.token);
    setUser(data.user);
    return data;
  }

  function logout() {
    clearSession();
    window.location.href = '/';
  }

  // -----------------------------------------------------------------------
  // Users
  // -----------------------------------------------------------------------

  const getUsers         = ()       => get('/users/');
  const getUserPublicKey = (userId) => get(`/users/${userId}/public-key`);

  // -----------------------------------------------------------------------
  // Files
  // -----------------------------------------------------------------------

  const listFiles    = ()         => get('/files/');
  const getFileKey   = (fileId)   => get(`/files/${fileId}/key`);
  const downloadBlob = (fileId)   => get(`/files/${fileId}/download`);
  const deleteFile   = (fileId)   => del(`/files/${fileId}`);

  async function uploadFile(file, encryptedPayload, recipients) {
    /**
     * encryptedPayload = { encrypted_file, nonce, wrappedKeys: { userId: b64 } }
     * recipients = [userId, ...]
     * We send one multipart request with a "virtual" encrypted file blob.
     */
    const fd = new FormData();

    // Create a Blob from the base64 ciphertext and attach as "file"
    // We encode it as JSON to also carry nonce, then the backend stores both.
    // Simpler: We POST JSON with the encrypted bytes inline.
    // Actually let's use FormData for proper file handling.

    // Encode ciphertext as a Blob (binary safe)
    const ciphertextBlob = new Blob([encryptedPayload.encrypted_file], { type: 'text/plain' });
    const virtualFile = new File([ciphertextBlob], file.name, { type: file.type || 'application/octet-stream' });
    fd.append('file', virtualFile);
    fd.append('recipients', JSON.stringify(recipients));
    fd.append('nonce', encryptedPayload.nonce);

    // We need to also include wrapped keys for recipients.
    // Extend the backend to accept nonce as a form field.
    // The backend handles nonce from form field.
    return upload('/files/upload-v2', fd);
  }

  async function shareFile(fileId, recipientId, encryptedAESKey) {
    return post(`/files/${fileId}/share`, {
      recipient_id: recipientId,
      encrypted_aes_key: encryptedAESKey,
    });
  }

  // -----------------------------------------------------------------------
  return {
    isLoggedIn, getToken, getUser, logout,
    register, login,
    getUsers, getUserPublicKey,
    listFiles, uploadFile, getFileKey, downloadBlob, deleteFile, shareFile,
  };
})();
