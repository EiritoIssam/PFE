/**
 * dashboard.js — Main application logic
 *
 * Handles: file listing, upload, download, share, private key management.
 * All crypto operations delegate to crypto.js (Web Crypto API).
 */

// ── Auth guard ───────────────────────────────────────────────────
if (!API.isLoggedIn()) window.location.href = '/';

// ── State ────────────────────────────────────────────────────────
let privateKey = null;       // CryptoKey (in-memory only)
let allFiles   = [];
let allUsers   = [];
let currentFileId = null;    // for share modal

// ── Init ─────────────────────────────────────────────────────────
const user = API.getUser();
document.getElementById('sidebarUsername').textContent = user.username;
document.getElementById('userAvatar').textContent = user.username[0].toUpperCase();

loadFiles();
loadUsers();

// ================================================================
// Toast helper
// ================================================================
function toast(message, type = 'info') {
  const icons = {
    success: `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>`,
    error:   `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`,
    info:    `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
  };
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `${icons[type] || icons.info}<span>${message}</span>`;
  document.getElementById('toastContainer').appendChild(el);
  setTimeout(() => el.remove(), 3200);
}

// ================================================================
// Navigation
// ================================================================
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', e => {
    e.preventDefault();
    document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
    item.classList.add('active');
    const section = item.dataset.section;
    showSection(section);
    document.getElementById('pageTitle').textContent = item.textContent.trim();
  });
});

function showSection(name) {
  const map = { myFiles: 'sectionMyFiles', sharedWithMe: 'sectionSharedWithMe', upload: 'sectionUpload' };
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.getElementById(map[name])?.classList.add('active');
}

document.getElementById('logoutBtn').addEventListener('click', API.logout);

// ================================================================
// Private Key Management
// ================================================================
document.getElementById('loadPrivateKeyBtn').addEventListener('click', () => {
  document.getElementById('loadKeyModal').classList.remove('hidden');
});
document.getElementById('cancelLoadKeyBtn').addEventListener('click', () => {
  document.getElementById('loadKeyModal').classList.add('hidden');
});
document.getElementById('confirmLoadKeyBtn').addEventListener('click', loadPrivateKeyFromModal);

document.getElementById('importKeyFile').addEventListener('change', async e => {
  const file = e.target.files[0];
  if (!file) return;
  const text = await file.text();
  document.getElementById('pastePrivateKey').value = text.trim();
});

async function loadPrivateKeyFromModal() {
  const pem = document.getElementById('pastePrivateKey').value.trim();
  const errEl = document.getElementById('loadKeyError');
  errEl.classList.add('hidden');

  if (!pem) {
    errEl.textContent = 'Veuillez coller ou importer votre clé privée.';
    errEl.classList.remove('hidden');
    return;
  }

  try {
    privateKey = await Crypto.importPrivateKey(pem);
    document.getElementById('keyStatus').innerHTML =
      `<span class="dot green"></span> Clé chargée`;
    document.getElementById('loadKeyModal').classList.add('hidden');
    document.getElementById('pastePrivateKey').value = '';
    toast('Clé privée chargée avec succès', 'success');
  } catch (err) {
    errEl.textContent = 'Clé invalide : ' + err.message;
    errEl.classList.remove('hidden');
  }
}

// ================================================================
// File listing
// ================================================================
async function loadFiles() {
  try {
    allFiles = await API.listFiles();
    renderMyFiles();
    renderSharedFiles();
  } catch (err) {
    toast('Erreur lors du chargement des fichiers', 'error');
  }
}

document.getElementById('refreshFilesBtn').addEventListener('click', loadFiles);

function getFileIcon(filename, mime) {
  const ext = filename.split('.').pop().toLowerCase();
  const images = ['jpg','jpeg','png','gif','webp','svg'];
  const code   = ['js','py','html','css','json','ts','jsx','php','c','cpp'];
  const zips   = ['zip','rar','7z','tar','gz'];
  const pdfs   = ['pdf'];

  if (images.includes(ext) || mime?.startsWith('image/')) return {
    cls: 'img',
    svg: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>`
  };
  if (pdfs.includes(ext)) return {
    cls: 'pdf',
    svg: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/></svg>`
  };
  if (code.includes(ext)) return {
    cls: 'code',
    svg: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>`
  };
  if (zips.includes(ext)) return {
    cls: 'zip',
    svg: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>`
  };
  return {
    cls: '',
    svg: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>`
  };
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} Ko`;
  return `${(bytes / 1048576).toFixed(1)} Mo`;
}

function formatDate(dt) {
  return new Date(dt).toLocaleDateString('fr-FR', { day: '2-digit', month: 'short', year: 'numeric' });
}

function buildFileCard(f) {
  const icon = getFileIcon(f.filename, f.mimetype);
  const isOwner = f.is_owner === 1 || f.is_owner === true;
  const card = document.createElement('div');
  card.className = 'file-card';
  card.innerHTML = `
    <div class="file-card-icon ${icon.cls}">${icon.svg}</div>
    <div class="file-card-info">
      <div class="file-name">${escHtml(f.filename)}</div>
      <div class="file-meta">
        <span>${formatSize(f.file_size)}</span>
        <span>·</span>
        <span>${formatDate(f.uploaded_at)}</span>
        <span>·</span>
        <span class="badge ${isOwner ? 'owner' : 'shared'}">${isOwner ? 'Propriétaire' : 'Partagé'}</span>
      </div>
      ${!isOwner ? `<div class="file-meta" style="margin-top:2px">Par ${escHtml(f.owner_name)}</div>` : ''}
    </div>
    <div class="file-card-actions">
      <button class="action-btn download" data-id="${f.id}" data-name="${escHtml(f.filename)}" data-mime="${f.mimetype}">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        Télécharger
      </button>
      ${isOwner ? `
      <button class="action-btn share" data-id="${f.id}" data-name="${escHtml(f.filename)}">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
      </button>
      <button class="action-btn delete" data-id="${f.id}">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>
      </button>` : ''}
    </div>
  `;

  card.querySelector('.action-btn.download').addEventListener('click', () =>
    handleDownload(f.id, f.filename, f.mimetype));

  if (isOwner) {
    card.querySelector('.action-btn.share').addEventListener('click', () =>
      openShareModal(f.id, f.filename));
    card.querySelector('.action-btn.delete').addEventListener('click', () =>
      handleDelete(f.id));
  }

  return card;
}

function renderMyFiles() {
  const grid = document.getElementById('myFilesGrid');
  const mine = allFiles.filter(f => f.is_owner === 1 || f.is_owner === true);
  grid.innerHTML = '';
  if (!mine.length) {
    grid.innerHTML = `<div class="empty-state">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
      <h3>Aucun fichier</h3>
      <p>Utilisez l'onglet "Envoyer" pour chiffrer et partager vos fichiers.</p>
    </div>`;
    return;
  }
  mine.forEach(f => grid.appendChild(buildFileCard(f)));
}

function renderSharedFiles() {
  const grid = document.getElementById('sharedFilesGrid');
  const shared = allFiles.filter(f => !(f.is_owner === 1 || f.is_owner === true));
  grid.innerHTML = '';
  if (!shared.length) {
    grid.innerHTML = `<div class="empty-state">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/></svg>
      <h3>Aucun fichier partagé</h3>
      <p>Les fichiers que d'autres utilisateurs partagent avec vous apparaîtront ici.</p>
    </div>`;
    return;
  }
  shared.forEach(f => grid.appendChild(buildFileCard(f)));
}

// ================================================================
// Download & Decrypt
// ================================================================
async function handleDownload(fileId, filename, mimetype) {
  if (!privateKey) {
    toast('Chargez votre clé privée pour déchiffrer les fichiers', 'error');
    document.getElementById('loadKeyModal').classList.remove('hidden');
    return;
  }
  try {
    toast('Téléchargement en cours…', 'info');
    const [keyData, blobData] = await Promise.all([
      API.getFileKey(fileId),
      API.downloadBlob(fileId),
    ]);
    const decrypted = await Crypto.decryptFileWithPrivateKey(
      blobData.encrypted_file,
      blobData.nonce,
      keyData.encrypted_aes_key,
      privateKey,
    );
    Crypto.triggerDownload(decrypted, filename, mimetype);
    toast(`"${filename}" déchiffré et téléchargé`, 'success');
  } catch (err) {
    console.error(err);
    toast('Erreur de déchiffrement : ' + (err.message || err), 'error');
  }
}

// ================================================================
// Delete
// ================================================================
async function handleDelete(fileId) {
  if (!confirm('Supprimer ce fichier définitivement ?')) return;
  try {
    await API.deleteFile(fileId);
    toast('Fichier supprimé', 'success');
    loadFiles();
  } catch (err) {
    toast(err.message, 'error');
  }
}

// ================================================================
// Share Modal
// ================================================================
function openShareModal(fileId, filename) {
  currentFileId = fileId;
  document.getElementById('shareModalFilename').textContent = `Fichier : ${filename}`;
  document.getElementById('shareError').classList.add('hidden');

  const select = document.getElementById('shareUserSelect');
  select.innerHTML = allUsers.map(u => `<option value="${u.id}">${u.username}</option>`).join('');

  // Pre-fill private key if loaded
  document.getElementById('sharePrivateKey').value = '';
  document.getElementById('shareModal').classList.remove('hidden');
}

document.getElementById('cancelShareBtn').addEventListener('click', () => {
  document.getElementById('shareModal').classList.add('hidden');
});

document.getElementById('confirmShareBtn').addEventListener('click', async () => {
  const recipientId = parseInt(document.getElementById('shareUserSelect').value);
  const pkPem = document.getElementById('sharePrivateKey').value.trim();
  const errEl = document.getElementById('shareError');
  errEl.classList.add('hidden');

  if (!pkPem) {
    errEl.textContent = 'Veuillez entrer votre clé privée pour ré-encapsuler la clé AES.';
    errEl.classList.remove('hidden');
    return;
  }

  try {
    const ownerPrivKey = await Crypto.importPrivateKey(pkPem);

    // Get owner's encrypted AES key
    const keyData = await API.getFileKey(currentFileId);

    // Get recipient's public key
    const recipientData = await API.getUserPublicKey(recipientId);

    // Re-wrap AES key for recipient
    const newEncKey = await Crypto.reWrapKeyForRecipient(
      keyData.encrypted_aes_key,
      ownerPrivKey,
      recipientData.public_key,
    );

    await API.shareFile(currentFileId, recipientId, newEncKey);
    document.getElementById('shareModal').classList.add('hidden');
    toast(`Fichier partagé avec ${recipientData.username}`, 'success');
  } catch (err) {
    errEl.textContent = err.message || 'Erreur lors du partage';
    errEl.classList.remove('hidden');
  }
});

// ================================================================
// Upload
// ================================================================
async function loadUsers() {
  try {
    allUsers = await API.getUsers();
    renderRecipients();
  } catch (_) {}
}

function renderRecipients() {
  const list = document.getElementById('recipientsList');
  list.innerHTML = '';
  if (!allUsers.length) {
    list.innerHTML = `<div style="padding:10px;color:var(--text-muted);font-size:12px">Aucun autre utilisateur trouvé.</div>`;
    return;
  }
  allUsers.forEach(u => {
    const item = document.createElement('div');
    item.className = 'recipient-item';
    item.innerHTML = `
      <input type="checkbox" id="rec_${u.id}" value="${u.id}" />
      <label for="rec_${u.id}">${escHtml(u.username)}</label>
    `;
    list.appendChild(item);
  });
}

let selectedFile = null;

const dropZone   = document.getElementById('dropZone');
const fileInput  = document.getElementById('fileInput');

dropZone.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => setSelectedFile(fileInput.files[0]));

dropZone.addEventListener('dragover',  e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  setSelectedFile(e.dataTransfer.files[0]);
});

document.getElementById('clearFileBtn').addEventListener('click', () => {
  selectedFile = null;
  fileInput.value = '';
  document.getElementById('selectedFile').classList.add('hidden');
  dropZone.style.display = '';
  document.getElementById('uploadBtn').disabled = true;
});

function setSelectedFile(file) {
  if (!file) return;
  selectedFile = file;
  document.getElementById('selectedName').textContent = file.name;
  document.getElementById('selectedSize').textContent = formatSize(file.size);
  document.getElementById('selectedFile').classList.remove('hidden');
  dropZone.style.display = 'none';
  document.getElementById('uploadBtn').disabled = false;
}

document.getElementById('uploadBtn').addEventListener('click', handleUpload);

async function handleUpload() {
  if (!selectedFile) return;

  const errEl  = document.getElementById('uploadError');
  const succEl = document.getElementById('uploadSuccess');
  errEl.classList.add('hidden');
  succEl.classList.add('hidden');

  // Get selected recipients
  const checked = [...document.querySelectorAll('#recipientsList input[type="checkbox"]:checked')];
  const recipientIds = checked.map(c => parseInt(c.value));

  // Collect all recipients' public keys (+ owner)
  const currentUser = API.getUser();
  const allRecipientIds = [currentUser.id, ...recipientIds];

  // Progress UI
  const progWrap = document.getElementById('uploadProgress');
  const progFill = document.getElementById('progressFill');
  const progText = document.getElementById('progressText');
  const progPct  = document.getElementById('progressPct');
  progWrap.classList.remove('hidden');

  const setProgress = (pct, label) => {
    progFill.style.width = pct + '%';
    progText.textContent = label;
    progPct.textContent  = pct + '%';
  };

  try {
    setProgress(10, 'Récupération des clés publiques…');

    // Fetch public keys for all recipients
    const pubKeyPromises = allRecipientIds.map(id => API.getUserPublicKey(id));
    const pubKeyResults  = await Promise.all(pubKeyPromises);

    setProgress(30, 'Chiffrement AES-256-GCM…');

    // Encrypt file + wrap keys
    const payload = await Crypto.encryptFileForRecipients(selectedFile, pubKeyResults);

    setProgress(60, 'Envoi au serveur…');

    // Build FormData
    const fd = new FormData();
    // Attach the encrypted file as a blob with original filename
    const encBlob = new Blob([payload.encrypted_file], { type: 'text/plain' });
    const encFile = new File([encBlob], selectedFile.name, { type: selectedFile.type || 'application/octet-stream' });
    fd.append('file', encFile);
    fd.append('recipients', JSON.stringify(allRecipientIds));

    // We need to also send the nonce and per-user wrapped keys.
    // We'll encode them as a JSON field.
    fd.append('nonce', payload.nonce);
    fd.append('wrapped_keys', JSON.stringify(payload.wrappedKeys));

    setProgress(80, 'Sauvegarde sécurisée…');

    const token = API.getToken();
    const res = await fetch('/api/files/upload', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}` },
      body: fd,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || 'Upload failed');

    setProgress(100, 'Terminé !');
    succEl.textContent = `Fichier "${selectedFile.name}" chiffré et envoyé avec succès.`;
    succEl.classList.remove('hidden');
    toast(`"${selectedFile.name}" partagé avec ${data.recipients} destinataire(s)`, 'success');

    setTimeout(() => {
      progWrap.classList.add('hidden');
      document.getElementById('clearFileBtn').click();
      succEl.classList.add('hidden');
      loadFiles();
    }, 1500);

  } catch (err) {
    console.error(err);
    errEl.textContent = err.message || 'Erreur lors de l\'envoi';
    errEl.classList.remove('hidden');
    progWrap.classList.add('hidden');
    toast(err.message, 'error');
  }
}

// ================================================================
// Helpers
// ================================================================
function escHtml(str) {
  const d = document.createElement('div');
  d.appendChild(document.createTextNode(str));
  return d.innerHTML;
}
