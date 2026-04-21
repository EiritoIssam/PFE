/**
 * auth.js — Login / Register page logic
 */

// Redirect to dashboard if already logged in
if (API.isLoggedIn()) window.location.href = 'http://127.0.0.1:5000/dashboard';
// ── Tab switching ────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab, .auth-form').forEach(el => el.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(tab.dataset.tab === 'login' ? 'loginForm' : 'registerForm').classList.add('active');
  });
});

// ── Password toggle ──────────────────────────────────────────────
document.querySelectorAll('.eye-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const input = document.getElementById(btn.dataset.target);
    input.type = input.type === 'password' ? 'text' : 'password';
  });
});

// ── Password strength ────────────────────────────────────────────
document.getElementById('regPassword').addEventListener('input', function () {
  const v = this.value;
  let score = 0;
  if (v.length >= 8)  score++;
  if (v.length >= 12) score++;
  if (/[A-Z]/.test(v)) score++;
  if (/[0-9]/.test(v)) score++;
  if (/[^A-Za-z0-9]/.test(v)) score++;

  const fill = document.getElementById('strengthFill');
  const text = document.getElementById('strengthText');
  const colors = ['#ef4444', '#f59e0b', '#f59e0b', '#10b981', '#10b981'];
  const labels = ['Très faible', 'Faible', 'Moyen', 'Fort', 'Très fort'];
  fill.style.width = `${(score / 5) * 100}%`;
  fill.style.background = colors[score - 1] || '#475569';
  text.textContent = v ? labels[score - 1] || '' : '';
  text.style.color = colors[score - 1] || 'var(--text-muted)';
});

// ── Login ────────────────────────────────────────────────────────
document.getElementById('loginForm').addEventListener('submit', async e => {
  e.preventDefault();
  const btn = document.getElementById('loginBtn');
  const err = document.getElementById('loginError');
  err.classList.add('hidden');
  btn.querySelector('.btn-text').classList.add('hidden');
  btn.querySelector('.btn-loader').classList.remove('hidden');
  btn.disabled = true;

  try {
    await API.login(
      document.getElementById('loginUsername').value.trim(),
      document.getElementById('loginPassword').value,
    );
    window.location.href = 'http://127.0.0.1:5000/dashboard';
  } catch (ex) {
    err.textContent = ex.message || 'Connexion échouée';
    err.classList.remove('hidden');
  } finally {
    btn.querySelector('.btn-text').classList.remove('hidden');
    btn.querySelector('.btn-loader').classList.add('hidden');
    btn.disabled = false;
  }
});

// ── Register ─────────────────────────────────────────────────────
document.getElementById('registerForm').addEventListener('submit', async e => {
  e.preventDefault();
  const btn = document.getElementById('registerBtn');
  const err = document.getElementById('registerError');
  err.classList.add('hidden');

  const username = document.getElementById('regUsername').value.trim();
  const password = document.getElementById('regPassword').value;
  const confirm  = document.getElementById('regConfirm').value;

  if (password !== confirm) {
    err.textContent = 'Les mots de passe ne correspondent pas.';
    err.classList.remove('hidden');
    return;
  }

  btn.querySelector('.btn-text').classList.add('hidden');
  btn.querySelector('.btn-loader').classList.remove('hidden');
  btn.disabled = true;

  try {
    const data = await API.register(username, password);

    // Show private key modal
    document.getElementById('privateKeyDisplay').textContent = data.private_key;
    document.getElementById('keyModal').classList.remove('hidden');

    // Download button
    document.getElementById('downloadKeyBtn').onclick = () => {
      const blob = new Blob([data.private_key], { type: 'text/plain' });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href = url;
      a.download = `${username}_private_key.pem`;
      a.click();
      URL.revokeObjectURL(url);
    };

    // Copy button
    document.getElementById('copyKeyBtn').onclick = async () => {
      await navigator.clipboard.writeText(data.private_key);
      document.getElementById('copyKeyBtn').textContent = '✓ Copié !';
      setTimeout(() => {
        document.getElementById('copyKeyBtn').innerHTML =
          `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg> Copier`;
      }, 2000);
    };

    document.getElementById('modalContinueBtn').onclick = () => {
      window.location.href = 'http://127.0.0.1:5000/dashboard';
    };
  } catch (ex) {
    err.textContent = ex.message || 'Inscription échouée';
    err.classList.remove('hidden');
  } finally {
    btn.querySelector('.btn-text').classList.remove('hidden');
    btn.querySelector('.btn-loader').classList.add('hidden');
    btn.disabled = false;
  }
});
