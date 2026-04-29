# 🔐 SecureShare — Partage de fichiers chiffré de bout en bout

Application web de partage de fichiers sécurisé utilisant **RSA-2048 + AES-256-GCM**.

---

## Architecture

```
[ Navigateur Web ]
     ↓ HTTPS (en production)
[ Python Backend — Flask ]
     ↓
[ SQLite Database ]
```

### Flux de chiffrement

```
User1 (Navigateur)
  ├─ Génère clé AES-256 aléatoire (Web Crypto API)
  ├─ Chiffre le fichier : AES-256-GCM(fichier, AES_key) → ciphertext
  ├─ Pour chaque destinataire :
  │     RSA-OAEP(AES_key, PublicKey_UserX) → encrypted_AES_key
  └─ Envoie au serveur : { ciphertext, nonce, encrypted_AES_key_per_user }

Serveur
  └─ Stocke tout en base sans jamais voir l'AES_key en clair

User2 (Navigateur)
  ├─ Télécharge ciphertext + encrypted_AES_key (pour lui)
  ├─ RSA-OAEP-decrypt(encrypted_AES_key, PrivateKey_User2) → AES_key
  └─ AES-256-GCM-decrypt(ciphertext, AES_key) → fichier original
```

---

## Structure du projet

```
secure-share-app/
├── backend/
│   ├── app.py              # Entry point Flask
│   ├── models.py           # DB schema + helpers
│   ├── routes/
│   │   ├── auth.py         # Register / Login / JWT
│   │   ├── files.py        # Upload / Download / Share / Delete
│   │   └── users.py        # List users / Get public key
│   ├── crypto/
│   │   ├── aes_utils.py    # AES-256-GCM (server-side, backup)
│   │   └── rsa_utils.py    # RSA-2048 key generation
│   └── database.db         # SQLite (auto-créé)
├── frontend/
│   ├── index.html          # Page Login / Register
│   ├── dashboard.html      # Application principale
│   ├── js/
│   │   ├── crypto.js       # Web Crypto API (AES + RSA client-side)
│   │   ├── api.js          # HTTP client + gestion JWT
│   │   ├── auth.js         # Logique authentification
│   │   └── dashboard.js    # Logique dashboard (upload, download, share)
│   └── css/
│       └── style.css       # Thème sombre moderne
└── README.md
```

---

## Base de données

```sql
-- Utilisateurs
users (id, username, password_hash, public_key, created_at)

-- Fichiers chiffrés
files (id, owner_id, filename, mimetype, file_size, encrypted_file, nonce, uploaded_at)

-- Clés AES par destinataire
file_keys (id, file_id, user_id, encrypted_aes_key, shared_at)
```

---

## Installation et lancement

### Prérequis
- Python 3.10+
- Flask et cryptography (déjà disponibles sur la plateforme)

### Lancement

```bash
# Depuis le dossier racine du projet
cd secure-share-app

# Lancer le serveur Flask
python -m backend.app

# L'application est disponible sur http://localhost:5000
```

### Variables d'environnement (production)

```bash
export SECRET_KEY="votre-cle-secrete-tres-longue-et-aleatoire"
```

---

## Sécurité

| Mécanisme | Algorithme | Détail |
|-----------|-----------|--------|
| Chiffrement fichiers | AES-256-GCM | Web Crypto API, côté client |
| Échange de clés | RSA-2048 OAEP | SHA-256 MGF |
| Authentification | JWT HS256 | Expire après 8h |
| Mots de passe | SHA-256 + sel | Stockés en DB uniquement |
| Clés privées | Jamais stockées | Retournées une fois à l'inscription |

> ⚠️ **Note** : La clé privée RSA est retournée une seule fois lors de l'inscription.
> Le serveur ne la stocke jamais. L'utilisateur doit la sauvegarder.

---

## Points d'amélioration (production)

- [ ] TLS/HTTPS (nginx + certbot)
- [ ] bcrypt pour le hachage des mots de passe
- [ ] Certificats X.509 / PKI complète
- [ ] Perfect Forward Secrecy (ECDH)
- [ ] Rate limiting (flask-limiter)
- [ ] 2FA (TOTP)
- [ ] Migration vers PostgreSQL
