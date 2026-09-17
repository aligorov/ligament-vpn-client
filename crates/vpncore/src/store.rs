//! Зашифрованное хранилище профилей и настроек (`profiles.dat`, спека §6).
//!
//! Формат файла: `nonce[12] || AES-256-GCM(ciphertext)`, где открытый текст —
//! JSON [`StoreData`]. Ключ — 32 байта службы (генерируется при первом старте,
//! хранится рядом с правильным ACL; постановка ключа — задача демона/инсталлера).

use crate::model::{Profile, Settings};
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use std::path::PathBuf;

/// Содержимое хранилища.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StoreData {
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(default)]
    pub settings: Settings,
    /// Токен сессии портала (после OIDC/логина) для `corpvpn.portal.sync`.
    #[serde(default)]
    pub portal_token: Option<String>,
    /// true — токен это кука `vpn_portal_session` (вход логин/пароль),
    /// false — Bearer API-токен (OIDC exchange).
    #[serde(default)]
    pub portal_token_is_cookie: bool,
}

/// Ошибка хранилища. `Display` — по-русски.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("Ошибка файла хранилища: {0}")]
    Io(String),
    #[error("Хранилище не удалось расшифровать (неверный ключ или файл повреждён)")]
    Crypto,
    #[error("Не удалось сохранить данные хранилища")]
    Serialize,
}

/// Точка входа для хранилищ.
pub trait ProfileStore: Send + Sync {
    fn load(&self) -> Result<StoreData, StoreError>;
    fn save(&self, data: &StoreData) -> Result<(), StoreError>;
}

/// Файловое хранилище, зашифрованное AES-256-GCM.
pub struct EncryptedFileStore {
    path: PathBuf,
    key: [u8; 32],
}

const NONCE_LEN: usize = 12;

impl EncryptedFileStore {
    /// Создаёт хранилище по пути с данным 32-байтным ключом.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, key: [u8; 32]) -> Self {
        Self { path: path.into(), key }
    }

    /// Путь файла хранилища (для изоляции повреждённого файла).
    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.path.clone()
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key))
    }

    /// `nonce || ciphertext`.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, StoreError> {
        let cipher = self.cipher();
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 12 случайных байт
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| StoreError::Crypto)?;
        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn decrypt(&self, blob: &[u8]) -> Result<Vec<u8>, StoreError> {
        if blob.len() <= NONCE_LEN {
            return Err(StoreError::Crypto);
        }
        let (nonce, ciphertext) = blob.split_at(NONCE_LEN);
        let cipher = self.cipher();
        cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| StoreError::Crypto)
    }
}

impl ProfileStore for EncryptedFileStore {
    fn load(&self) -> Result<StoreData, StoreError> {
        let blob = std::fs::read(&self.path).map_err(|e| StoreError::Io(e.to_string()))?;
        let plain = self.decrypt(&blob)?;
        serde_json::from_slice(&plain).map_err(|_| StoreError::Serialize)
    }

    fn save(&self, data: &StoreData) -> Result<(), StoreError> {
        let json = serde_json::to_vec(data).map_err(|_| StoreError::Serialize)?;
        let blob = self.encrypt(&json)?;
        // атомарная запись: tmp + rename, чтобы сбой не порвал хранилище
        let tmp = self.path.with_extension("dat.tmp");
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| StoreError::Io(e.to_string()))?;
        }
        std::fs::write(&tmp, &blob).map_err(|e| StoreError::Io(e.to_string()))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(())
    }
}

/// Загружает или создаёт ключ хранилища (32 случайных байта) в файле `path`.
/// Правильный ACL на файл (SYSTEM+Administrators) выставляет инсталлер —
/// см. спека §6.
pub fn load_or_create_key(path: &std::path::Path) -> std::io::Result<[u8; 32]> {
    use rand::RngCore;

    if path.exists() {
        let data = std::fs::read(path)?;
        if data.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&data);
            return Ok(key);
        }
        // Обрезанный/битый ключ (сбой записи при первом старте): старым ключом
        // хранилище всё не расшифровать — изолируем ОБА файла и начинаем заново
        // (аудит #3: раньше это был фатальный краш-цикл службы).
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let _ = std::fs::rename(path, path.with_extension(format!("corrupt-{ts}")));
        if let Some(dir) = path.parent() {
            let store = dir.join("profiles.dat");
            let _ = std::fs::rename(&store, store.with_extension(format!("corrupt-{ts}")));
        }
    }
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // атомарно: tmp + rename (как в save())
    let tmp = path.with_extension("key.tmp");
    std::fs::write(&tmp, key)?;
    std::fs::rename(&tmp, path)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Profile, ProfileKind, ProfileSource, VlessProfile};

    fn sample() -> StoreData {
        let mut p = Profile::new("Корпоративная сеть", ProfileKind::Vless, ProfileSource::Portal);
        p.vless = Some(VlessProfile {
            uri: "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@vpn.example.com:443?security=reality&type=tcp#CorpVPN".into(),
        });
        StoreData {
            profiles: vec![p],
            settings: Settings::default(),
            portal_token: Some("token".into()),
            portal_token_is_cookie: false,
        }
    }

    #[test]
    fn save_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profiles.dat");
        let store = EncryptedFileStore::new(&path, [7u8; 32]);
        let data = sample();
        store.save(&data).unwrap();
        assert!(path.exists());
        // файл точно не plaintext-JSON: имени профиля и фигурных скобок в нём нет
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.starts_with(b"{"));
        assert!(!raw.windows(9).any(|w| w == "Корпоратив".as_bytes()));
        assert_eq!(store.load().unwrap(), data);
    }

    #[test]
    fn empty_store_is_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/dir/profiles.dat");
        let store = EncryptedFileStore::new(&path, [1u8; 32]);
        store.save(&StoreData::default()).unwrap();
        assert_eq!(store.load().unwrap(), StoreData::default());
    }

    #[test]
    fn wrong_key_fails_with_crypto() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profiles.dat");
        EncryptedFileStore::new(&path, [1u8; 32]).save(&sample()).unwrap();
        let other = EncryptedFileStore::new(&path, [2u8; 32]);
        assert!(matches!(other.load(), Err(StoreError::Crypto)));
        // и мусорный файл тоже
        std::fs::write(&path, b"garbage").unwrap();
        assert!(matches!(other.load(), Err(StoreError::Crypto)));
        // пустой файл
        std::fs::write(&path, b"").unwrap();
        assert!(matches!(other.load(), Err(StoreError::Crypto)));
    }

    #[test]
    fn missing_file_is_io_error() {
        let store = EncryptedFileStore::new("/nonexistent/dir/profiles.dat", [3u8; 32]);
        assert!(matches!(store.load(), Err(StoreError::Io(_))));
    }

    #[test]
    fn key_created_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corpvpnd.key");
        let k1 = load_or_create_key(&path).unwrap();
        assert_eq!(k1.len(), 32);
        assert!(path.exists());
        let k2 = load_or_create_key(&path).unwrap();
        assert_eq!(k1, k2, "существующий ключ не перегенерируется");
    }

    #[test]
    fn every_save_uses_fresh_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profiles.dat");
        let store = EncryptedFileStore::new(&path, [9u8; 32]);
        let data = sample();
        store.save(&data).unwrap();
        let first = std::fs::read(&path).unwrap();
        store.save(&data).unwrap();
        let second = std::fs::read(&path).unwrap();
        assert_ne!(&first[..NONCE_LEN], &second[..NONCE_LEN]);
        // при этом оба читаются
        assert_eq!(store.load().unwrap(), data);
    }
}
