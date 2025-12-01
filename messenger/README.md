# Messenger

Библиотека для E2EE мессенджера на базе Aegis-Q.

## Модули

### Ratchet

Double Ratchet реализация:
- Post-quantum double ratchet
- Без центров доверия
- Forward secrecy

### Storage

Защищённое локальное хранилище:
- Шифрование медиа
- Шифрование реакций
- Шифрование профиля

## Использование

```rust
use messenger::ratchet::RatchetState;
use messenger::storage::{StorageEntry, MediaStorage, ProfileStorage};
```

