# Aegis-Q

**Квантово-устойчивое криптографическое шифрование максимальной стойкости**

Aegis-Q — это реализация криптографического алгоритма с четырёхслойной раундовой структурой, разработанного для обеспечения максимальной стойкости против квантовых атак.

## Архитектура

Aegis-Q использует четырёхслойную структуру:

1. **LatticeMix** — операции на решётках RLWE (уровень безопасности > Kyber1024)
2. **CodeMix** — линейные коды (порождающие матрицы G, перестановки P)
3. **ZKMix** — zero-knowledge трансформация (симулятор)
4. **MaskMix** — раундовые случайные маски

## Структура проекта

```
aegis-q/
├── core/                 # Ядро алгоритма Aegis-Q
├── pq-primitives/        # Реализация решёток, кодов и zk-элементов
│   ├── lattice/          # LatticeMix
│   ├── eccodes/          # CodeMix
│   └── zk/               # ZKMix
├── utils/                # Утилиты (RNG, memory)
├── transport/            # Библиотека шифрования трафика (VPN + TLS-замена)
│   ├── vpn/
│   ├── quic/
│   └── framing/
├── messenger/            # Библиотека для E2EE мессенджера
│   ├── ratchet/
│   └── storage/
└── licensing/            # Защита лицензий, обфускация, защищённый конфиг
```

## Использование

### Базовое шифрование

```rust
use aegis_q_core::{aegis_q_encrypt, aegis_q_decrypt};

let key = b"your-32-byte-key-1234567890123456";
let nonce = b"your-16-byte-nonce";
let plaintext = b"Hello, Aegis-Q!";

// Шифрование
let ciphertext = aegis_q_encrypt(key, nonce, plaintext);

// Расшифрование
let decrypted = aegis_q_decrypt(key, nonce, &ciphertext)?;
```

### VPN транспорт

```rust
use transport::vpn::{VpnSession, Handshake};

// Выполнить handshake
let handshake = Handshake::perform(client_key, server_key);
let session = VpnSession::from_handshake(&handshake.shared_secret, nonce);

// Шифрование данных
let encrypted = session.encrypt_data(data);
```

### Messenger (E2EE)

```rust
use messenger::ratchet::RatchetState;

let mut ratchet = RatchetState::new(root_key);
let encrypted = ratchet.encrypt(message);
```

## Параметры безопасности

- **LatticeMix**: n = 4096, q = 2^32 - 5
- **CodeMix**: матрицы 4096×4096
- **ZKMix**: SHA3-512 / SHAKE-256
- **Раунды**: 10 (настраивается)

## Тестирование

```bash
# Запуск всех тестов
cargo test

# Property-based тесты
cargo test --test property

# Known Answer Tests
cargo test --test kat

# Бенчмарки
cargo bench
```

## Документация

```bash
# Генерация документации
cargo doc --open
```

Подробная спецификация алгоритма доступна в [SPEC.md](SPEC.md).

## Лицензия

MIT OR Apache-2.0

## Предупреждение

Это экспериментальная реализация. Не используйте в продакшене без тщательного криптографического анализа и аудита.

