# Aegis-Q Core

Ядро алгоритма Aegis-Q — четырёхслойная раундовая криптографическая схема.

## Модули

- **state.rs** — структура состояния Aegis-Q
- **round.rs** — раундовая функция
- **encrypt.rs** — API шифрования/расшифрования

## Использование

```rust
use aegis_q_core::{aegis_q_encrypt, aegis_q_decrypt};

let key = b"your-key-32-bytes-1234567890123456";
let nonce = b"your-nonce-16";
let plaintext = b"Hello!";

let ciphertext = aegis_q_encrypt(key, nonce, plaintext);
let decrypted = aegis_q_decrypt(key, nonce, &ciphertext)?;
```

## Тестирование

```bash
cargo test
cargo test --test kat
cargo test --test property
cargo test --test constant_time
```

## Бенчмарки

```bash
cargo bench
```

