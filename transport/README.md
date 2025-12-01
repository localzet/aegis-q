# Transport Layer

Библиотека шифрования трафика для Aegis-Q.

## Модули

### Framing

Формат фреймов для транспортного слоя (замена TLS):
- Заголовки фреймов
- Типы фреймов (Handshake, Data, Close, Heartbeat)
- Шифрование payload

### VPN

VPN туннель с использованием Aegis-Q:
- Handshake протокол
- Stream wrapper
- Управление сессиями

### QUIC

QUIC-like протокол с Aegis-Q шифрованием:
- Управление сессиями
- Множественные потоки
- Потоковое шифрование

## Использование

```rust
use transport::vpn::{VpnSession, Handshake};
use transport::framing::Frame;
use transport::quic::QuicSession;
```

