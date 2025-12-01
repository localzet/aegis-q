# Utils

Утилиты для Aegis-Q.

## Модули

### RNG

Криптографически стойкая генерация случайных чисел:
- Thread-local RNG
- Constant-time операции

### Memory

Управление памятью:
- Secure memory arenas
- Zeroization
- Защита от утечек

## Использование

```rust
use utils::rng::{random_bytes, random_u32, secure_rng};
use utils::memory::{SecureArena, zeroize};
```

