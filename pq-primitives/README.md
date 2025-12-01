# PQ Primitives

Реализация криптографических примитивов для Aegis-Q.

## Модули

### LatticeMix

Реализация операций на решётках RLWE:
- Параметры: n = 4096, q = 2^32 - 5
- NTT для эффективного умножения полиномов
- Константное время операций

### CodeMix

Реализация линейных кодов:
- Порождающие матрицы 4096×4096
- Секретные перестановки
- Разреженное представление для эффективности

### ZKMix

Zero-knowledge трансформация:
- SHA3-512 / SHAKE-256
- Полная симулируемость
- Константное время

## Использование

```rust
use pq_primitives::lattice::{lattice_mix, derive_lattice_params};
use pq_primitives::eccodes::{code_mix, GeneratorMatrix, Permutation};
use pq_primitives::zk::zk_mix;
```

