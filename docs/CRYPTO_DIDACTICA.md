# Criptografía didáctica en el núcleo Bara

## Qué había (y sigue compilado)

En `src/crypto_native.rs` el núcleo incluye, **sin dependencias externas**:

| Primitiva | Uso previsto | ¿Seguridad real? |
|-----------|--------------|------------------|
| SHA-256 / HMAC / HKDF | Huellas, ADN del AST, sellos de marco | Hash/MAC de laboratorio; sin auditoría de canal lateral |
| X25519 | Intercambio de claves del túnel simulado | Didáctico |
| ChaCha20-Poly1305 (`aead_*`) | AEAD del camuflaje de red (`net_camouflage`) | **Didáctico / simulado** |
| AES-128-GCM (`aes128_gcm_*`) | Paridad con `TLS_AES_128_GCM_SHA256` en el mismo camuflaje | **Didáctico / simulado** |

`net_camouflage` es un apretón TLS 1.3 **simulado** (fuera de alcance de producción web). No sustituye a un cliente TLS del sistema.

## Feature `didactic_crypto` (off por defecto)

- **Sin la feature** (builds de liberación / consumidores): `aead_seal` / `aes128_gcm_seal` no sellan (`Vec` vacío / `None`); `*_open` siempre `None`.
- **Con `cargo test`** o `--features didactic_crypto`: las implementaciones se ejecutan para que los vectores NIST/RFC y el arnés de camuflaje sigan verdes.

Constante pública: `bara::crypto_native::DIDACTIC_AEAD_ENABLED`.

## Qué no se tocó

SHA-256 / HMAC / HKDF siguen disponibles: firman ADN y auditorías, no cifran tráfico de usuario.
