//! # Puente híbrido BSC/EVM — `bsc_bridge.rs`
//!
//! Puente entre el núcleo **Bara** (AETHER‑Ω) y **BNB Smart Chain**: consulta
//! estado de la cadena, construye llamadas ABI/BEP‑20 y firma transacciones
//! EIP‑155 para el *Chain ID* **56**, sin salir del lenguaje ni de sus axiomas.
//!
//! ## Qué implementa el puente (todo nativo, cero dependencias)
//! | Pieza | Dónde vive | Por qué |
//! |---|---|---|
//! | *Keccak‑256* | [`keccak256`] | selectores ABI, dirección desde clave pública, `EIP‑55` |
//! | *RLP* canónico | [`rlp_encode`] / [`rlp_decode`] | serialización de transacciones y listas |
//! | *secp256k1* + ECDSA | [`SigningKey`] | firmar sin delegar en una biblioteca externa |
//! | nonce determinista | RFC 6979 con `HMAC‑SHA256` de [`crypto_native`](crate::crypto_native) | dos firmas iguales para el mismo mensaje |
//! | ABI/BEP‑20 | [`balance_of_call`], [`transfer_call`] | carga útil de `eth_call` y `transfer` |
//! | JSON‑RPC | [`BscClient`] | consultas tipadas sobre un transporte enchufable |
//! | aislamiento | [`BscTransducer`], [`DataBubble`] | la respuesta se confina y se destila a *Shoresh* |
//!
//! Las primitivas criptográficas **no** se reimplementan a ciegas: `HMAC`,
//! `HKDF`, `SHA‑256` y el ADN del enjambre vienen de
//! [`crypto_native`](crate::crypto_native) y [`ast_dna`](crate::ast_dna) — el ADN
//! de la clave de firma es el **mismo** que identifica al nodo
//! ([`swarm_adn`](crate::net_camouflage::swarm_adn) =
//! [`golden_key`](crate::ast_dna::golden_key)), así que identidad de código e
//! identidad de red coinciden.
//!
//! ## Flujo completo
//! ```text
//! BscQuery ──► BscClient ──► RpcTransport ──► nodo BSC
//!                 │                              │
//!                 │  cuerpo JSON‑RPC             │  respuesta cruda
//!                 ▼                              ▼
//!          (texto exacto, sin copias) ──► BscDatum::decode
//!                                                │
//!                                    BscTransducer::admit
//!                                    ├─ Gateway::admit → burbuja de inmunidad
//!                                    ├─ AST *Shoresh*  → nodos con raíz triconsonántica
//!                                    └─ AstDna         → holograma firmado
//!                                                │
//!                                    DataBubble::publish → memoria holográfica
//! ```
//!
//! ## Límites declarados (sin adornos)
//! 1. **No es un nodo**: el puente no valida bloques ni ejecuta la EVM. La
//!    verdad la aporta el nodo consultado y, precisamente por eso, cada
//!    respuesta entra como **burbuja aislada** y se sella con el ADN del árbol.
//! 2. **HTTP en claro**: [`HttpTransport`] habla HTTP/1.1 sin cifrar contra el
//!    extremo público de BSC (`bsc-dataseed.binance.org:8545`). El extremo
//!    canónico `https://bsc-dataseed.binance.org/` se alcanza con
//!    [`SwarmTransport`], el canal camuflado del enjambre
//!    ([`net_camouflage`](crate::net_camouflage)): exige un **par Bara** al otro
//!    lado (un relevo del enjambre que sirva el RPC). El núcleo no delega TLS a
//!    terceros: su canal es el suyo.
//! 3. **Sin tiempo constante**: la aritmética de curva usa reducción bit a bit y
//!    exponenciación para el inverso — correcta y determinista, pero **no**
//!    blindada contra ataques de canal lateral. Sirve para firmar y verificar;
//!    las claves de valor real deben vivir fuera del proceso.
//! 4. **Cobertura de firma**: transacciones *legacy* con EIP‑155 (tipo 0), el
//!    formato que el puente emite. Los tipos `0x01`/`0x02` quedan fuera.
//! 5. **Reutilización**: el JSON lo analiza el escáner estricto de
//!    [`visual_builder`](crate::visual_builder) (`parse_json`), con sus topes de
//!    profundidad y tamaño: el puente **no** trae un segundo analizador.
//! 6. **Totalidad**: ninguna entrada provoca un pánico (A1). Todo fallo se
//!    degrada a un [`BridgeError`] explícito; no hay `unwrap()` ni `expect()`.

use std::cmp::Ordering;
use std::collections::VecDeque;
use std::fmt;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::ast_dna::{ast_dna, golden_key, key_id, merkle_root, node_dna, short_hex, AstDna};
use crate::crypto_native::{digest_eq, hkdf_32, hmac_sha256, sha256};
use crate::ffi_ingest::{root_from_name, BaraType, ShoreshAst, ShoreshNode};
use crate::immunity_gateway::{Bubble, Gateway, Packet};
use crate::net_camouflage::{CamouflageProfile, HttpsSession, CT_ALERT, CT_APPLICATION_DATA};
use crate::runtime::{BaraRuntime, Observation, QuantumState};
use crate::visual_builder::{parse_json, triconsonantal, Json};

/// *Chain ID* de BNB Smart Chain (mainnet).
pub const BSC_CHAIN_ID: u64 = 56;
/// Extremo público de BSC con HTTP en claro (el que habla [`HttpTransport`]).
pub const BSC_MAINNET_ADDRESS: &str = "bsc-dataseed.binance.org:8545";
/// Extremo canónico (TLS) servido por el enjambre a través de [`SwarmTransport`].
pub const BSC_MAINNET_ENDPOINT: &str = "https://bsc-dataseed.binance.org/";
/// Ruta HTTP del RPC público.
pub const BSC_RPC_PATH: &str = "/";
/// Techo de lectura de una respuesta (idéntico al del escáner JSON reutilizado).
pub const MAX_RPC_BYTES: usize = 64 * 1024;
/// Presupuesto de espera de cada operación de zócalo, en milisegundos.
pub const HTTP_TIMEOUT_MS: u64 = 8_000;
/// Contexto de derivación del ADN de firma (evita cruces con otras claves).
pub const SIGNING_KEY_INFO: &[u8] = b"bara:aether-omega:bsc:secp256k1:v1";
/// Intentos de nonce concedidos antes de declarar el fallo (RFC 6979).
pub const MAX_NONCE_ATTEMPTS: usize = 1024;

// ─────────────────────────────────────────────────────────────────────────
// Errores
// ─────────────────────────────────────────────────────────────────────────

/// Fallo del puente. Es la **única** forma de fallar: nunca hay pánico.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeError {
    /// El transporte no pudo entregar la petición (red, DNS, tiempo agotado).
    TransportUnavailable(String),
    /// El servidor respondió con un código HTTP distinto de `200`.
    HttpStatus(u16),
    /// La respuesta no tiene forma de HTTP/1.1 válido.
    HttpMalformed(&'static str),
    /// El cuerpo no es JSON estricto o excede los topes del escáner.
    JsonInvalid,
    /// Falta un campo obligatorio del sobre JSON‑RPC.
    JsonMissingField(&'static str),
    /// El nodo devolvió un error JSON‑RPC.
    RpcError {
        /// Código numérico del error.
        code: i64,
        /// Mensaje del nodo.
        message: String,
    },
    /// El nodo devolvió `result: null` (p. ej. recibo aún no minado).
    NoResult,
    /// Texto hexadecimal malformado (longitud impar o dígito no hexadecimal).
    HexInvalid,
    /// Texto decimal malformado (vacío o con dígitos no decimales).
    NotANumber,
    /// La cantidad no cabe en 256 bits.
    ValueOutOfRange,
    /// Longitud inesperada en un dato de tamaño fijo.
    LengthMismatch {
        /// Longitud exigida.
        expected: usize,
        /// Longitud encontrada.
        found: usize,
    },
    /// Escalar fuera de `[1, n−1]` o coordenada fuera del campo.
    ScalarOutOfRange,
    /// El punto resultante es el del infinito: no tiene forma afín.
    PointAtInfinity,
    /// El punto no pertenece a la curva (`y² ≠ x³ + 7`).
    NotOnCurve,
    /// La firma consumió los intentos de nonce concedidos.
    NonceExhausted,
    /// Sobran bytes tras decodificar un elemento RLP canónico.
    TrailingBytes,
    /// La codificación RLP no es canónica (longitud o carga no minimal).
    NonCanonicalRlp,
    /// RLP truncado, con prefijo imposible o anidamiento excesivo.
    MalformedRlp,
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BridgeError::TransportUnavailable(why) => write!(f, "transporte no disponible: {why}"),
            BridgeError::HttpStatus(code) => write!(f, "respuesta HTTP {code}"),
            BridgeError::HttpMalformed(what) => write!(f, "respuesta HTTP malformada: {what}"),
            BridgeError::JsonInvalid => write!(f, "cuerpo JSON inválido o demasiado grande"),
            BridgeError::JsonMissingField(field) => write!(f, "falta el campo «{field}»"),
            BridgeError::RpcError { code, message } => {
                write!(f, "error JSON-RPC {code}: {message}")
            }
            BridgeError::NoResult => write!(f, "el nodo devolvió `result: null`"),
            BridgeError::HexInvalid => write!(f, "texto hexadecimal inválido"),
            BridgeError::NotANumber => write!(f, "texto decimal inválido"),
            BridgeError::ValueOutOfRange => write!(f, "cantidad fuera de 256 bits"),
            BridgeError::LengthMismatch { expected, found } => {
                write!(f, "longitud {found} donde se esperaban {expected}")
            }
            BridgeError::ScalarOutOfRange => write!(f, "escalar fuera de rango"),
            BridgeError::PointAtInfinity => write!(f, "punto del infinito"),
            BridgeError::NotOnCurve => write!(f, "punto fuera de secp256k1"),
            BridgeError::NonceExhausted => write!(f, "nonce RFC 6979 agotado"),
            BridgeError::TrailingBytes => write!(f, "bytes sobrantes tras el elemento RLP"),
            BridgeError::NonCanonicalRlp => write!(f, "RLP no canónico"),
            BridgeError::MalformedRlp => write!(f, "RLP malformado"),
        }
    }
}

impl std::error::Error for BridgeError {}

// ─────────────────────────────────────────────────────────────────────────
// Enteros de 256 bits y hexadecimal
// ─────────────────────────────────────────────────────────────────────────

/// Convierte un dígito hexadecimal en su valor.
fn hex_nibble(byte: u8) -> Result<u8, BridgeError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(BridgeError::HexInvalid),
    }
}

/// Serializa bytes en hexadecimal **minúsculo sin prefijo**: el `0x` lo añade
/// el llamante. Reutiliza la misma primitiva que los sellos del ADN.
pub fn hex_encode(bytes: &[u8]) -> String {
    short_hex(bytes)
}

/// Lee un texto hexadecimal (con o sin `0x`) de cualquier longitud.
pub fn hex_decode(text: &str) -> Result<Vec<u8>, BridgeError> {
    let digits = strip_hex_prefix(text);
    if !digits.len().is_multiple_of(2) {
        return Err(BridgeError::HexInvalid);
    }
    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.as_bytes().chunks(2) {
        let (Some(high), Some(low)) = (pair.first(), pair.get(1)) else {
            return Err(BridgeError::HexInvalid);
        };
        out.push((hex_nibble(*high)? << 4) | hex_nibble(*low)?);
    }
    Ok(out)
}

/// Quita el prefijo `0x`/`0X` si está presente.
fn strip_hex_prefix(text: &str) -> &str {
    text.strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text)
}

/// Multiplica en sitio por un factor pequeño; `true` si desborda 256 bits.
fn mul_small_bytes(limbs: &mut [u8; 32], factor: u8) -> bool {
    let mut carry = 0u32;
    for byte in limbs.iter_mut().rev() {
        let value = u32::from(*byte) * u32::from(factor) + carry;
        *byte = value as u8;
        carry = value >> 8;
    }
    carry != 0
}

/// Suma en sitio un sumando pequeño; `true` si desborda 256 bits.
fn add_small_bytes(limbs: &mut [u8; 32], addend: u8) -> bool {
    let mut carry = u32::from(addend);
    for byte in limbs.iter_mut().rev() {
        let value = u32::from(*byte) + carry;
        *byte = value as u8;
        carry = value >> 8;
    }
    carry != 0
}

/// Divide en sitio por un divisor pequeño y devuelve el resto.
fn div_small_bytes(limbs: &mut [u8; 32], divisor: u8) -> u8 {
    let mut remainder = 0u32;
    for byte in limbs.iter_mut() {
        let value = (remainder << 8) | u32::from(*byte);
        *byte = (value / u32::from(divisor)) as u8;
        remainder = value % u32::from(divisor);
    }
    remainder as u8
}

/// Entero sin signo de 256 bits, en orden **big‑endian** (el de la EVM).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct U256([u8; 32]);

impl U256 {
    /// Cero.
    pub const ZERO: U256 = U256([0; 32]);
    /// Uno.
    pub const ONE: U256 = U256([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ]);

    /// Desde un `u64`.
    pub fn from_u64(value: u64) -> Self {
        let mut out = [0u8; 32];
        out[24..].copy_from_slice(&value.to_be_bytes());
        U256(out)
    }

    /// Desde bytes big‑endian de cualquier longitud ≤ 32 (alineados a la derecha).
    pub fn from_be_slice(bytes: &[u8]) -> Result<Self, BridgeError> {
        if bytes.len() > 32 {
            return Err(BridgeError::ValueOutOfRange);
        }
        let mut out = [0u8; 32];
        out[32 - bytes.len()..].copy_from_slice(bytes);
        Ok(U256(out))
    }

    /// Desde una palabra exacta de 32 bytes (no puede fallar).
    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        U256(bytes)
    }

    /// Desde un texto hexadecimal (con o sin `0x`).
    ///
    /// Se admiten las cantidades EVM canónicas (`0x0`, `0x1b4`) y las formas
    /// largas de 64 dígitos; más de 32 bytes se rechaza.
    pub fn from_hex(text: &str) -> Result<Self, BridgeError> {
        let digits = strip_hex_prefix(text).as_bytes();
        if digits.len() > 64 {
            return Err(BridgeError::ValueOutOfRange);
        }
        let mut out = [0u8; 32];
        let mut index = 32;
        let mut nibbles = digits.iter().rev();
        while let Some(low) = nibbles.next() {
            let low = hex_nibble(*low)?;
            let high = match nibbles.next() {
                Some(byte) => hex_nibble(*byte)?,
                None => 0,
            };
            index -= 1;
            out[index] = (high << 4) | low;
        }
        Ok(U256(out))
    }

    /// Desde un texto decimal.
    pub fn from_dec(text: &str) -> Result<Self, BridgeError> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err(BridgeError::NotANumber);
        }
        let mut out = [0u8; 32];
        for byte in trimmed.bytes() {
            if !byte.is_ascii_digit() {
                return Err(BridgeError::NotANumber);
            }
            if mul_small_bytes(&mut out, 10) || add_small_bytes(&mut out, byte - b'0') {
                return Err(BridgeError::ValueOutOfRange);
            }
        }
        Ok(U256(out))
    }

    /// Bytes big‑endian completos.
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Vista big‑endian **sin ceros a la izquierda**: la forma minimal que RLP
    /// exige para las cantidades.
    pub fn trimmed_be(&self) -> &[u8] {
        let start = self.0.iter().position(|byte| *byte != 0).unwrap_or(32);
        &self.0[start..]
    }

    /// ¿Es cero?
    pub fn is_zero(&self) -> bool {
        self.trimmed_be().is_empty()
    }

    /// Valor `u64`, si cabe.
    pub fn to_u64(&self) -> Option<u64> {
        let trimmed = self.trimmed_be();
        if trimmed.len() > 8 {
            return None;
        }
        Some(
            trimmed
                .iter()
                .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte)),
        )
    }

    /// Hexadecimal canónico de cantidad EVM: `0x` y sin ceros a la izquierda.
    pub fn to_hex(&self) -> String {
        let trimmed = self.trimmed_be();
        if trimmed.is_empty() {
            return "0x0".to_string();
        }
        let mut out = String::with_capacity(2 + trimmed.len() * 2);
        out.push_str("0x");
        out.push_str(&hex_encode(trimmed));
        out
    }

    /// Decimal en texto (base 10, sin ceros a la izquierda).
    pub fn to_dec(&self) -> String {
        let mut limbs = self.0;
        let mut digits = Vec::with_capacity(78);
        loop {
            digits.push(b'0' + div_small_bytes(&mut limbs, 10));
            if limbs.iter().all(|byte| *byte == 0) {
                break;
            }
        }
        digits.reverse();
        String::from_utf8_lossy(&digits).to_string()
    }
}

impl fmt::Display for U256 {
    /// Se muestra en decimal: es la forma legible para informes y manifiestos.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_dec())
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Keccak‑256 (la variante de Ethereum: relleno `0x01`, tasa 1088 bits)
// ─────────────────────────────────────────────────────────────────────────

/// Rondas de la permutación *Keccak‑f[1600]*.
const KECCAK_ROUNDS: usize = 24;
/// Constantes de ronda del paso `ι`.
const KECCAK_RC: [u64; KECCAK_ROUNDS] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];
/// Desplazamientos del paso `ρ`, indexados por `x + 5y`.
const KECCAK_RHO: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];
/// Tasa de absorción: `1600 − 512` bits.
const KECCAK_RATE: usize = 136;
/// Separador de dominio de *Keccak* original (Ethereum **no** usa `SHA‑3`).
const KECCAK_PAD: u8 = 0x01;

/// XOR de un byte del estado, en la posición `offset` del bloque.
fn keccak_xor_byte(state: &mut [u64; 25], offset: usize, byte: u8) {
    state[offset / 8] ^= u64::from(byte) << (8 * (offset % 8));
}

/// XOR de un bloque de bytes sobre el estado, en orden de carriles.
fn keccak_absorb(state: &mut [u64; 25], block: &[u8]) {
    for (index, byte) in block.iter().enumerate() {
        state[index / 8] ^= u64::from(*byte) << (8 * (index % 8));
    }
}

/// Permutación *Keccak‑f[1600]* completa: `θ`, `ρ`, `π`, `χ` e `ι`.
fn keccak_f1600(state: &mut [u64; 25]) {
    for round_constant in KECCAK_RC {
        // θ — paridad por columnas.
        let mut column = [0u64; 5];
        for (x, slot) in column.iter_mut().enumerate() {
            *slot = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for x in 0..5 {
            let delta = column[(x + 4) % 5] ^ column[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                state[x + 5 * y] ^= delta;
            }
        }
        // ρ (rotación) y π (permutación de carriles) sobre una copia.
        let mut moved = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                let index = x + 5 * y;
                let target = y + 5 * ((2 * x + 3 * y) % 5);
                moved[target] = state[index].rotate_left(KECCAK_RHO[index]);
            }
        }
        // χ — mezcla no lineal fila a fila.
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] =
                    moved[x + 5 * y] ^ (!moved[(x + 1) % 5 + 5 * y] & moved[(x + 2) % 5 + 5 * y]);
            }
        }
        // ι — constante de ronda.
        state[0] ^= round_constant;
    }
}

/// *Keccak‑256* de un mensaje completo.
///
/// Relleno `pad10*1` con separador `0x01`: exactamente el que Ethereum usa para
/// selectores ABI, direcciones y `EIP‑155`. El bucle absorbe tantos bloques como
/// haga falta, de modo que cualquier longitud es admisible.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut state = [0u64; 25];
    // Bloques completos: se absorben y se permutan, uno tras otro.
    let mut consumed = 0;
    while data.len() - consumed >= KECCAK_RATE {
        keccak_absorb(&mut state, &data[consumed..consumed + KECCAK_RATE]);
        keccak_f1600(&mut state);
        consumed += KECCAK_RATE;
    }
    // Bloque final: la cola que quedaba se absorbe **una sola vez** (nunca se
    // mezcló arriba) más el relleno `0x01` y el bit final `0x80`.
    let rest = data.len() - consumed;
    keccak_absorb(&mut state, &data[consumed..]);
    keccak_xor_byte(&mut state, rest, KECCAK_PAD);
    keccak_xor_byte(&mut state, KECCAK_RATE - 1, 0x80);
    keccak_f1600(&mut state);

    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = (state[index / 8] >> (8 * (index % 8))) as u8;
    }
    out
}

/// Selector ABI: los cuatro primeros bytes del *Keccak‑256* de la firma.
pub fn selector(signature: &str) -> [u8; 4] {
    let digest = keccak256(signature.as_bytes());
    [digest[0], digest[1], digest[2], digest[3]]
}

// ─────────────────────────────────────────────────────────────────────────
// RLP canónico
// ─────────────────────────────────────────────────────────────────────────

/// Profundidad máxima de anidamiento admitida al decodificar.
const MAX_RLP_DEPTH: usize = 32;

/// Elemento RLP: cadena de bytes o lista de elementos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RlpItem {
    /// Cadena de bytes (las cantidades van minimizadas).
    Bytes(Vec<u8>),
    /// Lista ordenada de elementos.
    List(Vec<RlpItem>),
}

/// Elemento de bytes.
pub fn rlp_data(bytes: &[u8]) -> RlpItem {
    RlpItem::Bytes(bytes.to_vec())
}

/// Elemento de lista.
pub fn rlp_list(items: Vec<RlpItem>) -> RlpItem {
    RlpItem::List(items)
}

/// Cantidad EVM como elemento RLP: **minimizada** (el cero es la cadena vacía).
pub fn rlp_quantity(value: &U256) -> RlpItem {
    RlpItem::Bytes(value.trimmed_be().to_vec())
}

impl RlpItem {
    /// Bytes del elemento, si lo es.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            RlpItem::Bytes(data) => Some(data.as_slice()),
            RlpItem::List(_) => None,
        }
    }

    /// Elementos de la lista, si lo es.
    pub fn as_list(&self) -> Option<&[RlpItem]> {
        match self {
            RlpItem::List(items) => Some(items.as_slice()),
            RlpItem::Bytes(_) => None,
        }
    }

    /// Cantidad de 256 bits, si el elemento es de bytes y no desborda.
    pub fn as_u256(&self) -> Result<U256, BridgeError> {
        let bytes = self.as_bytes().ok_or(BridgeError::MalformedRlp)?;
        U256::from_be_slice(bytes)
    }

    /// Número de elementos, si es lista.
    pub fn arity(&self) -> Option<usize> {
        self.as_list().map(<[RlpItem]>::len)
    }
}

/// Escribe el prefijo de longitud (`0x80`/`0xc0` en forma corta; `base + 55 + L`
/// y la longitud big‑endian minimizada en la larga).
fn rlp_write_length(out: &mut Vec<u8>, base: u8, length: usize) {
    if length < 56 {
        out.push(base + length as u8);
        return;
    }
    let digits = length.to_be_bytes();
    let start = digits.iter().position(|byte| *byte != 0).unwrap_or(8);
    out.push(base + 55 + (8 - start) as u8);
    out.extend_from_slice(&digits[start..]);
}

/// Codifica un elemento RLP.
pub fn rlp_encode(item: &RlpItem) -> Vec<u8> {
    let mut out = Vec::new();
    rlp_encode_into(item, &mut out);
    out
}

/// Codificación canónica: un byte suelto menor que `0x80` se emite tal cual, y
/// la longitud se declara con el mínimo número de bytes.
fn rlp_encode_into(item: &RlpItem, out: &mut Vec<u8>) {
    match item {
        RlpItem::Bytes(data) => {
            if let [single] = data.as_slice() {
                if *single < 0x80 {
                    out.push(*single);
                    return;
                }
            }
            rlp_write_length(out, 0x80, data.len());
            out.extend_from_slice(data);
        }
        RlpItem::List(items) => {
            let mut payload = Vec::new();
            for child in items {
                rlp_encode_into(child, &mut payload);
            }
            rlp_write_length(out, 0xc0, payload.len());
            out.extend_from_slice(&payload);
        }
    }
}

/// Decodifica **exactamente** un elemento canónico; si sobran bytes, falla.
///
/// La canonicidad se comprueba de verdad, no de adorno: `0x8100` (byte suelto
/// mal envuelto), longitudes declaradas en forma larga por debajo de 56 y
/// longitudes con ceros a la izquierda se rechazan con
/// [`BridgeError::NonCanonicalRlp`]. Igual que exige la EVM: una transacción se
/// firma sobre su forma canónica y sólo sobre ella.
pub fn rlp_decode(input: &[u8]) -> Result<RlpItem, BridgeError> {
    let (item, used) = rlp_decode_at(input, 0, 0)?;
    if used != input.len() {
        return Err(BridgeError::TrailingBytes);
    }
    Ok(item)
}

/// Decodifica un elemento a partir de `pos` y devuelve la posición siguiente.
fn rlp_decode_at(input: &[u8], pos: usize, depth: usize) -> Result<(RlpItem, usize), BridgeError> {
    if depth > MAX_RLP_DEPTH {
        return Err(BridgeError::MalformedRlp);
    }
    let Some(prefix) = input.get(pos).copied() else {
        return Err(BridgeError::MalformedRlp);
    };
    // Byte suelto (el propio valor).
    if prefix < 0x80 {
        return Ok((RlpItem::Bytes(vec![prefix]), pos + 1));
    }
    // Cadena corta: `0x80 + n`, `n < 56`.
    if prefix <= 0xb7 {
        let length = usize::from(prefix - 0x80);
        let start = pos + 1;
        let end = start.checked_add(length).ok_or(BridgeError::MalformedRlp)?;
        if input.len() < end {
            return Err(BridgeError::MalformedRlp);
        }
        if length == 1 && input[start] < 0x80 {
            return Err(BridgeError::NonCanonicalRlp);
        }
        return Ok((RlpItem::Bytes(input[start..end].to_vec()), end));
    }
    // Cadena larga: `0xb7 + L` más `L` bytes de longitud.
    if prefix <= 0xbf {
        let name = usize::from(prefix - 0xb7);
        let length = rlp_read_length(input, pos, name)?;
        if length < 56 {
            return Err(BridgeError::NonCanonicalRlp);
        }
        let start = pos + 1 + name;
        let end = start.checked_add(length).ok_or(BridgeError::MalformedRlp)?;
        if input.len() < end {
            return Err(BridgeError::MalformedRlp);
        }
        return Ok((RlpItem::Bytes(input[start..end].to_vec()), end));
    }
    // Lista: corta `0xc0 + n` o larga `0xf7 + L`.
    let (length, header) = if prefix <= 0xf7 {
        (usize::from(prefix - 0xc0), 1)
    } else {
        let name = usize::from(prefix - 0xf7);
        let length = rlp_read_length(input, pos, name)?;
        if length < 56 {
            return Err(BridgeError::NonCanonicalRlp);
        }
        (length, 1 + name)
    };
    let start = pos + header;
    let end = start.checked_add(length).ok_or(BridgeError::MalformedRlp)?;
    if input.len() < end {
        return Err(BridgeError::MalformedRlp);
    }
    let mut items = Vec::new();
    let mut cursor = start;
    while cursor < end {
        let (child, next) = rlp_decode_at(input, cursor, depth + 1)?;
        if next > end {
            return Err(BridgeError::MalformedRlp);
        }
        items.push(child);
        cursor = next;
    }
    Ok((RlpItem::List(items), end))
}

/// Lee la longitud declarada en la forma larga y rechaza el cero a la izquierda.
fn rlp_read_length(input: &[u8], pos: usize, name: usize) -> Result<usize, BridgeError> {
    let start = pos + 1;
    let end = start.checked_add(name).ok_or(BridgeError::MalformedRlp)?;
    if input.len() < end {
        return Err(BridgeError::MalformedRlp);
    }
    if input[start] == 0 {
        return Err(BridgeError::NonCanonicalRlp);
    }
    let mut total = 0usize;
    for byte in &input[start..end] {
        total = total
            .checked_mul(256)
            .and_then(|value| value.checked_add(usize::from(*byte)))
            .ok_or(BridgeError::MalformedRlp)?;
    }
    Ok(total)
}

// ─────────────────────────────────────────────────────────────────────────
// Direcciones (EIP‑55) y ABI/BEP‑20
// ─────────────────────────────────────────────────────────────────────────

/// Dirección EVM de 20 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address([u8; 20]);

impl Address {
    /// Desde bytes exactos de 20.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BridgeError> {
        if bytes.len() != 20 {
            return Err(BridgeError::LengthMismatch {
                expected: 20,
                found: bytes.len(),
            });
        }
        let mut out = [0u8; 20];
        out.copy_from_slice(bytes);
        Ok(Address(out))
    }

    /// Desde texto hexadecimal de 40 dígitos (con o sin `0x`).
    ///
    /// Se admite la forma con suma de comprobación EIP‑55 sin exigirla: el
    /// puente no rechaza una dirección por su tipografía, sólo por su longitud.
    pub fn from_hex(text: &str) -> Result<Self, BridgeError> {
        let digits = strip_hex_prefix(text);
        if digits.len() != 40 {
            return Err(BridgeError::LengthMismatch {
                expected: 40,
                found: digits.len(),
            });
        }
        Address::from_bytes(&hex_decode(digits)?)
    }

    /// Dirección derivada de una clave pública `X ‖ Y` (64 bytes sin comprimir).
    ///
    /// Es la regla de Ethereum: `keccak256(X ‖ Y)[12..]`.
    pub fn from_public_key(public: &[u8; 64]) -> Self {
        let digest = keccak256(public);
        let mut out = [0u8; 20];
        out.copy_from_slice(&digest[12..]);
        Address(out)
    }

    /// Bytes crudos de la dirección.
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Palabra ABI: 32 bytes con doce ceros a la izquierda.
    pub fn to_abi_word(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[12..].copy_from_slice(&self.0);
        out
    }

    /// Hexadecimal en minúsculas con `0x`.
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(42);
        out.push_str("0x");
        out.push_str(&hex_encode(&self.0));
        out
    }

    /// Hexadecimal con **suma de comprobación EIP‑55**: mayúscula donde el
    /// nibble correspondiente del `keccak256` del texto en minúsculas lo pida.
    pub fn to_checksum(&self) -> String {
        let lower = hex_encode(&self.0);
        let digest = keccak256(lower.as_bytes());
        let mut out = String::with_capacity(42);
        out.push_str("0x");
        for (index, digit) in lower.chars().enumerate() {
            let nibble = (digest[index / 2] >> (4 * (1 - (index % 2)))) & 0x0f;
            if nibble >= 8 {
                out.push(digit.to_ascii_uppercase());
            } else {
                out.push(digit);
            }
        }
        out
    }
}

impl fmt::Display for Address {
    /// Se muestra con suma de comprobación: una dirección sin ella se puede
    /// confundir, y aquí no hay prisa por ahorrar dos mayúsculas.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_checksum())
    }
}

/// Carga útil ABI: selector más palabras de 32 bytes ya codificadas.
pub fn abi_call(signature: &str, words: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + words.len() * 32);
    out.extend_from_slice(&selector(signature));
    for word in words {
        out.extend_from_slice(word);
    }
    out
}

/// Carga útil de `balanceOf(address)` (BEP‑20).
pub fn balance_of_call(holder: &Address) -> Vec<u8> {
    abi_call("balanceOf(address)", &[holder.to_abi_word()])
}

/// Carga útil de `transfer(address,uint256)` (BEP‑20).
pub fn transfer_call(to: &Address, amount: &U256) -> Vec<u8> {
    abi_call(
        "transfer(address,uint256)",
        &[to.to_abi_word(), amount.to_bytes()],
    )
}

/// Lee la primera palabra ABI (32 bytes) como cantidad de 256 bits.
pub fn decode_word(data: &[u8]) -> Result<U256, BridgeError> {
    let word = data.get(..32).ok_or(BridgeError::LengthMismatch {
        expected: 32,
        found: data.len(),
    })?;
    U256::from_be_slice(word)
}

// ─────────────────────────────────────────────────────────────────────────
// Campo y grupo de secp256k1 (aritmética de 256 bits exacta)
// ─────────────────────────────────────────────────────────────────────────

/// Escalar o coordenada: cuatro limbos `u64` en orden **big‑endian**.
type Fe = [u64; 4];

/// Primo del campo: `p = 2²⁵⁶ − 2³² − 977`.
const P: Fe = [
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_fffe_ffff_fc2f,
];
/// Orden del grupo: `n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141`.
const N: Fe = [
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_fffe,
    0xbaae_dce6_af48_a03b,
    0xbfd2_5e8c_d036_4141,
];
/// Coordenada `x` del generador `G`.
const GX: Fe = [
    0x79be_667e_f9dc_bbac,
    0x55a0_6295_ce87_0b07,
    0x029b_fcdb_2dce_28d9,
    0x59f2_815b_16f8_1798,
];
/// Coordenada `y` del generador `G`.
const GY: Fe = [
    0x483a_da77_26a3_c465,
    0x5da4_fbfc_0e11_08a8,
    0xfd17_b448_a685_5419,
    0x9c47_d08f_fb10_d4b8,
];

/// Cero.
fn fe_zero() -> Fe {
    [0; 4]
}

/// Uno.
fn fe_one() -> Fe {
    [0, 0, 0, 1]
}

/// ¿Es cero?
fn fe_is_zero(value: &Fe) -> bool {
    value.iter().all(|limb| *limb == 0)
}

/// ¿Es par?
fn fe_is_even(value: &Fe) -> bool {
    value[3] & 1 == 0
}

/// Comparación numérica (los limbos big‑endian ya se ordenan solos).
fn fe_cmp(left: &Fe, right: &Fe) -> Ordering {
    left.cmp(right)
}

/// Suma con acarreo; el booleano indica desbordamiento de 256 bits.
fn fe_add(left: &Fe, right: &Fe) -> (Fe, bool) {
    let mut out = fe_zero();
    let mut carry = 0u64;
    for (index, limb) in out.iter_mut().enumerate().rev() {
        let value = u128::from(left[index]) + u128::from(right[index]) + u128::from(carry);
        *limb = value as u64;
        carry = (value >> 64) as u64;
    }
    (out, carry != 0)
}

/// Resta con préstamo; el booleano indica que hubo que pedir a 2²⁵⁶.
fn fe_sub(left: &Fe, right: &Fe) -> (Fe, bool) {
    let mut out = fe_zero();
    let mut borrow = 0u64;
    for (index, limb) in out.iter_mut().enumerate().rev() {
        let (value, from_limb) = left[index].overflowing_sub(right[index]);
        let (value, from_borrow) = value.overflowing_sub(borrow);
        *limb = value;
        borrow = u64::from(from_limb || from_borrow);
    }
    (out, borrow != 0)
}

/// Suma modular.
fn fe_add_mod(left: &Fe, right: &Fe, modulus: &Fe) -> Fe {
    let (sum, overflow) = fe_add(left, right);
    if overflow || fe_cmp(&sum, modulus) != Ordering::Less {
        let (reduced, _) = fe_sub(&sum, modulus);
        return reduced;
    }
    sum
}

/// Resta modular (el resultado se ajusta con el módulo si hace falta).
fn fe_sub_mod(left: &Fe, right: &Fe, modulus: &Fe) -> Fe {
    if fe_cmp(left, right) != Ordering::Less {
        let (difference, _) = fe_sub(left, right);
        return difference;
    }
    let (wrapped, _) = fe_sub(left, right);
    let (fixed, _) = fe_add(&wrapped, modulus);
    fixed
}

/// Doble modular.
fn fe_double_mod(value: &Fe, modulus: &Fe) -> Fe {
    fe_add_mod(value, value, modulus)
}

/// Resta un número pequeño con propagación de préstamo.
fn fe_sub_small(value: &Fe, amount: u64) -> Fe {
    let mut out = *value;
    let mut borrow = amount;
    for limb in out.iter_mut().rev() {
        let (result, take) = limb.overflowing_sub(borrow);
        *limb = result;
        borrow = u64::from(take);
    }
    out
}

/// Desplaza a la derecha `shift` bits (`1..=63`).
fn fe_shr(value: &Fe, shift: u32) -> Fe {
    let mut out = fe_zero();
    let complement = 64 - shift;
    for index in 0..4 {
        // El acarreo de un desplazamiento a la derecha entra **desde arriba**:
        // los bits bajos del limbo más significativo son los que ocupan los
        // huecos altos del limbo actual. El limbo 0 los pierde, no los recibe.
        let high = if index > 0 { value[index - 1] } else { 0 };
        out[index] = (value[index] >> shift) | (high << complement);
    }
    out
}

/// Pasa a limbos little‑endian (la convención que simplifica el producto).
fn fe_to_le(value: &Fe) -> [u64; 4] {
    [value[3], value[2], value[1], value[0]]
}

/// Producto completo de 512 bits en limbos little‑endian.
fn mul_wide_le(left: &[u64; 4], right: &[u64; 4]) -> [u64; 8] {
    let mut out = [0u64; 8];
    for (row, left_limb) in left.iter().enumerate() {
        let mut carry = 0u128;
        for (column, right_limb) in right.iter().enumerate() {
            let value = u128::from(out[row + column])
                + u128::from(*left_limb) * u128::from(*right_limb)
                + carry;
            out[row + column] = value as u64;
            carry = value >> 64;
        }
        out[row + 4] = carry as u64;
    }
    out
}

/// Desplaza un bit a la izquierda y coloca `bit`; `true` si se escapa un bit.
fn fe_shl_one(value: &mut Fe, bit: u8) -> bool {
    let mut carry = u64::from(bit & 1);
    for limb in value.iter_mut().rev() {
        let next = *limb >> 63;
        *limb = (*limb << 1) | carry;
        carry = next;
    }
    carry != 0
}

/// Reduce módulo `modulus` por división larga binaria.
///
/// La invariante es la clásica: el resto parcial es siempre menor que el
/// módulo, así que tras desplazarlo un bit basta **una** resta; y si el
/// desplazamiento se lleva un bit por arriba (acarreo), hay que restar seguro.
/// La resta se hace en aritmética envolvente, que es exacta en ambos casos.
fn fe_reduce_mod(bytes: &[u8], modulus: &Fe) -> Fe {
    let mut remainder = fe_zero();
    for byte in bytes {
        for bit in (0..8).rev() {
            let carry = fe_shl_one(&mut remainder, (byte >> bit) & 1);
            if carry || fe_cmp(&remainder, modulus) != Ordering::Less {
                let (reduced, _) = fe_sub(&remainder, modulus);
                remainder = reduced;
            }
        }
    }
    remainder
}

/// Reduce un producto de 512 bits módulo `modulus`.
fn fe_reduce_wide(wide: [u64; 8], modulus: &Fe) -> Fe {
    let mut bytes = [0u8; 64];
    for (index, limb) in wide.iter().enumerate() {
        let start = 56 - 8 * index;
        bytes[start..start + 8].copy_from_slice(&limb.to_be_bytes());
    }
    fe_reduce_mod(&bytes, modulus)
}

/// Producto modular.
fn fe_mul_mod(left: &Fe, right: &Fe, modulus: &Fe) -> Fe {
    let wide = mul_wide_le(&fe_to_le(left), &fe_to_le(right));
    fe_reduce_wide(wide, modulus)
}

/// Cuadrado modular.
fn fe_sqr_mod(value: &Fe, modulus: &Fe) -> Fe {
    fe_mul_mod(value, value, modulus)
}

/// Multiplica por un factor pequeño (`8`, `2`, `3`…).
fn fe_mul_small(value: &Fe, factor: u64, modulus: &Fe) -> Fe {
    let mut scaled = fe_zero();
    scaled[3] = factor;
    fe_mul_mod(value, &scaled, modulus)
}

/// Potencia modular por cuadrado y multiplicación.
fn fe_pow_mod(base: &Fe, exponent: &Fe, modulus: &Fe) -> Fe {
    let mut result = fe_one();
    for limb in exponent.iter() {
        for bit in (0..64).rev() {
            result = fe_sqr_mod(&result, modulus);
            if (limb >> bit) & 1 == 1 {
                result = fe_mul_mod(&result, base, modulus);
            }
        }
    }
    result
}

/// Inverso multiplicativo: `a⁻¹ = a^(m−2) mod m`, válido con `m` primo.
fn fe_inv_mod(value: &Fe, modulus: &Fe) -> Fe {
    let exponent = fe_sub_small(modulus, 2);
    fe_pow_mod(value, &exponent, modulus)
}

/// Negativo modular.
fn fe_neg_mod(value: &Fe, modulus: &Fe) -> Fe {
    if fe_is_zero(value) {
        return fe_zero();
    }
    fe_sub_mod(modulus, value, modulus)
}

/// Bytes big‑endian a `Fe`.
fn fe_from_bytes(bytes: &[u8; 32]) -> Fe {
    let mut out = fe_zero();
    for (index, limb) in out.iter_mut().enumerate() {
        let start = index * 8;
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&bytes[start..start + 8]);
        *limb = u64::from_be_bytes(chunk);
    }
    out
}

/// `Fe` a bytes big‑endian.
fn fe_to_bytes(value: &Fe) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (index, limb) in value.iter().enumerate() {
        out[index * 8..index * 8 + 8].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

/// Reduce bytes big‑endian de cualquier longitud módulo el orden del grupo.
fn scalar_reduce(bytes: &[u8]) -> Fe {
    fe_reduce_mod(bytes, &N)
}

/// Escalar canónico a partir de 32 bytes: cae siempre en `[1, n−1]`.
///
/// La reducción módulo `n` deja el valor en `[0, n−1]`; el cero (probabilidad
/// 2⁻²⁵⁶) se eleva a uno en vez de abortar: la totalidad no admite excepciones.
fn scalar_from_bytes(bytes: &[u8; 32]) -> Fe {
    let reduced = scalar_reduce(bytes);
    if fe_is_zero(&reduced) {
        fe_one()
    } else {
        reduced
    }
}

/// Escalar de 32 bytes del usuario, exigido en `[1, n−1]`.
fn scalar_checked(bytes: &[u8; 32]) -> Result<Fe, BridgeError> {
    let value = fe_from_bytes(bytes);
    if fe_is_zero(&value) || fe_cmp(&value, &N) != Ordering::Less {
        return Err(BridgeError::ScalarOutOfRange);
    }
    Ok(value)
}

// ─────────────────────────────────────────────────────────────────────────
// Punto de la curva en coordenadas jacobianas
// ─────────────────────────────────────────────────────────────────────────

/// Punto en coordenadas **jacobianas** (`x/z²`, `y/z³`), reservando `z = 0` para
/// el punto del infinito: así duplicar y sumar no exigen inversiones y el coste
/// se queda en multiplicaciones modulares.
#[derive(Debug, Clone, Copy)]
struct Jacobian {
    /// Coordenada `x` proyectiva.
    x: Fe,
    /// Coordenada `y` proyectiva.
    y: Fe,
    /// Denominador común.
    z: Fe,
}

/// Constante `b = 7` de la curva `y² = x³ + 7`.
fn fe_seven() -> Fe {
    [0, 0, 0, 7]
}

impl Jacobian {
    /// Punto del infinito (elemento neutro).
    fn infinity() -> Self {
        Jacobian {
            x: fe_zero(),
            y: fe_zero(),
            z: fe_zero(),
        }
    }

    /// Generador `G` de secp256k1.
    fn generator() -> Self {
        Jacobian {
            x: GX,
            y: GY,
            z: fe_one(),
        }
    }

    /// Punto afín elevado a jacobianas (`z = 1`).
    fn from_affine(x: Fe, y: Fe) -> Self {
        Jacobian { x, y, z: fe_one() }
    }

    /// ¿Es el punto del infinito?
    fn is_infinity(&self) -> bool {
        fe_is_zero(&self.z)
    }

    /// Negativo: la curva es simétrica respecto de `y = 0`.
    fn neg(&self) -> Self {
        Jacobian {
            x: self.x,
            y: fe_neg_mod(&self.y, &P),
            z: self.z,
        }
    }

    /// Duplicación de punto (la curva tiene `a = 0`).
    fn double(&self) -> Self {
        if self.is_infinity() || fe_is_zero(&self.y) {
            return Jacobian::infinity();
        }
        let x_squared = fe_sqr_mod(&self.x, &P);
        let y_squared = fe_sqr_mod(&self.y, &P);
        let y_fourth = fe_sqr_mod(&y_squared, &P);
        let d = {
            let sum = fe_add_mod(&self.x, &y_squared, &P);
            let squared = fe_sqr_mod(&sum, &P);
            let partial = fe_sub_mod(&squared, &x_squared, &P);
            let partial = fe_sub_mod(&partial, &y_fourth, &P);
            fe_double_mod(&partial, &P)
        };
        let e = fe_mul_small(&x_squared, 3, &P);
        let f = fe_sqr_mod(&e, &P);
        let x_out = fe_sub_mod(&f, &fe_double_mod(&d, &P), &P);
        let y_out = {
            let difference = fe_sub_mod(&d, &x_out, &P);
            let scaled = fe_mul_mod(&e, &difference, &P);
            let eight_c = fe_mul_small(&y_fourth, 8, &P);
            fe_sub_mod(&scaled, &eight_c, &P)
        };
        let z_out = fe_double_mod(&fe_mul_mod(&self.y, &self.z, &P), &P);
        Jacobian {
            x: x_out,
            y: y_out,
            z: z_out,
        }
    }

    /// Suma de puntos: cubre igualdad (se duplica), opuestos (infinito) y neutro.
    fn add(&self, other: &Self) -> Self {
        if self.is_infinity() {
            return *other;
        }
        if other.is_infinity() {
            return *self;
        }
        let z1_squared = fe_sqr_mod(&self.z, &P);
        let z2_squared = fe_sqr_mod(&other.z, &P);
        let u1 = fe_mul_mod(&self.x, &z2_squared, &P);
        let u2 = fe_mul_mod(&other.x, &z1_squared, &P);
        let s1 = fe_mul_mod(&self.y, &fe_mul_mod(&other.z, &z2_squared, &P), &P);
        let s2 = fe_mul_mod(&other.y, &fe_mul_mod(&self.z, &z1_squared, &P), &P);
        if fe_cmp(&u1, &u2) == Ordering::Equal {
            if fe_cmp(&s1, &s2) == Ordering::Equal {
                return self.double();
            }
            return Jacobian::infinity();
        }
        let h = fe_sub_mod(&u2, &u1, &P);
        let i = fe_sqr_mod(&fe_double_mod(&h, &P), &P);
        let j = fe_mul_mod(&h, &i, &P);
        let r = fe_double_mod(&fe_sub_mod(&s2, &s1, &P), &P);
        let v = fe_mul_mod(&u1, &i, &P);
        let x_out = {
            let r_squared = fe_sqr_mod(&r, &P);
            let partial = fe_sub_mod(&r_squared, &j, &P);
            fe_sub_mod(&partial, &fe_double_mod(&v, &P), &P)
        };
        let y_out = {
            let difference = fe_sub_mod(&v, &x_out, &P);
            let scaled = fe_mul_mod(&r, &difference, &P);
            let s1_j = fe_mul_mod(&s1, &j, &P);
            fe_sub_mod(&scaled, &fe_double_mod(&s1_j, &P), &P)
        };
        let z_out = {
            let sum = fe_add_mod(&self.z, &other.z, &P);
            let squared = fe_sqr_mod(&sum, &P);
            let partial = fe_sub_mod(&squared, &z1_squared, &P);
            let partial = fe_sub_mod(&partial, &z2_squared, &P);
            fe_mul_mod(&partial, &h, &P)
        };
        Jacobian {
            x: x_out,
            y: y_out,
            z: z_out,
        }
    }

    /// Multiplicación escalar por doblado y suma, del bit más significativo al
    /// menos significativo (siempre 256 vueltas: el recorrido no filtra nada).
    fn mul(&self, scalar: &Fe) -> Self {
        let mut accumulator = Jacobian::infinity();
        for limb in scalar.iter() {
            for bit in (0..64).rev() {
                accumulator = accumulator.double();
                if (limb >> bit) & 1 == 1 {
                    accumulator = accumulator.add(self);
                }
            }
        }
        accumulator
    }

    /// Coordenadas afines, si el punto no es el del infinito.
    fn to_affine(self) -> Option<(Fe, Fe)> {
        if self.is_infinity() {
            return None;
        }
        let inverse = fe_inv_mod(&self.z, &P);
        let inverse_squared = fe_sqr_mod(&inverse, &P);
        let inverse_cubed = fe_mul_mod(&inverse_squared, &inverse, &P);
        Some((
            fe_mul_mod(&self.x, &inverse_squared, &P),
            fe_mul_mod(&self.y, &inverse_cubed, &P),
        ))
    }
}

/// Coordenada `y` de un punto con `x` dado y paridad pedida.
///
/// Con `p ≡ 3 (mod 4)` la raíz cuadrada de un resto es `r^((p+1)/4)`; si el
/// candidato no cuadra con el resto, el `x` no está en la curva y se rechaza.
fn recover_y(x: &Fe, odd: bool) -> Result<Fe, BridgeError> {
    let x_cubed = fe_mul_mod(x, &fe_sqr_mod(x, &P), &P);
    let rhs = fe_add_mod(&x_cubed, &fe_seven(), &P);
    let (numerator, _) = fe_add(&P, &fe_one());
    let exponent = fe_shr(&numerator, 2);
    let candidate = fe_pow_mod(&rhs, &exponent, &P);
    if fe_cmp(&fe_sqr_mod(&candidate, &P), &rhs) != Ordering::Equal {
        return Err(BridgeError::NotOnCurve);
    }
    if fe_is_even(&candidate) == odd {
        Ok(fe_neg_mod(&candidate, &P))
    } else {
        Ok(candidate)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// ECDSA determinista (RFC 6979) sobre secp256k1, con recuperación
// ─────────────────────────────────────────────────────────────────────────

/// Firma ECDSA recuperable de una transacción *legacy*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacySignature {
    /// Componente `r` (32 bytes big‑endian).
    pub r: [u8; 32],
    /// Componente `s` (32 bytes big‑endian), normalizada a la mitad inferior:
    /// es la regla de la EVM (`EIP‑2`), no una preferencia.
    pub s: [u8; 32],
    /// Identificador de recuperación: bit 0 = `y` impar, bit 1 = `x ≥ n`.
    pub recovery: u8,
}

impl LegacySignature {
    /// Valor `v` con **EIP‑155** para la cadena dada: `v = chain_id·2 + 35 + rec`.
    ///
    /// Con `chain_id = 0` se emite la forma anterior al EIP (`27`/`28`), que
    /// [`LegacyTx::decode_signed`] vuelve a leer como cadena 0.
    pub fn v(&self, chain_id: u64) -> u64 {
        if chain_id == 0 {
            27 + u64::from(self.recovery & 1)
        } else {
            chain_id * 2 + 35 + u64::from(self.recovery)
        }
    }
}

/// Generador de nonce de RFC 6979 con `HMAC‑SHA256`.
///
/// Las claves de este generador se derivan **sólo** del secreto y del mensaje:
/// la misma transacción produce siempre la misma firma, sin aleatoriedad y sin
/// estado oculto. Es lo que hace reproducible al puente.
struct NonceStream {
    /// Clave de la cadena HMAC.
    key: [u8; 32],
    /// Valor encadenado `V`.
    value: [u8; 32],
}

impl NonceStream {
    /// Inicializa `K` y `V` según RFC 6979 con `h1` = digest del mensaje.
    fn new(secret: &[u8; 32], digest: &[u8; 32]) -> Self {
        let mut key = [0u8; 32];
        let mut value = [0x01u8; 32];
        for separator in [0x00u8, 0x01u8] {
            let mut material = Vec::with_capacity(97);
            material.extend_from_slice(&value);
            material.push(separator);
            material.extend_from_slice(secret);
            material.extend_from_slice(digest);
            key = hmac_sha256(&key, &material);
            value = hmac_sha256(&key, &value);
        }
        NonceStream { key, value }
    }

    /// Siguiente candidato: `V = HMAC(K, V)` (el bloque `T` es de 32 bytes, así
    /// que el candidato cabe en un ciclo).
    fn candidate(&mut self) -> [u8; 32] {
        self.value = hmac_sha256(&self.key, &self.value);
        self.value
    }

    /// Reintento del RFC: `K = HMAC(K, V ‖ 0x00)` y `V = HMAC(K, V)`.
    fn retry(&mut self) {
        let mut material = Vec::with_capacity(33);
        material.extend_from_slice(&self.value);
        material.push(0x00);
        self.key = hmac_sha256(&self.key, &material);
        self.value = hmac_sha256(&self.key, &self.value);
    }
}

/// Firma un digest de 32 bytes con un secreto ya validado en `[1, n−1]`.
///
/// El nonce se reduce módulo `n`, variante tolerante de RFC 6979: cualquier
/// `k ∈ [1, n−1]` produce una firma válida, y el descarte estricto sólo se
/// aplicaría a `k = 0`, `r = 0` o `s = 0` (probabilidades del orden de 2⁻²⁵⁶).
/// Aun así el sondeo está acotado en [`MAX_NONCE_ATTEMPTS`]: la función termina
/// siempre, con firma o con [`BridgeError::NonceExhausted`].
fn sign_digest(secret: &[u8; 32], digest: &[u8; 32]) -> Result<LegacySignature, BridgeError> {
    let private = scalar_checked(secret)?;
    let message = scalar_reduce(digest);
    let half_order = fe_shr(&N, 1);
    let mut stream = NonceStream::new(secret, digest);
    for _ in 0..MAX_NONCE_ATTEMPTS {
        let nonce = scalar_reduce(&stream.candidate());
        if fe_is_zero(&nonce) {
            stream.retry();
            continue;
        }
        let Some((x, y)) = Jacobian::generator().mul(&nonce).to_affine() else {
            stream.retry();
            continue;
        };
        let r = scalar_reduce(&fe_to_bytes(&x));
        if fe_is_zero(&r) {
            stream.retry();
            continue;
        }
        let inverse = fe_inv_mod(&nonce, &N);
        let product = fe_mul_mod(&r, &private, &N);
        let mut s = fe_mul_mod(&inverse, &fe_add_mod(&message, &product, &N), &N);
        if fe_is_zero(&s) {
            stream.retry();
            continue;
        }
        let mut recovery =
            u8::from(!fe_is_even(&y)) | (u8::from(fe_cmp(&x, &N) != Ordering::Less) << 1);
        if fe_cmp(&s, &half_order) == Ordering::Greater {
            s = fe_sub_mod(&N, &s, &N);
            recovery ^= 1;
        }
        return Ok(LegacySignature {
            r: fe_to_bytes(&r),
            s: fe_to_bytes(&s),
            recovery,
        });
    }
    Err(BridgeError::NonceExhausted)
}

/// Recupera la dirección que firmó `digest` con la firma dada.
///
/// Es exactamente la comprobación que hace la EVM al validar `v`:
/// `Q = r⁻¹·(s·R − e·G)`, con `R` reconstruido a partir de `r` y del bit de
/// paridad. Un `r` que no produzca un punto de la curva se rechaza: no hay
/// recuperación a medias.
pub fn recover_address(
    digest: &[u8; 32],
    signature: &LegacySignature,
) -> Result<Address, BridgeError> {
    if signature.recovery > 3 {
        return Err(BridgeError::ScalarOutOfRange);
    }
    let r = fe_from_bytes(&signature.r);
    let s = fe_from_bytes(&signature.s);
    if fe_is_zero(&r)
        || fe_is_zero(&s)
        || fe_cmp(&r, &N) != Ordering::Less
        || fe_cmp(&s, &N) != Ordering::Less
    {
        return Err(BridgeError::ScalarOutOfRange);
    }
    let x = if signature.recovery & 2 == 0 {
        r
    } else {
        let (sum, overflow) = fe_add(&r, &N);
        if overflow || fe_cmp(&sum, &P) != Ordering::Less {
            return Err(BridgeError::ScalarOutOfRange);
        }
        sum
    };
    let y = recover_y(&x, signature.recovery & 1 == 1)?;
    let inverse = fe_inv_mod(&r, &N);
    let product = Jacobian::from_affine(x, y).mul(&s);
    let offset = Jacobian::generator().mul(&scalar_reduce(digest));
    let recovered = product.add(&offset.neg()).mul(&inverse);
    let Some((x_out, y_out)) = recovered.to_affine() else {
        return Err(BridgeError::PointAtInfinity);
    };
    let mut public = [0u8; 64];
    public[..32].copy_from_slice(&fe_to_bytes(&x_out));
    public[32..].copy_from_slice(&fe_to_bytes(&y_out));
    Ok(Address::from_public_key(&public))
}

/// ¿La firma sobre `digest` corresponde a `address`?
pub fn verify_digest(digest: &[u8; 32], signature: &LegacySignature, address: &Address) -> bool {
    match recover_address(digest, signature) {
        Ok(recovered) => &recovered == address,
        Err(_) => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Claves de firma y transacciones *legacy* con EIP‑155
// ─────────────────────────────────────────────────────────────────────────

/// Clave de firma secp256k1.
#[derive(Clone)]
pub struct SigningKey {
    /// Secreto de 32 bytes, siempre en `[1, n−1]`.
    secret: [u8; 32],
}

impl fmt::Debug for SigningKey {
    /// El secreto **no** se imprime jamás: un `Debug` que se cuele en un informe
    /// no debe revelar la clave, sólo el compromiso público (la dirección).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKey({})", self.address())
    }
}

impl SigningKey {
    /// Desde 32 bytes exactos, exigiendo `[1, n−1]`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BridgeError> {
        if bytes.len() != 32 {
            return Err(BridgeError::LengthMismatch {
                expected: 32,
                found: bytes.len(),
            });
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(bytes);
        scalar_checked(&secret)?;
        Ok(SigningKey { secret })
    }

    /// Desde el ADN del enjambre: **la misma semilla que identifica al nodo**.
    ///
    /// La clave sale de `HKDF‑SHA256` sobre [`golden_key`] —la primitiva del ADN
    /// y de la red— con [`SIGNING_KEY_INFO`] como contexto, y se reencuadra
    /// módulo `n`: identidad de código e identidad de firma coinciden. No falla
    /// nunca, porque el reencuadre cae en `[1, n−1]` por construcción.
    pub fn from_swarm_seed(seed: &[u8]) -> Self {
        let root = golden_key(seed);
        let material = hkdf_32(&root, SIGNING_KEY_INFO, b"identidad-de-firma");
        SigningKey {
            secret: fe_to_bytes(&scalar_from_bytes(&material)),
        }
    }

    /// Secreto crudo. Exportarlo es una decisión **explícita** del llamante, no
    /// un descuido del tipo.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret
    }

    /// Clave pública sin comprimir (`X ‖ Y`, 64 bytes).
    pub fn public_key(&self) -> Result<[u8; 64], BridgeError> {
        let scalar = scalar_checked(&self.secret)?;
        let Some((x, y)) = Jacobian::generator().mul(&scalar).to_affine() else {
            return Err(BridgeError::PointAtInfinity);
        };
        let mut public = [0u8; 64];
        public[..32].copy_from_slice(&fe_to_bytes(&x));
        public[32..].copy_from_slice(&fe_to_bytes(&y));
        Ok(public)
    }

    /// Dirección EVM correspondiente.
    pub fn address(&self) -> Address {
        match self.public_key() {
            Ok(public) => Address::from_public_key(&public),
            // Con `k ∈ [1, n−1]`, `k·G` no es nunca el infinito: la rama es
            // inalcanzable. Se degrada a la dirección cero en vez de abortar.
            Err(_) => Address([0u8; 20]),
        }
    }

    /// Firma un digest de 32 bytes ([`sign_digest`]).
    pub fn sign(&self, digest: &[u8; 32]) -> Result<LegacySignature, BridgeError> {
        sign_digest(&self.secret, digest)
    }

    /// Firma una transacción *legacy* para la cadena dada (EIP‑155).
    pub fn sign_transaction(
        &self,
        tx: &LegacyTx,
        chain_id: u64,
    ) -> Result<SignedTransaction, BridgeError> {
        let digest = tx.signing_digest(chain_id);
        let signature = self.sign(&digest)?;
        let raw = tx.encode_signed(&signature, chain_id);
        Ok(SignedTransaction {
            hash: keccak256(&raw),
            raw,
            signature,
            digest,
            sender: self.address(),
            chain_id,
        })
    }
}

/// Transacción *legacy* (tipo 0) de la EVM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyTx {
    /// Nonce de la cuenta emisora.
    pub nonce: U256,
    /// Precio del gas, en wei.
    pub gas_price: U256,
    /// Límite de gas.
    pub gas_limit: U256,
    /// Destinatario; `None` en un despliegue de contrato.
    pub to: Option<Address>,
    /// Valor transferido, en wei.
    pub value: U256,
    /// Carga útil (datos de llamada o *bytecode* de despliegue).
    pub data: Vec<u8>,
}

/// Deduce cadena y bit de recuperación desde el `v` firmado (EIP‑155).
///
/// Con EIP‑155, `v = chain_id·2 + 35 + rec`. Los valores `27`/`28` son firmas
/// anteriores al EIP (cadena 0) y se aceptan para poder leer historia antigua.
fn eip155_chain(v: &U256) -> Result<(u64, u8), BridgeError> {
    let value = v.to_u64().ok_or(BridgeError::ValueOutOfRange)?;
    if value == 27 || value == 28 {
        return Ok((0, (value - 27) as u8));
    }
    if value < 35 {
        return Err(BridgeError::ScalarOutOfRange);
    }
    let offset = value - 35;
    Ok((offset / 2, (offset % 2) as u8))
}

impl LegacyTx {
    /// Los seis campos firmables: `[nonce, gasPrice, gasLimit, to, value, data]`.
    fn fields(&self) -> Vec<RlpItem> {
        let to = match &self.to {
            Some(address) => rlp_data(address.as_bytes()),
            None => rlp_data(&[]),
        };
        vec![
            rlp_quantity(&self.nonce),
            rlp_quantity(&self.gas_price),
            rlp_quantity(&self.gas_limit),
            to,
            rlp_quantity(&self.value),
            rlp_data(&self.data),
        ]
    }

    /// Carga firmable con **EIP‑155**.
    ///
    /// Con `chain_id ≠ 0` es la lista de **nueve** elementos
    /// `[nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]`: los dos
    /// ceros finales son parte del estándar y omitirlos cambia el digest (y con
    /// él la firma). Con `chain_id = 0` se firma la forma anterior al EIP, que
    /// son sólo los seis campos de [`Self::fields`].
    pub fn signing_payload(&self, chain_id: u64) -> Vec<u8> {
        let mut fields = self.fields();
        if chain_id != 0 {
            fields.push(rlp_quantity(&U256::from_u64(chain_id)));
            fields.push(rlp_quantity(&U256::ZERO));
            fields.push(rlp_quantity(&U256::ZERO));
        }
        rlp_encode(&rlp_list(fields))
    }

    /// Digest que se firma con EIP‑155 (`keccak256` de la carga firmable).
    pub fn signing_digest(&self, chain_id: u64) -> [u8; 32] {
        keccak256(&self.signing_payload(chain_id))
    }

    /// Codificación RLP de la transacción **firmada**, con `v`, `r` y `s`.
    ///
    /// `r` y `s` se emiten como cantidades minimizadas —no como cadenas fijas de
    /// 32 bytes—, que es la forma que exige la EVM y la que produce cualquier
    /// nodo al reemitir la transacción.
    pub fn encode_signed(&self, signature: &LegacySignature, chain_id: u64) -> Vec<u8> {
        let mut fields = self.fields();
        fields.push(rlp_quantity(&U256::from_u64(signature.v(chain_id))));
        fields.push(rlp_quantity(&U256::from_be_bytes(signature.r)));
        fields.push(rlp_quantity(&U256::from_be_bytes(signature.s)));
        rlp_encode(&rlp_list(fields))
    }

    /// Decodifica una transacción *legacy* firmada: deduce la cadena, la firma y
    /// el remitente. Es el camino inverso completo (firmar → serializar →
    /// decodificar → recuperar) y el que permite auditar el puente sin red.
    pub fn decode_signed(raw: &[u8]) -> Result<SignedTransaction, BridgeError> {
        let item = rlp_decode(raw)?;
        let fields = item.as_list().ok_or(BridgeError::MalformedRlp)?;
        if fields.len() != 9 {
            return Err(BridgeError::LengthMismatch {
                expected: 9,
                found: fields.len(),
            });
        }
        let to = match fields[3].as_bytes().ok_or(BridgeError::MalformedRlp)? {
            [] => None,
            bytes => Some(Address::from_bytes(bytes)?),
        };
        let tx = LegacyTx {
            nonce: fields[0].as_u256()?,
            gas_price: fields[1].as_u256()?,
            gas_limit: fields[2].as_u256()?,
            to,
            value: fields[4].as_u256()?,
            data: fields[5]
                .as_bytes()
                .ok_or(BridgeError::MalformedRlp)?
                .to_vec(),
        };
        let (chain_id, recovery) = eip155_chain(&fields[6].as_u256()?)?;
        let signature = LegacySignature {
            r: fields[7].as_u256()?.to_bytes(),
            s: fields[8].as_u256()?.to_bytes(),
            recovery,
        };
        let digest = tx.signing_digest(chain_id);
        let sender = recover_address(&digest, &signature)?;
        Ok(SignedTransaction {
            hash: keccak256(raw),
            raw: raw.to_vec(),
            signature,
            digest,
            sender,
            chain_id,
        })
    }
}

/// Transacción firmada, lista para `eth_sendRawTransaction`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTransaction {
    /// Bytes RLP firmados: lo que se envía al nodo.
    pub raw: Vec<u8>,
    /// Hash de la transacción (`keccak256` de [`Self::raw`]).
    pub hash: [u8; 32],
    /// Firma ECDSA.
    pub signature: LegacySignature,
    /// Digest firmado.
    pub digest: [u8; 32],
    /// Remitente recuperado de la propia firma.
    pub sender: Address,
    /// Cadena para la que se firmó.
    pub chain_id: u64,
}

impl SignedTransaction {
    /// Transacción cruda en hexadecimal, como exige `eth_sendRawTransaction`.
    pub fn raw_hex(&self) -> String {
        let mut out = String::with_capacity(2 + self.raw.len() * 2);
        out.push_str("0x");
        out.push_str(&hex_encode(&self.raw));
        out
    }

    /// Hash en hexadecimal con `0x`.
    pub fn hash_hex(&self) -> String {
        let mut out = String::with_capacity(66);
        out.push_str("0x");
        out.push_str(&hex_encode(&self.hash));
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Red · extremos y transporte enchufable (cero `unsafe`, cero dependencias)
// ─────────────────────────────────────────────────────────────────────────

/// Puerto del RPC público que se asume cuando el extremo no lo declara.
pub const RPC_DEFAULT_PORT: u16 = 8545;
/// Techo de la cabecera HTTP admitida (el cuerpo lo acota [`MAX_RPC_BYTES`]).
pub const MAX_HTTP_HEADER_BYTES: usize = 8 * 1024;
/// Registros de aplicación admitidos como máximo por respuesta camuflada.
///
/// Acota el bucle de lectura del canal del enjambre aunque el par no declare la
/// longitud del cuerpo: el bucle **termina siempre**.
pub const MAX_SWARM_RECORDS: usize = 256;

/// Traduce un fallo de E/S a [`BridgeError`]: la red nunca entra en pánico.
fn unavailable(why: impl fmt::Display) -> BridgeError {
    BridgeError::TransportUnavailable(why.to_string())
}

/// Esquema del extremo consultado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// HTTP en claro: lo habla [`HttpTransport`].
    Http,
    /// HTTPS: sólo lo sirve el enjambre, vía [`SwarmTransport`].
    Https,
    /// Sin esquema declarado (`host:puerto`), como [`BSC_MAINNET_ADDRESS`].
    Bare,
}

impl Scheme {
    /// Etiqueta estable del esquema.
    pub fn label(&self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
            Scheme::Bare => "host:puerto",
        }
    }

    /// Puerto que se asume cuando el extremo no lo declara.
    pub fn default_port(&self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
            Scheme::Bare => RPC_DEFAULT_PORT,
        }
    }
}

/// Extremo HTTP de un nodo: esquema, host, puerto y ruta del RPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// Esquema declarado.
    pub scheme: Scheme,
    /// Nombre DNS o dirección del nodo (sin puerto).
    pub host: String,
    /// Puerto TCP.
    pub port: u16,
    /// Ruta del RPC (`/` en los nodos públicos).
    pub path: String,
}

impl Endpoint {
    /// Extremo del RPC público de BSC mainnet ([`BSC_MAINNET_ADDRESS`]).
    ///
    /// Es una constante del propio módulo, así que no puede fallar en la
    /// práctica; el `Result` se declara igualmente para no fingir totalidad.
    pub fn mainnet() -> Result<Self, BridgeError> {
        Endpoint::parse(BSC_MAINNET_ADDRESS)
    }

    /// Extremo canónico en `https` ([`BSC_MAINNET_ENDPOINT`]), el del enjambre.
    pub fn swarm_mainnet() -> Result<Self, BridgeError> {
        Endpoint::parse(BSC_MAINNET_ENDPOINT)
    }

    /// Extremo desde texto: `http://host:puerto/ruta`, `https://host/ruta` o
    /// simplemente `host:puerto`.
    ///
    /// Una ruta vacía se normaliza a `/` y un extremo sin puerto recibe el del
    /// esquema ([`RPC_DEFAULT_PORT`] si no hay esquema). Las direcciones IPv6
    /// literales quedan fuera: los nodos RPC se sirven por nombre.
    pub fn parse(text: &str) -> Result<Self, BridgeError> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err(unavailable("extremo vacío"));
        }
        let (scheme, rest) = match trimmed.split_once("://") {
            Some((label, rest)) => {
                let scheme = match label.to_ascii_lowercase().as_str() {
                    "http" => Scheme::Http,
                    "https" => Scheme::Https,
                    other => return Err(unavailable(format!("esquema «{other}» no soportado"))),
                };
                (scheme, rest)
            }
            None => (Scheme::Bare, trimmed),
        };
        let (authority, path) = match rest.split_once('/') {
            Some((authority, path)) => (authority, format!("/{path}")),
            None => (rest, BSC_RPC_PATH.to_string()),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => {
                let port = port.parse::<u16>().map_err(|_| {
                    unavailable(format!("puerto «{port}» fuera del rango de 16 bits"))
                })?;
                (host, port)
            }
            None => (authority, scheme.default_port()),
        };
        if host.is_empty() {
            return Err(unavailable("host vacío"));
        }
        Ok(Endpoint {
            scheme,
            host: host.to_string(),
            port,
            path,
        })
    }

    /// Autoridad `host:puerto`: la cabecera `Host` del HTTP/1.1.
    pub fn authority(&self) -> String {
        let host = &self.host;
        let port = self.port;
        format!("{host}:{port}")
    }

    /// Petición `POST` completa (cabecera y cuerpo) del RPC.
    ///
    /// `Connection: close` es deliberado: una petición, una conexión. No hay
    /// *keep-alive* porque no hay estado que conservar entre llamadas.
    pub fn http_post(&self, body: &[u8]) -> Vec<u8> {
        let path = &self.path;
        let authority = self.authority();
        let length = body.len();
        let head = format!(
            "POST {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: bara-aether-omega/1.0\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
        );
        let mut out = Vec::with_capacity(head.len() + body.len());
        out.extend_from_slice(head.as_bytes());
        out.extend_from_slice(body);
        out
    }

    /// Descripción de una línea del extremo.
    pub fn describe(&self) -> String {
        let authority = self.authority();
        let path = &self.path;
        match self.scheme {
            Scheme::Bare => format!("{authority}{path}"),
            named => format!("{}://{authority}{path}", named.label()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// HTTP/1.1 · separación estricta de cabecera y cuerpo
// ─────────────────────────────────────────────────────────────────────────

/// Separa la cabecera del cuerpo de un mensaje HTTP crudo.
///
/// Admite el terminador canónico `\r\n\r\n` y el tolerante `\n\n`; si ambos
/// aparecen, manda el primero. Sin terminador no hay mensaje completo: se
/// devuelve `None` en vez de adivinar.
fn split_headers(raw: &[u8]) -> Option<(&[u8], &[u8])> {
    let canonical = raw
        .windows(4)
        .position(|window| window == &b"\r\n\r\n"[..])
        .map(|at| (at + 4, at));
    let lenient = raw
        .windows(2)
        .position(|window| window == &b"\n\n"[..])
        .map(|at| (at + 2, at));
    let (body_start, head_end) = match (canonical, lenient) {
        (Some(left), Some(right)) => {
            if left.1 <= right.1 {
                left
            } else {
                right
            }
        }
        (Some(found), None) | (None, Some(found)) => found,
        (None, None) => return None,
    };
    Some((&raw[..head_end], &raw[body_start..]))
}

/// Respuesta HTTP completa con su longitud declarada.
///
/// Es la forma exacta que produce un nodo RPC, así que es también la que usan
/// el transporte de guion y las pruebas: lo que se prueba es el analizador
/// real, no un atajo.
pub fn http_response(code: u16, reason: &str, body: &str) -> String {
    let length = body.len();
    format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{body}"
    )
}

/// Longitud declarada del cuerpo, si la cabecera la declara y es admisible.
///
/// Un `Content-Length` no numérico o mayor que [`MAX_RPC_BYTES`] se rechaza
/// aquí, y `Transfer-Encoding: chunked` también: el puente no implementa el
/// troceado y prefiere declararlo antes que aceptar una respuesta a medias.
fn declared_body_len(head: &str) -> Result<Option<usize>, BridgeError> {
    let mut declared = None;
    for line in head.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "content-length" => {
                if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(BridgeError::HttpMalformed("content-length no numérico"));
                }
                let length = value
                    .parse::<usize>()
                    .map_err(|_| BridgeError::HttpMalformed("content-length fuera de rango"))?;
                if length > MAX_RPC_BYTES {
                    return Err(BridgeError::JsonInvalid);
                }
                declared = Some(length);
            }
            "transfer-encoding" if value.to_ascii_lowercase().contains("chunked") => {
                return Err(BridgeError::HttpMalformed(
                    "transfer-encoding chunked no soportado",
                ));
            }
            _ => {}
        }
    }
    Ok(declared)
}

/// Cuerpo de una respuesta HTTP/1.1, con la forma comprobada de verdad.
///
/// Sólo `200` es aceptable: cualquier otro código se declara
/// ([`BridgeError::HttpStatus`]) sin mirar el cuerpo. La longitud declarada se
/// respeta —una respuesta truncada se rechaza— y el cuerpo debe ser UTF‑8.
fn parse_http_response(raw: &[u8]) -> Result<String, BridgeError> {
    let (head_bytes, body_bytes) =
        split_headers(raw).ok_or(BridgeError::HttpMalformed("cabecera HTTP incompleta"))?;
    if head_bytes.len() > MAX_HTTP_HEADER_BYTES {
        return Err(BridgeError::HttpMalformed("cabecera HTTP demasiado larga"));
    }
    let head = std::str::from_utf8(head_bytes)
        .map_err(|_| BridgeError::HttpMalformed("cabecera HTTP no es UTF-8"))?;
    let status = head
        .lines()
        .next()
        .ok_or(BridgeError::HttpMalformed("línea de estado ausente"))?;
    let mut parts = status.split_whitespace();
    let version = parts
        .next()
        .ok_or(BridgeError::HttpMalformed("línea de estado ausente"))?;
    if !version.starts_with("HTTP/1.") {
        return Err(BridgeError::HttpMalformed("versión distinta de HTTP/1.x"));
    }
    let code_text = parts
        .next()
        .ok_or(BridgeError::HttpMalformed("código de estado ausente"))?;
    let code = code_text
        .parse::<u16>()
        .map_err(|_| BridgeError::HttpMalformed("código de estado no numérico"))?;
    if code != 200 {
        return Err(BridgeError::HttpStatus(code));
    }
    let body = match declared_body_len(head)? {
        Some(length) => body_bytes
            .get(..length)
            .ok_or(BridgeError::HttpMalformed("cuerpo HTTP truncado"))?,
        None => body_bytes,
    };
    if body.len() > MAX_RPC_BYTES {
        return Err(BridgeError::JsonInvalid);
    }
    let text = std::str::from_utf8(body).map_err(|_| BridgeError::JsonInvalid)?;
    Ok(text.to_string())
}

// ─────────────────────────────────────────────────────────────────────────
// Transporte enchufable
// ─────────────────────────────────────────────────────────────────────────

/// Transporte del puente: entrega un cuerpo JSON‑RPC y devuelve el cuerpo de la
/// respuesta HTTP.
///
/// Es la **única** dependencia del puente con el exterior. Lo cumplen
/// [`HttpTransport`] (zócalo TCP en claro), [`SwarmTransport`] (canal camuflado
/// del enjambre) y [`LoopbackTransport`] (guion en proceso, para pruebas y
/// demostraciones sin red).
pub trait Transport {
    /// Etiqueta corta del transporte (aparece en los informes).
    fn label(&self) -> &str;

    /// Entrega un cuerpo JSON‑RPC y devuelve el cuerpo de la respuesta.
    fn exchange(&mut self, body: &str) -> Result<String, BridgeError>;

    /// Extremo al que apunta el transporte, si es un único nodo.
    fn endpoint(&self) -> Option<&Endpoint> {
        None
    }

    /// Peticiones ya entregadas, si el transporte las conserva.
    ///
    /// La trazabilidad es opcional: el puente no exige memoria histórica, sólo
    /// que lo enviado se pueda auditar cuando el transporte la guarde.
    fn log(&self) -> &[String] {
        &[]
    }
}

/// Nombre del transporte en el diagrama de flujo del módulo.
pub use self::Transport as RpcTransport;

/// HTTP/1.1 en claro sobre `std::net::TcpStream` (cero `unsafe`).
///
/// Una conexión por petición, con presupuesto de espera en lectura y escritura:
/// si el nodo no contesta, se declara [`BridgeError::TransportUnavailable`] en
/// vez de esperar indefinidamente. Aquí no hay TLS a propósito: el canal
/// cifrado del núcleo es el del enjambre ([`SwarmTransport`]), no un añadido
/// de terceros.
pub struct HttpTransport {
    endpoint: Endpoint,
    timeout_ms: u64,
}

impl HttpTransport {
    /// Transporte hacia un extremo dado.
    pub fn new(endpoint: Endpoint) -> Self {
        HttpTransport {
            endpoint,
            timeout_ms: HTTP_TIMEOUT_MS,
        }
    }

    /// Transporte desde texto (`host:puerto`, `http://…`).
    pub fn from_url(url: &str) -> Result<Self, BridgeError> {
        Ok(HttpTransport::new(Endpoint::parse(url)?))
    }

    /// Transporte hacia el RPC público de BSC mainnet.
    pub fn mainnet() -> Result<Self, BridgeError> {
        Ok(HttpTransport::new(Endpoint::mainnet()?))
    }

    /// Cambia el presupuesto de espera, en milisegundos.
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Presupuesto de espera vigente, en milisegundos.
    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }
}

impl Transport for HttpTransport {
    fn label(&self) -> &str {
        "http"
    }

    fn endpoint(&self) -> Option<&Endpoint> {
        Some(&self.endpoint)
    }

    fn exchange(&mut self, body: &str) -> Result<String, BridgeError> {
        let request = self.endpoint.http_post(body.as_bytes());
        let address = (self.endpoint.host.as_str(), self.endpoint.port);
        let mut stream = TcpStream::connect(address).map_err(unavailable)?;
        let budget = Duration::from_millis(self.timeout_ms);
        stream.set_read_timeout(Some(budget)).map_err(unavailable)?;
        stream
            .set_write_timeout(Some(budget))
            .map_err(unavailable)?;
        let _ = stream.set_nodelay(true);
        stream.write_all(&request).map_err(unavailable)?;
        stream.flush().map_err(unavailable)?;
        let cap = (MAX_RPC_BYTES + MAX_HTTP_HEADER_BYTES) as u64;
        let mut raw = Vec::new();
        (&mut stream)
            .take(cap)
            .read_to_end(&mut raw)
            .map_err(unavailable)?;
        parse_http_response(&raw)
    }
}
// ─────────────────────────────────────────────────────────────────────────
// Canal camuflado del enjambre
// ─────────────────────────────────────────────────────────────────────────

/// RPC sobre el canal camuflado del enjambre (TLS 1.3 propio).
///
/// El apretón de manos es el de [`HttpsSession`] —saludo camuflado con marca de
/// enjambre, eco del servidor verificado, secreto X25519 y claves derivadas— y
/// la petición viaja como **registro de aplicación** sellado. Exige un par Bara
/// al otro lado (un relevo del enjambre que sirva el RPC): contra un servidor
/// ajeno, [`HttpsSession::connect`] no cuadra el eco y no hay sesión.
///
/// Límite declarado: la sesión llega hasta el `ServerHello`, de modo que las
/// claves de aplicación se derivan del transcript disponible (`ClientHello ‖
/// ServerHello`) tal como expone [`HttpsSession::application_keys_with`]; el
/// `Finished` del par no se verifica en esta ruta.
pub struct SwarmTransport {
    endpoint: Endpoint,
    session: HttpsSession,
}

impl SwarmTransport {
    /// Abre el canal camuflado hacia un extremo `https`.
    pub fn connect(endpoint: Endpoint, seed: &[u8]) -> Result<Self, BridgeError> {
        if endpoint.scheme != Scheme::Https {
            return Err(unavailable("el canal camuflado exige un extremo https"));
        }
        let profile = CamouflageProfile::swarm(&endpoint.host);
        let address = endpoint.authority();
        let session = HttpsSession::connect(&address, profile, seed)
            .ok_or_else(|| unavailable("apretón camuflado rechazado por el par"))?;
        Ok(SwarmTransport { endpoint, session })
    }

    /// Abre el canal camuflado desde texto (`https://host/ruta`).
    pub fn from_url(url: &str, seed: &[u8]) -> Result<Self, BridgeError> {
        SwarmTransport::connect(Endpoint::parse(url)?, seed)
    }

    /// ¿El saludo enviado lleva una marca de enjambre válida?
    pub fn is_swarm_member(&self) -> bool {
        self.session.is_swarm_member()
    }

    /// Descripción de una línea de la sesión camuflada.
    pub fn describe(&self) -> String {
        self.session.describe()
    }
}

impl Transport for SwarmTransport {
    fn label(&self) -> &str {
        "enjambre"
    }

    fn endpoint(&self) -> Option<&Endpoint> {
        Some(&self.endpoint)
    }

    fn exchange(&mut self, body: &str) -> Result<String, BridgeError> {
        let request = self.endpoint.http_post(body.as_bytes());
        if self
            .session
            .send_record(CT_APPLICATION_DATA, &request)
            .is_none()
        {
            return Err(unavailable("el par cerró el canal al enviar"));
        }
        let mut wire = Vec::new();
        let mut seen = 0;
        while seen < MAX_SWARM_RECORDS {
            seen += 1;
            let (kind, payload) = self
                .session
                .recv_record()
                .ok_or_else(|| unavailable("el par no respondió por el canal camuflado"))?;
            match kind {
                CT_ALERT => return Err(unavailable("alerta TLS del par")),
                CT_APPLICATION_DATA => wire.extend_from_slice(&payload),
                _ => continue,
            }
            if wire.len() > MAX_RPC_BYTES + MAX_HTTP_HEADER_BYTES {
                return Err(BridgeError::JsonInvalid);
            }
            if body_is_complete(&wire)? {
                break;
            }
        }
        parse_http_response(&wire)
    }
}

/// ¿Está ya completo el cuerpo declarado en el mensaje acumulado?
///
/// Sin `Content-Length` no hay forma de saberlo desde fuera, así que se
/// devuelve `false` y el llamante sigue leyendo hasta agotar su presupuesto de
/// registros: el bucle es acotado por construcción.
fn body_is_complete(wire: &[u8]) -> Result<bool, BridgeError> {
    let Some((head, body)) = split_headers(wire) else {
        return Ok(false);
    };
    let Ok(head) = std::str::from_utf8(head) else {
        return Ok(false);
    };
    match declared_body_len(head)? {
        Some(length) => Ok(body.len() >= length),
        None => Ok(false),
    }
}
// ─────────────────────────────────────────────────────────────────────────
// Transporte de guion (en proceso) · el bucle local de las pruebas
// ─────────────────────────────────────────────────────────────────────────

/// Transporte en proceso con respuestas **guionadas**.
///
/// No hay zócalos ni relojes: la misma cola de respuestas produce siempre los
/// mismos resultados, de modo que permite ejercitar el cliente entero —sobre
/// conservado, longitud declarada, errores JSON‑RPC— sin tocar la red. Es el
/// equivalente de [`LoopbackIngress`](crate::immunity_gateway::LoopbackIngress)
/// en el plano del transporte.
#[derive(Debug, Clone)]
pub struct LoopbackTransport {
    endpoint: Endpoint,
    pending: VecDeque<String>,
    sent: Vec<String>,
}

impl Default for LoopbackTransport {
    fn default() -> Self {
        LoopbackTransport::new()
    }
}

impl LoopbackTransport {
    /// Transporte de guion apuntando a un extremo en memoria.
    pub fn new() -> Self {
        LoopbackTransport::with_endpoint(Endpoint {
            scheme: Scheme::Http,
            host: "memoria.local".to_string(),
            port: RPC_DEFAULT_PORT,
            path: BSC_RPC_PATH.to_string(),
        })
    }

    /// Transporte de guion con un extremo declarado.
    pub fn with_endpoint(endpoint: Endpoint) -> Self {
        LoopbackTransport {
            endpoint,
            pending: VecDeque::new(),
            sent: Vec::new(),
        }
    }

    /// Encola una respuesta HTTP cruda; devuelve cuántas quedan pendientes.
    pub fn push_response(&mut self, response: &str) -> usize {
        self.pending.push_back(response.to_string());
        self.pending.len()
    }

    /// Encola una respuesta `200` con su longitud declarada.
    pub fn push_ok(&mut self, body: &str) -> usize {
        self.push_response(&http_response(200, "OK", body))
    }

    /// Encola una respuesta con un código de estado explícito.
    pub fn push_status(&mut self, code: u16, body: &str) -> usize {
        self.push_response(&http_response(code, "GUION", body))
    }

    /// Respuestas aún pendientes.
    pub fn queued(&self) -> usize {
        self.pending.len()
    }

    /// Cuerpos JSON‑RPC entregados, en orden.
    pub fn requests(&self) -> &[String] {
        &self.sent
    }
}

impl Transport for LoopbackTransport {
    fn label(&self) -> &str {
        "guion"
    }

    fn endpoint(&self) -> Option<&Endpoint> {
        Some(&self.endpoint)
    }

    fn exchange(&mut self, body: &str) -> Result<String, BridgeError> {
        self.sent.push(body.to_string());
        let response = self
            .pending
            .pop_front()
            .ok_or_else(|| unavailable("el guion se agotó: no hay respuesta preparada"))?;
        parse_http_response(response.as_bytes())
    }

    fn log(&self) -> &[String] {
        &self.sent
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Sobre JSON‑RPC 2.0 (texto exacto, sin copias divergentes)
// ─────────────────────────────────────────────────────────────────────────

/// Código JSON‑RPC de «petición inválida» (`-32600`).
pub const RPC_INVALID_REQUEST: i64 = -32600;
/// Código JSON‑RPC de error del servidor (`-32000`).
pub const RPC_SERVER_ERROR: i64 = -32000;

/// Escapa un texto como cadena JSON (comillas, control y barra invertida).
///
/// El puente escribe sus propios sobres en vez de tirar de una biblioteca de
/// serialización: así el texto que viaja se puede leer en el código.
pub fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            control if control < ' ' => {
                let code = control as u32;
                out.push_str(&format!("\\u{code:04x}"));
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Array JSON de cadenas.
pub fn json_array(items: &[&str]) -> String {
    let mut out = String::from("[");
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&json_escape(item));
    }
    out.push(']');
    out
}

/// Objeto JSON de campos de texto, en el orden dado.
pub fn json_object(fields: &[(&str, &str)]) -> String {
    let mut out = String::from("{");
    for (index, (key, value)) in fields.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&json_escape(key));
        out.push(':');
        out.push_str(&json_escape(value));
    }
    out.push('}');
    out
}

/// Texto hexadecimal con `0x` (el que exige la EVM en los parámetros).
pub fn hex_data(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    out.push_str(&hex_encode(bytes));
    out
}

/// Petición JSON‑RPC 2.0 con el sobre ya formado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcCall {
    /// Identificador correlativo (la respuesta debe traer el mismo).
    pub id: u64,
    /// Método consultado (`eth_getBalance`, `eth_call`, …).
    pub method: String,
    /// Array de parámetros **ya serializado** en JSON.
    pub params: String,
}

impl RpcCall {
    /// Petición cuyos parámetros son cadenas.
    pub fn new(id: u64, method: &str, params: &[&str]) -> Self {
        RpcCall::with_params(id, method, &json_array(params))
    }

    /// Petición con el array de parámetros ya serializado (objetos incluidos).
    pub fn with_params(id: u64, method: &str, params: &str) -> Self {
        RpcCall {
            id,
            method: method.to_string(),
            params: params.to_string(),
        }
    }

    /// Cuerpo JSON exacto que viaja por el cable.
    pub fn body(&self) -> String {
        let id = self.id;
        let method = json_escape(&self.method);
        let params = &self.params;
        format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":{method},\"params\":{params}}}")
    }
}

/// Extrae `result` de un sobre JSON‑RPC 2.0 ya analizado.
///
/// El sobre se inspecciona campo a campo: `jsonrpc` debe ser `2.0`, `id` debe
/// coincidir con el de la petición y un `error` no nulo tiene prioridad sobre
/// cualquier `result`. Nada de esto es cosmético: un identificador cruzado
/// significaría que la respuesta no es de esta llamada y nadie debe leerla.
fn rpc_result(json: &Json, id: u64) -> Result<&Json, BridgeError> {
    if json.as_object().is_none() {
        return Err(BridgeError::RpcError {
            code: RPC_INVALID_REQUEST,
            message: "el sobre de respuesta no es un objeto JSON".to_string(),
        });
    }
    let version = json
        .member("jsonrpc")
        .ok_or(BridgeError::JsonMissingField("jsonrpc"))?;
    if version.as_text() != Some("2.0") {
        return Err(BridgeError::RpcError {
            code: RPC_INVALID_REQUEST,
            message: "versión JSON-RPC distinta de 2.0".to_string(),
        });
    }
    let returned = json
        .member("id")
        .ok_or(BridgeError::JsonMissingField("id"))?;
    let returned = returned.as_number().ok_or(BridgeError::RpcError {
        code: RPC_INVALID_REQUEST,
        message: "identificador de respuesta no numérico".to_string(),
    })?;
    if returned < 0.0 || returned.trunc() != returned || returned as u64 != id {
        return Err(BridgeError::RpcError {
            code: RPC_INVALID_REQUEST,
            message: format!("respuesta con identificador {returned} y no {id}"),
        });
    }
    if let Some(error) = json.member("error") {
        if !matches!(error, Json::Null) {
            let code = error
                .member("code")
                .and_then(Json::as_number)
                .map_or(RPC_SERVER_ERROR, |value| value as i64);
            let message = error
                .member("message")
                .and_then(Json::as_text)
                .unwrap_or("sin mensaje")
                .to_string();
            return Err(BridgeError::RpcError { code, message });
        }
    }
    let result = json
        .member("result")
        .ok_or(BridgeError::JsonMissingField("result"))?;
    if matches!(result, Json::Null) {
        return Err(BridgeError::NoResult);
    }
    Ok(result)
}

/// Texto exacto de un `result` (el sobre debe traer una cadena).
///
/// Un `result` con otra forma —número, objeto, secuencia— no es un fallo del
/// medio sino del contenido, y se declara [`BridgeError::JsonInvalid`].
fn text_of(value: &Json) -> Result<String, BridgeError> {
    value
        .as_text()
        .map(str::to_string)
        .ok_or(BridgeError::JsonInvalid)
}

/// Cantidad de 256 bits de un `result` hexadecimal.
fn quantity_of(value: &Json) -> Result<U256, BridgeError> {
    U256::from_hex(&text_of(value)?)
}

/// Datos hexadecimales (longitud par) de un `result`.
fn data_of(value: &Json) -> Result<Vec<u8>, BridgeError> {
    hex_decode(&text_of(value)?)
}

/// Hash de 32 bytes de un `result` hexadecimal.
fn hash_of(value: &Json) -> Result<[u8; 32], BridgeError> {
    let bytes = data_of(value)?;
    if bytes.len() != 32 {
        return Err(BridgeError::LengthMismatch {
            expected: 32,
            found: bytes.len(),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Parámetros de las consultas de estado: `["0x…","latest"]`.
fn endpoint_params(address: &str) -> String {
    let quoted = json_escape(address);
    format!("[{quoted},\"latest\"]")
}

/// Parámetros de `eth_call`: `[{"to":"0x…","data":"0x…"},"latest"]`.
fn contract_params(to: &Address, data: &[u8]) -> String {
    let target = to.to_hex();
    let payload = hex_data(data);
    let object = json_object(&[("to", &target), ("data", &payload)]);
    format!("[{object},\"latest\"]")
}
// ─────────────────────────────────────────────────────────────────────────
// Cliente JSON‑RPC
// ─────────────────────────────────────────────────────────────────────────

/// Cliente JSON‑RPC de BSC sobre un [`Transport`] enchufable.
///
/// No guarda estado de la cadena: cada llamada es una petición con su
/// identificador correlativo y el sobre de la respuesta se verifica entero
/// antes de que nadie lea un solo campo. Cambiar de medio —HTTP en claro,
/// enjambre, guion— no cambia ni una línea del resto del puente.
pub struct BscClient {
    transport: Box<dyn Transport>,
    next_id: u64,
}

impl BscClient {
    /// Cliente sobre un transporte cualquiera.
    pub fn new<T: Transport + 'static>(transport: T) -> Self {
        BscClient::boxed(Box::new(transport))
    }

    /// Cliente sobre un transporte ya encapsulado.
    pub fn boxed(transport: Box<dyn Transport>) -> Self {
        BscClient {
            transport,
            next_id: 1,
        }
    }

    /// Etiqueta del transporte en uso.
    pub fn transport_label(&self) -> &str {
        self.transport.label()
    }

    /// Extremo del transporte, si apunta a un solo nodo.
    pub fn endpoint(&self) -> Option<&Endpoint> {
        self.transport.endpoint()
    }

    /// Peticiones ya entregadas (trazabilidad del transporte).
    pub fn log(&self) -> &[String] {
        self.transport.log()
    }

    /// Identificador que llevará la próxima petición.
    pub fn next_id(&self) -> u64 {
        self.next_id
    }

    /// Petición completa: sobre, transporte, análisis y verificación.
    ///
    /// Devuelve `(identificador, cuerpo crudo, result)`. El cuerpo crudo se
    /// conserva porque es la evidencia original del nodo y acaba siendo la
    /// carga que aísla la puerta de inmunidad.
    fn call_envelope(
        &mut self,
        method: &str,
        params: &str,
    ) -> Result<(u64, String, Json), BridgeError> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let call = RpcCall::with_params(id, method, params);
        let body = self.transport.exchange(&call.body())?;
        let json = parse_json(&body).ok_or(BridgeError::JsonInvalid)?;
        let result = rpc_result(&json, id)?.clone();
        Ok((id, body, result))
    }

    /// `result` de una petición con el array de parámetros ya serializado.
    pub fn call(&mut self, method: &str, params: &str) -> Result<String, BridgeError> {
        let (_id, _body, result) = self.call_envelope(method, params)?;
        text_of(&result)
    }

    /// `result` de una petición cuyos parámetros son cadenas.
    pub fn call_params(&mut self, method: &str, params: &[&str]) -> Result<String, BridgeError> {
        let payload = json_array(params);
        self.call(method, &payload)
    }

    /// `result` como cantidad de 256 bits.
    pub fn call_quantity(&mut self, method: &str, params: &str) -> Result<U256, BridgeError> {
        let (_id, _body, result) = self.call_envelope(method, params)?;
        quantity_of(&result)
    }

    /// `result` como datos hexadecimales.
    pub fn call_data(&mut self, method: &str, params: &str) -> Result<Vec<u8>, BridgeError> {
        let (_id, _body, result) = self.call_envelope(method, params)?;
        data_of(&result)
    }

    /// `eth_chainId`: cadena en la que está configurado el nodo.
    pub fn chain_id(&mut self) -> Result<u64, BridgeError> {
        self.call_quantity("eth_chainId", "[]")?
            .to_u64()
            .ok_or(BridgeError::ValueOutOfRange)
    }

    /// `eth_blockNumber`: altura del último bloque.
    pub fn block_number(&mut self) -> Result<u64, BridgeError> {
        self.call_quantity("eth_blockNumber", "[]")?
            .to_u64()
            .ok_or(BridgeError::ValueOutOfRange)
    }

    /// `eth_gasPrice`: precio del gas sugerido por el nodo.
    pub fn gas_price(&mut self) -> Result<U256, BridgeError> {
        self.call_quantity("eth_gasPrice", "[]")
    }

    /// `eth_getBalance`: saldo de una cuenta en el último bloque.
    pub fn balance(&mut self, holder: &Address) -> Result<U256, BridgeError> {
        let address = holder.to_hex();
        self.call_quantity("eth_getBalance", &endpoint_params(&address))
    }

    /// `eth_getTransactionCount`: `nonce` de una cuenta.
    ///
    /// Es el valor que exige [`LegacyTx::signing_digest`] antes de firmar: sin
    /// él la transacción se rechaza por repetida.
    pub fn nonce(&mut self, holder: &Address) -> Result<U256, BridgeError> {
        let address = holder.to_hex();
        self.call_quantity("eth_getTransactionCount", &endpoint_params(&address))
    }

    /// `eth_call`: llamada de sólo lectura a un contrato.
    pub fn call_contract(&mut self, to: &Address, data: &[u8]) -> Result<Vec<u8>, BridgeError> {
        let params = contract_params(to, data);
        self.call_data("eth_call", &params)
    }

    /// Saldo BEP‑20 de un tenedor (`balanceOf` por `eth_call`).
    pub fn token_balance(
        &mut self,
        token: &Address,
        holder: &Address,
    ) -> Result<U256, BridgeError> {
        let params = contract_params(token, &balance_of_call(holder));
        decode_word(&self.call_data("eth_call", &params)?)
    }

    /// `eth_sendRawTransaction`: difunde una transacción ya firmada.
    pub fn send_raw_transaction(&mut self, raw: &[u8]) -> Result<[u8; 32], BridgeError> {
        let payload = hex_data(raw);
        let params = json_array(&[&payload]);
        let (_id, _body, result) = self.call_envelope("eth_sendRawTransaction", &params)?;
        hash_of(&result)
    }

    /// Difunde una transacción firmada ([`SignedTransaction`]).
    pub fn broadcast(&mut self, transaction: &SignedTransaction) -> Result<[u8; 32], BridgeError> {
        self.send_raw_transaction(&transaction.raw)
    }
}
// ─────────────────────────────────────────────────────────────────────────
// Dato exacto del nodo
// ─────────────────────────────────────────────────────────────────────────

/// Dato devuelto por el nodo: el sobre íntegro **y** el `result` aislado.
///
/// Se conserva el texto exacto porque es la única evidencia disponible: el
/// puente no valida bloques ni ejecuta la EVM, así que la verdad la aporta el
/// nodo y lo que el núcleo hace con ella es aislarla, medirla y sellarla.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BscDatum {
    /// Método JSON‑RPC que lo produjo.
    pub method: String,
    /// Identificador de la petición.
    pub id: u64,
    /// Etiqueta del transporte que lo trajo.
    pub transport: String,
    /// Cuerpo JSON‑RPC íntegro, tal cual llegó del nodo.
    pub body: String,
    /// Texto exacto del campo `result`.
    pub text: String,
    /// Cantidad de 256 bits, si el texto es una cantidad EVM (`0x…`).
    pub quantity: Option<U256>,
    /// Bytes, si el texto es hexadecimal de longitud par.
    pub data: Vec<u8>,
}

impl BscDatum {
    /// Decodifica el texto exacto de un `result` hexadecimal.
    ///
    /// Una cantidad con número impar de dígitos (`0x1b4`) es una cantidad
    /// legítima pero **no** tiene forma de bytes canónica, así que deja `data`
    /// vacío; un texto sin prefijo `0x`, o que no sea hexadecimal, se rechaza
    /// con [`BridgeError::HexInvalid`].
    pub fn decode(
        method: &str,
        id: u64,
        transport: &str,
        body: &str,
        text: &str,
    ) -> Result<Self, BridgeError> {
        let digits = strip_hex_prefix(text);
        if digits.len() == text.len() {
            return Err(BridgeError::HexInvalid);
        }
        let data = hex_decode(text).unwrap_or_default();
        let quantity = U256::from_hex(text).ok();
        if data.is_empty() && quantity.is_none() {
            return Err(BridgeError::HexInvalid);
        }
        Ok(BscDatum {
            method: method.to_string(),
            id,
            transport: transport.to_string(),
            body: body.to_string(),
            text: text.to_string(),
            quantity,
            data,
        })
    }

    /// Digest SHA‑256 del texto exacto del dato.
    ///
    /// Es la huella con la que se puede citar el dato —o compararlo con otro—
    /// sin copiarlo entero.
    pub fn digest(&self) -> [u8; 32] {
        sha256(self.text.as_bytes())
    }

    /// Huella del dato en hexadecimal corto.
    pub fn fingerprint(&self) -> String {
        short_hex(&self.digest()[..8])
    }

    /// Palabra ABI (32 bytes) del dato.
    pub fn word(&self) -> Result<U256, BridgeError> {
        decode_word(&self.data)
    }
    /// Decimal del dato, si es una cantidad.
    pub fn to_dec(&self) -> Option<String> {
        self.quantity.as_ref().map(U256::to_dec)
    }

    /// Descripción de una línea.
    pub fn describe(&self) -> String {
        let method = &self.method;
        let id = self.id;
        let bytes = self.data.len();
        let transport = &self.transport;
        let fingerprint = self.fingerprint();
        format!("{method} · id {id} · {bytes} B · {transport} · huella {fingerprint}")
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Consulta tipada
// ─────────────────────────────────────────────────────────────────────────

/// Consulta tipada: método, parámetros y forma del resultado esperado.
///
/// Es la unidad del flujo del módulo: `BscQuery → BscClient → nodo →
/// BscDatum → BscTransducer → DataBubble`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BscQuery {
    /// Identificador de la cadena (`eth_chainId`).
    ChainId,
    /// Altura del último bloque (`eth_blockNumber`).
    BlockNumber,
    /// Precio del gas sugerido (`eth_gasPrice`).
    GasPrice,
    /// Saldo de una cuenta (`eth_getBalance`), en el último bloque.
    Balance(Address),
    /// `nonce` de una cuenta (`eth_getTransactionCount`).
    Nonce(Address),
    /// Llamada de sólo lectura a un contrato (`eth_call`).
    ContractCall {
        /// Contrato consultado.
        to: Address,
        /// Carga útil ABI (selector más palabras de 32 bytes).
        data: Vec<u8>,
    },
    /// Saldo BEP‑20 de un tenedor (`eth_call` a `balanceOf`).
    TokenBalance {
        /// Contrato del token.
        token: Address,
        /// Tenedor cuyo saldo se consulta.
        holder: Address,
    },
    /// Difusión de una transacción firmada (`eth_sendRawTransaction`).
    Broadcast(SignedTransaction),
}

impl BscQuery {
    /// Método JSON‑RPC que la sirve.
    pub fn method(&self) -> &'static str {
        match self {
            BscQuery::ChainId => "eth_chainId",
            BscQuery::BlockNumber => "eth_blockNumber",
            BscQuery::GasPrice => "eth_gasPrice",
            BscQuery::Balance(_) => "eth_getBalance",
            BscQuery::Nonce(_) => "eth_getTransactionCount",
            BscQuery::ContractCall { .. } | BscQuery::TokenBalance { .. } => "eth_call",
            BscQuery::Broadcast(_) => "eth_sendRawTransaction",
        }
    }

    /// Forma del resultado esperado (`cantidad`, `datos` o `hash`).
    pub fn shape(&self) -> &'static str {
        match self {
            BscQuery::ContractCall { .. } => "datos",
            BscQuery::Broadcast(_) => "hash",
            _ => "cantidad",
        }
    }

    /// Array de parámetros JSON ya serializado.
    pub fn params(&self) -> String {
        match self {
            BscQuery::ChainId | BscQuery::BlockNumber | BscQuery::GasPrice => "[]".to_string(),
            BscQuery::Balance(holder) => {
                let address = holder.to_hex();
                endpoint_params(&address)
            }
            BscQuery::Nonce(holder) => {
                let address = holder.to_hex();
                endpoint_params(&address)
            }
            BscQuery::ContractCall { to, data } => contract_params(to, data),
            BscQuery::TokenBalance { token, holder } => {
                contract_params(token, &balance_of_call(holder))
            }
            BscQuery::Broadcast(transaction) => {
                let raw = transaction.raw_hex();
                json_array(&[&raw])
            }
        }
    }

    /// Ejecuta la consulta y devuelve el dato exacto del nodo.
    ///
    /// El sobre de la respuesta ya viene verificado por el cliente; aquí sólo se
    /// comprueba la forma del `result` y se etiqueta la procedencia.
    pub fn execute(&self, client: &mut BscClient) -> Result<BscDatum, BridgeError> {
        let method = self.method();
        let params = self.params();
        let (id, body, result) = client.call_envelope(method, &params)?;
        let text = text_of(&result)?;
        let transport = client.transport_label();
        BscDatum::decode(method, id, transport, &body, &text)
    }
}
// ─────────────────────────────────────────────────────────────────────────
// Transducción · del dato externo a burbuja aislada, destilada y firmada
// ─────────────────────────────────────────────────────────────────────────

/// Nodos de forma que como máximo se destilan por dato (además del método).
pub const MAX_SHAPE_NODES: usize = 8;
/// Raíz de reserva si una etiqueta no produjera raíz triconsonántica.
const FALLBACK_ROOT: &str = "אאא";

/// Nodo de forma: hereda la valencia y el peligro de su burbuja.
///
/// El nodo no inventa una opinión propia: si la carga traía riesgo, el nodo
/// nace sellado bajo guarda (`שמר`) y su `hazard` es el mismo peligro en ‰ que
/// midió la puerta, dividido por mil.
fn shape_node(original: &str, ret: BaraType, bubble: &Bubble) -> ShoreshNode {
    let candidate = root_from_name(original);
    let root = if triconsonantal(&candidate) {
        candidate
    } else {
        FALLBACK_ROOT.to_string()
    };
    ShoreshNode {
        root,
        original: original.to_string(),
        arity: 0,
        ret,
        hazard: f64::from(bubble.danger) / 1000.0,
        valence: bubble.valence.clone(),
        sanitized: bubble.danger > 0,
    }
}

/// Transductor: cada dato externo entra aislado y sale como burbuja firmada.
///
/// Une las tres piezas del aislamiento sin saltarse ninguna: la puerta de
/// inmunidad ([`Gateway::admit`]) abre la burbuja, el AST *Shoresh* destila la
/// respuesta y el ADN la firma con la clave derivada de la geometría áurea
/// ([`golden_key`]). El digest del paquete y el de la burbuja se contrastan
/// después: si no coincidieran, la burbuja no se publica.
pub struct BscTransducer {
    gateway: Gateway,
    label: String,
    key: [u8; 32],
    admitted: usize,
}

impl BscTransducer {
    /// Transductor con su propio registro de burbujas y su clave de sellado.
    ///
    /// La etiqueta no es decorativa: es el origen declarado de los paquetes y la
    /// sal de la clave, de modo que dos transductores con etiquetas distintas
    /// producen ADN distintos para el mismo dato.
    pub fn new(label: &str) -> Self {
        BscTransducer {
            gateway: Gateway::new(),
            key: golden_key(label.as_bytes()),
            label: label.to_string(),
            admitted: 0,
        }
    }

    /// Etiqueta del transductor (origen declarado de los paquetes).
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Clave de sellado identificada sin revelarla.
    pub fn key_id(&self) -> u64 {
        key_id(&self.key)
    }

    /// Datos admitidos hasta ahora.
    pub fn admitted(&self) -> usize {
        self.admitted
    }

    /// Burbujas vivas en la puerta de inmunidad.
    pub fn bubbles(&self) -> usize {
        let (innocuous, absorbed, neutralized, quarantined) = self.gateway.census();
        innocuous + absorbed + neutralized + quarantined
    }

    /// Admite el texto exacto de un `result` y devuelve la burbuja sellada.
    ///
    /// Es el atajo de `BscDatum::decode` más [`Self::admit`], con el mismo
    /// camino: no hay versión «de prueba» del aislamiento.
    pub fn admit_text(
        &mut self,
        method: &str,
        id: u64,
        transport: &str,
        body: &str,
        text: &str,
    ) -> Result<DataBubble, BridgeError> {
        let datum = BscDatum::decode(method, id, transport, body, text)?;
        Ok(self.admit(&datum))
    }

    /// Admite un dato ya decodificado: burbuja, AST destilado y holograma.
    ///
    /// La carga que entra por la puerta es el **sobre íntegro**, no un resumen:
    /// es la evidencia original y así el AST se destila del documento real. A
    /// esa lectura se le añade la *forma* del dato —el método y una palabra por
    /// bloque de 32 bytes—, que es lo que el núcleo puede volver a comprobar sin
    /// entender JSON‑RPC.
    pub fn admit(&mut self, datum: &BscDatum) -> DataBubble {
        // El paquete normaliza la carga (recorte a `MAX_PAYLOAD`) **antes** de
        // tocar la puerta: así el digest del paquete y el de la burbuja cubren
        // exactamente los mismos bytes y el contraste posterior es real.
        let packet = Packet::new(&self.label, datum.id, datum.body.as_bytes());
        let bubble = self
            .gateway
            .admit(&packet.origin, packet.sequence, &packet.payload)
            .clone();

        let mut ast = bubble.ast.clone();
        ast.nodes
            .push(shape_node(&datum.method, BaraType::Text, &bubble));
        let words = datum.data.chunks(32).take(MAX_SHAPE_NODES).count();
        if words == 0 {
            let label = format!("{}[cantidad]", datum.method);
            ast.nodes
                .push(shape_node(&label, BaraType::Number, &bubble));
        }
        for index in 0..words {
            let label = format!("{}[{index}]", datum.method);
            ast.nodes
                .push(shape_node(&label, BaraType::Number, &bubble));
        }

        let dna = ast_dna(&format!("{}:{}", self.label, datum.method), &ast, &self.key);
        self.admitted += 1;
        DataBubble {
            packet_digest: packet.digest(),
            bubble,
            datum: datum.clone(),
            ast,
            dna,
            published: false,
            key: None,
        }
    }
}

/// Burbuja de datos: el dato externo aislado, destilado y firmado.
///
/// Es el único camino hacia el núcleo: nada entra sin pasar por aquí, y lo que
/// entra trae su propia valencia, su propio holograma y su propia clave de
/// registro en la memoria holográfica.
#[derive(Debug, Clone)]
pub struct DataBubble {
    /// Digest del paquete tal como entró por la puerta.
    pub packet_digest: [u8; 32],
    /// Burbuja de inmunidad que lo aisló.
    pub bubble: Bubble,
    /// Dato exacto del nodo.
    pub datum: BscDatum,
    /// AST *Shoresh* destilado (lo leído por la puerta más la forma del dato).
    pub ast: ShoreshAst,
    /// Holograma firmado del AST.
    pub dna: AstDna,
    /// ¿Se publicó ya en la memoria holográfica del núcleo?
    pub published: bool,
    /// Clave topológica de su registro, si se publicó.
    pub key: Option<u64>,
}

impl DataBubble {
    /// Holograma del ADN (raíz de Merkle) en hexadecimal corto.
    pub fn hologram(&self) -> String {
        short_hex(&self.dna.root[..8])
    }

    /// ¿El digest del paquete coincide con el que guardó la burbuja?
    ///
    /// Es el contraste entre dos caminos independientes: el digest que calcula
    /// el paquete al entrar y el que la puerta guardó al abrir la burbuja. Si no
    /// cuadraran, algo habría tocado la carga por el camino.
    pub fn is_verified(&self) -> bool {
        digest_eq(&self.packet_digest, &self.bubble.payload_digest)
    }

    /// Raíz de Merkle del AST recalculada desde los nodos.
    ///
    /// Recalcularla —en vez de creerse la del ADN— es una comprobación
    /// independiente: si el AST se hubiera tocado después de firmarse, las dos
    /// raíces dejarían de coincidir.
    pub fn ast_root(&self) -> [u8; 32] {
        let digests: Vec<[u8; 32]> = self
            .ast
            .nodes
            .iter()
            .map(|node| node_dna(node).digest)
            .collect();
        merkle_root(&digests)
    }

    /// ¿El ADN sigue correspondiendo a este AST?
    pub fn is_sealed(&self) -> bool {
        digest_eq(&self.ast_root(), &self.dna.root)
    }

    /// ¿La burbuja es fiable? Digest coincidente, ADN coherente con el AST y
    /// veredicto que alcanza el núcleo: lo hostil y lo ilegible **nunca** pasan.
    pub fn is_trustworthy(&self) -> bool {
        self.is_verified() && self.is_sealed() && self.bubble.verdict.reaches_core()
    }

    /// Valencia paraconsistente `(⊤, ⊥)` del dato, tal como la midió la puerta.
    pub fn valence(&self) -> &QuantumState {
        &self.bubble.valence
    }

    /// Colapso tetravalente de la valencia.
    pub fn observation(&self) -> Observation {
        self.bubble.observation
    }

    /// Etiqueta con la que se registra en la memoria holográfica.
    pub fn label(&self) -> &str {
        &self.bubble.label
    }

    /// Publica el AST y el dato en la memoria holográfica del núcleo.
    ///
    /// Devuelve cuántos registros **nuevos** entraron. Un veredicto que no alcanza el
    /// núcleo —o un digest que no cuadre— publica **cero**: el aislamiento no se
    /// negocia por conveniencia, y la escritura es idempotente porque la memoria
    /// está direccionada por contenido.
    pub fn publish(&mut self, core: &mut BaraRuntime) -> usize {
        if !self.is_trustworthy() {
            return 0;
        }
        let before = core.memory.len();
        for node in &self.ast.nodes {
            core.memory.store(&node.root, node.valence.clone());
        }
        let key = core
            .memory
            .store(&self.bubble.label, self.bubble.valence.clone());
        core.push(self.bubble.valence.clone());
        let inserted = core.memory.len().saturating_sub(before);
        self.key = Some(key);
        self.published = true;
        inserted
    }

    /// Descripción de una línea.
    pub fn describe(&self) -> String {
        let nodes = self.ast.nodes.len();
        let hologram = self.hologram();
        let state = if self.published {
            "publicada"
        } else {
            "aislada"
        };
        format!(
            "{} · {nodes} nodos · ADN {hologram} · {state}",
            self.bubble.describe()
        )
    }
}
/// Ronda completa del puente: consulta → dato → burbuja → memoria del núcleo.
///
/// Es el atajo del flujo documentado en el módulo, con todas las piezas reales:
/// transporte, sobre verificado, aislamiento, ADN y publicación. La burbuja se
/// devuelve con su acta (valencia, holograma y clave) para que quien consulte
/// pueda auditar exactamente qué entró.
pub fn bridge_round(
    client: &mut BscClient,
    transducer: &mut BscTransducer,
    query: &BscQuery,
    core: &mut BaraRuntime,
) -> Result<DataBubble, BridgeError> {
    let datum = query.execute(client)?;
    let mut bubble = transducer.admit(&datum);
    bubble.publish(core);
    Ok(bubble)
}
#[cfg(test)]
mod pruebas {
    use super::*;

    /// Contrato cualquiera de BEP‑20, en totalidad: `None` si la constante no
    /// fuera una dirección (la prueba devuelve, no aborta).
    fn token() -> Option<Address> {
        Address::from_hex("1111111111111111111111111111111111111111").ok()
    }

    /// Tenedor cualquiera, con la misma totalidad que [`token`].
    fn holder() -> Option<Address> {
        Address::from_hex("2222222222222222222222222222222222222222").ok()
    }

    /// Cliente con respuestas guionadas, en orden.
    fn scripted(responses: &[&str]) -> BscClient {
        let mut transport = LoopbackTransport::new();
        for response in responses {
            transport.push_ok(response);
        }
        BscClient::new(transport)
    }

    /// Sobre JSON‑RPC correcto con un `result` ya serializado.
    fn envelope(id: u64, result: &str) -> String {
        format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{result}}}")
    }

    #[test]
    fn endpoint_parses_schemes_ports_and_paths() {
        let bare = Endpoint::parse("nodo.test");
        assert!(bare.is_ok(), "host sin esquema");
        let Ok(bare) = bare else { return };
        assert_eq!(bare.scheme, Scheme::Bare);
        assert_eq!(bare.port, RPC_DEFAULT_PORT);
        assert_eq!(bare.path, "/");

        let http = Endpoint::parse("http://nodo.test:8545/rpc");
        assert!(http.is_ok(), "url con ruta");
        let Ok(http) = http else { return };
        assert_eq!(http.scheme, Scheme::Http);
        assert_eq!(http.port, 8545);
        assert_eq!(http.path, "/rpc");
        assert_eq!(http.authority(), "nodo.test:8545");
        assert_eq!(http.describe(), "http://nodo.test:8545/rpc");

        let https = Endpoint::parse("https://nodo.test");
        assert!(https.is_ok(), "https sin puerto");
        let Ok(https) = https else { return };
        assert_eq!(https.port, 443);
        assert_eq!(https.scheme, Scheme::Https);

        assert!(Endpoint::parse("ftp://nodo.test").is_err());
        assert!(Endpoint::parse("nodo.test:no-es-puerto").is_err());
        assert!(Endpoint::parse("  ").is_err());
    }

    #[test]
    fn mainnet_endpoints_come_from_the_module_constants() {
        let plain = Endpoint::mainnet();
        assert!(plain.is_ok(), "extremo público");
        let Ok(plain) = plain else { return };
        assert_eq!(plain.host, "bsc-dataseed.binance.org");
        assert_eq!(plain.port, RPC_DEFAULT_PORT);
        assert_eq!(
            plain.describe(),
            format!("{BSC_MAINNET_ADDRESS}{BSC_RPC_PATH}")
        );

        let swarm = Endpoint::swarm_mainnet();
        assert!(swarm.is_ok(), "extremo del enjambre");
        let Ok(swarm) = swarm else { return };
        assert_eq!(swarm.scheme, Scheme::Https);
        assert_eq!(swarm.port, 443);
        assert_eq!(swarm.host, plain.host);
    }

    #[test]
    fn http_post_has_the_expected_envelope() {
        let endpoint = Endpoint::parse("http://nodo.test:8545/rpc");
        assert!(endpoint.is_ok(), "extremo");
        let Ok(endpoint) = endpoint else { return };
        let request = String::from_utf8(endpoint.http_post(b"{\"id\":1}"));
        assert!(request.is_ok(), "petición UTF-8");
        let Ok(request) = request else { return };
        assert!(request.starts_with("POST /rpc HTTP/1.1\r\n"));
        assert!(request.contains("Host: nodo.test:8545\r\n"));
        assert!(request.contains("Content-Length: 8\r\n"));
        assert!(request.ends_with("\r\n\r\n{\"id\":1}"));
    }

    #[test]
    fn http_transport_talks_to_an_unreachable_endpoint_without_panicking() {
        // Puerto reservado y sin escucha: el fallo es declarado, no un pánico.
        let transport = HttpTransport::from_url("http://127.0.0.1:9/");
        assert!(transport.is_ok(), "extremo local");
        let Ok(transport) = transport else { return };
        assert_eq!(transport.timeout_ms(), HTTP_TIMEOUT_MS);
        assert_eq!(transport.label(), "http");
        assert_eq!(
            transport.endpoint().map(Endpoint::describe).as_deref(),
            Some("http://127.0.0.1:9/")
        );
        let mut transport = transport.with_timeout(200);
        assert!(matches!(
            transport.exchange("{\"jsonrpc\":\"2.0\"}"),
            Err(BridgeError::TransportUnavailable(_))
        ));
    }

    #[test]
    fn http_parsing_is_strict_about_shape() {
        let ok = http_response(200, "OK", "{\"id\":1}");
        assert_eq!(
            parse_http_response(ok.as_bytes()),
            Ok("{\"id\":1}".to_string())
        );

        // Longitud declarada mayor que el cuerpo: se rechaza, no se adivina.
        let truncated = "HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n{}";
        assert_eq!(
            parse_http_response(truncated.as_bytes()),
            Err(BridgeError::HttpMalformed("cuerpo HTTP truncado"))
        );

        // Código distinto de `200`.
        let status = http_response(503, "UNAVAILABLE", "{}");
        assert_eq!(
            parse_http_response(status.as_bytes()),
            Err(BridgeError::HttpStatus(503))
        );

        // Sin terminador de cabecera no hay mensaje.
        assert!(matches!(
            parse_http_response(b"HTTP/1.1 200 OK"),
            Err(BridgeError::HttpMalformed(_))
        ));

        // Troceado explícito: se declara en vez de aceptarse a medias.
        let chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhola\r\n";
        assert_eq!(
            parse_http_response(chunked.as_bytes()),
            Err(BridgeError::HttpMalformed(
                "transfer-encoding chunked no soportado"
            ))
        );

        // `Content-Length` no numérico y versión ajena al protocolo.
        let bogus = "HTTP/1.1 200 OK\r\nContent-Length: muchos\r\n\r\n{}";
        assert!(matches!(
            parse_http_response(bogus.as_bytes()),
            Err(BridgeError::HttpMalformed(_))
        ));
        assert!(matches!(
            parse_http_response(b"HTTP/2 200 OK\n\n{}"),
            Err(BridgeError::HttpMalformed(_))
        ));
    }

    #[test]
    fn json_escaping_covers_control_characters() {
        assert_eq!(json_escape("simple"), "\"simple\"");
        assert_eq!(json_escape("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(json_escape("salto\nlínea"), "\"salto\\nlínea\"");
        assert_eq!(json_escape("\u{1}"), "\"\\u0001\"");
        assert_eq!(json_array(&["a", "b"]), "[\"a\",\"b\"]");
        assert_eq!(json_array(&[]), "[]");
        assert_eq!(json_object(&[("to", "0x01")]), "{\"to\":\"0x01\"}");
    }

    #[test]
    fn rpc_call_body_is_minimal_json() {
        let call = RpcCall::new(7, "eth_chainId", &[]);
        assert_eq!(
            call.body(),
            "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"eth_chainId\",\"params\":[]}"
        );
        let call = RpcCall::with_params(1, "eth_call", "[{\"to\":\"0x01\"},\"latest\"]");
        assert!(call
            .body()
            .contains("\"params\":[{\"to\":\"0x01\"},\"latest\"]"));
    }

    #[test]
    fn loopback_transport_returns_the_scripted_body() {
        let mut transport = LoopbackTransport::new();
        assert_eq!(transport.push_ok(&envelope(1, "\"0x38\"")), 1);
        assert_eq!(transport.queued(), 1);
        let body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_chainId\",\"params\":[]}";
        let response = transport.exchange(body);
        assert!(response.is_ok(), "respuesta del guion");
        let Ok(response) = response else { return };
        assert_eq!(response, envelope(1, "\"0x38\""));
        assert_eq!(transport.queued(), 0);
        assert_eq!(transport.requests().first().map(String::as_str), Some(body));
        assert!(matches!(
            transport.exchange(body),
            Err(BridgeError::TransportUnavailable(_))
        ));
    }
    #[test]
    fn client_decodes_quantity_and_data() {
        let mut client = scripted(&[
            &envelope(1, "\"0x38\""),
            &envelope(2, "\"0x1b4\""),
            &envelope(3, "\"0x01ff\""),
        ]);
        assert_eq!(client.chain_id(), Ok(BSC_CHAIN_ID));
        assert_eq!(
            client.call_quantity("eth_blockNumber", "[]"),
            Ok(U256::from_u64(0x1b4))
        );
        assert_eq!(client.call_data("eth_call", "[]"), Ok(vec![0x01, 0xff]));
        assert_eq!(client.transport_label(), "guion");
        assert_eq!(client.next_id(), 4);
        assert_eq!(client.log().len(), 3);
    }

    #[test]
    fn client_reports_rpc_errors_and_null_results() {
        let mut empty = scripted(&[&envelope(1, "null")]);
        assert_eq!(empty.chain_id(), Err(BridgeError::NoResult));

        let mut failed = scripted(&[
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000,\"message\":\"sin fondos\"}}",
        ]);
        assert_eq!(
            failed.chain_id(),
            Err(BridgeError::RpcError {
                code: RPC_SERVER_ERROR,
                message: "sin fondos".to_string(),
            })
        );

        // Un `error` sin código numérico no pierde el mensaje del nodo.
        let mut odd =
            scripted(&["{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"message\":\"genérico\"}}"]);
        assert_eq!(
            odd.chain_id(),
            Err(BridgeError::RpcError {
                code: RPC_SERVER_ERROR,
                message: "genérico".to_string(),
            })
        );
    }

    #[test]
    fn client_rejects_faulty_envelopes() {
        // Identificador cruzado: la respuesta no es de esta llamada.
        let mut crossed = scripted(&[&envelope(9, "\"0x38\"")]);
        assert!(matches!(
            crossed.chain_id(),
            Err(BridgeError::RpcError {
                code: RPC_INVALID_REQUEST,
                ..
            })
        ));

        // Cuerpo que no es JSON y sobre sin campo `jsonrpc`.
        let mut broken = scripted(&["no soy json", "{\"id\":1,\"result\":\"0x1\"}"]);
        assert_eq!(broken.chain_id(), Err(BridgeError::JsonInvalid));
        assert_eq!(
            broken.chain_id(),
            Err(BridgeError::JsonMissingField("jsonrpc"))
        );

        // `result` que no es una cadena hexadecimal.
        let mut numeric = scripted(&[&envelope(1, "56")]);
        assert_eq!(numeric.chain_id(), Err(BridgeError::JsonInvalid));
    }

    #[test]
    fn http_status_is_reported_without_reading_the_body() {
        let mut transport = LoopbackTransport::new();
        transport.push_status(429, "{\"error\":\"demasiadas peticiones\"}");
        let mut client = BscClient::new(transport);
        assert_eq!(client.chain_id(), Err(BridgeError::HttpStatus(429)));
    }

    #[test]
    fn token_balance_sends_the_bep20_selector() {
        let word = "0x00000000000000000000000000000000000000000000000000000000000000c8";
        let mut transport = LoopbackTransport::new();
        transport.push_ok(&envelope(1, &json_escape(word)));
        let Some(contract) = token() else { return };
        let Some(account) = holder() else { return };
        let mut client = BscClient::new(transport);
        assert_eq!(
            client.token_balance(&contract, &account),
            Ok(U256::from_u64(200))
        );
        let request = client.log().first().cloned().unwrap_or_default();
        assert!(request.contains("eth_call"));
        assert!(
            request.contains("70a08231"),
            "el selector de `balanceOf` viaja en la carga"
        );
        assert!(
            request.contains(&hex_encode(&account.to_abi_word())),
            "el tenedor viaja como palabra ABI, alineado a la derecha"
        );
        assert!(request.contains(&contract.to_hex()));
    }

    #[test]
    fn swarm_transport_demands_an_https_endpoint() {
        let plain = Endpoint::parse("http://nodo.test:8545");
        assert!(plain.is_ok(), "extremo en claro");
        let Ok(plain) = plain else { return };
        assert!(matches!(
            SwarmTransport::connect(plain, b"semilla"),
            Err(BridgeError::TransportUnavailable(_))
        ));
    }
    #[test]
    fn datum_decode_classifies_quantities_and_data() {
        let body = envelope(1, "\"0x1b4\"");
        let quantity = BscDatum::decode("eth_blockNumber", 1, "guion", &body, "0x1b4");
        assert!(quantity.is_ok(), "cantidad impar");
        let Ok(quantity) = quantity else { return };
        assert_eq!(quantity.quantity, Some(U256::from_u64(0x1b4)));
        assert!(
            quantity.data.is_empty(),
            "un número impar de dígitos no tiene forma de bytes"
        );
        assert_eq!(quantity.to_dec().as_deref(), Some("436"));
        assert_eq!(
            quantity.word(),
            Err(BridgeError::LengthMismatch {
                expected: 32,
                found: 0
            })
        );
        assert!(quantity.describe().contains("eth_blockNumber"));

        let data = BscDatum::decode("eth_call", 2, "guion", &body, "0x01ff");
        assert!(data.is_ok(), "datos pares");
        let Ok(data) = data else { return };
        assert_eq!(data.data, vec![0x01, 0xff]);
        assert_eq!(data.quantity, Some(U256::from_u64(0x01ff)));
        assert_eq!(
            data.word(),
            Err(BridgeError::LengthMismatch {
                expected: 32,
                found: 2
            })
        );

        assert_eq!(
            BscDatum::decode("eth_call", 3, "guion", &body, "1b4"),
            Err(BridgeError::HexInvalid)
        );
        assert_eq!(
            BscDatum::decode("eth_call", 4, "guion", &body, "0xzz"),
            Err(BridgeError::HexInvalid)
        );
    }

    #[test]
    fn transducer_isolates_the_datum_and_signs_the_tree() {
        let mut transducer = BscTransducer::new("prueba");
        let body = envelope(1, "\"0x38\"");
        let bubble = transducer.admit_text("eth_chainId", 1, "guion", &body, "0x38");
        assert!(bubble.is_ok(), "dato válido");
        let Ok(bubble) = bubble else { return };
        assert!(bubble.is_verified(), "mismo digest por los dos caminos");
        assert!(bubble.is_sealed(), "el ADN corresponde al AST admitido");
        assert!(bubble.is_trustworthy());
        assert!(
            bubble.ast.nodes.len() >= 2,
            "el método más la forma del dato"
        );
        assert_eq!(transducer.admitted(), 1);
        assert_eq!(transducer.bubbles(), 1);
        assert_eq!(transducer.label(), "prueba");
        assert_ne!(transducer.key_id(), 0);
        assert!(!bubble.hologram().is_empty());
        assert!(crate::ast_dna::verify(
            &bubble.dna.label,
            &bubble.ast,
            &bubble.dna,
            &transducer.key
        ));
        assert!(!bubble.published);
        assert!(bubble.key.is_none());
        assert!(bubble.describe().contains("aislada"));
        assert_eq!(bubble.observation(), Observation::True);
        assert!(bubble.valence().truth_mass() > 0.5);
    }

    #[test]
    fn publishing_reaches_the_holographic_memory() {
        let mut transducer = BscTransducer::new("prueba");
        let mut core = BaraRuntime::new();
        let body = envelope(1, "\"0x38\"");
        let bubble = transducer.admit_text("eth_chainId", 1, "guion", &body, "0x38");
        assert!(bubble.is_ok(), "dato válido");
        let Ok(mut bubble) = bubble else { return };
        let records = bubble.publish(&mut core);
        assert!(records >= 1, "al menos el registro del propio dato");
        assert!(bubble.published);
        assert!(bubble.key.is_some());
        assert!(core.memory.recall(bubble.label()).is_some());
        assert!(core.memory.len() >= records);
        assert!(bubble.describe().contains("publicada"));
    }

    #[test]
    fn hostile_payloads_never_reach_the_core() {
        let mut transducer = BscTransducer::new("hostil");
        let mut core = BaraRuntime::new();

        // Legible, con más de `SIZE_BOMB_BYTES` y un 40 % de bytes nulos: la
        // puerta suma bomba de tamaño (300), relleno de control (200) y byte
        // nulo (100), o sea 600 ‰ de peligro y veredicto `⊥`.
        let mut body = "\u{0}".repeat(2000);
        body.push_str(&"b".repeat(3000));
        let bubble = transducer.admit_text("eth_call", 1, "guion", &body, "0x00");
        assert!(bubble.is_ok(), "dato hexadecimal válido");
        let Ok(mut bubble) = bubble else { return };
        assert_eq!(bubble.bubble.danger, 600);
        assert!(!bubble.is_trustworthy());
        assert_eq!(bubble.publish(&mut core), 0);
        assert!(!bubble.published);
        assert!(bubble.key.is_none());

        // Sin un solo alfanumérico: ilegible, veredicto `∅` (cuarentena).
        let illegible = "?".repeat(1200);
        let bubble = transducer.admit_text("eth_call", 2, "guion", &illegible, "0x00");
        assert!(bubble.is_ok(), "dato hexadecimal válido");
        let Ok(mut bubble) = bubble else { return };
        assert!(!bubble.is_trustworthy());
        assert_eq!(bubble.publish(&mut core), 0);
        assert!(core.memory.is_empty(), "el núcleo queda sin tocar");
    }

    #[test]
    fn balance_query_builds_its_parameters() {
        let Some(account) = holder() else { return };
        let query = BscQuery::Balance(account);
        assert_eq!(query.method(), "eth_getBalance");
        assert_eq!(query.shape(), "cantidad");
        assert_eq!(
            query.params(),
            format!("[\"{}\",\"latest\"]", account.to_hex())
        );

        let mut client = scripted(&[&envelope(1, "\"0x0de0b6b3a7640000\"")]);
        let datum = query.execute(&mut client);
        assert!(datum.is_ok(), "saldo del guion");
        let Ok(datum) = datum else { return };
        let ether = U256::from_dec("1000000000000000000");
        assert!(ether.is_ok(), "un ether");
        let Ok(ether) = ether else { return };
        assert_eq!(datum.quantity, Some(ether));
        assert!(client
            .log()
            .first()
            .is_some_and(|body| body.contains("eth_getBalance")));
    }

    #[test]
    fn broadcast_query_sends_the_raw_transaction() {
        let key = SigningKey::from_bytes(&[0x11_u8; 32]);
        assert!(key.is_ok(), "clave dentro de rango");
        let Ok(key) = key else { return };
        let price = U256::from_dec("5000000000");
        assert!(price.is_ok(), "precio");
        let Ok(price) = price else { return };
        let template = LegacyTx {
            nonce: U256::from_u64(3),
            gas_price: price,
            gas_limit: U256::from_u64(21000),
            to: holder(),
            value: U256::from_u64(1),
            data: Vec::new(),
        };
        let transaction = key.sign_transaction(&template, BSC_CHAIN_ID);
        assert!(transaction.is_ok(), "transacción firmada");
        let Ok(transaction) = transaction else { return };

        let hash = "0x".to_string() + &hex_encode(&transaction.hash);
        let mut client = scripted(&[&envelope(1, &json_escape(&hash))]);
        let query = BscQuery::Broadcast(transaction.clone());
        assert_eq!(query.method(), "eth_sendRawTransaction");
        assert_eq!(query.shape(), "hash");
        assert!(query.params().contains(&transaction.raw_hex()));

        let datum = query.execute(&mut client);
        assert!(datum.is_ok(), "hash de difusión");
        let Ok(datum) = datum else { return };
        assert_eq!(datum.data.len(), 32);
        assert_eq!(datum.data, transaction.hash.to_vec());
    }

    #[test]
    fn bridge_round_joins_every_piece() {
        let mut client = scripted(&[&envelope(1, "\"0x38\"")]);
        let mut transducer = BscTransducer::new("ronda");
        let mut core = BaraRuntime::new();
        let bubble = bridge_round(&mut client, &mut transducer, &BscQuery::ChainId, &mut core);
        assert!(bubble.is_ok(), "ronda completa");
        let Ok(bubble) = bubble else { return };
        assert!(bubble.is_trustworthy());
        assert!(bubble.published);
        assert!(bubble.key.is_some());
        assert_eq!(bubble.datum.method, "eth_chainId");
        assert_eq!(bubble.datum.transport, "guion");
        assert_eq!(bubble.datum.quantity, Some(U256::from_u64(BSC_CHAIN_ID)));
        assert_eq!(transducer.admitted(), 1);
        assert!(
            !core.memory.is_empty(),
            "la memoria holográfica recibió la ronda"
        );
    }
}
// ─────────────────────────────────────────────────────────────────────────
// Fin del puente BSC · `BscQuery → BscClient → Transport → BscDatum →
// BscTransducer → DataBubble → memoria holográfica del núcleo`
// ─────────────────────────────────────────────────────────────────────────
