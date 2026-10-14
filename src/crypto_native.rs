//! # Criptografía nativa — `crypto_native.rs`
//!
//! Bóveda de primitivas **autóctonas** del motor AETHER‑Ω: todo lo que la capa
//! de emisión y la pasarela de inmunidad necesitan para firmar, sellar y
//! acordar claves, implementado desde cero y sin una sola dependencia externa
//! (ni `OpenSSL`, ni `ring`, ni `sha2`: sólo `std`).
//!
//! ## Primitivas (verificadas contra vectores normativos)
//! * [`sha256`] — *hash* SHA‑256 (FIPS 180‑4), con API incremental
//!   ([`Sha256`]) para sellar artefactos grandes sin copiarlos.
//! * [`hmac_sha256`] — MAC de clave compartida (RFC 2104 / RFC 4231).
//! * [`hkdf_sha256`] — derivación de claves *extract‑and‑expand* (RFC 5869),
//!   el bloque con el que el camuflaje de red construye su calendario de claves.
//! * [`chacha20_block`] / [`chacha20_xor`] — cifrador de flujo ChaCha20
//!   (RFC 8439 §2.3‑2.4).
//! * [`aead_seal`] / [`aead_open`] — AEAD `AEAD_CHACHA20_POLY1305`
//!   (RFC 8439 §2.8): confidencialidad y autenticación en una sola pasada.
//! * [`x25519`] / [`x25519_base`] — Diffie‑Hellman sobre Curve25519 (RFC 7748),
//!   la curva que exige el `key_share` de TLS 1.3.
//!
//! ## Contrato de pureza
//! * **Cero dependencias** — la bóveda sólo usa `std`.
//! * **Cero `unsafe`** — aritmética de campo con `u32`/`u64`/`u128` seguros.
//! * **Totalidad** — ninguna entrada provoca pánico: una longitud fuera de
//!   rango se recorta o devuelve `None` en lugar de abortar (axioma A1).
//! * **Determinismo** — son funciones puras: la misma entrada produce el mismo
//!   resultado, sin relojes ni entropía del sistema. La aleatoriedad no es un
//!   ingrediente del núcleo: las claves se derivan de material determinista y
//!   de la propia geometría áurea, de modo que una sesión completa es
//!   reproducible bit a bit.
//!
//! ## Alcance y límites (declarados sin adornos)
//! Las primitivas coinciden con los vectores de los RFC citados (el propio
//! módulo los comprueba), pero **no** están auditadas ni blindadas contra
//! ataques de canal lateral por tiempo: sólo la comparación de etiquetas
//! ([`digest_eq`]) es de tiempo constante, que es la que decide si un mensaje
//! se acepta. El objetivo es la **soberanía**: firmar el ADN del AST y
//! camuflar el tráfico sin arrastrar bibliotecas externas al núcleo.

// ─────────────────────────────────────────────────────────────────────────
// SHA-256 (FIPS 180-4)
// ─────────────────────────────────────────────────────────────────────────

/// Constantes de ronda de SHA‑256: los 32 bits altos de las raíces cúbicas de
/// los sesenta y cuatro primeros primos.
const K256: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Estado inicial de SHA‑256: las raíces cuadradas de los ocho primeros primos.
const H256: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// Digestor SHA‑256 incremental (FIPS 180‑4).
///
/// Acumula los bytes que se le entreguen y, al cerrar, devuelve los 32 bytes
/// del *hash*. La longitud se lleva en un `u64` con aritmética de módulo 2⁶⁴,
/// de modo que ni un flujo gigantesco desborda (totalidad).
#[derive(Debug, Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    length: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Sha256 {
            state: H256,
            buffer: [0u8; 64],
            buffered: 0,
            length: 0,
        }
    }
}

impl Sha256 {
    /// Digestor virgen.
    pub fn new() -> Self {
        Self::default()
    }

    /// Incorpora un bloque de bytes al mensaje.
    pub fn update(&mut self, data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        let mut rest = data;

        // Rellena el bloque pendiente, si lo había.
        if self.buffered > 0 {
            let need = 64 - self.buffered;
            let take = need.min(rest.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&rest[..take]);
            self.buffered += take;
            rest = &rest[take..];
            if self.buffered == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffered = 0;
            }
        }

        // Consume bloques completos.
        while rest.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&rest[..64]);
            self.compress(&block);
            rest = &rest[64..];
        }

        // Guarda el sobrante para la próxima llamada.
        if !rest.is_empty() {
            self.buffer[..rest.len()].copy_from_slice(rest);
            self.buffered = rest.len();
        }
    }

    /// Cierra el mensaje y devuelve el digest de 32 bytes.
    pub fn finish(mut self) -> [u8; 32] {
        let bit_length = self.length.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buffered != 56 {
            self.update(&[0x00]);
        }
        self.update(&bit_length.to_be_bytes());

        let mut digest = [0u8; 32];
        for (index, word) in self.state.iter().enumerate() {
            digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    /// Función de compresión sobre un bloque de 64 bytes.
    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (index, chunk) in block.chunks(4).enumerate() {
            let mut word = [0u8; 4];
            word.copy_from_slice(chunk);
            w[index] = u32::from_be_bytes(word);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for (k, wi) in K256.iter().zip(w.iter()) {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(choose)
                .wrapping_add(*k)
                .wrapping_add(*wi);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(majority);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        let mixed = [a, b, c, d, e, f, g, h];
        for (slot, value) in self.state.iter_mut().zip(mixed.iter()) {
            *slot = slot.wrapping_add(*value);
        }
    }
}

/// SHA‑256 de un mensaje completo.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finish()
}

/// SHA‑256 en hexadecimal minúsculo (fichas, sellos y log ontológico).
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = sha256(data);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

/// ¿Son iguales dos digests, sin que el tiempo revele dónde difieren?
///
/// El recorrido es **completo** (nunca sale antes) y acumula la diferencia en
/// un `u8`; no hay bifurcación dependiente de los datos, así que el tiempo no
/// filtra el prefijo acertado. Es la comparación que decide si un mensaje
/// autenticado se acepta.
pub fn digest_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

// ─────────────────────────────────────────────────────────────────────────
// HMAC-SHA256 (RFC 2104 · vectores de RFC 4231)
// ─────────────────────────────────────────────────────────────────────────

/// Tamaño de bloque interno de SHA‑256, en bytes.
pub const SHA256_BLOCK: usize = 64;

/// MAC `HMAC-SHA-256` sobre una clave de longitud arbitraria.
///
/// Una clave más larga que el bloque se comprime primero con SHA‑256, tal como
/// exige el RFC 2104: así una clave de cualquier tamaño es admisible sin
/// abortar (totalidad).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut padded = [0u8; SHA256_BLOCK];
    if key.len() > SHA256_BLOCK {
        let digest = sha256(key);
        padded[..digest.len()].copy_from_slice(&digest);
    } else {
        padded[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36u8; SHA256_BLOCK];
    let mut outer_pad = [0x5cu8; SHA256_BLOCK];
    for index in 0..SHA256_BLOCK {
        inner_pad[index] ^= padded[index];
        outer_pad[index] ^= padded[index];
    }

    let mut inner = Sha256::new();
    inner.update(&inner_pad);
    inner.update(message);
    let inner_digest = inner.finish();

    let mut outer = Sha256::new();
    outer.update(&outer_pad);
    outer.update(&inner_digest);
    outer.finish()
}

// ─────────────────────────────────────────────────────────────────────────
// HKDF (RFC 5869) — derivación de claves
// ─────────────────────────────────────────────────────────────────────────

/// Paso *extract*: condensa el material de clave en una clave pseudaleatoria.
///
/// Si no se aporta sal (o se aporta vacía) se usa el valor por omisión del RFC:
/// tantos ceros como mida el digest.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    if salt.is_empty() {
        hmac_sha256(&[0u8; 32], ikm)
    } else {
        hmac_sha256(salt, ikm)
    }
}

/// Paso *expand*: estira la clave pseudaleatoria cuantos bytes se pidan.
///
/// Devuelve cuántos bytes escribió. El techo es el del RFC 5869 —255 bloques de
/// 32 bytes (8 160)—; por encima de ahí lo que sobra queda a cero en lugar de
/// provocar un pánico (totalidad).
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) -> usize {
    let mut previous: Vec<u8> = Vec::new();
    let mut written = 0usize;
    for (index, chunk) in out.chunks_mut(32).enumerate() {
        let counter = (index + 1) as u8;
        if counter == 0 {
            // Se superó el techo de 255 bloques: se detiene sin abortar.
            break;
        }
        let mut input = Vec::with_capacity(previous.len() + info.len() + 1);
        input.extend_from_slice(&previous);
        input.extend_from_slice(info);
        input.push(counter);
        let block = hmac_sha256(prk, &input);
        let take = chunk.len().min(block.len());
        chunk[..take].copy_from_slice(&block[..take]);
        written += take;
        previous = block.to_vec();
    }
    written
}

/// HKDF completo (*extract* + *expand*) en una sola llamada.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> usize {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, out)
}

/// Deriva exactamente 32 bytes (el caso que usan el ADN y el túnel de red).
pub fn hkdf_32(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let written = hkdf_sha256(salt, ikm, info, &mut out);
    if written < 32 {
        // Sólo alcanzable violando el techo del RFC; el núcleo no aborta.
        out = [0u8; 32];
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────
// ChaCha20 (RFC 8439 §2.3-2.4)
// ─────────────────────────────────────────────────────────────────────────

/// Constantes de la función de bloque: `"expand 32-byte k"` en *little-endian*.
const CHACHA_SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// Lee 4 bytes en *little-endian* sin poder salirse del *slice*.
fn load32(data: &[u8], at: usize) -> u32 {
    let b0 = data.get(at).copied().unwrap_or(0);
    let b1 = data.get(at + 1).copied().unwrap_or(0);
    let b2 = data.get(at + 2).copied().unwrap_or(0);
    let b3 = data.get(at + 3).copied().unwrap_or(0);
    u32::from_le_bytes([b0, b1, b2, b3])
}

/// Ronda de cuarto de ChaCha: mezcla cuatro palabras del estado.
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

/// Función de bloque de ChaCha20: 64 bytes de keystream.
///
/// El estado es `constantes | clave | contador | nonce`; tras veinte rondas se
/// le suma el estado inicial y se serializa en *little-endian*.
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[0] = CHACHA_SIGMA[0];
    state[1] = CHACHA_SIGMA[1];
    state[2] = CHACHA_SIGMA[2];
    state[3] = CHACHA_SIGMA[3];
    for (index, chunk) in key.chunks(4).enumerate() {
        let mut word = [0u8; 4];
        word.copy_from_slice(chunk);
        state[4 + index] = u32::from_le_bytes(word);
    }
    state[12] = counter;
    for (index, chunk) in nonce.chunks(4).enumerate() {
        let mut word = [0u8; 4];
        word.copy_from_slice(chunk);
        state[13 + index] = u32::from_le_bytes(word);
    }

    let initial = state;
    for _ in 0..10 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }
    for (slot, seed) in state.iter_mut().zip(initial.iter()) {
        *slot = slot.wrapping_add(*seed);
    }

    let mut out = [0u8; 64];
    for (index, word) in state.iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// Cifra (o descifra: la operación es su propia inversa) en modo contador.
///
/// El contador arranca en `counter` y avanza un bloque por cada 64 bytes, con
/// aritmética de módulo 2³²: ningún tamaño de entrada desborda (totalidad).
pub fn chacha20_xor(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    for (index, chunk) in data.chunks_mut(64).enumerate() {
        let block = chacha20_block(key, counter.wrapping_add(index as u32), nonce);
        for (byte, mask) in chunk.iter_mut().zip(block.iter()) {
            *byte ^= *mask;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Poly1305 (RFC 8439 §2.5)
// ─────────────────────────────────────────────────────────────────────────

/// Máscara de un limbo de 26 bits.
const POLY_MASK: u32 = 0x03ff_ffff;

/// Autenticador `Poly1305` con clave de un solo uso de 32 bytes.
///
/// La aritmética vive en `𝔽(2¹³⁰ − 5)` con cinco limbos de 26 bits y productos
/// en `u64`: no hay números grandes ni reservas dinámicas, así que el coste es
/// constante y no depende del contenido del mensaje.
pub fn poly1305_mac(message: &[u8], key: &[u8; 32]) -> [u8; 16] {
    // Recorte normativo (`clamping`) aplicado **byte a byte**, tal y como lo
    // describe el RFC: así no hay ninguna constante recordada de memoria.
    let mut r_bytes = [0u8; 16];
    for (slot, value) in r_bytes.iter_mut().zip(key.iter()) {
        *slot = *value;
    }
    r_bytes[3] &= 15;
    r_bytes[7] &= 15;
    r_bytes[11] &= 15;
    r_bytes[4] &= 252;
    r_bytes[8] &= 252;
    r_bytes[12] &= 252;
    // `r` es, por definición, un número de 124 bits: su nibble más alto es cero
    // (es lo que codifica la constante `0x0ffffffc0ffffffc0ffffffc0fffffff`).
    r_bytes[15] &= 15;

    // `r` en cinco limbos limpios de 26 bits.
    let w0 = load32(&r_bytes, 0);
    let w1 = load32(&r_bytes, 4);
    let w2 = load32(&r_bytes, 8);
    let w3 = load32(&r_bytes, 12);
    let r = [
        w0 & POLY_MASK,
        ((w0 >> 26) | (w1 << 6)) & POLY_MASK,
        ((w1 >> 20) | (w2 << 12)) & POLY_MASK,
        ((w2 >> 14) | (w3 << 18)) & POLY_MASK,
        (w3 >> 8) & POLY_MASK,
    ];
    let mask64 = POLY_MASK as u64;
    let (r0, r1, r2, r3, r4) = (
        r[0] as u64,
        r[1] as u64,
        r[2] as u64,
        r[3] as u64,
        r[4] as u64,
    );
    let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);

    let mut h = [0u32; 5];
    let mut at = 0usize;
    while at < message.len() {
        let take = (message.len() - at).min(16);
        if take == 0 {
            break;
        }
        let mut block = [0u8; 16];
        block[..take].copy_from_slice(&message[at..at + take]);

        // Bloque completo: el bit 2¹²⁸ se aporta aparte. Bloque parcial: el
        // `0x01` normativo se escribe justo después de los bytes útiles.
        let mut high_bit = 1u32 << 24;
        if take < 16 {
            block[take] = 1;
            high_bit = 0;
        }

        let b0 = load32(&block, 0);
        let b1 = load32(&block, 4);
        let b2 = load32(&block, 8);
        let b3 = load32(&block, 12);

        h[0] = h[0].wrapping_add(b0 & POLY_MASK);
        h[1] = h[1].wrapping_add(((b0 >> 26) | (b1 << 6)) & POLY_MASK);
        h[2] = h[2].wrapping_add(((b1 >> 20) | (b2 << 12)) & POLY_MASK);
        h[3] = h[3].wrapping_add(((b2 >> 14) | (b3 << 18)) & POLY_MASK);
        h[4] = h[4].wrapping_add((b3 >> 8) | high_bit);

        // Producto escalar `(h + bloque) · r` en 𝔽(2¹³⁰ − 5).
        let (h0, h1, h2, h3, h4) = (
            h[0] as u64,
            h[1] as u64,
            h[2] as u64,
            h[3] as u64,
            h[4] as u64,
        );
        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        // Acarreo en cascada y plegado del limbo 5 (2¹³⁰ ≡ 5·2⁰).
        let mut carry = d0 >> 26;
        let mut part0 = (d0 & mask64) as u32;
        let sum1 = d1 + carry;
        carry = sum1 >> 26;
        let part1 = (sum1 & mask64) as u32;
        let sum2 = d2 + carry;
        carry = sum2 >> 26;
        let part2 = (sum2 & mask64) as u32;
        let sum3 = d3 + carry;
        carry = sum3 >> 26;
        let part3 = (sum3 & mask64) as u32;
        let sum4 = d4 + carry;
        carry = sum4 >> 26;
        let part4 = (sum4 & mask64) as u32;

        part0 = part0.wrapping_add((carry as u32).wrapping_mul(5));
        let extra = part0 >> 26;

        h = [
            part0 & POLY_MASK,
            part1.wrapping_add(extra),
            part2,
            part3,
            part4,
        ];
        at += take;
    }

    // Acarreo final completo: `h < 2¹²⁶ + …` pasa a limbos limpios.
    let mut carry = h[1] >> 26;
    h[1] &= POLY_MASK;
    h[2] = h[2].wrapping_add(carry);
    carry = h[2] >> 26;
    h[2] &= POLY_MASK;
    h[3] = h[3].wrapping_add(carry);
    carry = h[3] >> 26;
    h[3] &= POLY_MASK;
    h[4] = h[4].wrapping_add(carry);
    carry = h[4] >> 26;
    h[4] &= POLY_MASK;
    h[0] = h[0].wrapping_add(carry.wrapping_mul(5));
    carry = h[0] >> 26;
    h[0] &= POLY_MASK;
    h[1] = h[1].wrapping_add(carry);

    // Reducción condicional: si `h ≥ p` se toma `h + 5 mod 2¹³⁰`.
    let mut candidate = [0u32; 5];
    let mut bump = 5u32;
    let mut index = 0;
    while index < 5 {
        let sum = h[index].wrapping_add(bump);
        candidate[index] = sum & POLY_MASK;
        bump = sum >> 26;
        index += 1;
    }
    let select = 0u32.wrapping_sub(bump);
    for (slot, alternative) in h.iter_mut().zip(candidate.iter()) {
        *slot = (*slot & !select) | (*alternative & select);
    }

    // Empaqueta 130 bits en 128 (el bit 2¹²⁸ se descarta) y suma el pad.
    let word0 = h[0] | (h[1] << 26);
    let word1 = (h[1] >> 6) | (h[2] << 20);
    let word2 = (h[2] >> 12) | (h[3] << 14);
    let word3 = (h[3] >> 18) | (h[4] << 8);

    let mut sum = word0 as u64 + load32(key, 16) as u64;
    let out0 = sum as u32;
    sum = word1 as u64 + load32(key, 20) as u64 + (sum >> 32);
    let out1 = sum as u32;
    sum = word2 as u64 + load32(key, 24) as u64 + (sum >> 32);
    let out2 = sum as u32;
    sum = word3 as u64 + load32(key, 28) as u64 + (sum >> 32);
    let out3 = sum as u32;

    let mut tag = [0u8; 16];
    tag[0..4].copy_from_slice(&out0.to_le_bytes());
    tag[4..8].copy_from_slice(&out1.to_le_bytes());
    tag[8..12].copy_from_slice(&out2.to_le_bytes());
    tag[12..16].copy_from_slice(&out3.to_le_bytes());
    tag
}

// ─────────────────────────────────────────────────────────────────────────
// AEAD_CHACHA20_POLY1305 (RFC 8439 §2.8)
// ─────────────────────────────────────────────────────────────────────────

/// Longitud de la etiqueta de autenticación, en bytes.
pub const AEAD_TAG: usize = 16;

/// Compara dos etiquetas sin salida temprana (ni recorre de más).
fn tags_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Rellena con ceros hasta el siguiente múltiplo de 16 (norma del AEAD).
fn pad_to_16(buffer: &mut Vec<u8>) {
    // Redondeo hacia arriba al múltiplo de 16: `(n + 15) & !15`.
    let rounded = (buffer.len() + 15) & !15;
    while buffer.len() < rounded {
        buffer.push(0);
    }
}

/// Clave de un solo uso de Poly1305: el primer bloque de ChaCha20 con contador 0.
fn poly_one_time_key(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let block = chacha20_block(key, 0, nonce);
    let mut one_time = [0u8; 32];
    one_time.copy_from_slice(&block[..32]);
    one_time
}

/// Etiqueta Poly1305 sobre `AAD ‖ relleno ‖ cifrado ‖ relleno ‖ longitudes`.
fn aead_tag(one_time_key: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut mac = Vec::with_capacity(aad.len() + ciphertext.len() + 32);
    mac.extend_from_slice(aad);
    pad_to_16(&mut mac);
    mac.extend_from_slice(ciphertext);
    pad_to_16(&mut mac);
    mac.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    poly1305_mac(&mac, one_time_key)
}

/// **Sella** un mensaje: devuelve `cifrado ‖ etiqueta` (longitud = claro + 16).
///
/// El *nonce* jamás debe repetirse con la misma clave: la unicidad la garantiza
/// el llamante (el túnel de red usa un contador monótono).
pub fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let one_time_key = poly_one_time_key(key, nonce);
    let mut sealed = plaintext.to_vec();
    chacha20_xor(key, 1, nonce, &mut sealed);
    let tag = aead_tag(&one_time_key, aad, &sealed);
    sealed.extend_from_slice(&tag);
    sealed
}

/// **Abre** un mensaje sellado. Devuelve `None` si la etiqueta no cuadra:
/// un solo bit alterado invalida el mensaje completo (inmunidad de integridad).
pub fn aead_open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < AEAD_TAG {
        return None;
    }
    let split = sealed.len() - AEAD_TAG;
    let (ciphertext, tag) = sealed.split_at(split);
    let one_time_key = poly_one_time_key(key, nonce);
    let expected = aead_tag(&one_time_key, aad, ciphertext);
    if !tags_equal(&expected, tag) {
        return None;
    }
    let mut plaintext = ciphertext.to_vec();
    chacha20_xor(key, 1, nonce, &mut plaintext);
    Some(plaintext)
}

// ─────────────────────────────────────────────────────────────────────────
// AES-128 (FIPS 197) · AEAD AES-128-GCM (NIST SP 800-38D)
// ─────────────────────────────────────────────────────────────────────────

/// Bytes de la clave de AES-128.
pub const AES128_KEY: usize = 16;
/// Bytes de un bloque AES.
pub const AES_BLOCK: usize = 16;
/// Bytes de la expansión de clave de AES-128: 11 claves de ronda.
pub const AES128_SCHEDULE: usize = 176;
/// Longitud de la etiqueta de GCM, en bytes.
pub const GCM_TAG: usize = 16;

/// Caja de sustitución de AES-128 (`S[byte]`, FIPS 197 §5.1.1).
///
/// Se escribe como datos —no se computa—: la tabla es un estándar publicado y
/// así no hay ninguna ruta de código que pueda equivocarse al derivarla.
const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// Multiplica por `x` en `𝔽₂[x]/(x⁸ + x⁴ + x³ + x + 1)` (FIPS 197 §4.2.1).
fn aes_xtime(byte: u8) -> u8 {
    // El desplazamiento ya es de 8 bits (`u8`), así que la máscara `0xff` sería
    // una operación identidad y clippy la rechaza (`identity_op`).
    (byte << 1) ^ (((byte >> 7) & 1) * 0x1b)
}

/// `SubBytes`: substitución byte a byte por la caja `S`.
fn sub_bytes(state: &mut [u8; AES_BLOCK]) {
    for byte in state.iter_mut() {
        if let Some(mapped) = AES_SBOX.get(usize::from(*byte)) {
            *byte = *mapped;
        }
    }
}

/// `ShiftRows`: rotación a la izquierda de cada fila por su índice de fila.
fn shift_rows(state: &mut [u8; AES_BLOCK]) {
    let previous = *state;
    for column in 0..4 {
        for row in 0..4 {
            // El byte `(fila, columna)` toma el de la columna `(columna + fila)`.
            let source = 4 * ((column + row) % 4) + row;
            if let (Some(slot), Some(byte)) =
                (state.get_mut(4 * column + row), previous.get(source))
            {
                *slot = *byte;
            }
        }
    }
}

/// `MixColumns`: multiplica cada columna por el polinomio `03 01 01 02`.
fn mix_columns(state: &mut [u8; AES_BLOCK]) {
    let previous = *state;
    for column in 0..4 {
        let mut bytes = [0u8; 4];
        for (row, slot) in bytes.iter_mut().enumerate() {
            if let Some(byte) = previous.get(4 * column + row) {
                *slot = *byte;
            }
        }
        let doubled = [
            aes_xtime(bytes[0]),
            aes_xtime(bytes[1]),
            aes_xtime(bytes[2]),
            aes_xtime(bytes[3]),
        ];
        let mixed = [
            doubled[0] ^ doubled[1] ^ bytes[1] ^ bytes[2] ^ bytes[3],
            bytes[0] ^ doubled[1] ^ doubled[2] ^ bytes[2] ^ bytes[3],
            bytes[0] ^ bytes[1] ^ doubled[2] ^ doubled[3] ^ bytes[3],
            doubled[0] ^ bytes[0] ^ bytes[1] ^ bytes[2] ^ doubled[3],
        ];
        for (row, byte) in mixed.iter().enumerate() {
            if let Some(slot) = state.get_mut(4 * column + row) {
                *slot = *byte;
            }
        }
    }
}

/// `AddRoundKey`: suma (XOR) la clave de ronda correspondiente.
fn add_round_key(state: &mut [u8; AES_BLOCK], schedule: &[u8; AES128_SCHEDULE], round: usize) {
    for (index, byte) in state.iter_mut().enumerate() {
        if let Some(key) = schedule.get(round * AES_BLOCK + index) {
            *byte ^= *key;
        }
    }
}

/// Rondas de AES-128 (FIPS 197): 10 rondas + la suma inicial de clave.
pub const AES128_ROUNDS: usize = 10;

/// Cifrador de bloque **AES-128** con su calendario de claves expandido.
///
/// Sólo implementa el cifrado (el camuflaje nunca descifra con AES: deriva la
/// clave de sesión y sella registros), y no expone ninguna operación que pueda
/// abortar: cualquier `&[u8]` de otra longitud se rechaza con `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aes128 {
    /// Once claves de ronda consecutivas de 16 bytes (FIPS 197 §5.2).
    schedule: [u8; AES128_SCHEDULE],
}

impl Aes128 {
    /// Expande la clave de 128 bits (FIPS 197 §5.2).
    pub fn new(key: &[u8; AES128_KEY]) -> Self {
        let mut schedule = [0u8; AES128_SCHEDULE];
        schedule[..AES128_KEY].copy_from_slice(key);
        let mut rcon = 1u8;
        let mut at = AES128_KEY;
        while at < AES128_SCHEDULE {
            let mut word = [
                schedule[at - 4],
                schedule[at - 3],
                schedule[at - 2],
                schedule[at - 1],
            ];
            if at.is_multiple_of(AES128_KEY) {
                // RotWord ‖ SubWord ‖ Rcon, sólo en la primera palabra de ronda.
                word = [word[1], word[2], word[3], word[0]];
                for slot in word.iter_mut() {
                    *slot = AES_SBOX.get(usize::from(*slot)).copied().unwrap_or(*slot);
                }
                word[0] ^= rcon;
                rcon = aes_xtime(rcon);
            }
            for (index, byte) in word.iter().enumerate() {
                // La palabra previa está siempre dentro del calendario; el
                // destino también porque el bucle termina en `at = 172`.
                let previous = schedule[at - AES128_KEY + index];
                if let Some(slot) = schedule.get_mut(at + index) {
                    *slot = previous ^ *byte;
                }
            }
            at += 4;
        }
        Aes128 { schedule }
    }

    /// Cifra un bloque de 16 bytes (FIPS 197 §5.1).
    ///
    /// El estado se dispone por columnas, como manda el estándar: el byte `i`
    /// del bloque es la fila `i % 4` de la columna `i / 4`.
    pub fn encrypt_block(&self, block: &[u8; AES_BLOCK]) -> [u8; AES_BLOCK] {
        let mut state = *block;
        add_round_key(&mut state, &self.schedule, 0);
        for round in 1..AES128_ROUNDS {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            add_round_key(&mut state, &self.schedule, round);
        }
        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_round_key(&mut state, &self.schedule, AES128_ROUNDS);
        state
    }

    /// Deriva un cifrador de un material de clave de longitud arbitraria.
    ///
    /// Devuelve `None` si el material no mide exactamente 16 bytes: el núcleo
    /// nunca recorta ni rellena una clave en silencio (totalidad declarada).
    pub fn from_key_material(material: &[u8]) -> Option<Self> {
        let key = <[u8; AES128_KEY]>::try_from(material).ok()?;
        Some(Aes128::new(&key))
    }
}

/// Polinomio de reducción de GCM: `R = 11100001 ‖ 0¹²⁰` (SP 800-38D §6.3).
const GCM_R: u128 = 0xe1 << 120;

/// Lee un bloque de 16 bytes como entero de 128 bits, en orden de red.
fn digest_to_u128(bytes: &[u8]) -> u128 {
    let mut block = [0u8; AES_BLOCK];
    for (slot, byte) in block.iter_mut().zip(bytes.iter()) {
        *slot = *byte;
    }
    u128::from_be_bytes(block)
}

/// Multiplica dos elementos de `GF(2¹²⁸)` con la convención de GCM.
///
/// El bit 127 es el coeficiente de `x⁰`, así que el recorrido empieza por el
/// bit más significativo y reduce con `R` cuando el desplazamiento desborda: es
/// exactamente el algoritmo *Multiply* de SP 800-38D §6.3 (sin tablas, para no
/// añadir estado compartido al kernel).
fn gcm_multiply(left: u128, right: u128) -> u128 {
    let mut product = 0u128;
    let mut value = right;
    for bit in 0..128 {
        if (left >> (127 - bit)) & 1 == 1 {
            product ^= value;
        }
        let carry = value & 1;
        value >>= 1;
        if carry == 1 {
            value ^= GCM_R;
        }
    }
    product
}

/// `GHASH`: autentica una secuencia de bloques, rellenando a 16 bytes.
///
/// Los datos ya llegan con los rellenos y las longitudes que exige el modo; la
/// función sólo los consume en bloques de 16 bytes (`(X_i ⊕ B_i) · H`).
fn ghash(key: u128, message: &[u8]) -> u128 {
    let mut digest = 0u128;
    let mut padded = message.to_vec();
    pad_to_16(&mut padded);
    for chunk in padded.chunks(AES_BLOCK) {
        digest = gcm_multiply(digest ^ digest_to_u128(chunk), key);
    }
    digest
}

/// `inc32`: incrementa módulo `2³²` el contador de 32 bits final del bloque.
fn inc32(counter: u128) -> u128 {
    let low = ((counter & 0xffff_ffff) as u32).wrapping_add(1);
    (counter & !0xffff_ffffu128) | u128::from(low)
}

/// Prepara el cifrador y los valores fijos del modo: `H = E_K(0¹²⁸)` y `J₀`.
///
/// Para un `nonce` de 96 bits —el que usa el camuflaje— `J₀ = nonce ‖ 0³² ‖ 1`.
fn gcm_setup(key: &[u8], nonce: &[u8; 12]) -> Option<(Aes128, u128, u128)> {
    let cipher = Aes128::from_key_material(key)?;
    let h = digest_to_u128(&cipher.encrypt_block(&[0u8; AES_BLOCK]));
    let mut j0 = [0u8; AES_BLOCK];
    j0[..12].copy_from_slice(nonce);
    j0[AES_BLOCK - 1] = 1;
    Some((cipher, h, u128::from_be_bytes(j0)))
}

/// Aplica el flujo del contador de GCM: **su propio inverso** (XOR).
fn gcm_stream(cipher: &Aes128, j0: u128, data: &mut [u8]) {
    let mut counter = j0;
    for chunk in data.chunks_mut(AES_BLOCK) {
        counter = inc32(counter);
        let block = cipher.encrypt_block(&counter.to_be_bytes());
        for (byte, stream) in chunk.iter_mut().zip(block.iter()) {
            *byte ^= *stream;
        }
    }
}

/// Etiqueta `T = E_K(J₀) ⊕ GHASH_H(A ‖ pad ‖ C ‖ pad ‖ len(A) ‖ len(C))`.
fn gcm_tag(cipher: &Aes128, h: u128, j0: u128, aad: &[u8], ciphertext: &[u8]) -> [u8; GCM_TAG] {
    let mut authenticated = Vec::with_capacity(aad.len() + ciphertext.len() + 2 * AES_BLOCK);
    authenticated.extend_from_slice(aad);
    pad_to_16(&mut authenticated);
    authenticated.extend_from_slice(ciphertext);
    pad_to_16(&mut authenticated);
    authenticated.extend_from_slice(&(aad.len() as u64).wrapping_mul(8).to_be_bytes());
    authenticated.extend_from_slice(&(ciphertext.len() as u64).wrapping_mul(8).to_be_bytes());
    let mask = digest_to_u128(&cipher.encrypt_block(&j0.to_be_bytes()));
    (ghash(h, &authenticated) ^ mask).to_be_bytes()
}

/// ¿Coincide la etiqueta calculada con la recibida? (recorrido completo)
fn gcm_tag_matches(expected: &[u8; GCM_TAG], received: &[u8]) -> bool {
    let mut difference = if received.len() == GCM_TAG { 0u8 } else { 1u8 };
    for (index, byte) in expected.iter().enumerate() {
        let other = received.get(index).copied().unwrap_or(0);
        difference |= byte ^ other;
    }
    difference == 0
}

/// **AEAD `AES-128-GCM`** (NIST SP 800-38D): sella y autentica en una pasada.
///
/// Devuelve `cifrado ‖ etiqueta` (16 bytes de etiqueta) o `None` si la clave no
/// mide 16 bytes. La `nonce` es de 96 bits, como exige el perfil de TLS 1.3; el
/// `aad` es la cabecera del registro, que viaja en claro pero autenticada.
///
/// Es el AEAD que activa la paridad con `TLS_AES_128_GCM_SHA256` sin depender de
/// ninguna biblioteca externa: el cifrador de bloque es [`Aes128`] y `GHASH` se
/// calcula aquí mismo.
pub fn aes128_gcm_seal(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    let (cipher, h, j0) = gcm_setup(key, nonce)?;
    let mut sealed = plaintext.to_vec();
    gcm_stream(&cipher, j0, &mut sealed);
    let tag = gcm_tag(&cipher, h, j0, aad, &sealed);
    sealed.extend_from_slice(&tag);
    Some(sealed)
}

/// Abre un mensaje sellado con [`aes128_gcm_seal`], o `None` si es inconsistente.
///
/// La etiqueta se contrasta **antes** de devolver un solo byte de texto claro y
/// el contraste recorre los 16 bytes siempre (tiempo constante): un registro
/// manipulado no filtra por dónde iba bien.
pub fn aes128_gcm_open(key: &[u8], nonce: &[u8; 12], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    let (cipher, h, j0) = gcm_setup(key, nonce)?;
    if sealed.len() < GCM_TAG {
        return None;
    }
    let split = sealed.len() - GCM_TAG;
    let (ciphertext, tag) = sealed.split_at(split);
    let expected = gcm_tag(&cipher, h, j0, aad, ciphertext);
    if !gcm_tag_matches(&expected, tag) {
        return None;
    }
    let mut plaintext = ciphertext.to_vec();
    gcm_stream(&cipher, j0, &mut plaintext);
    Some(plaintext)
}

// ─────────────────────────────────────────────────────────────────────────
// X25519 · Curve25519 (RFC 7748)
// ─────────────────────────────────────────────────────────────────────────

/// Máscara de un limbo de 51 bits del campo `𝔽(2²⁵⁵ − 19)`.
const FE_MASK: u64 = (1u64 << 51) - 1;

/// Constante de la escalera de Montgomery: `(486662 − 2) / 4`.
const A24: u64 = 121_665;

/// Lee 8 bytes en *little-endian* sin poder salirse del *slice*.
fn load8(data: &[u8], at: usize) -> u64 {
    let mut chunk = [0u8; 8];
    for (offset, slot) in chunk.iter_mut().enumerate() {
        *slot = data.get(at + offset).copied().unwrap_or(0);
    }
    u64::from_le_bytes(chunk)
}

/// Elemento de `𝔽(2²⁵⁵ − 19)` en cinco limbos de 51 bits.
///
/// La representación es *redundante*: los limbos no se normalizan tras cada
/// operación (sólo se acarrean al multiplicar y al serializar). Eso mantiene la
/// aritmética en `u128` y evita cualquier número grande con reserva dinámica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Field25519([u64; 5]);

impl Field25519 {
    /// Cero del campo.
    const ZERO: Field25519 = Field25519([0, 0, 0, 0, 0]);
    /// Uno del campo.
    const ONE: Field25519 = Field25519([1, 0, 0, 0, 0]);
    /// Representación de `2p`, usada para restar sin signo.
    const TWO_P: Field25519 = Field25519([
        4_503_599_627_370_458,
        4_503_599_627_370_494,
        4_503_599_627_370_494,
        4_503_599_627_370_494,
        4_503_599_627_370_494,
    ]);

    /// Deserializa 32 bytes (se ignoran los bits por encima de `2²⁵⁵`).
    fn from_bytes(bytes: &[u8; 32]) -> Self {
        let l0 = load8(bytes, 0);
        let l1 = load8(bytes, 6);
        let l2 = load8(bytes, 12);
        let l3 = load8(bytes, 19);
        let l4 = load8(bytes, 24);
        Field25519([
            l0 & FE_MASK,
            (l1 >> 3) & FE_MASK,
            (l2 >> 6) & FE_MASK,
            (l3 >> 1) & FE_MASK,
            (l4 >> 12) & FE_MASK,
        ])
    }

    /// Serializa reduciendo por completo módulo `p` (forma canónica).
    fn to_bytes(self) -> [u8; 32] {
        let mut t = self.0;
        let mut carry = t[0] >> 51;
        t[0] &= FE_MASK;
        t[1] += carry;
        carry = t[1] >> 51;
        t[1] &= FE_MASK;
        t[2] += carry;
        carry = t[2] >> 51;
        t[2] &= FE_MASK;
        t[3] += carry;
        carry = t[3] >> 51;
        t[3] &= FE_MASK;
        t[4] += carry;
        carry = t[4] >> 51;
        t[4] &= FE_MASK;
        t[0] += carry * 19;
        carry = t[0] >> 51;
        t[0] &= FE_MASK;
        t[1] += carry;

        // Resta condicional de `p`: `q` vale 1 sólo si el valor alcanza `p`.
        let mut q = (t[0] + 19) >> 51;
        q = (t[1] + q) >> 51;
        q = (t[2] + q) >> 51;
        q = (t[3] + q) >> 51;
        q = (t[4] + q) >> 51;
        t[0] += 19 * q;
        carry = t[0] >> 51;
        t[0] &= FE_MASK;
        t[1] += carry;
        carry = t[1] >> 51;
        t[1] &= FE_MASK;
        t[2] += carry;
        carry = t[2] >> 51;
        t[2] &= FE_MASK;
        t[3] += carry;
        carry = t[3] >> 51;
        t[3] &= FE_MASK;
        t[4] = (t[4] + carry) & FE_MASK;

        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&(t[0] | (t[1] << 51)).to_le_bytes());
        out[8..16].copy_from_slice(&((t[1] >> 13) | (t[2] << 38)).to_le_bytes());
        out[16..24].copy_from_slice(&((t[2] >> 26) | (t[3] << 25)).to_le_bytes());
        out[24..32].copy_from_slice(&((t[3] >> 39) | (t[4] << 12)).to_le_bytes());
        out
    }

    /// Suma con acarreo inmediato (los limbos quedan por debajo de `2⁵²`).
    fn add(&self, other: &Field25519) -> Field25519 {
        let mut out = [0u64; 5];
        let mut carry = 0u64;
        for (index, slot) in out.iter_mut().enumerate() {
            let sum = self.0[index] + other.0[index] + carry;
            *slot = sum & FE_MASK;
            carry = sum >> 51;
        }
        out[0] += carry * 19;
        let tail = out[0] >> 51;
        out[0] &= FE_MASK;
        out[1] += tail;
        Field25519(out)
    }

    /// Resta como `self + (2p − other)`: nunca hay desbordamiento hacia abajo.
    fn sub(&self, other: &Field25519) -> Field25519 {
        let mut negated = [0u64; 5];
        let mut borrow = 0u64;
        for (index, slot) in negated.iter_mut().enumerate() {
            let (value, underflow) = Self::TWO_P.0[index].overflowing_sub(other.0[index] + borrow);
            *slot = value;
            borrow = u64::from(underflow);
        }
        self.add(&Field25519(negated))
    }
}

impl Field25519 {
    /// Producto en `𝔽(2²⁵⁵ − 19)` con plegado `2²⁵⁵ ≡ 19`.
    fn mul(&self, other: &Field25519) -> Field25519 {
        let mut products = [0u128; 9];
        for (index, left) in self.0.iter().enumerate() {
            for (offset, right) in other.0.iter().enumerate() {
                products[index + offset] += (*left as u128) * (*right as u128);
            }
        }

        let mut folded = [0u128; 5];
        for (index, value) in products.iter().enumerate() {
            if index < 5 {
                folded[index] += *value;
            } else {
                folded[index - 5] += *value * 19;
            }
        }

        let mut limbs = [0u64; 5];
        let mut carry = 0u128;
        for (index, slot) in limbs.iter_mut().enumerate() {
            let total = folded[index] + carry;
            *slot = (total & FE_MASK as u128) as u64;
            carry = total >> 51;
        }

        // Acarreo sobrante plegado en el limbo 0 sin salirse de `u64`.
        let mut head = (limbs[0] as u128) + carry * 19;
        limbs[0] = (head & FE_MASK as u128) as u64;
        head >>= 51;
        limbs[1] = limbs[1].wrapping_add(head as u64);
        let tail = limbs[1] >> 51;
        limbs[1] &= FE_MASK;
        limbs[2] = limbs[2].wrapping_add(tail);
        Field25519(limbs)
    }

    /// Cuadrado (caso particular de [`Field25519::mul`]).
    fn square(&self) -> Field25519 {
        self.mul(self)
    }

    /// Multiplica por un escalar pequeño de 64 bits.
    fn mul_small(&self, scalar: u64) -> Field25519 {
        let mut products = [0u128; 5];
        for (index, limb) in self.0.iter().enumerate() {
            products[index] = (*limb as u128) * (scalar as u128);
        }
        let mut limbs = [0u64; 5];
        let mut carry = 0u128;
        for (index, slot) in limbs.iter_mut().enumerate() {
            let total = products[index] + carry;
            *slot = (total & FE_MASK as u128) as u64;
            carry = total >> 51;
        }
        limbs[0] = limbs[0].wrapping_add((carry as u64).wrapping_mul(19));
        let tail = limbs[0] >> 51;
        limbs[0] &= FE_MASK;
        limbs[1] = limbs[1].wrapping_add(tail);
        Field25519(limbs)
    }

    /// Inverso multiplicativo por `x^(p−2)` (pequeño teorema de Fermat).
    fn invert(&self) -> Field25519 {
        // `p − 2 = 2²⁵⁵ − 21`: `0xeb`, treinta `0xff` y un `0x7f` final.
        let mut exponent = [0xffu8; 32];
        exponent[0] = 0xeb;
        exponent[31] = 0x7f;

        let mut result = Field25519::ONE;
        let mut base = *self;
        for bit in 0..255 {
            let byte = bit / 8;
            let shift = bit % 8;
            if (exponent[byte] >> shift) & 1 == 1 {
                result = result.mul(&base);
            }
            base = base.square();
        }
        result
    }
}

/// Intercambio condicional de dos elementos según `swap` (0 o 1), sin bifurcar.
fn conditional_swap(left: &mut Field25519, right: &mut Field25519, swap: u64) {
    let mask = 0u64.wrapping_sub(swap);
    for (a, b) in left.0.iter_mut().zip(right.0.iter_mut()) {
        let delta = mask & (*a ^ *b);
        *a ^= delta;
        *b ^= delta;
    }
}

/// **X25519**: multiplicación escalar Diffie‑Hellman sobre Curve25519.
///
/// El escalar se recorta como manda el RFC 7748 (`k[0] &= 248`, `k[31] &= 127`,
/// `k[31] |= 64`) y se recorre la escalera de Montgomery en 255 pasos. Las dos
/// partes de una sesión obtienen el mismo secreto bit a bit.
pub fn x25519(scalar: &[u8; 32], u_coordinate: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    let mut masked_u = *u_coordinate;
    masked_u[31] &= 127;

    let x1 = Field25519::from_bytes(&masked_u);
    let mut x2 = Field25519::ONE;
    let mut z2 = Field25519::ZERO;
    let mut x3 = x1;
    let mut z3 = Field25519::ONE;
    let mut swap = 0u64;

    for step in (0..255).rev() {
        let bit = u64::from((k[step / 8] >> (step % 8)) & 1);
        swap ^= bit;
        conditional_swap(&mut x2, &mut x3, swap);
        conditional_swap(&mut z2, &mut z3, swap);
        swap = bit;

        let a = x2.add(&z2);
        let aa = a.square();
        let b = x2.sub(&z2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        let difference = da.sub(&cb);
        x3 = da.add(&cb).square();
        z3 = x1.mul(&difference.square());
        x2 = aa.mul(&bb);
        z2 = e.mul(&aa.add(&e.mul_small(A24)));
    }

    conditional_swap(&mut x2, &mut x3, swap);
    conditional_swap(&mut z2, &mut z3, swap);
    x2.mul(&z2.invert()).to_bytes()
}

/// X25519 contra la base canónica (`u = 9`): genera la clave pública.
pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    let mut base = [0u8; 32];
    base[0] = 9;
    x25519(scalar, &base)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodifica hexadecimal ignorando separadores (`:`, espacios, saltos).
    fn hex(text: &str) -> Vec<u8> {
        let nibbles: Vec<u8> = text
            .chars()
            .filter_map(|character| character.to_digit(16).map(|digit| digit as u8))
            .collect();
        nibbles
            .chunks(2)
            .map(|pair| (pair[0] << 4) | pair.get(1).copied().unwrap_or(0))
            .collect()
    }

    /// Empaqueta un vector hexadecimal de 32 bytes.
    fn key32(text: &str) -> [u8; 32] {
        let bytes = hex(text);
        let mut out = [0u8; 32];
        for (slot, value) in out.iter_mut().zip(bytes.iter()) {
            *slot = *value;
        }
        out
    }

    /// Empaqueta un vector hexadecimal de 12 bytes.
    fn nonce12(text: &str) -> [u8; 12] {
        let bytes = hex(text);
        let mut out = [0u8; 12];
        for (slot, value) in out.iter_mut().zip(bytes.iter()) {
            *slot = *value;
        }
        out
    }

    /// Empaqueta un vector hexadecimal de 16 bytes.
    fn bytes16(text: &str) -> [u8; 16] {
        let bytes = hex(text);
        let mut out = [0u8; 16];
        for (slot, value) in out.iter_mut().zip(bytes.iter()) {
            *slot = *value;
        }
        out
    }

    /// Vector C.1 de FIPS 197: la prueba de referencia del cifrador de bloque.
    #[test]
    fn aes128_coincide_con_fips_197() {
        // Apéndice C.1: clave `000102…0f`, bloque `00112233…ff`.
        let cipher = Aes128::new(&bytes16("000102030405060708090a0b0c0d0e0f"));
        assert_eq!(
            cipher
                .encrypt_block(&bytes16("00112233445566778899aabbccddeeff"))
                .to_vec(),
            hex("69c4e0d86a7b0430d8cdb78070b4c55a")
        );

        // Apéndice B: el ejemplo «legendario» del estándar.
        let cipher = Aes128::new(&bytes16("2b7e151628aed2a6abf7158809cf4f3c"));
        assert_eq!(
            cipher
                .encrypt_block(&bytes16("3243f6a8885a308d313198a2e0370734"))
                .to_vec(),
            hex("3925841d02dc09fbdc118597196a0b32")
        );

        // El calendario de claves es determinista y reproducible.
        assert_eq!(Aes128::new(&[0u8; 16]), Aes128::new(&[0u8; 16]));
        // Y el material de clave sólo se acepta con la longitud exacta.
        assert!(Aes128::from_key_material(&[0u8; 15]).is_none());
        assert!(Aes128::from_key_material(&[0u8; 17]).is_none());
        assert!(Aes128::from_key_material(&[0u8; 16]).is_some());
    }

    /// Vectores de McGrew‑Viega / NIST para `AES-128-GCM` (casos 1 a 4).
    #[test]
    fn aes128_gcm_coincide_con_los_vectores_nist() {
        let zero_key = [0u8; 16];
        let zero_nonce = [0u8; 12];

        // Caso 1: texto claro vacío ⇒ sólo la etiqueta.
        let sealed = aes128_gcm_seal(&zero_key, &zero_nonce, &[], &[]);
        assert_eq!(
            sealed.as_deref(),
            Some(&hex("58e2fccefa7e3061367f1d57a4e7455a")[..])
        );

        // Caso 2: un bloque nulo descubierto antes de autenticarlo.
        let sealed = aes128_gcm_seal(&zero_key, &zero_nonce, &[], &[0u8; 16]);
        assert_eq!(
            sealed.as_deref(),
            Some(&hex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")[..])
        );

        // Caso 3: 64 bytes de texto claro con su etiqueta.
        let key = hex("feffe9928665731c6d6a8f9467308308");
        let nonce = nonce12("cafebabefacedbaddecaf888");
        let plaintext = hex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        );
        let sealed = aes128_gcm_seal(&key, &nonce, &[], &plaintext);
        assert_eq!(
            sealed.as_deref(),
            Some(
                &hex(
                    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                     21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985\
                     4d5c2af327cd64a62cf35abd2ba6fab4",
                )[..]
            )
        );

        // Caso 4: 60 bytes con datos autenticados adicionales (el `aad` pesa).
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let plaintext = hex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let sealed = aes128_gcm_seal(&key, &nonce, &aad, &plaintext);
        assert_eq!(
            sealed.as_deref(),
            Some(
                &hex(
                    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                     21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091\
                     5bc94fbc3221a5db94fae95ae7121a47",
                )[..]
            )
        );

        // Sellar y abrir es la identidad, también con longitudes irregulares.
        for length in [0usize, 1, 15, 16, 17, 63, 64, 65, 255] {
            let text: Vec<u8> = (0..length).map(|index| (index * 7 + 3) as u8).collect();
            let sealed = aes128_gcm_seal(&key, &nonce, &aad, &text);
            assert!(sealed.is_some());
            let Some(sealed) = sealed else { continue };
            assert_eq!(sealed.len(), length + GCM_TAG);
            assert_eq!(aes128_gcm_open(&key, &nonce, &aad, &sealed), Some(text));
        }
    }

    #[test]
    fn aes128_gcm_rechaza_manipulaciones_y_claves_ajenas() {
        let key = bytes16("feffe9928665731c6d6a8f9467308308");
        let nonce = nonce12("cafebabefacedbaddecaf888");
        let aad = b"cabecera del registro";
        let sealed = aes128_gcm_seal(&key, &nonce, aad, b"soberania del nodo");
        assert!(sealed.is_some());
        let Some(sealed) = sealed else { return };
        assert_eq!(
            aes128_gcm_open(&key, &nonce, aad, &sealed).as_deref(),
            Some(&b"soberania del nodo"[..])
        );

        // Un bit en la etiqueta rompe la autenticación.
        let mut tag_touched = sealed.clone();
        let last = tag_touched.len() - 1;
        tag_touched[last] ^= 0x01;
        assert!(aes128_gcm_open(&key, &nonce, aad, &tag_touched).is_none());

        // Un bit en el cifrado también.
        let mut body_touched = sealed.clone();
        body_touched[0] ^= 0x80;
        assert!(aes128_gcm_open(&key, &nonce, aad, &body_touched).is_none());

        // El `aad` está autenticado: cambiarlo invalida la apertura.
        assert!(aes128_gcm_open(&key, &nonce, b"otra cabecera", &sealed).is_none());

        // Otra `nonce` (mismo texto, distinto mensaje) tampoco abre.
        let other_nonce = nonce12("cafebabefacedbaddecaf889");
        assert!(aes128_gcm_open(&key, &other_nonce, aad, &sealed).is_none());

        // Otra clave tampoco, y una clave de longitud distinta se rechaza.
        let other_key = bytes16("00000000000000000000000000000000");
        assert!(aes128_gcm_open(&other_key, &nonce, aad, &sealed).is_none());
        assert!(aes128_gcm_seal(&key[..15], &nonce, aad, b"x").is_none());
        let long_key = [0u8; 17];
        assert!(aes128_gcm_open(&long_key[..], &nonce, aad, &sealed).is_none());

        // Sellar dos veces con la misma entrada da el mismo resultado y no toca
        // el texto claro del llamante.
        let again = aes128_gcm_seal(&key, &nonce, aad, b"soberania del nodo");
        assert_eq!(again, Some(sealed.clone()));
        // Un mensaje sellado truncado por debajo de la etiqueta no abre.
        assert!(aes128_gcm_open(&key, &nonce, aad, &sealed[..GCM_TAG - 1]).is_none());
    }

    #[test]
    fn sha256_coincide_con_fips_180_4() {
        assert_eq!(
            sha256(b"").to_vec(),
            hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            sha256(b"abc").to_vec(),
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        // La vía incremental y la de una sola pasada coinciden byte a byte.
        let mut streaming = Sha256::new();
        for byte in b"abc" {
            streaming.update(&[*byte]);
        }
        assert!(digest_eq(&streaming.finish(), &sha256(b"abc")));
        assert_eq!(sha256_hex(b"abc").len(), 64);
    }

    #[test]
    fn hmac_sha256_coincide_con_rfc_4231() {
        // Caso 1: clave de 20 bytes y datos cortos.
        assert_eq!(
            hmac_sha256(
                &hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                b"Hi There"
            )
            .to_vec(),
            hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
        // Caso 2: clave más corta que el digest.
        assert_eq!(
            hmac_sha256(b"Jefe", b"what do ya want for nothing?").to_vec(),
            hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
        // Caso 3: clave y datos que juntos superan el bloque de 64 bytes.
        assert_eq!(
            hmac_sha256(&hex(&"aa".repeat(20)), &hex(&"dd".repeat(50))).to_vec(),
            hex("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
        );
    }

    #[test]
    fn chacha20_reproduce_el_keystream_de_rfc_8439() {
        let keystream = hex(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
             d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
        );
        let block = chacha20_block(
            &key32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            1,
            &nonce12("000000090000004a00000000"),
        );
        assert_eq!(block.to_vec(), keystream);

        // El cifrado en modo contador es su propia inversa.
        let key = key32(&"00".repeat(32));
        let nonce = nonce12(&"00".repeat(12));
        let mut payload = b"soberania".to_vec();
        let original = payload.clone();
        chacha20_xor(&key, 7, &nonce, &mut payload);
        assert_ne!(payload, original);
        chacha20_xor(&key, 7, &nonce, &mut payload);
        assert_eq!(payload, original);
    }

    #[test]
    fn poly1305_coincide_con_rfc_8439() {
        let key = key32("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        assert_eq!(
            poly1305_mac(b"Cryptographic Forum Research Group", &key).to_vec(),
            hex("a8061dc1305136c6c22b8baf0c0127a9")
        );
        // Las longitudes que no son múltiplo de 16 también autentican.
        assert_ne!(poly1305_mac(b"", &key), poly1305_mac(b"\0", &key));
    }

    #[test]
    fn el_aead_coincide_con_rfc_8439() {
        let key = key32("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = nonce12("070000004041424344454647");
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext =
            b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip \
                          for the future, sunscreen would be it.";
        let expected = hex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3\
             692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b6116",
        );

        let sealed = aead_seal(&key, &nonce, &aad, plaintext);
        assert_eq!(sealed.len(), plaintext.len() + AEAD_TAG);
        let split = sealed.len() - AEAD_TAG;
        assert_eq!(sealed[..split].to_vec(), expected);
        assert_eq!(
            &sealed[split..],
            &hex("1ae10b594f09e26a7e902ecbd0600691")[..]
        );
        assert_eq!(
            aead_open(&key, &nonce, &aad, &sealed).as_deref(),
            Some(&plaintext[..])
        );
    }

    #[test]
    fn el_aead_rechaza_cualquier_alteracion() {
        let key = key32(&"11".repeat(32));
        let nonce = nonce12(&"22".repeat(12));
        let sealed = aead_seal(&key, &nonce, b"cabecera", b"payload soberano");
        assert!(aead_open(&key, &nonce, b"cabecera", &sealed).is_some());

        // Cabecera asociada distinta, un bit cambiado, recorte, truncado y vacío.
        assert!(aead_open(&key, &nonce, b"cabecera!", &sealed).is_none());
        let mut altered = sealed.clone();
        if let Some(byte) = altered.first_mut() {
            *byte ^= 0x01;
        }
        assert!(aead_open(&key, &nonce, b"cabecera", &altered).is_none());
        assert!(aead_open(&key, &nonce, b"cabecera", &sealed[..sealed.len() - 1]).is_none());
        assert!(aead_open(&key, &nonce, b"cabecera", b"").is_none());
    }

    #[test]
    fn hkdf_deriva_claves_distintas_estables_y_acotadas() {
        let salt = hex("000102030405060708090a0b0c");
        let ikm = hex(&"0b".repeat(22));
        let first = hkdf_32(&salt, &ikm, b"aether-adn");
        assert_eq!(first, hkdf_32(&salt, &ikm, b"aether-adn"));
        assert_ne!(first, hkdf_32(&salt, &ikm, b"aether-camuflaje"));
        assert_ne!(first, hkdf_32(b"otra-sal", &ikm, b"aether-adn"));

        let mut long = [0u8; 64];
        assert_eq!(hkdf_sha256(&salt, &ikm, b"info", &mut long), 64);
        assert_ne!(&long[..32], &long[32..]);

        // Techo del RFC 5869: 255 bloques; lo que sobra se recorta sin abortar.
        let mut huge = vec![0u8; 255 * 32 + 16];
        assert_eq!(hkdf_sha256(&salt, &ikm, b"techo", &mut huge), 255 * 32);
        assert_eq!(huge[255 * 32], 0);
    }

    #[test]
    fn x25519_coincide_con_rfc_7748() {
        assert_eq!(
            x25519(
                &key32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
                &key32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
            )
            .to_vec(),
            hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        );
        assert_eq!(
            x25519(
                &key32("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
                &key32("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
            )
            .to_vec(),
            hex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
        );
    }

    #[test]
    fn dos_partes_de_una_sesion_acuerdan_el_mismo_secreto() {
        let alice = key32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob = key32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

        let alice_public = x25519_base(&alice);
        let bob_public = x25519_base(&bob);
        let shared_alice = x25519(&alice, &bob_public);
        let shared_bob = x25519(&bob, &alice_public);

        // Las dos partes llegan al mismo punto por caminos distintos.
        assert_eq!(shared_alice, shared_bob);
        assert_ne!(shared_alice, [0u8; 32]);
        assert_ne!(alice_public, bob_public);
        // Las claves recortadas hacen que el escalar sea sí o sí determinista.
        assert_eq!(x25519_base(&alice), alice_public);
    }
}
