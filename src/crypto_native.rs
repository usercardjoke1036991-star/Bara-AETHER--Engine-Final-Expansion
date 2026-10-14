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
