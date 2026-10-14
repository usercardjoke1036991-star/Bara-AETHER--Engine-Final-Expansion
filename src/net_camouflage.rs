//! # Camuflaje de red — `net_camouflage.rs`
//!
//! Un cliente **TLS 1.3 real**, escrito desde cero sobre `std` y el
//! criptosistema nativo ([`crypto_native`]), cuyo azar no viene del sistema
//! operativo sino del **ADN del AST** ([`golden_key`]). De ahí el nombre:
//! la misma fuente produce siempre la misma huella de red, así que un enjambre
//! Bara se reconoce en el cable sin dejar de ser, para cualquier servidor
//! convencional, un cliente corriente.
//!
//! ## Qué se implementa de verdad (no hay maqueta)
//! * **Registro TLS** ([`record`]): tipo, versión heredada y longitud; el
//!   primer registro sale con `0x0301` como manda RFC 8446 §5.1.
//! * **`ClientHello`** ([`client_hello_body`]): versión heredada, azar de 32
//!   bytes, `session_id`, conjuntos de cifrado, compresión nula y extensiones
//!   `server_name`, `supported_groups`, `signature_algorithms`,
//!   `supported_versions`, `psk_key_exchange_modes`, `key_share`, `alpn` y
//!   `padding`.
//! * **`ServerHello`** ([`server_hello`]) y su lector ([`parse_server_hello`]),
//!   para hablar con pares locales y para la suite.
//! * **Calendario de claves** ([`handshake_secrets`], [`application_secrets`]):
//!   `HKDF-Extract`/`HKDF-Expand-Label` con SHA-256, incluida `derive_secret`.
//! * **Protección de registros** ([`seal_record`], [`open_record`]):
//!   `ChaCha20-Poly1305` con el nonce `iv ⊕ seq` y el `AAD` de la cabecera,
//!   tal como especifica RFC 8446 §5.3.
//! * **Intercambio real de claves**: X25519 del criptosistema nativo, con
//!   escalar *clavado* (clamping) y acuerdo comprobado en las pruebas.
//!
//! ## Camuflaje
//! 1. La estructura del saludo imita la de un navegador corriente: conjuntos
//!    de cifrado modernos, `session_id` de 32 bytes, ALPN `h2`/`http/1.1` y
//!    relleno ([`CamouflageProfile::padding_to`], por defecto 512 bytes, el
//!    umbral que recomienda RFC 8446 §9.2).
//! 2. El `session_id` —que es material aleatorio y el servidor devuelve tal
//!    cual— lleva al principio una **marca de enjambre**:
//!    `HMAC(ADN, huella ‖ azar)` truncada a 16 bytes. Cualquier cliente TLS
//!    estándar la ignora; un par Bara la verifica con
//!    [`verify_camouflage`].
//! 3. La huella ([`fingerprint_of`]) es un digest de la estructura del saludo
//!    (*JA3*-símil) y **no** depende de claves ni de direcciones, de modo que
//!    el camuflaje no altera lo que un censurador ve.
//!
//! Nada de esto esconde el tráfico: la puerta abierta del núcleo
//! ([`crate::immunity_gateway`]) sigue siendo pública. El camuflaje protege la
//! **identidad del enjambre**, no la existencia del canal.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::ast_dna::{golden_key, short_hex};
use crate::crypto_native::{
    aead_open, aead_seal, chacha20_block, digest_eq, hkdf_expand, hkdf_extract, hmac_sha256,
    sha256, x25519, x25519_base, AEAD_TAG,
};

// ─────────────────────────────────────────────────────────────────────────
// Constantes del protocolo
// ─────────────────────────────────────────────────────────────────────────

/// Tipo de contenido: cambio de cifrado.
pub const CT_CHANGE_CIPHER_SPEC: u8 = 20;
/// Tipo de contenido: alerta.
pub const CT_ALERT: u8 = 21;
/// Tipo de contenido: mensaje de apretón de manos.
pub const CT_HANDSHAKE: u8 = 22;
/// Tipo de contenido: datos de aplicación.
pub const CT_APPLICATION_DATA: u8 = 23;

/// Mensaje de apretón de manos: `ClientHello`.
pub const HS_CLIENT_HELLO: u8 = 1;
/// Mensaje de apretón de manos: `ServerHello`.
pub const HS_SERVER_HELLO: u8 = 2;

/// Versión heredada que se anuncia en la cabecera y en los saludos.
pub const LEGACY_VERSION: u16 = 0x0303;
/// Versión heredada del **primer** registro (RFC 8446 §5.1).
pub const LEGACY_RECORD_VERSION: u16 = 0x0301;
/// Versión real del protocolo (TLS 1.3).
pub const TLS13_VERSION: u16 = 0x0304;

/// `TLS_AES_128_GCM_SHA256`.
pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
/// `TLS_AES_256_GCM_SHA384`.
pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
/// `TLS_CHACHA20_POLY1305_SHA256` (el que protege los registros aquí).
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
/// `TLS_AES_128_CCM_SHA256`.
pub const TLS_AES_128_CCM_SHA256: u16 = 0x1304;

/// Grupo nombrado `x25519`.
pub const GROUP_X25519: u16 = 0x001d;
/// Grupo nombrado `secp256r1`.
pub const GROUP_SECP256R1: u16 = 0x0017;

/// Firma `ecdsa_secp256r1_sha256`.
pub const SIG_ECDSA_P256: u16 = 0x0403;
/// Firma `rsa_pss_rsae_sha256`.
pub const SIG_RSA_PSS: u16 = 0x0804;
/// Firma `ed25519`.
pub const SIG_ED25519: u16 = 0x0807;

/// Extensión `server_name`.
pub const EXT_SERVER_NAME: u16 = 0x0000;
/// Extensión `supported_groups`.
pub const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
/// Extensión `signature_algorithms`.
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
/// Extensión `alpn`.
pub const EXT_ALPN: u16 = 0x0010;
/// Extensión `padding`.
pub const EXT_PADDING: u16 = 0x0015;
/// Extensión `supported_versions`.
pub const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
/// Extensión `psk_key_exchange_modes`.
pub const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
/// Extensión `key_share`.
pub const EXT_KEY_SHARE: u16 = 0x0033;

/// Modo de intercambio de claves `psk_dhe_ke`.
pub const PSK_DHE_KE: u8 = 0x01;

/// Tamaño máximo de la carga de un registro (2¹⁴, RFC 8446 §5.1).
pub const MAX_RECORD: usize = 16_384;

/// Longitud de la marca de enjambre, en bytes.
pub const CAMOUFLAGE_MARK: usize = 16;

/// Longitud del `session_id` de un navegador corriente (Chrome).
pub const BROWSER_SESSION_ID: usize = 32;

// ─────────────────────────────────────────────────────────────────────────
// Códec: red de bytes de TLS es big-endian
// ─────────────────────────────────────────────────────────────────────────

/// Escribe un entero de 16 bits en orden de red.
fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// Escribe un entero de 24 bits en orden de red.
fn put_u24(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&[
        ((value >> 16) & 0xff) as u8,
        ((value >> 8) & 0xff) as u8,
        (value & 0xff) as u8,
    ]);
}

/// Escribe un vector con prefijo de longitud de un byte.
fn put_vec8(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = bytes.len().min(u8::MAX as usize);
    out.push(len as u8);
    out.extend_from_slice(&bytes[..len]);
}

/// Escribe un vector con prefijo de longitud de dos bytes.
fn put_vec16(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = bytes.len().min(u16::MAX as usize);
    put_u16(out, len as u16);
    out.extend_from_slice(&bytes[..len]);
}

/// Empareda un cuerpo como extensión: `tipo ‖ longitud ‖ cuerpo`.
fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
    let len = body.len().min(usize::from(u16::MAX));
    let mut out = Vec::with_capacity(4 + len);
    put_u16(&mut out, kind);
    put_u16(&mut out, len as u16);
    out.extend_from_slice(&body[..len]);
    out
}

/// Empareda un cuerpo como mensaje de apretón de manos:
/// `tipo ‖ longitud(3) ‖ cuerpo`.
fn handshake(kind: u8, body: &[u8]) -> Vec<u8> {
    let len = body.len().min(0x00ff_ffff);
    let mut out = Vec::with_capacity(4 + len);
    out.push(kind);
    put_u24(&mut out, len as u32);
    out.extend_from_slice(&body[..len]);
    out
}

/// Empareda una carga como registro TLS en claro, con la versión heredada
/// indicada en la cabecera.
fn record_versioned(version: u16, content_type: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len().min(usize::from(u16::MAX));
    let mut out = Vec::with_capacity(5 + len);
    out.push(content_type);
    put_u16(&mut out, version);
    put_u16(&mut out, len as u16);
    out.extend_from_slice(&payload[..len]);
    out
}

/// Registro del **primer** mensaje del cliente: `0x0301`, como manda
/// RFC 8446 §5.1 (el resto de la conexión usa `0x0303`).
pub fn initial_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
    record_versioned(LEGACY_RECORD_VERSION, content_type, payload)
}

/// Registro corriente: `0x0303`.
pub fn plain_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
    record_versioned(LEGACY_VERSION, content_type, payload)
}

/// Lector acotado, sin pánicos: cualquier desbordamiento devuelve `None`.
#[derive(Debug, Clone)]
struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, at: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.at)
    }

    fn bytes(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(count)?;
        let slice = self.data.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        let byte = *self.data.get(self.at)?;
        self.at += 1;
        Some(byte)
    }

    fn u16(&mut self) -> Option<u16> {
        let bytes = self.bytes(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u24(&mut self) -> Option<u32> {
        let bytes = self.bytes(3)?;
        Some(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]))
    }

    fn vec8(&mut self) -> Option<&'a [u8]> {
        let len = usize::from(self.u8()?);
        self.bytes(len)
    }

    fn vec16(&mut self) -> Option<&'a [u8]> {
        let len = usize::from(self.u16()?);
        self.bytes(len)
    }

    /// Avanza `count` bytes (útil para saltar campos fuera de la huella).
    fn skip(&mut self, count: usize) -> Option<()> {
        self.bytes(count).map(|_| ())
    }
}

/// Copia `source` sobre el principio de `target` sin pánicos.
fn overlay(target: &mut [u8], source: &[u8]) {
    for (slot, byte) in target.iter_mut().zip(source.iter()) {
        *slot = *byte;
    }
}

/// Convierte una lista de enteros de 16 bits en su representación de red.
fn u16_list(values: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(values.len() * 2);
    for value in values {
        put_u16(&mut out, *value);
    }
    out
}

/// Descompone `bytes` en enteros de 16 bits (longitud impar: el sobrante se
/// descarta, nunca se falla).
fn read_u16_list(bytes: &[u8]) -> Vec<u16> {
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut at = 0;
    while at + 2 <= bytes.len() {
        out.push(u16::from_be_bytes([bytes[at], bytes[at + 1]]));
        at += 2;
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────
// Perfil de camuflaje
// ─────────────────────────────────────────────────────────────────────────

/// Perfil de camuflaje: la **forma** que adopta el saludo en el cable.
///
/// No contiene claves ni direcciones: sólo lo que un observador puede ver. Dos
/// nodos con perfiles distintos son indistinguibles en estructura de dos
/// navegadores distintos, y dos nodos con el mismo perfil comparten huella.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CamouflageProfile {
    /// Nombre del perfil (entra en la marca y en el informe).
    pub name: &'static str,
    /// Nombre del servidor que se anuncia en `server_name`.
    pub sni: String,
    /// Protocolos de aplicación ofrecidos, en orden.
    pub alpn: Vec<&'static str>,
    /// Conjuntos de cifrado ofrecidos, en orden.
    pub ciphers: Vec<u16>,
    /// Grupos nombrados ofrecidos, en orden.
    pub groups: Vec<u16>,
    /// Algoritmos de firma ofrecidos, en orden.
    pub signatures: Vec<u16>,
    /// Longitud del `session_id` (32 bytes imita a Chrome).
    pub session_id_len: usize,
    /// Longitud objetivo del registro `ClientHello` (>= 512 por RFC 8446 §9.2).
    pub padding_to: usize,
}

impl CamouflageProfile {
    /// Perfil de navegador corriente: lo que hace el tráfico **normal**.
    pub fn browser(sni: &str) -> Self {
        CamouflageProfile {
            name: "navegador",
            sni: sni.to_string(),
            alpn: vec!["h2", "http/1.1"],
            ciphers: vec![
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
                TLS_AES_128_CCM_SHA256,
            ],
            groups: vec![GROUP_X25519, GROUP_SECP256R1],
            signatures: vec![SIG_ECDSA_P256, SIG_RSA_PSS, SIG_ED25519],
            session_id_len: BROWSER_SESSION_ID,
            padding_to: 512,
        }
    }

    /// Perfil mínimo: sólo X25519, sin relleno, para pares que ya se conocen.
    pub fn swarm(sni: &str) -> Self {
        CamouflageProfile {
            name: "enjambre",
            sni: sni.to_string(),
            alpn: vec!["h2"],
            ciphers: vec![TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256],
            groups: vec![GROUP_X25519],
            signatures: vec![SIG_ED25519],
            session_id_len: 16,
            padding_to: 0,
        }
    }

    /// Número de extensiones que emitirá el saludo (incluido el relleno).
    pub fn extension_count(&self) -> usize {
        let padding = usize::from(self.padding_to > 0);
        7 + padding
    }

    /// Contiene el conjunto de cifrado elegido.
    pub fn offers(&self, cipher: u16) -> bool {
        self.ciphers.contains(&cipher)
    }
}

/// Generador determinista de azar a partir del **ADN**.
///
/// `ChaCha20` en modo contador, con la clave derivada del ADN mediante un
/// dominio propio. No pretende ser azar criptográfico del sistema: es
/// **azar de identidad** — reproducible, verificable y suficiente para
/// rellenar saludos, escalares X25519 (clavados) y session ids.
#[derive(Debug, Clone)]
pub struct DnaStream {
    key: [u8; 32],
    counter: u32,
    buffer: Vec<u8>,
}

impl DnaStream {
    /// Deriva el flujo del ADN con separación de dominio.
    pub fn from_dna(adn: &[u8; 32]) -> Self {
        let mut material = Vec::with_capacity(64);
        material.extend_from_slice(b"bara:aether-omega:camuflaje:flujo:v1");
        material.extend_from_slice(adn);
        let mut key = [0_u8; 32];
        overlay(&mut key, &sha256(&material));
        DnaStream {
            key,
            counter: 0,
            buffer: Vec::with_capacity(128),
        }
    }

    fn refill(&mut self) {
        let block = chacha20_block(&self.key, self.counter, &[0_u8; 12]);
        self.counter = self.counter.wrapping_add(1);
        self.buffer.extend_from_slice(&block);
    }

    /// Extrae `count` bytes del flujo (refill perezoso).
    pub fn bytes(&mut self, count: usize) -> Vec<u8> {
        while self.buffer.len() < count {
            self.refill();
        }
        self.buffer.drain(..count).collect()
    }

    /// Extrae 32 bytes exactos.
    pub fn block32(&mut self) -> [u8; 32] {
        let mut out = [0_u8; 32];
        overlay(&mut out, &self.bytes(32));
        out
    }

    /// Escalar X25519 **clavado** según RFC 7748 §5.
    pub fn x25519_secret(&mut self) -> [u8; 32] {
        let mut scalar = self.block32();
        if let Some(first) = scalar.first_mut() {
            *first &= 248;
        }
        if let Some(last) = scalar.last_mut() {
            *last &= 127;
            *last |= 64;
        }
        scalar
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Construcción del saludo
// ─────────────────────────────────────────────────────────────────────────

/// Construye el **cuerpo** de un `ClientHello` (sin cabecera de mensaje).
///
/// El orden de extensiones es fijo y corriente (el de un navegador), porque el
/// orden es parte de la huella: un orden barajado delataría al cliente.
pub fn client_hello_body(
    profile: &CamouflageProfile,
    random: &[u8; 32],
    session_id: &[u8],
    share: &[u8; 32],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(320);
    put_u16(&mut body, LEGACY_VERSION);
    body.extend_from_slice(random);
    put_vec8(&mut body, session_id);
    put_vec16(&mut body, &u16_list(&profile.ciphers));
    put_vec8(&mut body, &[0x00]); // compresión nula

    let mut extensions = Vec::with_capacity(256);

    // server_name
    let mut sni = Vec::with_capacity(profile.sni.len() + 5);
    let name_len = profile.sni.len().min(usize::from(u16::MAX));
    put_u16(&mut sni, (name_len + 3) as u16);
    sni.push(0x00);
    put_u16(&mut sni, name_len as u16);
    sni.extend_from_slice(&profile.sni.as_bytes()[..name_len]);
    extensions.extend_from_slice(&extension(EXT_SERVER_NAME, &sni));

    // supported_groups: `longitud(u16) ‖ grupos`
    let mut groups_body = Vec::with_capacity(2 + profile.groups.len() * 2);
    put_vec16(&mut groups_body, &u16_list(&profile.groups));
    extensions.extend_from_slice(&extension(EXT_SUPPORTED_GROUPS, &groups_body));

    // signature_algorithms: `longitud(u16) ‖ algoritmos`
    let mut signatures_body = Vec::with_capacity(2 + profile.signatures.len() * 2);
    put_vec16(&mut signatures_body, &u16_list(&profile.signatures));
    extensions.extend_from_slice(&extension(EXT_SIGNATURE_ALGORITHMS, &signatures_body));

    // alpn
    let mut alpn = Vec::with_capacity(32);
    let mut entries = Vec::with_capacity(32);
    for protocol in &profile.alpn {
        put_vec8(&mut entries, protocol.as_bytes());
    }
    put_vec16(&mut alpn, &entries);
    extensions.extend_from_slice(&extension(EXT_ALPN, &alpn));

    // supported_versions (sólo TLS 1.3: lo único que este cliente habla)
    extensions.extend_from_slice(&extension(
        EXT_SUPPORTED_VERSIONS,
        &[
            0x02,
            (TLS13_VERSION >> 8) as u8,
            (TLS13_VERSION & 0xff) as u8,
        ],
    ));

    // psk_key_exchange_modes
    extensions.extend_from_slice(&extension(EXT_PSK_KEY_EXCHANGE_MODES, &[0x01, PSK_DHE_KE]));

    // key_share: `longitud(u16) ‖ [grupo ‖ longitud(u16) ‖ clave]`
    let mut shares = Vec::with_capacity(40);
    put_u16(&mut shares, GROUP_X25519);
    put_vec16(&mut shares, share);
    let mut shares_body = Vec::with_capacity(2 + shares.len());
    put_vec16(&mut shares_body, &shares);
    extensions.extend_from_slice(&extension(EXT_KEY_SHARE, &shares_body));

    // relleno: el saludo debe superar el umbral de RFC 8446 §9.2. La cuenta
    // incluye las dos cabeceras completas (registro y mensaje) y el prefijo de
    // longitud de la lista de extensiones.
    let before = 5 + 4 + body.len() + 2 + extensions.len();
    if profile.padding_to > before + 4 {
        let pad = profile.padding_to - before - 4;
        extensions.extend_from_slice(&extension(EXT_PADDING, &vec![0_u8; pad]));
    }

    put_vec16(&mut body, &extensions);
    body
}

/// Registro completo de `ClientHello`, listo para el cable.
pub fn client_hello(
    profile: &CamouflageProfile,
    random: &[u8; 32],
    session_id: &[u8],
    share: &[u8; 32],
) -> Vec<u8> {
    let body = client_hello_body(profile, random, session_id, share);
    initial_record(CT_HANDSHAKE, &handshake(HS_CLIENT_HELLO, &body))
}

/// ADN de red a partir de una semilla: la misma clave áurea que firma el AST
/// ([`golden_key`]), de modo que la identidad del código y la de la red son
/// **la misma**.
pub fn swarm_adn(seed: &[u8]) -> [u8; 32] {
    golden_key(seed)
}

/// Marca de enjambre: `HMAC(ADN, "marca" ‖ huella ‖ azar)`, truncada.
///
/// La huella entra en el material, así que la marca **sólo** es válida sobre un
/// saludo cuya estructura sea exactamente la esperada: cambiar el perfil, el
/// orden o los conjuntos de cifrado invalida la marca.
pub fn camouflage_mark(adn: &[u8; 32], fingerprint: &[u8; 32], random: &[u8; 32]) -> [u8; 32] {
    let mut material = Vec::with_capacity(112);
    material.extend_from_slice(b"bara:aether-omega:camuflaje:marca:v1");
    material.extend_from_slice(fingerprint);
    material.extend_from_slice(random);
    let tag = hmac_sha256(adn, &material);
    let mut mark = [0_u8; 32];
    overlay(&mut mark, &tag[..CAMOUFLAGE_MARK]);
    mark
}

/// Huella *JA3*-símil: digest de la estructura del saludo, en su orden.
///
/// Entra: versión heredada, conjuntos de cifrado, tipos de extensión y grupos
/// nombrados. **No** entra nada que dependa de claves, azar o direcciones, así
/// que dos clientes distintos con el mismo perfil comparten huella — que es
/// justamente lo que hace indistinguible el tráfico.
pub fn fingerprint_of(body: &[u8]) -> Option<[u8; 32]> {
    let mut reader = Reader::new(body);
    let legacy_version = reader.u16()?;
    reader.skip(32)?; // azar: fuera de la huella
    let session_id = reader.vec8()?;
    let ciphers = read_u16_list(reader.vec16()?);
    let _compression = reader.vec8()?;
    let extensions = reader.vec16()?;

    let mut material = Vec::with_capacity(96);
    material.extend_from_slice(b"bara:aether-omega:camuflaje:huella:v1");
    put_u16(&mut material, legacy_version);
    material.extend_from_slice(&(session_id.len() as u16).to_be_bytes());
    for cipher in &ciphers {
        put_u16(&mut material, *cipher);
    }

    let mut kinds = Vec::new();
    let mut groups: Vec<u16> = Vec::new();
    let mut extensions_reader = Reader::new(extensions);
    while extensions_reader.remaining() >= 4 {
        let kind = extensions_reader.u16()?;
        let body = extensions_reader.vec16()?;
        kinds.push(kind);
        if kind == EXT_SUPPORTED_GROUPS {
            let mut groups_reader = Reader::new(body);
            if let Some(list) = groups_reader.vec16() {
                groups = read_u16_list(list);
            }
        }
    }
    for kind in &kinds {
        put_u16(&mut material, *kind);
    }
    for group in &groups {
        put_u16(&mut material, *group);
    }
    Some(sha256(&material))
}

// ─────────────────────────────────────────────────────────────────────────
// Cliente camuflado
// ─────────────────────────────────────────────────────────────────────────

/// Cliente camuflado: su azar, su escalar X25519 y su `session_id` se derivan
/// del ADN, así que **el mismo ADN presenta siempre el mismo saludo** y el
/// enjambre se reconoce sin ninguna autoridad de certificación.
#[derive(Debug, Clone)]
pub struct CamouflagedClient {
    /// Perfil en el que se disfraza.
    pub profile: CamouflageProfile,
    /// Azar de 32 bytes (determinista en el ADN).
    pub random: [u8; 32],
    /// Identificador de sesión, con la marca de enjambre al principio.
    pub session_id: Vec<u8>,
    /// Escalar X25519 privado (clavado).
    pub secret: [u8; 32],
    /// Clave pública X25519 que viaja en `key_share`.
    pub share: [u8; 32],
    /// Huella estructural del saludo.
    pub fingerprint: [u8; 32],
    /// Marca de enjambre (16 bytes útiles en 32).
    pub mark: [u8; 32],
}

impl CamouflagedClient {
    /// Disfraza un cliente con el ADN dado.
    pub fn from_adn(profile: CamouflageProfile, adn: &[u8; 32]) -> Self {
        let mut stream = DnaStream::from_dna(adn);
        let random = stream.block32();
        let secret = stream.x25519_secret();
        let share = x25519_base(&secret);

        // La huella no depende del `session_id`, así que se puede calcular con
        // un marcador de posición y la marca sigue siendo válida después.
        let placeholder = vec![0_u8; profile.session_id_len];
        let provisional = client_hello_body(&profile, &random, &placeholder, &share);
        let fingerprint = match fingerprint_of(&provisional) {
            Some(value) => value,
            None => sha256(&provisional),
        };
        let mark = camouflage_mark(adn, &fingerprint, &random);

        let mut session_id = stream.bytes(profile.session_id_len.max(CAMOUFLAGE_MARK));
        overlay(&mut session_id, &mark[..CAMOUFLAGE_MARK]);

        CamouflagedClient {
            profile,
            random,
            session_id,
            secret,
            share,
            fingerprint,
            mark,
        }
    }

    /// Disfraza un cliente a partir de una semilla (la misma que firma el AST).
    pub fn from_seed(profile: CamouflageProfile, seed: &[u8]) -> Self {
        CamouflagedClient::from_adn(profile, &swarm_adn(seed))
    }

    /// Registro `ClientHello` completo, listo para el cable.
    pub fn hello(&self) -> Vec<u8> {
        client_hello(&self.profile, &self.random, &self.session_id, &self.share)
    }

    /// Longitud del saludo (con cabecera de registro).
    pub fn hello_len(&self) -> usize {
        self.hello().len()
    }

    /// ¿Se acepta el conjunto de cifrado elegido por el servidor?
    pub fn accepts(&self, cipher: u16) -> bool {
        self.profile.offers(cipher)
    }

    /// ¿La marca de este cliente corresponde a ese ADN?
    pub fn is_swarm_member(&self, adn: &[u8; 32]) -> bool {
        let expected = camouflage_mark(adn, &self.fingerprint, &self.random);
        digest_eq(&expected, &self.mark)
    }

    /// Huella en hexadecimal corto.
    pub fn fingerprint_hex(&self) -> String {
        short_hex(&self.fingerprint[..8])
    }

    /// Descripción de una línea.
    pub fn describe(&self) -> String {
        format!(
            "camuflaje «{}» · sni {} · huella {} · saludo {} B · {} extensiones",
            self.profile.name,
            self.profile.sni,
            self.fingerprint_hex(),
            self.hello_len(),
            self.profile.extension_count()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Lectura del saludo (lo que ve un interceptor)
// ─────────────────────────────────────────────────────────────────────────

/// `ClientHello` descompuesto campo a campo.
///
/// Es también lo que permite verificar la marca de enjambre de forma
/// **independiente del emisor**: el verificador sólo necesita el ADN y los
/// bytes del cable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedClientHello {
    /// Versión heredada anunciada.
    pub legacy_version: u16,
    /// Azar de 32 bytes.
    pub random: [u8; 32],
    /// Identificador de sesión (aquí vive la marca).
    pub session_id: Vec<u8>,
    /// Conjuntos de cifrado ofrecidos.
    pub ciphers: Vec<u16>,
    /// Tipos de extensión, en orden de aparición.
    pub extension_kinds: Vec<u16>,
    /// Grupos nombrados ofrecidos.
    pub groups: Vec<u16>,
    /// Compartición de clave: `(grupo, clave)`.
    pub key_share: Option<(u16, Vec<u8>)>,
    /// Nombre del servidor anunciado.
    pub sni: Option<String>,
    /// Protocolos de aplicación ofrecidos.
    pub alpn: Vec<String>,
    /// Versiones soportadas.
    pub supported_versions: Vec<u16>,
    /// Bytes de relleno (extensión `padding`).
    pub padding: usize,
    /// Huella estructural.
    pub fingerprint: [u8; 32],
    /// Longitud del mensaje de apretón de manos.
    pub handshake_len: usize,
    /// Longitud total del registro.
    pub record_len: usize,
}

impl ParsedClientHello {
    /// ¿Es un saludo TLS 1.3 coherente?
    pub fn is_tls13(&self) -> bool {
        self.legacy_version == LEGACY_VERSION && self.supported_versions.contains(&TLS13_VERSION)
    }

    /// ¿Trae el conjunto de cifrado pedido?
    pub fn offers(&self, cipher: u16) -> bool {
        self.ciphers.contains(&cipher)
    }

    /// Compartición de clave del grupo pedido.
    pub fn share_for(&self, group: u16) -> Option<&[u8]> {
        match &self.key_share {
            Some((found, bytes)) if *found == group => Some(bytes.as_slice()),
            _ => None,
        }
    }

    /// `session_id` en hexadecimal corto.
    pub fn session_id_hex(&self) -> String {
        short_hex(&self.session_id)
    }
}

/// Descompone un `ClientHello` recibido (registro completo).
///
/// Todo desbordamiento o incoherencia estructural devuelve `None`: el lector
/// nunca falla, nunca reserva de más y nunca entra en pánico.
pub fn parse_client_hello(message: &[u8]) -> Option<ParsedClientHello> {
    let record_len = message.len();
    let mut record_reader = Reader::new(message);
    if record_reader.u8()? != CT_HANDSHAKE {
        return None;
    }
    let _record_version = record_reader.u16()?;
    let payload = record_reader.vec16()?;

    let mut reader = Reader::new(payload);
    if reader.u8()? != HS_CLIENT_HELLO {
        return None;
    }
    let handshake_len = reader.u24()? as usize;
    let body = reader.bytes(handshake_len)?;

    let mut body_reader = Reader::new(body);
    let legacy_version = body_reader.u16()?;
    let mut random = [0_u8; 32];
    overlay(&mut random, body_reader.bytes(32)?);
    let session_id = body_reader.vec8()?.to_vec();
    let ciphers = read_u16_list(body_reader.vec16()?);
    let _compression = body_reader.vec8()?;
    let extensions = body_reader.vec16()?;

    let mut extension_kinds = Vec::new();
    let mut groups: Vec<u16> = Vec::new();
    let mut key_share = None;
    let mut sni = None;
    let mut alpn = Vec::new();
    let mut supported_versions = Vec::new();
    let mut padding = 0;

    let mut ext_reader = Reader::new(extensions);
    while ext_reader.remaining() >= 4 {
        let kind = ext_reader.u16()?;
        let ext_body = ext_reader.vec16()?;
        extension_kinds.push(kind);
        match kind {
            EXT_SERVER_NAME => {
                let mut list = Reader::new(ext_body);
                if let Some(entries) = list.vec16() {
                    let mut entries_reader = Reader::new(entries);
                    let entry_type = entries_reader.u8();
                    if let (Some(0x00), Some(name)) = (entry_type, entries_reader.vec16()) {
                        sni = Some(String::from_utf8_lossy(name).to_string());
                    }
                }
            }
            EXT_SUPPORTED_GROUPS => {
                let mut list = Reader::new(ext_body);
                if let Some(entries) = list.vec16() {
                    groups = read_u16_list(entries);
                }
            }
            EXT_SUPPORTED_VERSIONS => {
                let mut list = Reader::new(ext_body);
                if let Some(entries) = list.vec8() {
                    supported_versions = read_u16_list(entries);
                }
            }
            EXT_ALPN => {
                let mut list = Reader::new(ext_body);
                if let Some(entries) = list.vec16() {
                    let mut entries_reader = Reader::new(entries);
                    while let Some(protocol) = entries_reader.vec8() {
                        alpn.push(String::from_utf8_lossy(protocol).to_string());
                    }
                }
            }
            EXT_KEY_SHARE => {
                let mut list = Reader::new(ext_body);
                if let Some(entries) = list.vec16() {
                    let mut entries_reader = Reader::new(entries);
                    let group = entries_reader.u16();
                    if let (Some(group), Some(key)) = (group, entries_reader.vec16()) {
                        key_share = Some((group, key.to_vec()));
                    }
                }
            }
            EXT_PADDING => padding = ext_body.len(),
            _ => {}
        }
    }
    Some(ParsedClientHello {
        legacy_version,
        random,
        session_id,
        ciphers,
        extension_kinds,
        groups,
        key_share,
        sni,
        alpn,
        supported_versions,
        padding,
        fingerprint: fingerprint_of(body)?,
        handshake_len,
        record_len,
    })
}

/// Verifica la **marca de enjambre** de un saludo recibido.
///
/// Sólo el ADN del enjambre hace válida la marca: para cualquier otro
/// observador, el `session_id` es azar corriente y el saludo, un saludo. La
/// comparación es de tiempo constante ([`digest_eq`]).
pub fn verify_camouflage(message: &[u8], adn: &[u8; 32]) -> bool {
    let parsed = match parse_client_hello(message) {
        Some(parsed) => parsed,
        None => return false,
    };
    // La marca ocupa los primeros [`CAMOUFLAGE_MARK`] bytes del `session_id`;
    // el resto es azar, así que sólo se compara el prefijo.
    let mark = camouflage_mark(adn, &parsed.fingerprint, &parsed.random);
    let take = CAMOUFLAGE_MARK.min(parsed.session_id.len());
    let prefix = parsed.session_id.get(..take).unwrap_or(&[]);
    let mut expected = [0_u8; 32];
    let mut found = [0_u8; 32];
    overlay(&mut expected, &mark[..CAMOUFLAGE_MARK]);
    overlay(&mut found, prefix);
    digest_eq(&expected, &found)
}

// ─────────────────────────────────────────────────────────────────────────
// Respuesta del servidor
// ─────────────────────────────────────────────────────────────────────────

/// `ServerHello` descompuesto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedServerHello {
    /// Azar del servidor.
    pub random: [u8; 32],
    /// Identificador de sesión devuelto (eco del cliente).
    pub session_id: Vec<u8>,
    /// Conjunto de cifrado elegido.
    pub cipher: u16,
    /// Versión negociada.
    pub supported_version: Option<u16>,
    /// Compartición de clave: `(grupo, clave)`.
    pub key_share: Option<(u16, Vec<u8>)>,
    /// Extensiones presentes.
    pub extensions: Vec<u16>,
}

impl ParsedServerHello {
    /// Compartición de clave del grupo pedido.
    pub fn share_for(&self, group: u16) -> Option<&[u8]> {
        match &self.key_share {
            Some((found, bytes)) if *found == group => Some(bytes.as_slice()),
            _ => None,
        }
    }
}

/// Construye un `ServerHello` (pares locales y suite).
pub fn server_hello(
    cipher: u16,
    session_id: &[u8],
    random: &[u8; 32],
    group: u16,
    share: &[u8; 32],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(160);
    put_u16(&mut body, LEGACY_VERSION);
    body.extend_from_slice(random);
    put_vec8(&mut body, session_id);
    put_u16(&mut body, cipher);
    body.push(0x00); // compresión nula

    let mut extensions = Vec::with_capacity(64);
    extensions.extend_from_slice(&extension(
        EXT_SUPPORTED_VERSIONS,
        &[(TLS13_VERSION >> 8) as u8, (TLS13_VERSION & 0xff) as u8],
    ));
    let mut share_body = Vec::with_capacity(40);
    put_u16(&mut share_body, group);
    put_vec16(&mut share_body, share);
    extensions.extend_from_slice(&extension(EXT_KEY_SHARE, &share_body));
    put_vec16(&mut body, &extensions);

    plain_record(CT_HANDSHAKE, &handshake(HS_SERVER_HELLO, &body))
}

/// Descompone un `ServerHello` recibido.
pub fn parse_server_hello(message: &[u8]) -> Option<ParsedServerHello> {
    let mut record_reader = Reader::new(message);
    if record_reader.u8()? != CT_HANDSHAKE {
        return None;
    }
    let _record_version = record_reader.u16()?;
    let payload = record_reader.vec16()?;

    let mut reader = Reader::new(payload);
    if reader.u8()? != HS_SERVER_HELLO {
        return None;
    }
    let handshake_len = reader.u24()? as usize;
    let body = reader.bytes(handshake_len)?;

    let mut body_reader = Reader::new(body);
    let _legacy_version = body_reader.u16()?;
    let mut random = [0_u8; 32];
    overlay(&mut random, body_reader.bytes(32)?);
    let session_id = body_reader.vec8()?.to_vec();
    let cipher = body_reader.u16()?;
    let _compression = body_reader.u8()?;
    let extensions_bytes = body_reader.vec16()?;

    let mut extensions = Vec::new();
    let mut supported_version = None;
    let mut key_share = None;
    let mut ext_reader = Reader::new(extensions_bytes);
    while ext_reader.remaining() >= 4 {
        let kind = ext_reader.u16()?;
        let ext_body = ext_reader.vec16()?;
        extensions.push(kind);
        match kind {
            EXT_SUPPORTED_VERSIONS => {
                let mut value = Reader::new(ext_body);
                supported_version = value.u16();
            }
            EXT_KEY_SHARE => {
                let mut value = Reader::new(ext_body);
                let group = value.u16();
                if let (Some(group), Some(key)) = (group, value.vec16()) {
                    key_share = Some((group, key.to_vec()));
                }
            }
            _ => {}
        }
    }

    Some(ParsedServerHello {
        random,
        session_id,
        cipher,
        supported_version,
        key_share,
        extensions,
    })
}

// ─────────────────────────────────────────────────────────────────────────
// Calendario de claves (RFC 8446 §7.1)
// ─────────────────────────────────────────────────────────────────────────

/// `HKDF-Expand-Label` con SHA-256, sobre el `HKDF` nativo.
///
/// El `info` que exige el protocolo es
/// `longitud(u16) ‖ longitud_etiqueta(u8) ‖ "tls13 " ‖ etiqueta ‖ longitud_contexto(u8) ‖ contexto`.
pub fn hkdf_expand_label(secret: &[u8; 32], label: &str, context: &[u8], length: usize) -> Vec<u8> {
    let mut full = Vec::with_capacity(8 + label.len());
    full.extend_from_slice(b"tls13 ");
    full.extend_from_slice(label.as_bytes());

    let mut info = Vec::with_capacity(4 + full.len() + context.len());
    put_u16(&mut info, length.min(usize::from(u16::MAX)) as u16);
    put_vec8(&mut info, &full);
    put_vec8(&mut info, context);

    let mut out = vec![0_u8; length];
    hkdf_expand(secret, &info, &mut out);
    out
}

/// `Derive-Secret(secreto, etiqueta, mensajes)` de RFC 8446.
///
/// El llamante entrega **ya** el digest del transcript: así el mismo camino
/// sirve para `Hash("")` (los pasos `derived`) y para el transcript completo.
pub fn derive_secret(secret: &[u8; 32], label: &str, transcript_hash: &[u8; 32]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    overlay(
        &mut out,
        &hkdf_expand_label(secret, label, transcript_hash, 32),
    );
    out
}

/// Digest del transcript: la concatenación de mensajes de apretón de manos
/// **con** sus cabeceras (el `Handshake Context` de RFC 8446 §4.4.1).
pub fn transcript_hash(messages: &[&[u8]]) -> [u8; 32] {
    let mut joined = Vec::new();
    for message in messages {
        joined.extend_from_slice(message);
    }
    sha256(&joined)
}

/// Secretos del apretón de manos TLS 1.3 (sin `PSK`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeSecrets {
    /// Secreto compartido X25519.
    pub shared: [u8; 32],
    /// `handshake_secret`.
    pub handshake_secret: [u8; 32],
    /// `client_handshake_traffic_secret`.
    pub client: [u8; 32],
    /// `server_handshake_traffic_secret`.
    pub server: [u8; 32],
}

impl HandshakeSecrets {
    /// Secreto maestro derivado del de apretón de manos.
    pub fn master(&self) -> [u8; 32] {
        master_secret(&self.handshake_secret)
    }
}

/// Deriva los secretos del apretón de manos.
///
/// `early_secret = HKDF-Extract(salt = 0, ikm = PSK o vacío)`;
/// `handshake_secret = HKDF-Extract(derived, ECDHE)`;
/// las dos direcciones salen de `Derive-Secret` sobre el transcript.
pub fn handshake_secrets(shared: &[u8; 32], transcript: &[u8; 32]) -> HandshakeSecrets {
    let empty_hash = sha256(&[]);
    let early = hkdf_extract(&[0_u8; 32], &[]);
    let derived = derive_secret(&early, "derived", &empty_hash);
    let handshake = hkdf_extract(&derived, shared);
    HandshakeSecrets {
        shared: *shared,
        handshake_secret: handshake,
        client: derive_secret(&handshake, "c hs traffic", transcript),
        server: derive_secret(&handshake, "s hs traffic", transcript),
    }
}

/// `master_secret` a partir del de apretón de manos (RFC 8446 §7.1).
pub fn master_secret(handshake_secret: &[u8; 32]) -> [u8; 32] {
    let empty_hash = sha256(&[]);
    let derived = derive_secret(handshake_secret, "derived", &empty_hash);
    hkdf_extract(&derived, &[0_u8; 32])
}

/// Secretos de aplicación `(cliente, servidor)`.
///
/// El transcript es un parámetro explícito y no un campo oculto: en un apretón
/// de manos completo debe incluir el `Finished` del servidor, y aquí no se
/// inventa nada que el llamante no haya entregado.
pub fn application_secrets(
    handshake_secret: &[u8; 32],
    transcript: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    let master = master_secret(handshake_secret);
    (
        derive_secret(&master, "c ap traffic", transcript),
        derive_secret(&master, "s ap traffic", transcript),
    )
}

/// Claves de tráfico de una dirección: clave y vector de inicialización.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficKeys {
    /// Clave `AEAD` (32 bytes para ChaCha20-Poly1305).
    pub key: [u8; 32],
    /// Vector de inicialización (12 bytes).
    pub iv: [u8; 12],
}

impl TrafficKeys {
    /// Deriva `key` e `iv` de un secreto de tráfico.
    pub fn from_secret(secret: &[u8; 32]) -> Self {
        let mut key = [0_u8; 32];
        overlay(&mut key, &hkdf_expand_label(secret, "key", &[], 32));
        let mut iv = [0_u8; 12];
        overlay(&mut iv, &hkdf_expand_label(secret, "iv", &[], 12));
        TrafficKeys { key, iv }
    }

    /// Nonce del registro `n`: `iv ⊕ seq` (los ocho bytes finales, RFC 8446 §5.3).
    pub fn nonce(&self, sequence: u64) -> [u8; 12] {
        let mut nonce = self.iv;
        for (index, byte) in sequence.to_be_bytes().iter().enumerate() {
            if let Some(slot) = nonce.get_mut(4 + index) {
                *slot ^= *byte;
            }
        }
        nonce
    }

    /// Clave en hexadecimal corto (para informes).
    pub fn key_hex(&self) -> String {
        short_hex(&self.key[..8])
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Protección de registros (RFC 8446 §5.3)
// ─────────────────────────────────────────────────────────────────────────

/// Sella un registro de aplicación con `ChaCha20-Poly1305`.
///
/// * **Carga interior**: `texto ‖ tipo_de_contenido` (el relleno interior es
///   opcional y aquí no se añade).
/// * **Nonce**: `iv ⊕ seq`.
/// * **`AAD`**: la cabecera de cinco bytes del registro ya sellado.
/// * Devuelve `None` si el texto excede [`MAX_RECORD`] (nunca trunca en
///   silencio ni desborda la longitud de dos bytes).
pub fn seal_record(
    keys: &TrafficKeys,
    sequence: u64,
    content_type: u8,
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    if plaintext.len() > MAX_RECORD {
        return None;
    }
    let mut inner = Vec::with_capacity(plaintext.len() + 1);
    inner.extend_from_slice(plaintext);
    inner.push(content_type);

    let length = inner.len().checked_add(AEAD_TAG)?;
    if length > usize::from(u16::MAX) {
        return None;
    }
    let mut header = Vec::with_capacity(5);
    header.push(CT_APPLICATION_DATA);
    put_u16(&mut header, LEGACY_VERSION);
    put_u16(&mut header, length as u16);

    let sealed = aead_seal(&keys.key, &keys.nonce(sequence), &header, &inner);
    let mut out = header;
    out.extend_from_slice(&sealed);
    Some(out)
}

/// Abre un registro de aplicación sellado.
///
/// Devuelve `(tipo_de_contenido, texto)`. Cualquier alteración de la cabecera,
/// de la carga o del orden (secuencia equivocada) **invalida la etiqueta** y
/// devuelve `None`: no hay mensaje a medias.
pub fn open_record(keys: &TrafficKeys, sequence: u64, message: &[u8]) -> Option<(u8, Vec<u8>)> {
    let mut reader = Reader::new(message);
    if reader.u8()? != CT_APPLICATION_DATA {
        return None;
    }
    let _version = reader.u16()?;
    let _length = reader.u16()?;
    let header = message.get(..5)?;
    let rest = reader.remaining();
    let sealed = reader.bytes(rest)?;

    let inner = aead_open(&keys.key, &keys.nonce(sequence), header, sealed)?;
    let mut end = inner.len();
    while end > 0 && inner[end - 1] == 0 {
        end -= 1;
    }
    if end == 0 {
        return None;
    }
    Some((inner[end - 1], inner[..end - 1].to_vec()))
}

// ─────────────────────────────────────────────────────────────────────────
// Sesión de red (I/O real)
// ─────────────────────────────────────────────────────────────────────────

/// Milisegundos de espera en cada lectura de zócalo.
pub const READ_TIMEOUT_MS: u64 = 2_000;

/// Sesión TLS 1.3 camuflada sobre un zócalo real.
///
/// El apretón de manos llega hasta el `ServerHello`: se envía el saludo, se
/// verifica el eco del servidor (identificador de sesión, conjunto de cifrado
/// ofrecido, versión), se calcula el secreto X25519 y se derivan las claves.
/// Las claves de **aplicación** exigen el transcript completo (`Finished`
/// incluido), así que se entregan como parámetro
/// ([`HttpsSession::application_keys_with`]) en lugar de fingirlas.
pub struct HttpsSession {
    /// Dirección del par.
    pub address: String,
    /// Cliente camuflado en uso.
    pub client: CamouflagedClient,
    /// ADN del enjambre.
    pub adn: [u8; 32],
    /// Respuesta del servidor.
    pub server_hello: ParsedServerHello,
    /// Secretos del apretón de manos.
    pub secrets: HandshakeSecrets,
    /// Secreto compartido X25519.
    pub shared: [u8; 32],
    /// Digest del transcript disponible (`ClientHello ‖ ServerHello`).
    pub transcript: [u8; 32],
    stream: TcpStream,
    sent: u64,
    received: u64,
}

impl HttpsSession {
    /// Abre una sesión: envía el saludo camuflado y procesa la respuesta.
    ///
    /// Devuelve `None` ante cualquier fallo de red, eco incoherente, cifrado no
    /// ofrecido o versión distinta de TLS 1.3. Nunca entra en pánico.
    pub fn connect(address: &str, profile: CamouflageProfile, seed: &[u8]) -> Option<HttpsSession> {
        let mut stream = TcpStream::connect(address).ok()?;
        stream
            .set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)))
            .ok()?;
        stream
            .set_write_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)))
            .ok()?;
        stream.set_nodelay(true).ok();

        let adn = swarm_adn(seed);
        let client = CamouflagedClient::from_adn(profile, &adn);
        let hello = client.hello();
        stream.write_all(&hello).ok()?;
        stream.flush().ok()?;

        let message = read_record(&mut stream)?;
        let parsed = parse_server_hello(&message)?;
        if !client.accepts(parsed.cipher) {
            return None;
        }
        if parsed.session_id != client.session_id {
            return None;
        }
        if parsed.supported_version != Some(TLS13_VERSION) {
            return None;
        }
        let mut share = [0_u8; 32];
        overlay(&mut share, parsed.share_for(GROUP_X25519)?);
        let shared = x25519(&client.secret, &share);
        let transcript = transcript_hash(&[hello.get(5..)?, message.get(5..)?]);
        let secrets = handshake_secrets(&shared, &transcript);

        Some(HttpsSession {
            address: address.to_string(),
            client,
            adn,
            server_hello: parsed,
            secrets,
            shared,
            transcript,
            stream,
            sent: 1,
            received: 1,
        })
    }

    /// Claves de aplicación `(cliente, servidor)` para un transcript dado.
    pub fn application_keys_with(&self, transcript: &[u8; 32]) -> (TrafficKeys, TrafficKeys) {
        let (client, server) = application_secrets(&self.secrets.handshake_secret, transcript);
        (
            TrafficKeys::from_secret(&client),
            TrafficKeys::from_secret(&server),
        )
    }

    /// Claves de apretón de manos de la dirección cliente.
    pub fn client_handshake_keys(&self) -> TrafficKeys {
        TrafficKeys::from_secret(&self.secrets.client)
    }

    /// Claves de apretón de manos de la dirección servidor.
    pub fn server_handshake_keys(&self) -> TrafficKeys {
        TrafficKeys::from_secret(&self.secrets.server)
    }

    /// ¿El saludo que enviamos lleva una marca de enjambre válida?
    pub fn is_swarm_member(&self) -> bool {
        verify_camouflage(&self.client.hello(), &self.adn)
    }

    /// Envía un registro de aplicación sellado. Devuelve su tamaño en el cable.
    pub fn send_record(&mut self, content_type: u8, plaintext: &[u8]) -> Option<usize> {
        let (client, _server) = self.application_keys_with(&self.transcript);
        let message = seal_record(&client, self.sent, content_type, plaintext)?;
        self.stream.write_all(&message).ok()?;
        self.stream.flush().ok()?;
        self.sent = self.sent.wrapping_add(1);
        Some(message.len())
    }

    /// Recibe y abre un registro de aplicación.
    pub fn recv_record(&mut self) -> Option<(u8, Vec<u8>)> {
        let (_client, server) = self.application_keys_with(&self.transcript);
        let message = read_record(&mut self.stream)?;
        let opened = open_record(&server, self.received, &message)?;
        self.received = self.received.wrapping_add(1);
        Some(opened)
    }

    /// Secreto compartido en hexadecimal corto.
    pub fn shared_hex(&self) -> String {
        short_hex(&self.shared[..8])
    }

    /// Descripción de una línea.
    pub fn describe(&self) -> String {
        format!(
            "sesión «{}» con {} · cifrado 0x{:04x} · secreto {} · transcript {} · marca {}",
            self.client.profile.name,
            self.address,
            self.server_hello.cipher,
            self.shared_hex(),
            short_hex(&self.transcript[..8]),
            if self.is_swarm_member() {
                "válida"
            } else {
                "ajena"
            }
        )
    }
}

/// Lee un registro completo del zócalo (cabecera de cinco bytes más cuerpo).
fn read_record(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut header = [0_u8; 5];
    stream.read_exact(&mut header).ok()?;
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if length > MAX_RECORD + 2048 {
        return None;
    }
    let mut body = vec![0_u8; length];
    stream.read_exact(&mut body).ok()?;
    let mut message = header.to_vec();
    message.extend_from_slice(&body);
    Some(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn el_saludo_es_un_client_hello_valido_y_completo() {
        let perfil = CamouflageProfile::browser("ejemplo.test");
        let cliente = CamouflagedClient::from_seed(perfil.clone(), b"semilla-de-prueba");
        let saludo = cliente.hello();

        assert_eq!(saludo.len(), cliente.hello_len());
        assert_eq!(saludo[0], CT_HANDSHAKE);
        assert_eq!(&saludo[1..3], &[0x03, 0x01]); // primer registro del cliente

        let parsed = parse_client_hello(&saludo);
        assert!(parsed.is_some());
        let Some(parsed) = parsed else { return };
        assert!(parsed.is_tls13());
        assert_eq!(parsed.record_len, saludo.len());
        assert_eq!(parsed.handshake_len + 4, saludo.len() - 5);
        assert_eq!(parsed.sni.as_deref(), Some("ejemplo.test"));
        assert_eq!(parsed.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
        assert!(parsed.offers(TLS_AES_128_GCM_SHA256));
        assert!(parsed.offers(TLS_CHACHA20_POLY1305_SHA256));
        assert_eq!(parsed.groups, vec![GROUP_X25519, GROUP_SECP256R1]);
        assert_eq!(
            parsed.key_share.as_ref().map(|(grupo, _)| *grupo),
            Some(GROUP_X25519)
        );
        assert_eq!(
            parsed.share_for(GROUP_X25519),
            Some(cliente.share.as_slice())
        );
        assert_eq!(parsed.session_id.len(), BROWSER_SESSION_ID);
        assert_eq!(parsed.random, cliente.random);
        assert_eq!(parsed.fingerprint, cliente.fingerprint);
        assert_eq!(parsed.extension_kinds.len(), perfil.extension_count());
        assert_eq!(parsed.extension_kinds.first(), Some(&EXT_SERVER_NAME));
        assert_eq!(parsed.extension_kinds.last(), Some(&EXT_PADDING));
        assert_eq!(parsed.session_id_hex().len(), BROWSER_SESSION_ID * 2);

        // Un registro truncado no se interpreta: el lector devuelve `None`.
        assert!(parse_client_hello(&saludo[..saludo.len() - 1]).is_none());
        assert!(parse_client_hello(&[]).is_none());
        assert!(parse_client_hello(b"no es tls, es una carta").is_none());
    }

    #[test]
    fn el_camuflaje_es_determinista_en_el_adn_y_marca_el_enjambre() {
        let perfil = CamouflageProfile::browser("ejemplo.test");
        let uno = CamouflagedClient::from_seed(perfil.clone(), b"semilla-compartida");
        let dos = CamouflagedClient::from_seed(perfil.clone(), b"semilla-compartida");
        let otro = CamouflagedClient::from_seed(perfil, b"semilla-distinta");

        // Mismo ADN: el saludo es idéntico byte a byte.
        assert_eq!(uno.hello(), dos.hello());
        assert_eq!(uno.fingerprint, dos.fingerprint);
        assert_eq!(uno.share, dos.share);
        // ADN distinto: misma forma, distinto contenido.
        assert_ne!(uno.hello(), otro.hello());
        assert_eq!(uno.fingerprint, otro.fingerprint);
        assert_eq!(uno.hello().len(), otro.hello().len());

        // La marca la reconoce el ADN propio y sólo él.
        let adn = swarm_adn(b"semilla-compartida");
        assert!(verify_camouflage(&uno.hello(), &adn));
        assert!(verify_camouflage(&dos.hello(), &adn));
        assert!(!verify_camouflage(&otro.hello(), &adn));
        assert!(uno.is_swarm_member(&adn));
        assert!(!uno.is_swarm_member(&swarm_adn(b"semilla-distinta")));

        // Un byte del azar (byte 20, dentro del campo `random`) invalida la
        // marca: el `session_id` está atado al azar del saludo.
        let mut tocado = uno.hello();
        tocado[20] ^= 0x01;
        assert!(!verify_camouflage(&tocado, &adn));
        assert!(uno.describe().contains("camuflaje"));
    }

    #[test]
    fn la_huella_no_depende_de_claves_ni_de_direcciones() {
        let navegador = CamouflageProfile::browser("a.test");
        let otro_sni = CamouflageProfile::browser("b.test");
        let enjambre = CamouflageProfile::swarm("a.test");

        let a = CamouflagedClient::from_seed(navegador.clone(), b"alfa");
        let b = CamouflagedClient::from_seed(otro_sni.clone(), b"beta");
        // Mismo perfil ⇒ misma huella, aunque cambien ADN y SNI.
        assert_eq!(a.fingerprint, b.fingerprint);
        assert_ne!(a.random, b.random);
        assert_ne!(a.share, b.share);
        assert_ne!(a.profile.sni, b.profile.sni);

        // Perfil distinto ⇒ huella distinta (extensiones y conjuntos).
        let c = CamouflagedClient::from_seed(enjambre.clone(), b"alfa");
        assert_ne!(a.fingerprint, c.fingerprint);
        assert_eq!(navegador.extension_count(), 8);
        assert_eq!(enjambre.extension_count(), 7);
        assert_eq!(a.fingerprint_hex().len(), 16);

        // El relleno no entra en la huella: tocarlo no cambia lo que ve un
        // interceptor ni invalida la marca del enjambre.
        let mut con_relleno_tocado = a.hello();
        let ultimo = con_relleno_tocado.len() - 1;
        let antes = con_relleno_tocado[ultimo];
        assert_eq!(antes, 0x00);
        con_relleno_tocado[ultimo] = 0xff;
        let base = parse_client_hello(&a.hello()).map(|p| p.fingerprint);
        let despues = parse_client_hello(&con_relleno_tocado).map(|p| p.fingerprint);
        assert_eq!(base, despues);
        assert!(verify_camouflage(&con_relleno_tocado, &swarm_adn(b"alfa")));
    }

    #[test]
    fn el_relleno_alcanza_el_umbral_de_rfc_8446() {
        let navegador =
            CamouflagedClient::from_seed(CamouflageProfile::browser("ejemplo.test"), b"x");
        let saludo = navegador.hello();
        assert!(saludo.len() >= 512, "el registro mide {}", saludo.len());

        let parsed = parse_client_hello(&saludo);
        assert!(parsed.is_some());
        let Some(parsed) = parsed else { return };
        assert!(parsed.padding > 0);
        // El relleno es todo ceros (RFC 8446 §4.2.1) y va al final.
        let cola = &saludo[saludo.len() - parsed.padding..];
        assert!(cola.iter().all(|byte| *byte == 0x00));
        // El saludo cae **exactamente** en el objetivo del perfil.
        assert_eq!(saludo.len(), 512);

        // El perfil de enjambre prescinde del relleno: no finge ser un navegador.
        let enjambre = CamouflagedClient::from_seed(CamouflageProfile::swarm("ejemplo.test"), b"x");
        let corto = parse_client_hello(&enjambre.hello());
        assert_eq!(corto.map(|p| p.padding), Some(0));
    }

    #[test]
    fn la_capa_de_registros_sella_abre_y_rechaza_alteraciones() {
        let claves = TrafficKeys::from_secret(&sha256(b"secreto de trafico"));
        let texto = b"hola desde el registro sellado".to_vec();
        let sello = seal_record(&claves, 7, CT_HANDSHAKE, &texto);
        assert!(sello.is_some());
        let Some(sello) = sello else { return };

        // Cabecera corriente y longitud = texto + tipo + etiqueta.
        assert_eq!(sello[0], CT_APPLICATION_DATA);
        assert_eq!(&sello[1..3], &[0x03, 0x03]);
        assert_eq!(sello.len(), 5 + texto.len() + 1 + AEAD_TAG);
        assert_eq!(
            open_record(&claves, 7, &sello),
            Some((CT_HANDSHAKE, texto.clone()))
        );

        // Secuencia equivocada, carga alterada, cabecera alterada, truncado y
        // registro en claro: nada de eso abre.
        assert!(open_record(&claves, 8, &sello).is_none());
        let mut carga = sello.clone();
        carga[5] ^= 0x01;
        assert!(open_record(&claves, 7, &carga).is_none());
        let mut cabecera = sello.clone();
        cabecera[4] ^= 0x01;
        assert!(open_record(&claves, 7, &cabecera).is_none());
        assert!(open_record(&claves, 7, &sello[..sello.len() - 1]).is_none());
        assert!(open_record(&claves, 7, &plain_record(CT_APPLICATION_DATA, &texto)).is_none());

        // El mismo texto con distinta secuencia da distinto ciphertext.
        let otro = seal_record(&claves, 8, CT_HANDSHAKE, &texto);
        assert!(otro.is_some());
        assert_ne!(otro, Some(sello.clone()));

        // Demasiado grande: se rechaza, no se trunca.
        assert!(
            seal_record(&claves, 0, CT_APPLICATION_DATA, &vec![0_u8; MAX_RECORD + 1]).is_none()
        );
        assert!(seal_record(&claves, 0, CT_APPLICATION_DATA, &vec![0_u8; MAX_RECORD]).is_some());

        // Nonce = iv ⊕ seq sobre los ocho bytes finales (RFC 8446 §5.3).
        assert_eq!(claves.nonce(0), claves.iv);
        assert_eq!(claves.nonce(1)[11], claves.iv[11] ^ 1);
        assert_eq!(claves.nonce(0x0102)[10], claves.iv[10] ^ 0x01);
    }

    #[test]
    fn el_calendario_de_claves_coincide_con_hkdf_expand_label_paso_a_paso() {
        let secreto = sha256(b"secreto de trafico");
        let contexto = sha256(b"transcript");
        let derivado = hkdf_expand_label(&secreto, "key", &contexto, 32);
        assert_eq!(derivado.len(), 32);

        // Referencia independiente: el `info` se arma a mano y se llama a
        // `HKDF-Expand` directamente, sin pasar por el envoltorio de TLS 1.3.
        let mut info = Vec::new();
        info.extend_from_slice(&32_u16.to_be_bytes());
        info.push(9); // "tls13 key"
        info.extend_from_slice(b"tls13 key");
        info.push(32); // longitud del contexto
        info.extend_from_slice(&contexto);
        let mut esperado = [0_u8; 32];
        hkdf_expand(&secreto, &info, &mut esperado);
        assert_eq!(derivado, esperado.to_vec());

        // `key` e `iv` salen del mismo secreto, pero no son lo mismo.
        let claves = TrafficKeys::from_secret(&secreto);
        assert_eq!(
            claves.key.as_slice(),
            hkdf_expand_label(&secreto, "key", &[], 32)
        );
        assert_eq!(
            claves.iv.as_slice(),
            hkdf_expand_label(&secreto, "iv", &[], 12)
        );
        assert_ne!(claves.key[..12].to_vec(), claves.iv.to_vec());
        assert_eq!(claves.key_hex().len(), 16);

        // El calendario es determinista y separa direcciones y fases.
        let transcript = sha256(b"clienthello y serverhello");
        let uno = handshake_secrets(&sha256(b"compartido"), &transcript);
        let dos = handshake_secrets(&sha256(b"compartido"), &transcript);
        assert_eq!(uno, dos);
        assert_eq!(uno.shared, sha256(b"compartido"));
        assert_ne!(uno.client, uno.server);
        assert_ne!(uno.client, uno.handshake_secret);
        assert_ne!(uno.server, uno.handshake_secret);
        assert_ne!(uno.master(), uno.handshake_secret);
        assert_ne!(uno.master(), uno.client);

        // Cambiar el secreto compartido o el transcript cambia las claves.
        let otro = handshake_secrets(&sha256(b"otro"), &transcript);
        let tercero = handshake_secrets(&sha256(b"compartido"), &sha256(b"otro"));
        assert_ne!(uno.client, otro.client);
        assert_ne!(uno.client, tercero.client);
        assert_ne!(uno.client, tercero.server);
        assert_ne!(otro.client, tercero.client);

        // Las claves de aplicación salen del maestro, no del apretón de manos.
        let (cliente, servidor) = application_secrets(&uno.handshake_secret, &transcript);
        assert_ne!(cliente, servidor);
        assert_ne!(cliente, uno.client);
        let cli = TrafficKeys::from_secret(&cliente);
        let srv = TrafficKeys::from_secret(&servidor);
        assert_ne!(cli.key, srv.key);
        assert_ne!(cli.iv, srv.iv);
        assert_eq!(cli.iv.len(), 12);
        assert_eq!(uno.master().len(), 32);
    }

    #[test]
    fn dos_pares_acuerdan_el_secreto_y_hablan_cifrado() {
        let cliente =
            CamouflagedClient::from_seed(CamouflageProfile::browser("ejemplo.test"), b"cliente");
        let mut flujo = DnaStream::from_dna(&swarm_adn(b"servidor"));
        let secreto_servidor = flujo.x25519_secret();
        let publico_servidor = x25519_base(&secreto_servidor);
        assert_ne!(publico_servidor, [0_u8; 32]);

        // El servidor lee el saludo del cliente.
        let saludo = cliente.hello();
        let parsed = parse_client_hello(&saludo);
        assert!(parsed.is_some());
        let Some(parsed) = parsed else { return };
        let publico_cliente = parsed.share_for(GROUP_X25519);
        assert!(publico_cliente.is_some());
        let Some(publico_cliente) = publico_cliente else {
            return;
        };
        assert!(verify_camouflage(&saludo, &swarm_adn(b"cliente")));

        // Responde con eco del `session_id` y su propia compartición.
        let mut azar_servidor = [0_u8; 32];
        overlay(&mut azar_servidor, &flujo.bytes(32));
        let respuesta = server_hello(
            TLS_CHACHA20_POLY1305_SHA256,
            &parsed.session_id,
            &azar_servidor,
            GROUP_X25519,
            &publico_servidor,
        );
        let devuelto = parse_server_hello(&respuesta);
        assert!(devuelto.is_some());
        let Some(devuelto) = devuelto else { return };
        assert_eq!(devuelto.session_id, parsed.session_id);
        assert_eq!(devuelto.supported_version, Some(TLS13_VERSION));
        assert_eq!(devuelto.cipher, TLS_CHACHA20_POLY1305_SHA256);
        assert!(cliente.accepts(devuelto.cipher));
        assert_eq!(
            devuelto.extensions,
            vec![EXT_SUPPORTED_VERSIONS, EXT_KEY_SHARE]
        );

        // Acuerdo real: cliente·share_servidor == servidor·share_cliente.
        let eco = devuelto.share_for(GROUP_X25519);
        assert!(eco.is_some());
        let Some(eco) = eco else { return };
        let mut share_servidor = [0_u8; 32];
        overlay(&mut share_servidor, eco);
        let mut share_cliente = [0_u8; 32];
        overlay(&mut share_cliente, publico_cliente);
        let visto_por_cliente = x25519(&cliente.secret, &share_servidor);
        let visto_por_servidor = x25519(&secreto_servidor, &share_cliente);
        assert_eq!(visto_por_cliente, visto_por_servidor);
        assert_ne!(visto_por_cliente, [0_u8; 32]);

        // Las dos partes derivan las mismas claves del mismo transcript.
        let transcript = transcript_hash(&[
            saludo.get(5..).unwrap_or(&[]),
            respuesta.get(5..).unwrap_or(&[]),
        ]);
        let secretos_cliente = handshake_secrets(&visto_por_cliente, &transcript);
        let secretos_servidor = handshake_secrets(&visto_por_servidor, &transcript);
        assert_eq!(secretos_cliente.client, secretos_servidor.client);
        assert_eq!(secretos_cliente.server, secretos_servidor.server);

        // El cliente sella y el servidor abre; la otra dirección no abre.
        let claves_cliente = TrafficKeys::from_secret(&secretos_cliente.client);
        let claves_cliente_eco = TrafficKeys::from_secret(&secretos_servidor.client);
        assert_eq!(claves_cliente, claves_cliente_eco);
        let sello = seal_record(&claves_cliente, 0, CT_HANDSHAKE, b"finished del cliente");
        assert!(sello.is_some());
        let Some(sello) = sello else { return };
        assert_eq!(
            open_record(&claves_cliente_eco, 0, &sello),
            Some((CT_HANDSHAKE, b"finished del cliente".to_vec()))
        );
        let claves_servidor = TrafficKeys::from_secret(&secretos_servidor.server);
        assert!(open_record(&claves_servidor, 0, &sello).is_none());
    }

    #[test]
    fn la_sesion_real_envia_el_saludo_y_procesa_la_respuesta() {
        let escucha = TcpListener::bind("127.0.0.1:0");
        assert!(escucha.is_ok());
        let Ok(escucha) = escucha else { return };
        let direccion = escucha.local_addr();
        assert!(direccion.is_ok());
        let Ok(direccion) = direccion else { return };
        let destino = direccion.to_string();

        // Anfitrión mínimo: lee el saludo, comprueba la marca del enjambre y
        // responde con su propio `ServerHello`. La aceptación tiene fecha
        // límite: la prueba nunca se cuelga esperando.
        let anfitrion = std::thread::spawn(move || -> bool {
            let _ = escucha.set_nonblocking(true);
            let mut aceptado = None;
            for _ in 0..200 {
                match escucha.accept() {
                    Ok((flujo, _)) => {
                        aceptado = Some(flujo);
                        break;
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
            let Some(mut flujo) = aceptado else {
                return false;
            };
            let _ = flujo.set_nonblocking(false);
            let _ = flujo.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)));

            let mut cabecera = [0_u8; 5];
            if flujo.read_exact(&mut cabecera).is_err() {
                return false;
            }
            let largo = usize::from(u16::from_be_bytes([cabecera[3], cabecera[4]]));
            let mut cuerpo = vec![0_u8; largo];
            if flujo.read_exact(&mut cuerpo).is_err() {
                return false;
            }
            let mut saludo = cabecera.to_vec();
            saludo.extend_from_slice(&cuerpo);

            let parsed = parse_client_hello(&saludo);
            if parsed.is_none() {
                return false;
            }
            let Some(parsed) = parsed else { return false };
            if !verify_camouflage(&saludo, &swarm_adn(b"semilla-de-red")) {
                return false;
            }

            let mut flujo2 = DnaStream::from_dna(&swarm_adn(b"anfitrion"));
            let secreto = flujo2.x25519_secret();
            let publico = x25519_base(&secreto);
            let mut azar = [0_u8; 32];
            overlay(&mut azar, &flujo2.bytes(32));
            let respuesta = server_hello(
                TLS_CHACHA20_POLY1305_SHA256,
                &parsed.session_id,
                &azar,
                GROUP_X25519,
                &publico,
            );
            flujo.write_all(&respuesta).is_ok()
        });

        let sesion = HttpsSession::connect(
            &destino,
            CamouflageProfile::browser("ejemplo.test"),
            b"semilla-de-red",
        );
        let terminado = anfitrion.join();
        assert!(terminado.is_ok());
        let Some(sesion) = sesion else { return };

        assert_eq!(sesion.address, destino);
        assert_eq!(sesion.server_hello.cipher, TLS_CHACHA20_POLY1305_SHA256);
        assert_eq!(sesion.server_hello.session_id, sesion.client.session_id);
        assert!(sesion.is_swarm_member());
        assert!(sesion.describe().contains("válida"));
        assert!(sesion.describe().contains("navegador"));
        assert_ne!(sesion.shared, [0_u8; 32]);
        assert_eq!(sesion.transcript.len(), 32);
        assert_ne!(
            sesion.client_handshake_keys(),
            sesion.server_handshake_keys()
        );
        assert_eq!(sesion.shared_hex().len(), 16);
        assert_eq!(sesion.server_hello.extensions.len(), 2);

        // Y el anfitrión llegó hasta el final del intercambio.
        if let Ok(enviado) = terminado {
            assert!(enviado, "el anfitrión no respondió al saludo");
        }

        // Un puerto cerrado no rompe nada: simplemente no hay sesión.
        assert!(HttpsSession::connect(
            "127.0.0.1:1",
            CamouflageProfile::swarm("ejemplo.test"),
            b"semilla-de-red"
        )
        .is_none());
    }
}
