//! # Frontera FFI nativa para Android (APK) — `ffi.rs`
//!
//! Superficie **C‑ABI** mínima para que un *wrapper* móvil (JNI/Flutter/Unity o
//! cualquier consumidor que hable C) use el kernel sin compartir memoria ni
//! tipos vivos de Rust.
//!
//! ## Contrato de la frontera
//! 1. **Sólo tipos planos** — enteros, `#[repr(C)]` de campos primitivos y
//!    arreglos de bytes de tamaño fijo. Ninguna función `extern "C"` recibe
//!    `&T`, `&mut T`, `String`, `Vec` ni punteros: el llamante no puede
//!    conservar una referencia al estado del kernel, así que no hay *aliasing*
//!    que un `unsafe` ajeno pueda romper.
//! 2. **Sin bloques `unsafe`** — el módulo entero es Rust seguro. `rustc`
//!    clasifica `#[no_mangle]` como atributo `unsafe` (desde 1.82), así que el
//!    módulo recibe `allow(unsafe_code)` desde `lib.rs`; aun así no hay ni un
//!    bloque `unsafe` en el archivo, y la prueba
//!    `el_modulo_ffi_no_contiene_codigo_unsafe` lo comprueba sobre su propio
//!    código fuente. La copia desde el arreglo del llamante a un *slice*
//!    interno se hace con indexación comprobada (`get(..len)`).
//! 3. **Todo fallo es un número** — cada función devuelve una estructura con
//!    `status: i32`. El perfil global `panic = "abort"` garantiza que ni
//!    siquiera un fallo catastrófico desenrolle a través de la frontera: aborta
//!    el proceso en lugar de cruzar el ABI con estado indeterminado.
//! 4. **Estado encapsulado** — una única `Session` bajo `Mutex` (sin
//!    `RwLock`, sin variables globales mutables ni `unsafe`). El `Mutex` también
//!    serializa las admisiones, que es exactamente la semántica de secuencia que
//!    espera [`Gateway`].
//! 5. **Sin red, sin ficheros** — la superficie sólo admite cargas, consulta el
//!    núcleo y lee la caja negra local.
//!
//! ## Uso desde Kotlin/JNI (resumen)
//! ```text
//! bara_ffi_init(FfiSeed)                → 0            // arranca el núcleo
//! bara_ffi_admit(seq, len, FfiPayload)  → FfiVerdict   // admite una carga
//! bara_ffi_kernel()                     → FfiKernel    // revisión + digest
//! bara_ffi_black_box()                  → FfiBlackBox  // censo forense
//! bara_ffi_incident(i)                  → FfiIncident  // incidente i-ésimo
//! bara_ffi_render_chunk(offset)         → FfiText      // volcado por trozos
//! ```
//! Las dos entradas van envueltas en estructuras `#[repr(C)]` ([`FfiSeed`] y
//! [`FfiPayload`]): un arreglo suelto por valor no es FFI-safe. La carga es de
//! [`PAYLOAD_MAX`] bytes; el llamante indica `len` y el resto se ignora. Una
//! carga mayor se trocea en varias llamadas: la frontera **no** reserva memoria
//! dinámica por el tamaño que declare el llamante.
//!
//! ## Compilación para `aarch64-linux-android`
//! `Cargo.toml` declara `crate-type = ["rlib", "cdylib"]`, así que
//! `cargo build --release --target aarch64-linux-android` produce
//! `libbara.so` con el perfil soberano (`opt-level = 3`, `lto = true`,
//! `codegen-units = 1`, `panic = "abort"`). El guion
//! `scripts/build_android.ps1` automatiza la compilación y el copiado a
//! `dist/android/<abi>/`.

// Sin `#![forbid(unsafe_code)]`: `#[no_mangle]` es un atributo clasificado como
// `unsafe` desde Rust 1.82. El permiso lo concede `lib.rs` a este módulo y aquí
// no se escribe ni un bloque `unsafe` (auditado por la prueba del final).
#![deny(clippy::all)]

use std::sync::{Mutex, MutexGuard};

use crate::autopoietic::KernelCore;
use crate::ffi_ingest::{BaraType, ShoreshAst, ShoreshNode};
use crate::flight_recorder;
use crate::immunity_gateway::{BubbleVerdict, Gateway};
use crate::runtime::QuantumState;

// ─────────────────────────────────────────────────────────────────────────
// Constantes del ABI
// ─────────────────────────────────────────────────────────────────────────

/// Versión del ABI. Cambia sólo si cambia la forma de alguna estructura.
pub const ABI_VERSION: u32 = 1;

/// Bytes máximos de una carga en una sola llamada.
///
/// Es una constante de compilación: el arreglo viaja **por valor**, de modo que
/// el llamante no puede pedir una reserva arbitraria.
pub const PAYLOAD_MAX: usize = 4096;

/// Bytes máximos de un trozo de volcado legible.
pub const TEXT_CHUNK: usize = 256;

/// Orígenes admitidos. El llamante elige un índice, nunca una cadena: así no
/// puede inyectar texto en las etiquetas de la pasarela.
pub const ORIGINS: [&str; 4] = ["android", "jni", "bara-ide", "ffi"];

// Códigos de estado (planos, estables y documentados).
/// Operación completada.
pub const STATUS_OK: i32 = 0;
/// La sesión no se ha inicializado (o se reinició).
pub const STATUS_NOT_INITIALIZED: i32 = -1;
/// `len` excede [`PAYLOAD_MAX`] o el desplazamiento es inalcanzable.
pub const STATUS_INVALID_LENGTH: i32 = -2;
/// El `Mutex` de la sesión quedó envenenado por un pánico previo.
pub const STATUS_POISONED: i32 = -3;
/// Índice de origen fuera de [`ORIGINS`].
pub const STATUS_INVALID_TAG: i32 = -4;
/// No existe el incidente solicitado.
pub const STATUS_NO_INCIDENT: i32 = -5;
/// El núcleo no verifica su propio ADN (nunca ocurre en una sesión sana).
pub const STATUS_UNVERIFIED: i32 = -6;

/// Códigos de veredicto de burbuja, estables para el cliente móvil.
pub const VERDICT_INNOCUOUS: u32 = 0;
/// Paradoja absorbida (`⊤∧⊥`).
pub const VERDICT_ABSORBED: u32 = 1;
/// Carga hostil neutralizada (`⊥`).
pub const VERDICT_NEUTRALIZED: u32 = 2;
/// Carga ilegible en cuarentena (`∅`).
pub const VERDICT_QUARANTINED: u32 = 3;

// ─────────────────────────────────────────────────────────────────────────
// Entradas del ABI (arreglos envueltos: un arreglo suelto no es FFI-safe)
// ─────────────────────────────────────────────────────────────────────────

/// Semilla soberana de 32 bytes.
///
/// Va envuelta en `#[repr(C)]` porque Rust no considera FFI-safe pasar un
/// arreglo por valor en la firma de una función `extern "C"`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FfiSeed {
    /// Bytes de la semilla (el llamante decide su contenido).
    pub bytes: [u8; 32],
}

impl FfiSeed {
    /// Semilla a partir de un arreglo.
    pub const fn new(bytes: [u8; 32]) -> FfiSeed {
        FfiSeed { bytes }
    }
}

/// Carga externa de tamaño fijo.
///
/// El llamante rellena `bytes` y declara `len` en [`bara_ffi_admit`]; el resto
/// se ignora. Al ser `#[repr(C)]`, el arreglo viaja por valor sin punteros y el
/// llamante conserva la propiedad de su copia.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FfiPayload {
    /// Bytes de la carga (sólo los primeros `len` se interpretan).
    pub bytes: [u8; PAYLOAD_MAX],
}

impl FfiPayload {
    /// Carga vacía.
    pub const fn empty() -> FfiPayload {
        FfiPayload {
            bytes: [0; PAYLOAD_MAX],
        }
    }

    /// Prefijo útil de la carga.
    pub fn prefix(&self, len: usize) -> Option<&[u8]> {
        self.bytes.get(..len)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Estructuras planas (FFI-safe)
// ─────────────────────────────────────────────────────────────────────────

/// Resultado de admitir una carga.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FfiVerdict {
    /// Código de estado ([`STATUS_OK`] si todo fue bien).
    pub status: i32,
    /// Veredicto tetravalente (`VERDICT_*`).
    pub verdict: u32,
    /// Identificador de la burbuja (monótono dentro de la sesión).
    pub bubble_id: u64,
    /// Secuencia declarada por el llamante.
    pub sequence: u64,
    /// Peligro reconocido, en ‰.
    pub danger_permille: u32,
    /// Nodos *Shoresh* destilados de la carga.
    pub nodes: u32,
    /// Techo de riesgo del AST destilado, en ‰.
    pub hazard_permille: u32,
    /// Masa de verdad de la burbuja, en ‰.
    pub truth_permille: u32,
    /// Masa de falsedad de la burbuja, en ‰.
    pub falsity_permille: u32,
    /// Huella de 64 bits del digest de la carga (nunca la carga).
    pub payload_hash: u64,
}

impl FfiVerdict {
    /// Respuesta de error sin datos: una sola forma de fallar.
    const fn failed(status: i32) -> FfiVerdict {
        FfiVerdict {
            status,
            verdict: 0,
            bubble_id: 0,
            sequence: 0,
            danger_permille: 0,
            nodes: 0,
            hazard_permille: 0,
            truth_permille: 0,
            falsity_permille: 0,
            payload_hash: 0,
        }
    }
}

/// Fotografía del núcleo inmutable.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FfiKernel {
    /// Código de estado.
    pub status: i32,
    /// Revisión monotónica (0 en el génesis).
    pub revision: u64,
    /// Identificador público de la clave soberana.
    pub key_id: u64,
    /// Raíces del AST.
    pub roots: u32,
    /// `1` si el ADN verifica, `0` si no.
    pub verified: u32,
    /// Huella soberana del núcleo.
    pub digest: [u8; 32],
}

impl FfiKernel {
    /// Respuesta de error.
    const fn failed(status: i32) -> FfiKernel {
        FfiKernel {
            status,
            revision: 0,
            key_id: 0,
            roots: 0,
            verified: 0,
            digest: [0; 32],
        }
    }
}

/// Censo de la caja negra.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FfiBlackBox {
    /// Código de estado.
    pub status: i32,
    /// Ranuras del anillo (siempre [`flight_recorder::CAPACITY`]).
    pub capacity: u64,
    /// Billetes repartidos.
    pub reserved: u64,
    /// Entradas publicadas.
    pub published: u64,
    /// Entradas pisadas por el desbordamiento circular.
    pub overwritten: u64,
    /// Escrituras en vuelo.
    pub in_flight: u64,
}

/// Incidente de la caja negra.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FfiIncident {
    /// Código de estado ([`STATUS_NO_INCIDENT`] si el índice no existe).
    pub status: i32,
    /// Billete del anillo.
    pub sequence: u64,
    /// Clase del evento (`EventKind::code`).
    pub event: u32,
    /// Código de la regla violada.
    pub violation: u32,
    /// Huella de 64 bits del paquete (nunca la carga).
    pub payload_hash: u64,
}

impl FfiIncident {
    /// Respuesta de error.
    const fn failed(status: i32) -> FfiIncident {
        FfiIncident {
            status,
            sequence: 0,
            event: 0,
            violation: 0,
            payload_hash: 0,
        }
    }
}

/// Trozo del volcado legible de la caja negra.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FfiText {
    /// Código de estado.
    pub status: i32,
    /// Bytes válidos en `bytes`.
    pub len: u32,
    /// Longitud total del volcado (para trocear).
    pub total: u32,
    /// Bytes UTF‑8 del trozo (el resto queda a cero).
    pub bytes: [u8; TEXT_CHUNK],
}

impl FfiText {
    /// Respuesta vacía.
    const fn failed(status: i32) -> FfiText {
        FfiText {
            status,
            len: 0,
            total: 0,
            bytes: [0; TEXT_CHUNK],
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Sesión encapsulada
// ─────────────────────────────────────────────────────────────────────────

/// Estado soberano de la sesión móvil.
#[derive(Debug)]
struct Session {
    kernel: KernelCore,
    gateway: Gateway,
    origin: usize,
}

// `Mutex::new` es `const`: la sesión vive en un `static` sin `OnceLock`, sin
// `lazy_static` y sin `unsafe`.
static SESSION: Mutex<Option<Session>> = Mutex::new(None);

/// Bloquea la sesión; un mutex envenenado se convierte en código plano.
fn session() -> Result<MutexGuard<'static, Option<Session>>, i32> {
    SESSION.lock().map_err(|_| STATUS_POISONED)
}

/// Origen efectivo: el índice guardado sólo puede ser válido, pero se comprueba
/// igualmente para no indexar jamás sin cota.
fn origin_of(index: usize) -> &'static str {
    ORIGINS.get(index).copied().unwrap_or(ORIGINS[0])
}

/// Convierte una masa `[0, 1]` en ‰ sin desbordar.
fn permille(mass: f64) -> u32 {
    if !mass.is_finite() {
        return 0;
    }
    let clamped = mass.clamp(0.0, 1.0);
    (clamped * 1000.0).round() as u32
}

/// Código plano de un veredicto.
fn verdict_code(verdict: BubbleVerdict) -> u32 {
    match verdict {
        BubbleVerdict::Innocuous => VERDICT_INNOCUOUS,
        BubbleVerdict::Absorbed => VERDICT_ABSORBED,
        BubbleVerdict::Neutralized => VERDICT_NEUTRALIZED,
        BubbleVerdict::Quarantined => VERDICT_QUARANTINED,
    }
}

/// AST de génesis: una única raíz triconsonántica `אמת` (verdad).
///
/// Es el punto de apoyo estable de la sesión móvil: el núcleo nace con un nodo
/// estructuralmente admisible y sin riesgo, y el cliente puede consultar su
/// digest desde el primer instante.
fn genesis_ast() -> ShoreshAst {
    ShoreshAst {
        nodes: vec![ShoreshNode {
            root: "אמת".to_string(),
            original: "ffi:genesis".to_string(),
            arity: 0,
            ret: BaraType::Truth,
            hazard: 0.0,
            valence: QuantumState::paraconsistent(1.0, 0.0),
            sanitized: false,
        }],
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Frontera C-ABI: todo por valor, todo con código de estado
// ─────────────────────────────────────────────────────────────────────────

/// Versión del ABI que habla esta biblioteca.
#[no_mangle]
pub extern "C" fn bara_ffi_abi_version() -> u32 {
    ABI_VERSION
}

/// Arranca (o reinicia) la sesión con la semilla soberana de 32 bytes.
///
/// Devuelve [`STATUS_OK`] o un código plano. La semilla **no** se conserva en
/// claro: el núcleo guarda la clave derivada y su digest.
#[no_mangle]
pub extern "C" fn bara_ffi_init(seed: FfiSeed) -> i32 {
    let kernel = KernelCore::genesis("bara-ffi", genesis_ast(), &seed.bytes);
    if !kernel.verify() {
        return STATUS_UNVERIFIED;
    }
    let mut guard = match session() {
        Ok(guard) => guard,
        Err(status) => return status,
    };
    *guard = Some(Session {
        kernel,
        gateway: Gateway::new(),
        origin: 0,
    });
    STATUS_OK
}

/// Libera la sesión (el `Drop` del núcleo borra la clave en memoria).
#[no_mangle]
pub extern "C" fn bara_ffi_reset() -> i32 {
    let mut guard = match session() {
        Ok(guard) => guard,
        Err(status) => return status,
    };
    *guard = None;
    STATUS_OK
}

/// Elige el origen de las próximas admisiones (`0..ORIGINS.len()`).
#[no_mangle]
pub extern "C" fn bara_ffi_set_origin(tag: u32) -> i32 {
    let index = match usize::try_from(tag) {
        Ok(index) => index,
        Err(_) => return STATUS_INVALID_TAG,
    };
    if index >= ORIGINS.len() {
        return STATUS_INVALID_TAG;
    }
    let mut guard = match session() {
        Ok(guard) => guard,
        Err(status) => return status,
    };
    match guard.as_mut() {
        Some(state) => {
            state.origin = index;
            STATUS_OK
        }
        None => STATUS_NOT_INITIALIZED,
    }
}

/// Admite una carga de `len` bytes (el resto del arreglo se ignora).
#[no_mangle]
pub extern "C" fn bara_ffi_admit(sequence: u64, len: u32, payload: FfiPayload) -> FfiVerdict {
    let length = match usize::try_from(len) {
        Ok(length) if length <= PAYLOAD_MAX => length,
        _ => return FfiVerdict::failed(STATUS_INVALID_LENGTH),
    };
    let slice = match payload.prefix(length) {
        Some(slice) => slice,
        None => return FfiVerdict::failed(STATUS_INVALID_LENGTH),
    };
    let mut guard = match session() {
        Ok(guard) => guard,
        Err(status) => return FfiVerdict::failed(status),
    };
    let state = match guard.as_mut() {
        Some(state) => state,
        None => return FfiVerdict::failed(STATUS_NOT_INITIALIZED),
    };
    let origin = origin_of(state.origin);
    let bubble = state.gateway.admit(origin, sequence, slice);
    let (truth, falsity) = bubble.valence.belnap();
    FfiVerdict {
        status: STATUS_OK,
        verdict: verdict_code(bubble.verdict),
        bubble_id: bubble.id,
        sequence: bubble.sequence,
        danger_permille: bubble.danger,
        nodes: bubble.ast.nodes.len().min(u32::MAX as usize) as u32,
        hazard_permille: permille(bubble.ast.hazard_ceiling()),
        truth_permille: permille(truth),
        falsity_permille: permille(falsity),
        payload_hash: flight_recorder::digest_fingerprint(&bubble.payload_digest),
    }
}

/// Fotografía del núcleo: revisión, raíces, clave y digest.
#[no_mangle]
pub extern "C" fn bara_ffi_kernel() -> FfiKernel {
    let guard = match session() {
        Ok(guard) => guard,
        Err(status) => return FfiKernel::failed(status),
    };
    let state = match guard.as_ref() {
        Some(state) => state,
        None => return FfiKernel::failed(STATUS_NOT_INITIALIZED),
    };
    let verified = state.kernel.verify();
    FfiKernel {
        status: if verified {
            STATUS_OK
        } else {
            STATUS_UNVERIFIED
        },
        revision: state.kernel.revision(),
        key_id: state.kernel.key_id(),
        roots: state.kernel.roots().min(u32::MAX as usize) as u32,
        verified: u32::from(verified),
        digest: state.kernel.digest(),
    }
}

/// Censo de la caja negra del proceso.
#[no_mangle]
pub extern "C" fn bara_ffi_black_box() -> FfiBlackBox {
    let counters = flight_recorder::counters();
    FfiBlackBox {
        status: STATUS_OK,
        capacity: counters.capacity as u64,
        reserved: counters.reserved,
        published: counters.published,
        overwritten: counters.overwritten,
        in_flight: counters.in_flight,
    }
}

/// Número de incidentes legibles en la caja negra.
#[no_mangle]
pub extern "C" fn bara_ffi_incident_count() -> u32 {
    let inspected = flight_recorder::inspect();
    inspected.entries.len().min(u32::MAX as usize) as u32
}

/// Incidente `index`-ésimo (del más antiguo al más reciente).
#[no_mangle]
pub extern "C" fn bara_ffi_incident(index: u32) -> FfiIncident {
    let inspected = flight_recorder::inspect();
    let position = match usize::try_from(index) {
        Ok(position) => position,
        Err(_) => return FfiIncident::failed(STATUS_NO_INCIDENT),
    };
    match inspected.entries.get(position) {
        Some(entry) => FfiIncident {
            status: STATUS_OK,
            sequence: entry.sequence,
            event: u32::from(entry.event.code()),
            violation: u32::from(entry.violation.code()),
            payload_hash: entry.payload_hash,
        },
        None => FfiIncident::failed(STATUS_NO_INCIDENT),
    }
}

/// Trozo del volcado legible, a partir del byte `offset`.
///
/// El corte respeta los límites de carácter UTF‑8: el cliente puede concatenar
/// los trozos sin producir texto inválido.
#[no_mangle]
pub extern "C" fn bara_ffi_render_chunk(offset: u32) -> FfiText {
    let text = flight_recorder::render();
    let total = text.len();
    let requested = match usize::try_from(offset) {
        Ok(requested) => requested,
        Err(_) => return FfiText::failed(STATUS_INVALID_LENGTH),
    };
    let mut start = requested.min(total);
    while start < total && !text.is_char_boundary(start) {
        start = start.saturating_add(1);
    }
    let mut end = start.saturating_add(TEXT_CHUNK).min(total);
    while end > start && !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let chunk = match text.as_bytes().get(start..end) {
        Some(chunk) => chunk,
        None => return FfiText::failed(STATUS_INVALID_LENGTH),
    };
    let mut bytes = [0u8; TEXT_CHUNK];
    for (slot, byte) in bytes.iter_mut().zip(chunk.iter()) {
        *slot = *byte;
    }
    FfiText {
        status: STATUS_OK,
        len: chunk.len().min(u32::MAX as usize) as u32,
        total: total.min(u32::MAX as usize) as u32,
        bytes,
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Auditoría del propio módulo
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// El permiso `allow(unsafe_code)` existe **sólo** por `#[no_mangle]`: el
    /// archivo no puede contener ni un bloque ni una declaración `unsafe`.
    ///
    /// El escaneo se detiene en `#[cfg(test)]`: este mismo módulo cita los
    /// patrones prohibidos como texto y, sin el corte, se delataría a sí mismo.
    #[test]
    fn el_modulo_ffi_no_contiene_codigo_unsafe() {
        let source = include_str!("ffi.rs");
        let production = source
            .split_once("#[cfg(test)]")
            .map_or(source, |(production, _)| production);
        for needle in ["unsafe {", "unsafe fn", "unsafe impl", "unsafe("] {
            assert!(
                !production.contains(needle),
                "la frontera FFI no debe contener «{needle}»"
            );
        }
        assert!(
            production.contains("#[no_mangle]"),
            "los símbolos del ABI deben exportarse con #[no_mangle]"
        );
    }

    /// Las estructuras del ABI son planas: tamaño fijo, sin punteros ni tipos
    /// vivos. Si dejaran de serlo, `improper_ctypes_definitions` lo delataría.
    #[test]
    fn las_estructuras_del_abi_son_planas() {
        assert_eq!(core::mem::size_of::<FfiSeed>(), 32);
        assert_eq!(core::mem::size_of::<FfiPayload>(), PAYLOAD_MAX);
        assert_eq!(
            core::mem::size_of::<FfiText>(),
            4 + 4 + 4 + TEXT_CHUNK,
            "status + len + total + bytes"
        );
        assert!(FfiPayload::empty().prefix(0).is_some());
        assert!(FfiPayload::empty().prefix(PAYLOAD_MAX).is_some());
        assert!(FfiPayload::empty().prefix(PAYLOAD_MAX + 1).is_none());
    }
}
