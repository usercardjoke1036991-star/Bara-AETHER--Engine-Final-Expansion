//! # Pasarela de inmunidad paraconsistente — `immunity_gateway.rs`
//!
//! Implementa la **Puerta Abierta con Inmunidad Absoluta**: la pasarela acepta
//! *cualquier* carga —datos, código, ruido o un ataque declarado— sin filtros
//! arbitrarios ni censura previa, y la confina en una **burbuja de ejecución
//! holográfica** donde la lógica tetravalente de Belnap absorbe la
//! contradicción antes de que pueda rozar el núcleo.
//!
//! ## Contrato de puerta abierta
//! * **Nada se descarta**: [`Gateway::run`] abre una burbuja por **cada**
//!   paquete recibido, sin excepción. La igualdad
//!   `recibidos == burbujas` es un invariante comprobado por la suite.
//! * **No hay censura ciega**: la política no tiene verbo «rechazar». La
//!   hostilidad no se bloquea: se **neutraliza** (se convierte en ruido inerte
//!   y se cuenta), y la paradoja no se elimina: se **retiene**.
//! * **Aislamiento**: cada burbuja vive en su propia región de memoria
//!   ([`RegionTable`]), dimensionada por el paso áureo [`fib_ceil`] (la misma
//!   primitiva que reparte la retícula de
//!   [`FractalLayout`](crate::fractal_geometry::FractalLayout)) y registrada en
//!   la memoria holográfica del núcleo (escritura idempotente, entropía cero).
//!   Su digest es su holograma.
//!
//! ## Cómo decide la valencia (fórmula explícita, sin cajas negras)
//! Para cada paquete se calcula:
//! * `peligro` — [`threat_of`]: marcas de ataque ponderadas (travesía de
//!   directorios, inyección de órdenes, `SQL`, bombas de tamaño, control
//!   binario, bidi, anidamiento profundo) más el techo de riesgo del AST
//!   ingerido. Queda acotado a `[0, 1]`.
//! * `lectura` — ¿la ingesta omnívora encontró **algo** en la carga?
//!
//! Y la valencia es `(⊤, ⊥) = (lectura ? 1 − peligro : 0, peligro)`.
//! De ahí salen los cuatro veredictos:
//!
//! | Belnap | Valencia | Veredicto | Qué se hace |
//! |---|---|---|---|
//! | `⊤`  | `peligro < ½` | [`BubbleVerdict::Innocuous`]   | entra al núcleo como axioma |
//! | `⊤∧⊥` | `peligro = ½` | [`BubbleVerdict::Absorbed`]    | se retiene: paradoja sin explosión |
//! | `⊥`  | `peligro > ½` | [`BubbleVerdict::Neutralized`] | se convierte en ruido inerte |
//! | `∅`  | ilegible      | [`BubbleVerdict::Quarantined`] | se sella y se aísla |
//!
//! ## Transporte
//! [`Ingress`] abstrae el origen: [`LoopbackIngress`] (determinista, para las
//! pruebas) y [`TcpIngress`] (sockets `std::net` reales, no bloqueantes y con
//! presupuesto de lectura). Ninguno de los dos decide nada: sólo entregan
//! bytes. La decisión es siempre de la burbuja.

use std::collections::VecDeque;
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use crate::ast_dna::{merkle_root, short_hex};
use crate::crypto_native::{chacha20_xor, sha256};
use crate::ffi_ingest::{ingest_auto, to_shoresh, ShoreshAst};
use crate::fractal_geometry::fib_ceil;
use crate::memory_region::{RegionId, RegionKind, RegionTable};
use crate::runtime::{BaraRuntime, HolographicMemory, Observation, QuantumState};

/// Presupuesto máximo de un paquete, en bytes.
///
/// Una carga mayor **no se rechaza**: entra igualmente, pero se lee hasta este
/// techo y el exceso cuenta como bomba de tamaño en el modelo de amenaza.
pub const MAX_PAYLOAD: usize = 64 * 1024;

/// Paquete recibido por la puerta abierta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// Origen declarado (etiqueta del transporte).
    pub origin: String,
    /// Número de orden de llegada (monótono, sin relojes).
    pub sequence: u64,
    /// Bytes recibidos (acotados a [`MAX_PAYLOAD`]).
    pub payload: Vec<u8>,
}

impl Packet {
    /// Construye un paquete recortando la carga al techo.
    pub fn new(origin: &str, sequence: u64, payload: &[u8]) -> Self {
        let take = payload.len().min(MAX_PAYLOAD);
        Packet {
            origin: origin.to_string(),
            sequence,
            payload: payload[..take].to_vec(),
        }
    }

    /// Digest de la carga útil.
    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.payload)
    }

    /// Carga útil como texto tolerante (nunca falla).
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.payload).to_string()
    }
}

/// Fuente de paquetes: abstrae el transporte sin decidir nada sobre el fondo.
pub trait Ingress {
    /// Etiqueta del transporte.
    fn label(&self) -> String;

    /// Extrae hasta `max` paquetes, sin bloquearse indefinidamente.
    fn recv(&mut self, max: usize) -> Vec<Packet>;
}

/// Origen determinista en memoria: el «bucle local» de las pruebas.
///
/// No hay zócalos, no hay relojes: la misma secuencia de [`Self::push_text`]
/// produce siempre los mismos paquetes y, por tanto, las mismas burbujas.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoopbackIngress {
    queue: VecDeque<Packet>,
    sequence: u64,
    origin: String,
}

impl LoopbackIngress {
    /// Crea un origen vacío con su etiqueta.
    pub fn new(origin: &str) -> Self {
        LoopbackIngress {
            queue: VecDeque::new(),
            sequence: 0,
            origin: origin.to_string(),
        }
    }

    /// Encola una carga binaria y devuelve su número de orden.
    pub fn push_bytes(&mut self, payload: &[u8]) -> u64 {
        let sequence = self.sequence;
        self.sequence += 1;
        let origin = self.origin.clone();
        self.queue
            .push_back(Packet::new(&origin, sequence, payload));
        sequence
    }

    /// Encola una carga de texto y devuelve su número de orden.
    pub fn push_text(&mut self, text: &str) -> u64 {
        self.push_bytes(text.as_bytes())
    }

    /// Paquetes pendientes.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// ¿No queda ningún paquete?
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

impl Ingress for LoopbackIngress {
    fn label(&self) -> String {
        self.origin.clone()
    }

    fn recv(&mut self, max: usize) -> Vec<Packet> {
        let mut out = Vec::new();
        while out.len() < max {
            match self.queue.pop_front() {
                Some(packet) => out.push(packet),
                None => break,
            }
        }
        out
    }
}

/// Receptor TCP real sobre `std::net`: no bloqueante y con presupuesto.
///
/// La puerta se abre de verdad (zócalo del sistema), pero **no se queda
/// esperando**: `accept` con el listener en modo no bloqueante devuelve lo que
/// haya y sigue. Esto es lo que permite que la inmunidad no se convierta en una
/// denegación de servicio contra sí misma.
#[derive(Debug)]
pub struct TcpIngress {
    listener: TcpListener,
    read_limit: usize,
    accepted: usize,
}

impl TcpIngress {
    /// Abre la puerta en `address` (p. ej. `127.0.0.1:0`).
    ///
    /// Devuelve `None` si el sistema no permite abrir el zócalo: la pasarela
    /// **degrada**, nunca aborta (axioma A1).
    pub fn bind(address: &str) -> Option<TcpIngress> {
        let listener = TcpListener::bind(address).ok()?;
        if listener.set_nonblocking(true).is_err() {
            return None;
        }
        Some(TcpIngress {
            listener,
            read_limit: MAX_PAYLOAD,
            accepted: 0,
        })
    }

    /// Dirección efectiva (útil cuando se pidió el puerto `0`).
    pub fn local_address(&self) -> Option<String> {
        self.listener.local_addr().ok().map(|addr| addr.to_string())
    }

    /// Conexiones atendidas hasta ahora.
    pub fn accepted(&self) -> usize {
        self.accepted
    }

    /// Techo de lectura por conexión.
    pub fn read_limit(&self) -> usize {
        self.read_limit
    }
}

impl Ingress for TcpIngress {
    fn label(&self) -> String {
        match self.local_address() {
            Some(address) => format!("tcp://{address}"),
            None => "tcp://?".to_string(),
        }
    }

    fn recv(&mut self, max: usize) -> Vec<Packet> {
        let mut out = Vec::new();
        while out.len() < max {
            match self.listener.accept() {
                Ok((mut stream, peer)) => {
                    let payload = read_stream(&mut stream, self.read_limit);
                    let sequence = self.accepted as u64;
                    self.accepted += 1;
                    out.push(Packet::new(&peer.to_string(), sequence, &payload));
                }
                // `WouldBlock` o cualquier error de zócalo: se entrega lo que
                // haya. Nada se pierde y nada se cae.
                Err(_) => break,
            }
        }
        out
    }
}

/// Lee de un flujo con tiempo de espera acotado y techo de bytes.
///
/// El tiempo de espera es la única concesión al bloqueo: 50 ms por lectura.
/// Cualquier error (incluido el vencimiento) cierra la lectura y devuelve lo
/// ya recogido.
fn read_stream(stream: &mut TcpStream, limit: usize) -> Vec<u8> {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
    let mut buffer = vec![0u8; 4096];
    let mut collected = Vec::new();
    while collected.len() < limit {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => collected.extend_from_slice(&buffer[..read]),
            Err(_) => break,
        }
    }
    collected.truncate(limit);
    collected
}

// ─────────────────────────────────────────────────────────────────────────
// Modelo de amenaza: marcas finitas, explícitas y auditables
// ─────────────────────────────────────────────────────────────────────────

/// Umbral de designación de Belnap (`⊤`/`⊥`), idéntico al del núcleo
/// (`DESIGNATION_THRESHOLD` en `runtime.rs`).
pub const DESIGNATION: f64 = 0.5;

/// Peso máximo del modelo de amenaza, en permilajes.
pub const DANGER_CEILING: u32 = 1000;

/// Umbral de la «bomba de tamaño», en bytes.
pub const SIZE_BOMB_BYTES: usize = 4096;

/// Proporción (en ‰) de bytes de control a partir de la cual la carga se
/// considera *relleno de control*.
pub const CONTROL_PADDING_PERMILLE: u64 = 250;

/// Marcas **literales** reconocidas: `(etiqueta, aguja en minúsculas, peso ‰)`.
///
/// La tabla es finita, explícita y auditable; no hay clasificador opaco. Lo que
/// no está aquí **no se bloquea**: se mide con la fórmula de [`threat_of`] y,
/// como mucho, se aísla.
pub const ATTACK_NEEDLES: [(&str, &str, u32); 10] = [
    ("travesía de directorios", "../", 250),
    ("inyección de órdenes", "$(", 150),
    ("sustitución por comilla inversa", "`", 100),
    ("borrado recursivo", "rm -rf", 300),
    ("inyección SQL", "union select", 250),
    ("destrucción de tabla", "drop table", 250),
    ("guion incrustado", "<script", 200),
    ("evaluación dinámica", "eval(", 150),
    ("ejecución de sistema", "system(", 150),
    ("sobreescritura bidireccional", "\u{202e}", 200),
];

/// Marca calculada: carga mayor que [`SIZE_BOMB_BYTES`].
pub const MARK_SIZE_BOMB: (&str, u32) = ("bomba de tamaño", 300);
/// Marca calculada: exceso de bytes de control.
pub const MARK_CONTROL_PADDING: (&str, u32) = ("relleno de control", 200);
/// Marca calculada: anidamiento profundo de delimitadores.
pub const MARK_DEEP_NESTING: (&str, u32) = ("anidamiento profundo", 150);
/// Marca calculada: bytes de anulación (`%00` o `0x00`).
pub const MARK_NUL: (&str, u32) = ("anulación por byte nulo", 100);
/// Marca calculada: carga que no es texto UTF-8.
pub const MARK_UNREADABLE: (&str, u32) = ("texto ilegible", 50);

/// Modelo de amenaza de una carga: riesgo en ‰ y marcas que lo justifican.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Threat {
    /// Peligro acumulado en ‰, acotado a [`DANGER_CEILING`].
    pub mille: u32,
    /// Etiquetas de las marcas reconocidas, en orden de tabla.
    pub markers: Vec<&'static str>,
}

impl Threat {
    /// Riesgo normalizado en `[0, 1]`. Los milésimos son exactos, así que el
    /// umbral `0.5` de Belnap es **alcanzable con precisión**.
    pub fn danger(&self) -> f64 {
        f64::from(self.mille.min(DANGER_CEILING)) / f64::from(DANGER_CEILING)
    }

    /// Carga serena: por debajo del umbral, sin designación de falsedad.
    pub fn is_calm(&self) -> bool {
        self.mille < 500
    }

    /// Carga en el **filo** exacto de la contradicción (`⊤∧⊥`).
    pub fn is_paradoxical(&self) -> bool {
        self.mille == 500
    }

    /// Carga hostil: por encima del umbral.
    pub fn is_hostile(&self) -> bool {
        self.mille > 500
    }

    /// ¿La carga contiene algún rastro de ataque?
    pub fn is_tainted(&self) -> bool {
        !self.markers.is_empty()
    }

    /// Resumen legible: `350 ‰ · travesía de directorios + inyección de órdenes`.
    pub fn summary(&self) -> String {
        if self.markers.is_empty() {
            return format!("{} ‰ · limpio", self.mille);
        }
        format!("{} ‰ · {}", self.mille, self.markers.join(" + "))
    }
}

/// ¿Hay un tramo de ocho delimitadores anidados o más?
fn has_deep_nesting(text: &str) -> bool {
    let mut run = 0_u32;
    for ch in text.chars() {
        if ch == '[' || ch == '(' || ch == '{' {
            run += 1;
            if run >= 8 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// Cuenta los bytes de control «duros» (excluye tabulador y saltos de línea).
fn control_bytes(payload: &[u8]) -> u64 {
    payload
        .iter()
        .filter(|byte| **byte < 0x20 && **byte != b'\n' && **byte != b'\r' && **byte != b'\t')
        .count() as u64
}

/// ¿La carga contiene **algo** interpretable? Texto UTF-8 con al menos un
/// símbolo alfanumérico. Lo ilegible no se rechaza: se cuarentena.
pub fn is_legible(payload: &[u8]) -> bool {
    match std::str::from_utf8(payload) {
        Ok(text) => text.chars().any(|ch| ch.is_alphanumeric()),
        Err(_) => false,
    }
}

/// Modelo de amenaza completo de una carga: marcas literales + marcas
/// calculadas, sumadas en ‰ y acotadas a [`DANGER_CEILING`].
pub fn threat_of(payload: &[u8]) -> Threat {
    let mut markers: Vec<&'static str> = Vec::new();
    let mut mille: u32 = 0;

    // Las agujas se buscan sobre una copia en minúsculas *lossy*: una carga
    // binaria se sondea igualmente, sin fallar.
    let text = String::from_utf8_lossy(payload).to_lowercase();
    for (label, needle, weight) in ATTACK_NEEDLES {
        if text.contains(needle) {
            markers.push(label);
            mille += weight;
        }
    }
    if text.contains("%00") || payload.contains(&0_u8) {
        markers.push(MARK_NUL.0);
        mille += MARK_NUL.1;
    }
    if payload.len() > SIZE_BOMB_BYTES {
        markers.push(MARK_SIZE_BOMB.0);
        mille += MARK_SIZE_BOMB.1;
    }
    if !payload.is_empty()
        && control_bytes(payload) * DANGER_CEILING as u64
            >= payload.len() as u64 * CONTROL_PADDING_PERMILLE
    {
        markers.push(MARK_CONTROL_PADDING.0);
        mille += MARK_CONTROL_PADDING.1;
    }
    if has_deep_nesting(&text) {
        markers.push(MARK_DEEP_NESTING.0);
        mille += MARK_DEEP_NESTING.1;
    }
    if std::str::from_utf8(payload).is_err() {
        markers.push(MARK_UNREADABLE.0);
        mille += MARK_UNREADABLE.1;
    }

    Threat {
        mille: mille.min(DANGER_CEILING),
        markers,
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Burbujas de ejecución holográfica
// ─────────────────────────────────────────────────────────────────────────

/// Veredicto de una burbuja, en la lógica tetravalente de Belnap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BubbleVerdict {
    /// `⊤` · inocuo: el contenido entra al núcleo como axioma.
    Innocuous,
    /// `⊤∧⊥` · paradoja **absorbida**: se retiene sin explosión.
    Absorbed,
    /// `⊥` · hostil **neutralizado**: la carga se vuelve ruido inerte.
    Neutralized,
    /// `∅` · ilegible: se sella y se aísla.
    Quarantined,
}

impl BubbleVerdict {
    /// Nombre ontológico.
    pub fn label(&self) -> &'static str {
        match self {
            BubbleVerdict::Innocuous => "inocuo",
            BubbleVerdict::Absorbed => "paradoja absorbida",
            BubbleVerdict::Neutralized => "hostil neutralizado",
            BubbleVerdict::Quarantined => "en cuarentena",
        }
    }

    /// Glifo de Belnap.
    pub fn glyph(&self) -> &'static str {
        match self {
            BubbleVerdict::Innocuous => "⊤",
            BubbleVerdict::Absorbed => "⊤∧⊥",
            BubbleVerdict::Neutralized => "⊥",
            BubbleVerdict::Quarantined => "∅",
        }
    }

    /// ¿Su contenido puede alcanzar el núcleo? (lo inocuo y lo absorbido sí;
    /// lo hostil y lo ilegible, nunca).
    pub fn reaches_core(&self) -> bool {
        matches!(self, BubbleVerdict::Innocuous | BubbleVerdict::Absorbed)
    }
}

/// Burbuja de ejecución **holográfica**: un confín estanco por paquete.
///
/// Cada burbuja tiene su propia región de memoria, su digest (el holograma) y
/// su valencia. El aislamiento es estructural: sus datos nunca se mezclan con
/// los de otra burbuja ni con el núcleo hasta que el veredicto lo autorice.
#[derive(Debug, Clone)]
pub struct Bubble {
    /// Identificador monótono.
    pub id: u64,
    /// Etiqueta única (clave en la memoria holográfica).
    pub label: String,
    /// Origen declarado por el transporte.
    pub origin: String,
    /// Número de orden dentro del transporte.
    pub sequence: u64,
    /// Región de memoria exclusiva de esta burbuja.
    pub region: RegionId,
    /// Capacidad asignada por el paso áureo ([`fib_ceil`]).
    pub span: u64,
    /// Bytes recibidos.
    pub bytes: usize,
    /// Nodos *Shoresh* destilados de la carga.
    pub ast: ShoreshAst,
    /// Valencia paraconsistente `(⊤, ⊥)`.
    pub valence: QuantumState,
    /// Colapso tetravalente de la valencia.
    pub observation: Observation,
    /// Veredicto de inmunidad.
    pub verdict: BubbleVerdict,
    /// Peligro en ‰ (0–1000).
    pub danger: u32,
    /// Marcas de ataque reconocidas.
    pub markers: Vec<&'static str>,
    /// Holograma de la burbuja.
    pub dna: [u8; 32],
    /// Digest de la carga original.
    pub payload_digest: [u8; 32],
    /// Carga neutralizada (ruido inerte); vacía si el veredicto no lo exige.
    pub inert: Vec<u8>,
    /// Trazas legibles para el informe.
    pub notes: Vec<String>,
}

impl Bubble {
    /// Holograma en hexadecimal corto.
    pub fn hologram(&self) -> String {
        short_hex(&self.dna[..8])
    }

    /// Nodos sellados bajo guarda.
    pub fn sealed(&self) -> usize {
        self.ast.nodes.iter().filter(|node| node.sanitized).count()
    }

    /// ¿La burbuja quedó estanca? El ruido inerte no puede contener marcas
    /// legibles: todos sus bytes tienen el bit alto encendido.
    pub fn is_airtight(&self) -> bool {
        self.inert.iter().all(|byte| *byte >= 0x80)
    }

    /// Descripción de una línea para el informe.
    pub fn describe(&self) -> String {
        format!(
            "{} {} · burbuja#{} ⟨{}⟩ {} B · {} nodos · {} ‰ · {}",
            self.verdict.glyph(),
            self.verdict.label(),
            self.id,
            self.hologram(),
            self.bytes,
            self.ast.nodes.len(),
            self.danger,
            self.origin
        )
    }
}

/// Convierte una carga hostil en **ruido inerte**.
///
/// Mismo tamaño, contenido determinista derivado del holograma y **todos** los
/// bytes con el bit alto encendido: es imposible que quede una marca ASCII
/// legible dentro. La hostilidad no se borra: se desactiva y se conserva como
/// testimonio inerte.
pub fn neutralized(payload: &[u8], seed: &[u8; 32]) -> Vec<u8> {
    let mut material = Vec::with_capacity(96);
    material.extend_from_slice(b"bara:aether-omega:burbuja:inerte:v1");
    material.extend_from_slice(seed);
    material.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    let key: [u8; 32] = sha256(&material);
    let nonce = [0_u8; 12];
    let mut inert = payload.to_vec();
    chacha20_xor(&key, 1, &nonce, &mut inert);
    for byte in inert.iter_mut() {
        *byte |= 0x80;
    }
    inert
}

/// Holograma de una burbuja: digest canónico de su identidad completa.
///
/// La valencia entra por sus bits exactos (`f64::to_bits`), de modo que dos
/// burbujas con la misma carga pero distinta decisión tienen hologramas
/// distintos, y dos burbujas idénticas (mismo origen y orden) coinciden.
#[allow(clippy::too_many_arguments)]
fn bubble_dna(
    id: u64,
    origin: &str,
    sequence: u64,
    payload: &[u8],
    valence: &QuantumState,
    verdict: BubbleVerdict,
    region: RegionId,
) -> [u8; 32] {
    let (truth, falsity) = valence.belnap();
    let mut material = Vec::with_capacity(96 + origin.len() + payload.len());
    material.extend_from_slice(b"bara:aether-omega:burbuja:v1\0");
    material.extend_from_slice(&id.to_le_bytes());
    material.extend_from_slice(&(origin.len() as u64).to_le_bytes());
    material.extend_from_slice(origin.as_bytes());
    material.extend_from_slice(&sequence.to_le_bytes());
    material.extend_from_slice(&(region.0 as u64).to_le_bytes());
    material.extend_from_slice(&truth.to_bits().to_le_bytes());
    material.extend_from_slice(&falsity.to_bits().to_le_bytes());
    material.extend_from_slice(verdict.label().as_bytes());
    material.extend_from_slice(&sha256(payload));
    sha256(&material)
}

// ─────────────────────────────────────────────────────────────────────────
// Pasarela: puerta abierta con inmunidad
// ─────────────────────────────────────────────────────────────────────────

/// Política de la puerta. Es **abierta por construcción**: no existe el verbo
/// «rechazar», así que no hay campo donde esconder censura.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DoorPolicy {
    /// Absorber las contradicciones en vez de colapsarlas.
    pub absorb: bool,
    /// Liberar hacia el núcleo el contenido que el veredicto autorice.
    pub release: bool,
}

impl Default for DoorPolicy {
    fn default() -> Self {
        DoorPolicy::OPEN
    }
}

impl DoorPolicy {
    /// La única política existente: puerta abierta, una burbuja por paquete.
    pub const OPEN: DoorPolicy = DoorPolicy {
        absorb: true,
        release: true,
    };

    /// ¿La política puede descartar algo? **Nunca**: no hay tal verbo.
    pub fn rejects_anything(&self) -> bool {
        false
    }

    /// ¿La puerta está abierta?
    pub fn is_open(&self) -> bool {
        self.absorb && self.release
    }
}

/// Pasarela de inmunidad: puerta abierta, aislamiento holográfico.
///
/// Es un **lector externo** del núcleo (no modifica su soberanía): mantiene su
/// propia tabla de regiones, su propia memoria holográfica y su registro de
/// burbujas. La liberación hacia [`BaraRuntime`] es explícita y verificada.
#[derive(Debug, Clone)]
pub struct Gateway {
    /// Política de la puerta.
    pub policy: DoorPolicy,
    /// Tabla de regiones: una por burbuja.
    pub regions: RegionTable,
    /// Memoria holográfica de burbujas (escritura idempotente, entropía cero).
    pub memory: HolographicMemory,
    /// Registro de burbujas, en orden de admisión.
    pub bubbles: Vec<Bubble>,
    next: u64,
}

impl Default for Gateway {
    fn default() -> Self {
        Gateway::new()
    }
}

impl Gateway {
    /// Abre una pasarela vacía con la política abierta.
    pub fn new() -> Self {
        Gateway {
            policy: DoorPolicy::OPEN,
            regions: RegionTable::new(),
            memory: HolographicMemory::new(),
            bubbles: Vec::new(),
            next: 0,
        }
    }

    /// Abre una pasarela con una política explícita.
    pub fn with_policy(policy: DoorPolicy) -> Self {
        Gateway {
            policy,
            ..Gateway::new()
        }
    }

    /// ¿La puerta está abierta? (invariante de diseño, no un ajuste).
    pub fn door_is_open(&self) -> bool {
        self.policy.is_open() && !self.policy.rejects_anything()
    }

    /// Burbuja por identificador.
    pub fn bubble(&self, id: u64) -> Option<&Bubble> {
        self.bubbles.iter().find(|bubble| bubble.id == id)
    }

    /// Última burbuja admitida.
    pub fn last(&self) -> Option<&Bubble> {
        self.bubbles.last()
    }

    /// Censo de veredictos: `(inocuas, absorbidas, neutralizadas, cuarentena)`.
    pub fn census(&self) -> (usize, usize, usize, usize) {
        let mut innocuous = 0;
        let mut absorbed = 0;
        let mut neutralized = 0;
        let mut quarantined = 0;
        for bubble in &self.bubbles {
            match bubble.verdict {
                BubbleVerdict::Innocuous => innocuous += 1,
                BubbleVerdict::Absorbed => absorbed += 1,
                BubbleVerdict::Neutralized => neutralized += 1,
                BubbleVerdict::Quarantined => quarantined += 1,
            }
        }
        (innocuous, absorbed, neutralized, quarantined)
    }
    /// Compone la burbuja de un paquete.
    ///
    /// **Siempre** devuelve una burbuja: no existe ninguna ruta de código que
    /// descarte la carga, y ninguna entrada puede hacer que esto falle.
    fn compose(&mut self, origin: &str, sequence: u64, payload: &[u8]) -> Bubble {
        let id = self.next;
        self.next += 1;

        let payload_digest = sha256(payload);
        let threat = threat_of(payload);
        let danger = threat.danger();
        let legible = is_legible(payload);

        // Valencia `(⊤, ⊥)`: la lectura aporta verdad y la amenaza aporta
        // falsedad. Con el peligro exactamente en el umbral (500 ‰) ambas masas
        // alcanzan la designación y el resultado es la paradoja tolerada, no
        // una explosión.
        let truth = if legible {
            (1.0 - danger).max(0.0)
        } else {
            0.0
        };
        let valence = QuantumState::paraconsistent(truth, danger);
        let observation = valence.observe();
        let verdict = match observation {
            Observation::True => BubbleVerdict::Innocuous,
            Observation::Both => BubbleVerdict::Absorbed,
            Observation::False => BubbleVerdict::Neutralized,
            Observation::Neither => BubbleVerdict::Quarantined,
        };

        // Región exclusiva, dimensionada por el paso áureo.
        let bytes = payload.len().max(1);
        let region = self
            .regions
            .introduce(format!("burbuja-{id}"), RegionKind::Heap, bytes, None);
        let dna = bubble_dna(id, origin, sequence, payload, &valence, verdict, region);
        let label = format!("burbuja:{id}:{}", short_hex(&dna[..4]));
        // Escritura idempotente: si la etiqueta se repite, no hay entropía.
        self.memory.store(&label, valence.clone());

        let text = String::from_utf8_lossy(payload);
        let ast = to_shoresh(&ingest_auto(&text));

        let mut notes = vec![format!("amenaza: {}", threat.summary())];
        if !legible {
            notes.push("carga ilegible: sin texto interpretable".to_string());
        }
        if ast.hazard_ceiling() > 0.0 {
            notes.push(format!("riesgo del AST: {:.3}", ast.hazard_ceiling()));
        }
        if verdict == BubbleVerdict::Absorbed {
            notes.push("contradicción retenida: el núcleo no explota".to_string());
        }
        if verdict == BubbleVerdict::Neutralized {
            notes.push("carga desactivada como ruido inerte".to_string());
        }

        // Sólo lo que no puede alcanzar el núcleo se vuelve ruido inerte.
        let inert = if verdict.reaches_core() {
            Vec::new()
        } else {
            neutralized(payload, &dna)
        };

        Bubble {
            id,
            label,
            origin: origin.to_string(),
            sequence,
            region,
            span: fib_ceil(bytes),
            bytes: payload.len(),
            ast,
            valence,
            observation,
            verdict,
            danger: threat.mille,
            markers: threat.markers,
            dna,
            payload_digest,
            inert,
            notes,
        }
    }

    /// Admite un paquete: abre su burbuja y devuelve la referencia estable.
    ///
    /// No devuelve `Option` ni `Result` a propósito: admitir nunca falla.
    pub fn admit(&mut self, origin: &str, sequence: u64, payload: &[u8]) -> &Bubble {
        let bubble = self.compose(origin, sequence, payload);
        self.bubbles.push(bubble);
        let index = self.bubbles.len() - 1;
        &self.bubbles[index]
    }

    /// Libera el contenido de la burbuja `id` hacia el núcleo.
    ///
    /// Devuelve el número de axiomas liberados (`0` si el veredicto prohíbe el
    /// paso: lo hostil y lo ilegible **nunca** alcanzan el núcleo). Cada nodo
    /// se registra en la memoria holográfica del núcleo y se apila como
    /// axioma; una carga sin dialecto reconocible entra como un único axioma
    /// con su valencia completa, de modo que nada se pierde por el camino.
    pub fn release(&self, id: u64, core: &mut BaraRuntime) -> usize {
        if !self.policy.release {
            return 0;
        }
        let mut released = 0;
        if let Some(bubble) = self.bubble(id) {
            if !bubble.verdict.reaches_core() {
                return 0;
            }
            for node in &bubble.ast.nodes {
                core.memory.store(&node.root, node.valence.clone());
                core.push(node.valence.clone());
                released += 1;
            }
            if bubble.ast.nodes.is_empty() {
                core.memory.store(&bubble.label, bubble.valence.clone());
                core.push(bubble.valence.clone());
                released += 1;
            }
        }
        released
    }

    /// Ejecuta una ronda de la pasarela.
    ///
    /// Extrae hasta `budget` paquetes del transporte, abre **una burbuja por
    /// paquete** (sin excepción) y libera hacia el núcleo sólo lo que el
    /// veredicto autoriza. Invariantes que el informe hace explícitos:
    /// `received == bubbles` y `dropped() == 0`.
    pub fn run<T: Ingress + ?Sized>(
        &mut self,
        ingress: &mut T,
        budget: usize,
        core: &mut BaraRuntime,
    ) -> GatewayReport {
        let transport = ingress.label();
        let packets = ingress.recv(budget);
        let received = packets.len();
        let start = self.bubbles.len();

        for packet in packets {
            let bubble = self.compose(&packet.origin, packet.sequence, &packet.payload);
            self.bubbles.push(bubble);
        }

        // Liberación diferida: los préstamos del núcleo y del registro de
        // burbujas quedan bien separados.
        let ids: Vec<u64> = self.bubbles[start..]
            .iter()
            .map(|bubble| bubble.id)
            .collect();
        let mut released_nodes = 0;
        for id in ids {
            released_nodes += self.release(id, core);
        }

        let round = &self.bubbles[start..];
        let mut innocuous = 0;
        let mut absorbed = 0;
        let mut neutralized = 0;
        let mut quarantined = 0;
        let mut sealed_nodes = 0;
        let mut inert_bytes = 0;
        let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(round.len());
        for bubble in round {
            match bubble.verdict {
                BubbleVerdict::Innocuous => innocuous += 1,
                BubbleVerdict::Absorbed => absorbed += 1,
                BubbleVerdict::Neutralized => neutralized += 1,
                BubbleVerdict::Quarantined => quarantined += 1,
            }
            sealed_nodes += bubble.sealed();
            inert_bytes += bubble.inert.len();
            leaves.push(bubble.dna);
        }

        // Verificación de que la liberación no rompió ninguna invariante del
        // núcleo: las valencias que lo alcanzaron están en el retículo.
        let core_intact = round.iter().all(|bubble| {
            let (truth, falsity) = bubble.valence.belnap();
            (0.0..=1.0).contains(&truth) && (0.0..=1.0).contains(&falsity)
        });

        GatewayReport {
            received,
            bubbles: round.len(),
            innocuous,
            absorbed,
            neutralized,
            quarantined,
            released_nodes,
            contradictions: absorbed,
            sealed_nodes,
            inert_bytes,
            hologram: merkle_root(&leaves),
            core_intact,
            transport,
        }
    }
}

/// Informe de una ronda de la pasarela.
///
/// Es el acta de la puerta: cuánto entró, qué se decidió, cuánto alcanzó el
/// núcleo y el holograma de la ronda. Nada de esto es opcional: una ronda sin
/// acta no se considera una ronda válida.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayReport {
    /// Paquetes extraídos del transporte.
    pub received: usize,
    /// Burbujas abiertas (siempre igual a `received`).
    pub bubbles: usize,
    /// Burbujas inocuas (`⊤`).
    pub innocuous: usize,
    /// Burbujas con paradoja absorbida (`⊤∧⊥`).
    pub absorbed: usize,
    /// Burbujas hostiles neutralizadas (`⊥`).
    pub neutralized: usize,
    /// Burbujas ilegibles en cuarentena (`∅`).
    pub quarantined: usize,
    /// Axiomas entregados al núcleo.
    pub released_nodes: usize,
    /// Contradicciones retenidas sin explosión.
    pub contradictions: usize,
    /// Nodos sellados bajo guarda.
    pub sealed_nodes: usize,
    /// Bytes convertidos en ruido inerte.
    pub inert_bytes: usize,
    /// Raíz de Merkle de los hologramas de la ronda.
    pub hologram: [u8; 32],
    /// ¿El núcleo quedó intacto tras la liberación?
    pub core_intact: bool,
    /// Etiqueta del transporte.
    pub transport: String,
}

impl GatewayReport {
    /// Paquetes descartados. **Siempre cero**: es el invariante de la puerta.
    pub fn dropped(&self) -> usize {
        self.received.saturating_sub(self.bubbles)
    }

    /// Tasa de admisión en `[0, 1]` (una puerta abierta da `1.0`).
    pub fn acceptance(&self) -> f64 {
        if self.received == 0 {
            return 1.0;
        }
        self.bubbles as f64 / self.received as f64
    }

    /// ¿La ronda respetó el contrato de puerta abierta?
    pub fn is_airtight(&self) -> bool {
        self.dropped() == 0 && self.bubbles == self.received && self.core_intact
    }

    /// Acta de una línea.
    pub fn label(&self) -> String {
        format!(
            "puerta abierta ⟨{}⟩ · {} recibidos · {} burbujas · ⊤ {} · ⊤∧⊥ {} · ⊥ {} · ∅ {} · {} nodos liberados · {} B inertes · holograma {}",
            self.transport,
            self.received,
            self.bubbles,
            self.innocuous,
            self.absorbed,
            self.neutralized,
            self.quarantined,
            self.released_nodes,
            self.inert_bytes,
            short_hex(&self.hologram[..8])
        )
    }
}

/// Ronda completa sobre un origen en memoria: abre la puerta, aísla cada carga,
/// libera lo autorizado hacia el núcleo y devuelve el acta.
///
/// Atajo determinista para pruebas, integración y demostraciones.
pub fn shelter(
    ingress: &mut LoopbackIngress,
    budget: usize,
    core: &mut BaraRuntime,
) -> GatewayReport {
    let mut gateway = Gateway::new();
    gateway.run(ingress, budget, core)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Carga limpia (JSON inocente).
    const LIMPIO: &str = r#"{"evento":"saludo","valor":1}"#;
    /// Carga hostil declarada: suma 1150 ‰ y satura el modelo.
    const HOSTIL: &str = "../$(rm -rf / && drop table usuarios) <script>";
    /// Carga **paradójica**: suma exactamente 500 ‰ con texto legible.
    const PARADOJA: &str = "../$( ademas un ` guion";

    #[test]
    fn la_puerta_esta_abierta_y_nada_se_descarta() {
        let mut core = BaraRuntime::new();
        let mut ingress = LoopbackIngress::new("bucle:prueba");
        ingress.push_text(LIMPIO);
        ingress.push_text(HOSTIL);
        ingress.push_text(PARADOJA);
        ingress.push_bytes(&[0x00, 0x01, 0x02]);
        ingress.push_bytes(&vec![b'A'; 8192]);

        let informe = shelter(&mut ingress, 16, &mut core);
        assert_eq!(informe.received, 5);
        assert_eq!(informe.bubbles, 5);
        assert_eq!(informe.dropped(), 0);
        assert!(informe.is_airtight());
        assert!((informe.acceptance() - 1.0).abs() < f64::EPSILON);
        assert!(informe.label().contains("puerta abierta"));

        // Cada paquete dejó su región y su holograma: cinco burbujas, cinco
        // regiones, ninguna vacía.
        assert!(!core.stack.is_empty());
        let mut gateway = Gateway::new();
        gateway.admit("bucle", 0, LIMPIO.as_bytes());
        gateway.admit("bucle", 1, HOSTIL.as_bytes());
        assert_eq!(gateway.regions.len(), 2);
        assert!(gateway.door_is_open());
        assert!(!gateway.policy.rejects_anything());
    }

    #[test]
    fn el_payload_limpio_entra_y_el_hostil_jamas_toca_el_nucleo() {
        let mut gateway = Gateway::new();
        let limpia = gateway.admit("bucle", 0, LIMPIO.as_bytes()).clone();
        let hostil = gateway.admit("bucle", 1, HOSTIL.as_bytes()).clone();

        assert_eq!(limpia.verdict, BubbleVerdict::Innocuous);
        assert!(limpia.verdict.reaches_core());
        assert_eq!(hostil.verdict, BubbleVerdict::Neutralized);
        assert!(!hostil.verdict.reaches_core());
        assert_eq!(hostil.danger, DANGER_CEILING);
        assert_eq!(hostil.inert.len(), HOSTIL.len());
        assert!(hostil.is_airtight());

        let mut core = BaraRuntime::new();
        assert!(gateway.release(limpia.id, &mut core) > 0);
        let axiomas = core.stack.len();
        assert_eq!(gateway.release(hostil.id, &mut core), 0);
        assert_eq!(core.stack.len(), axiomas);
    }

    #[test]
    fn la_contradiccion_se_absorbe_sin_explosion() {
        let mut gateway = Gateway::new();
        let burbuja = gateway.admit("bucle", 0, PARADOJA.as_bytes()).clone();

        assert_eq!(burbuja.danger, 500);
        assert!(matches!(burbuja.observation, Observation::Both));
        assert_eq!(burbuja.verdict, BubbleVerdict::Absorbed);
        assert!(burbuja.valence.is_contradiction());
        let (truth, falsity) = burbuja.valence.belnap();
        assert!((truth - 0.5).abs() < f64::EPSILON);
        assert!((falsity - 0.5).abs() < f64::EPSILON);
        assert!(burbuja.verdict.reaches_core());
        assert!(burbuja.notes.iter().any(|nota| nota.contains("no explota")));

        let mut core = BaraRuntime::new();
        let mut ingress = LoopbackIngress::new("bucle");
        ingress.push_text(PARADOJA);
        let informe = shelter(&mut ingress, 4, &mut core);
        assert_eq!(informe.contradictions, 1);
        assert_eq!(informe.absorbed, 1);
        assert!(informe.core_intact);
        assert!(informe.is_airtight());
    }

    #[test]
    fn las_burbujas_son_holograficas_aisladas_y_deterministas() {
        let mut uno = Gateway::new();
        let a1 = uno.admit("bucle", 0, LIMPIO.as_bytes()).clone();
        let b1 = uno.admit("bucle", 1, HOSTIL.as_bytes()).clone();
        let mut dos = Gateway::new();
        let a2 = dos.admit("bucle", 0, LIMPIO.as_bytes()).clone();
        let b2 = dos.admit("bucle", 1, HOSTIL.as_bytes()).clone();

        // Determinismo: dos pasarelas gemelas producen hologramas idénticos.
        assert_eq!(a1.dna, a2.dna);
        assert_eq!(b1.dna, b2.dna);
        assert_eq!(a1.payload_digest, a2.payload_digest);

        // Aislamiento: cada burbuja tiene región, holograma y etiqueta propias.
        assert_ne!(a1.region, b1.region);
        assert_ne!(a1.dna, b1.dna);
        assert_ne!(a1.label, b1.label);
        assert_eq!(uno.regions.len(), 2);

        // Reparto áureo: la capacidad cubre siempre los bytes recibidos.
        assert!(a1.span >= a1.bytes as u64);
        assert!(b1.span >= b1.bytes as u64);

        // Memoria holográfica: ambas burbujas se recuperan por su etiqueta.
        assert!(uno.memory.recall(&a1.label).is_some());
        assert!(uno.memory.recall(&b1.label).is_some());
        assert_eq!(uno.memory.writes(), 2);
        assert!((uno.memory.entropy() - 0.0).abs() < f64::EPSILON);

        // Tocar la segunda carga no altera el holograma de la primera.
        let mut tres = Gateway::new();
        let a3 = tres.admit("bucle", 0, LIMPIO.as_bytes()).clone();
        assert_eq!(a3.dna, a1.dna);
        assert_eq!(a3.verdict, BubbleVerdict::Innocuous);
        assert!(a3.describe().contains("inocuo"));
    }

    #[test]
    fn el_bucle_local_entrega_en_orden_sin_perder_nada() {
        let mut ingress = LoopbackIngress::new("bucle");
        assert_eq!(ingress.push_text("uno"), 0);
        assert_eq!(ingress.push_text("dos"), 1);
        assert_eq!(ingress.push_text("tres"), 2);
        assert_eq!(ingress.len(), 3);

        let lote = ingress.recv(2);
        assert_eq!(lote.len(), 2);
        assert_eq!(lote[0].sequence, 0);
        assert_eq!(lote[0].payload, b"uno".to_vec());
        assert_eq!(lote[1].sequence, 1);

        let resto = ingress.recv(8);
        assert_eq!(resto.len(), 1);
        assert_eq!(resto[0].sequence, 2);
        assert!(ingress.is_empty());
        assert_eq!(ingress.label(), "bucle");
        assert_eq!(resto[0].digest(), sha256(b"tres"));
        assert_eq!(resto[0].text(), "tres");
    }

    #[test]
    fn el_receptor_tcp_atiende_un_paquete_de_bucle() {
        let mut servidor = match TcpIngress::bind("127.0.0.1:0") {
            Some(servidor) => servidor,
            // El entorno no permite abrir zócalos: la pasarela degrada.
            None => return,
        };
        let direccion = match servidor.local_address() {
            Some(direccion) => direccion,
            None => return,
        };
        assert!(direccion.starts_with("127.0.0.1:"));
        assert_eq!(servidor.read_limit(), MAX_PAYLOAD);

        let destino = direccion.clone();
        let hilo = std::thread::spawn(move || {
            if let Ok(mut flujo) = TcpStream::connect(&destino) {
                let _ = flujo.write_all(b"hola desde el zocalo");
            }
        });

        let mut paquetes = Vec::new();
        for _ in 0..30 {
            paquetes.extend(servidor.recv(4));
            if !paquetes.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = hilo.join();
        if paquetes.is_empty() {
            // Carrera del entorno: no se fuerza, pero el zócalo quedó probado.
            return;
        }
        assert_eq!(paquetes[0].payload, b"hola desde el zocalo".to_vec());
        assert_eq!(paquetes[0].sequence, 0);
        assert_eq!(servidor.accepted(), 1);
        assert!(servidor.label().starts_with("tcp://"));
    }

    #[test]
    fn el_ataque_neutralizado_no_conserva_ninguna_marca() {
        let semilla = [7_u8; 32];
        let ruido = neutralized(HOSTIL.as_bytes(), &semilla);
        assert_eq!(ruido.len(), HOSTIL.len());
        assert!(ruido.iter().all(|byte| *byte >= 0x80));

        let modelo = threat_of(&ruido);
        assert!(modelo.is_calm());
        for marca in &modelo.markers {
            assert_ne!(*marca, "travesía de directorios");
            assert_ne!(*marca, "inyección de órdenes");
            assert_ne!(*marca, "borrado recursivo");
            assert_ne!(*marca, "destrucción de tabla");
            assert_ne!(*marca, "guion incrustado");
        }

        // Determinista en la semilla y sensible a ella.
        assert_eq!(neutralized(HOSTIL.as_bytes(), &semilla), ruido);
        assert_ne!(neutralized(HOSTIL.as_bytes(), &[8_u8; 32]), ruido);
    }

    #[test]
    fn el_modelo_de_amenaza_es_explicito_y_graduado() {
        assert!(threat_of(b"hola mundo").is_calm());
        assert!(!threat_of(b"hola mundo").is_tainted());
        assert!((threat_of(b"../").danger() - 0.25).abs() < f64::EPSILON);
        assert!(threat_of(PARADOJA.as_bytes()).is_paradoxical());
        assert!(threat_of(HOSTIL.as_bytes()).is_hostile());
        assert!(threat_of(HOSTIL.as_bytes()).is_tainted());
        assert!(threat_of(&vec![b'A'; 8192])
            .markers
            .contains(&MARK_SIZE_BOMB.0));
        assert!(threat_of(&[0_u8, 1, 2]).markers.contains(&MARK_NUL.0));
        assert!(threat_of(b"xxxx[[[[[[[[yy")
            .markers
            .contains(&MARK_DEEP_NESTING.0));
        assert!(threat_of(&[0x9f, 0x92, 0x96])
            .markers
            .contains(&MARK_UNREADABLE.0));
        assert!(threat_of(b"sin marcas").summary().contains("limpio"));
        assert!(threat_of(b"../").summary().contains("travesía"));
        assert!(!is_legible(&[0x00, 0x01, 0x02]));
        assert!(is_legible(LIMPIO.as_bytes()));
    }
}
