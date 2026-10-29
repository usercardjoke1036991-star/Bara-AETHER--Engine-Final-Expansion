//! # Autopoiesis soberana — núcleo inmutable (BAR‑Core) y *sandbox* Synapse
//!
//! Este módulo implementa la única vía por la que el kernel Bara se reescribe a
//! sí mismo **sin dejar de ser inmutable**: el núcleo es un artefacto firmado de
//! sólo lectura y toda mutación ocurre en células *sandbox* efímeras que jamás
//! tocan la memoria del núcleo. La fusión es un suceso atómico que, o bien
//! devuelve un núcleo nuevo verificado, o bien no devuelve nada.
//!
//! ```text
//! ┌────────────────────── BAR‑Core (inmutable, soberano) ───────────────────────┐
//! │ KernelCore · ADN firmado HMAC‑SHA‑256 · revision · huella soberana           │
//! │ sin ningún `&mut self`: capacidad única `Capability::ReadOnly` (writes = ✗)  │
//! └──────────────▲───────────────────────────────────────────┬──────────────────┘
//!                │ KernelRead  (solo lectura, copia)         │ fusión atómica
//!                │                                           │ (núcleo NUEVO)
//! ┌──────────────┴───────────────────────────────────────────▼──────────────────┐
//! │ Synapse‑Sandbox · células AST efímeras + IPC firmado por marco               │
//! │   Mutation ▸ SandboxCell (rama propia) ▸ audit_ast (Shoresh) ▸ ADN firmado   │
//! │        ▸ BelnapMatrix ⟦⊤ ⊥ ⊤∧⊥ ∅⟧ ▸ Proposal ▸ commit (CAS + ADN + juicio)   │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## FASE 1 — Núcleo inmutable
//! * [`KernelCore`] no expone **ningún** método `&mut self`: no hay API de
//!   escritura que auditar porque no existe. La soberanía es estructural, no una
//!   promesa.
//! * [`KernelRead`] es la única capacidad que la periferia puede obtener
//!   ([`KernelCore::read`]) y [`Capability::writes`] es `false` por construcción.
//! * El ADN del núcleo nace firmado ([`crate::ast_dna::ast_dna`]) y
//!   [`KernelCore::verify`] lo recompone entero en cada comprobación: la huella
//!   [`KernelCore::digest`] cubre etiqueta, revisión, raíz de Merkle y firma.
//!
//! ## FASE 1.2 — Puerta de enlace y memoria dinámica
//! * Todo lo externo entra como bytes no confiables por [`SynapseGateway`], que
//!   aplica **traducción estricta**: techo de tamaño ([`MAX_FRAME`], el mismo de
//!   [`crate::immunity_gateway`]), forma exacta ([`WIRE_MARKER`]), firma
//!   `HMAC‑SHA‑256` ([`crate::crypto_native::hmac_sha256`]) y monotonía de
//!   secuencia. Un marco manipulado **no se rechaza en silencio**: se cuenta
//!   ([`SynapseGateway::counters`]) y se descarta.
//! * El canal entre núcleo y células es [`SynapseLink`], tipado por
//!   [`FrameKind`] y verificado marco a marco; nada llega al árbol *Shoresh* sin
//!   haber pasado por la puerta.
//!
//! ## FASE 2 — Autoevaluación estática (Shoresh)
//! * [`audit_ast`] comprueba el parche **antes** de compilarlo: plan no vacío,
//!   aridad acotada, raíces triconsonánticas únicas, masas y riesgo en `[0,1]`,
//!   tipo declarado, guarda coherente (`שמר`: riesgo sobre [`SEAL_THRESHOLD`]
//!   obliga a sellar) y determinismo de la raíz de Merkle.
//! * El parche **nace firmado**: [`Proposal::dna`] es el ADN de la rama mutada
//!   con etiqueta propia, y [`SandboxCell`] guarda su sello.
//!
//! ## FASE 3.1 — Células *sandbox*
//! * [`SandboxCell::fork`] copia los nodos del núcleo a memoria dinámica propia:
//!   la rama es del *sandbox* y el núcleo queda intacto por construcción.
//! * [`SandboxCell::attempt`] **atrapa** cualquier error: la célula se aísla, la
//!   rama se conserva congelada para forense y el núcleo ni se entera.
//! * Presupuesto acotado ([`MAX_CELL_OPS`], [`MAX_CELL_NODES`]) y liberación
//!   explícita ([`AutopoieticMutator::release`]).
//!
//! ## FASE 3.2 — Compuerta paraconsistente (Belnap `FOUR`)
//! * [`BelnapValue`] expone la retícula completa: orden de verdad (`∧`, `∨`,
//!   `¬`) y orden de información (consenso `⊓`, unión `⊔`).
//! * [`BelnapMatrix::evaluate`] emite un [`BelnapVerdict`]: la periferia debe ser
//!   **determinadamente verdadera** (`⊤`) y su unión informativa con el testigo
//!   del núcleo también, de modo que una contradicción (`⊤∧⊥`) o una evidencia
//!   insuficiente (`∅`) **detienen la fusión** en lugar de propagarse.
//!
//! ## FASE 3.3 — Fusión atómica y sincronización con el IDE
//! * [`AutopoieticMutator::commit`] exige revisión y huella base (CAS optimista),
//!   auditoría conforme, juicio `⊤`, ADN del parche válido y núcleo verificado.
//!   Sólo entonces **forja** un [`KernelCore`] nuevo; el anterior sigue siendo
//!   válido e intacto ([`AutopoieticMutator::commit`] recibe `&KernelCore`, jamás
//!   `&mut`).
//! * [`MutationDiff`] es la API limpia para el IDE visual (`bara-ide`):
//!   [`MutationDiff::unified`] y [`MutationDiff::json`] describen al vuelo el AST
//!   mutado, y [`AutopoieticMutator::ide_payload`] entrega el JSON del juicio.
//!
//! ## Invariantes del módulo
//! 1. **Cero `unsafe`** — el *crate* entero es Rust seguro (`#![forbid(unsafe_code)]`).
//! 2. **Totalidad (axioma A1)** — ningún camino aborta: no hay `unwrap`, `expect`
//!    ni `panic` en este archivo, ni siquiera en las pruebas (se usa
//!    `assert!(…is_ok())` seguido de `if let`, o `Option` explícito).
//! 3. **Determinismo** — sólo hashes; el único campo no determinista es
//!    [`Evidence::elapsed_micros`], marcado como tal y excluido de toda huella.
//!
//! ## Desambiguación
//! [`crate::runtime::AutopoieticMutator`] es el **sintetizador de axiomas
//! semánticos** del evaluador (inventa una regla para una raíz desconocida).
//! Este módulo implementa el **mutador estructural en sandbox**; se accede como
//! `bara::autopoietic::AutopoieticMutator` para no confundir ambos papeles.

use crate::ast_dna::{self, AstDna};
use crate::crypto_native::{digest_eq, hmac_sha256, sha256};
use crate::ffi_ingest::{BaraType, ShoreshAst, ShoreshNode};
use crate::flight_recorder::{self, EventKind, ViolationCode};
use crate::immunity_gateway;
use crate::runtime::{Observation, QuantumState};
use crate::visual_builder::triconsonantal;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::mpsc;

// ─────────────────────────────────────────────────────────────────────────
// Constantes de la arquitectura
// ─────────────────────────────────────────────────────────────────────────

/// Techo de un marco IPC: idéntico al de la puerta de inmunidad, porque la
/// frontera de confianza es una sola para todo lo que llega de fuera.
pub const MAX_FRAME: usize = immunity_gateway::MAX_PAYLOAD;

/// Aridad máxima admitida en un nodo del parche.
pub const MAX_ARITY: usize = 8;

/// Presupuesto de operaciones de una célula *sandbox*.
pub const MAX_CELL_OPS: usize = 64;

/// Techo de nodos de una célula *sandbox* (memoria dinámica acotada).
pub const MAX_CELL_NODES: usize = 32;

/// Guarda `שמר`: por encima de este riesgo el nodo debe nacer sellado.
pub const SEAL_THRESHOLD: f64 = 0.5;

/// Umbral de designación de Belnap (idéntico a `runtime::DESIGNATION_THRESHOLD`).
pub const DESIGNATION_THRESHOLD: f64 = 0.5;

/// Etiqueta de dominio del cable IPC (una clave/firma por contexto de uso).
pub const IPC_DOMAIN: &[u8] = b"bara:aether-omega:synapse:ipc:v1";

/// Etiqueta de dominio de la huella de un parche propuesto.
pub const PATCH_DOMAIN: &[u8] = b"bara:aether-omega:synapse:parche:v1";

/// Etiqueta de dominio de la huella de una rama de célula.
pub const BRANCH_DOMAIN: &[u8] = b"bara:aether-omega:synapse:rama:v1";

/// Marca de forma del cable IPC: traducción estricta, sin ambigüedad posible.
pub const WIRE_MARKER: &str = "BARA-IPC/1";

// ─────────────────────────────────────────────────────────────────────────
// FASE 1 · Capacidad otorgada a la periferia
// ─────────────────────────────────────────────────────────────────────────

/// Permiso que un componente de la periferia puede obtener sobre el núcleo.
///
/// Existe **un solo** permiso y es de lectura: el núcleo no sabe escribir, así
/// que la soberanía no depende de la buena voluntad de la periferia sino de la
/// forma de los tipos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// Sólo lectura: [`Capability::writes`] es `false` por construcción.
    ReadOnly,
}

impl Capability {
    /// ¿Concede escritura sobre el núcleo? Nunca.
    pub const fn writes(self) -> bool {
        match self {
            Capability::ReadOnly => false,
        }
    }

    /// Nombre canónico del permiso.
    pub const fn label(self) -> &'static str {
        match self {
            Capability::ReadOnly => "solo-lectura",
        }
    }

    /// Glifo del permiso.
    pub const fn glyph(self) -> &'static str {
        match self {
            Capability::ReadOnly => "ר",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// FASE 1 · Errores de la frontera
// ─────────────────────────────────────────────────────────────────────────

/// Fallo en la frontera del núcleo (puerta IPC, ADN o concurrencia optimista).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelError {
    /// El parche no aporta ninguna operación.
    EmptyPatch,
    /// Alguien pidió escribir con una capacidad que no lo permite.
    WriteDenied {
        /// Operación intentada.
        operation: &'static str,
        /// Capacidad realmente otorgada.
        capability: &'static str,
    },
    /// El marco no respeta la forma del cable.
    MalformedFrame {
        /// Parte del marco que no se pudo leer.
        marker: &'static str,
    },
    /// El marco excede el techo de la frontera.
    FrameTooLarge {
        /// Bytes recibidos.
        found: usize,
        /// Techo admitido.
        limit: usize,
    },
    /// La firma no corresponde a la clave soberana: manipulación.
    SignatureMismatch,
    /// La secuencia llegó repetida o hacia atrás (*replay*).
    SequenceRegression {
        /// Secuencia esperada.
        expected: u64,
        /// Secuencia recibida.
        found: u64,
    },
    /// El ADN no verifica contra su clave.
    DnaBroken {
        /// Etiqueta del artefacto.
        label: String,
    },
    /// La revisión observada no es la que se esperaba.
    CoreMismatch {
        /// Revisión esperada.
        expected: u64,
        /// Revisión observada.
        found: u64,
    },
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KernelError::EmptyPatch => {
                write!(f, "el parche está vacío: no hay nada que fusionar")
            }
            KernelError::WriteDenied {
                operation,
                capability,
            } => write!(
                f,
                "escritura denegada en «{}»: la capacidad otorgada es {}",
                operation, capability
            ),
            KernelError::MalformedFrame { marker } => {
                write!(f, "marco IPC ilegible en {}", marker)
            }
            KernelError::FrameTooLarge { found, limit } => {
                write!(f, "marco IPC de {} bytes (tope {})", found, limit)
            }
            KernelError::SignatureMismatch => {
                write!(f, "la firma del marco no corresponde a la clave soberana")
            }
            KernelError::SequenceRegression { expected, found } => write!(
                f,
                "secuencia IPC regresiva: se esperaba {} y llegó {}",
                expected, found
            ),
            KernelError::DnaBroken { label } => {
                write!(f, "el ADN de «{}» no verifica contra su clave", label)
            }
            KernelError::CoreMismatch { expected, found } => write!(
                f,
                "núcleo inesperado: se esperaba la revisión {} y hay {}",
                expected, found
            ),
        }
    }
}

impl std::error::Error for KernelError {}
// ─────────────────────────────────────────────────────────────────────────
// FASE 1 · Núcleo inmutable (BAR‑Core)
// ─────────────────────────────────────────────────────────────────────────

/// Núcleo soberano: AST *Shoresh* + ADN firmado + revisión monotónica.
///
/// No expone **ningún** método que reciba `&mut self`. La única puerta de
/// construcción es `KernelCore::forge`, privada, y sólo la fusión atómica la
/// usa tras verificar el parche; el resultado es siempre un núcleo **nuevo**,
/// nunca una modificación *in situ*. Por eso «el núcleo no se puede escribir» es
/// una propiedad verificable por el compilador y no un acuerdo de caballeros.
#[derive(Debug, Clone)]
pub struct KernelCore {
    label: String,
    ast: ShoreshAst,
    dna: AstDna,
    key: [u8; 32],
    revision: u64,
}

impl KernelCore {
    /// Núcleo génesis (revisión 0) a partir de un AST y una semilla soberana.
    ///
    /// La clave se deriva con [`crate::ast_dna::golden_key`] (misma derivación
    /// que usa el resto del kernel): la semilla es el secreto y la clave nunca
    /// se serializa.
    pub fn genesis(label: &str, ast: ShoreshAst, seed: &[u8]) -> Self {
        let key = ast_dna::golden_key(seed);
        Self::forge(label, ast, 0, key)
    }

    /// Constructor privado del núcleo: única puerta de escritura del sistema.
    fn forge(label: &str, ast: ShoreshAst, revision: u64, key: [u8; 32]) -> Self {
        let dna = ast_dna::ast_dna(label, &ast, &key);
        Self {
            label: label.to_string(),
            ast,
            dna,
            key,
            revision,
        }
    }

    /// Etiqueta del módulo.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// AST *Shoresh* del núcleo (sólo lectura).
    pub fn ast(&self) -> &ShoreshAst {
        &self.ast
    }

    /// Nodos del núcleo (sólo lectura).
    pub fn nodes(&self) -> &[ShoreshNode] {
        &self.ast.nodes
    }

    /// ADN firmado del núcleo.
    pub fn dna(&self) -> &AstDna {
        &self.dna
    }

    /// Revisión monotónica (cada fusión forja la siguiente).
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Identificador público de la clave soberana que firmó el núcleo.
    pub fn key_id(&self) -> u64 {
        self.dna.key_id
    }

    /// Número de nodos (raíces) del núcleo.
    pub fn roots(&self) -> usize {
        self.ast.nodes.len()
    }

    /// Techo de riesgo del núcleo.
    pub fn hazard_ceiling(&self) -> f64 {
        self.ast.hazard_ceiling()
    }

    /// Huella soberana: cubre etiqueta, revisión, raíz de Merkle y firma.
    ///
    /// Es la referencia del CAS optimista de [`AutopoieticMutator::commit`]: si
    /// el núcleo cambió por debajo, la huella deja de coincidir y la fusión se
    /// detiene.
    pub fn digest(&self) -> [u8; 32] {
        let mut statement = Vec::with_capacity(96);
        statement.extend_from_slice(b"nucleo:");
        statement.extend_from_slice(&(self.label.len() as u32).to_le_bytes());
        statement.extend_from_slice(self.label.as_bytes());
        statement.extend_from_slice(&self.revision.to_le_bytes());
        statement.extend_from_slice(&self.dna.root);
        statement.extend_from_slice(&self.dna.signature);
        sha256(&statement)
    }

    /// ¿El ADN del núcleo verifica contra su propia clave?
    ///
    /// Recompone el ADN desde cero y lo contrasta: detecta reordenaciones,
    /// nodos añadidos o alterados y claves ajenas.
    pub fn verify(&self) -> bool {
        ast_dna::verify(&self.label, &self.ast, &self.dna, &self.key)
    }

    /// Capacidad de sólo lectura: la única que la periferia puede obtener.
    pub fn read(&self) -> KernelRead<'_> {
        KernelRead { core: self }
    }
}

/// Vista de sólo lectura del núcleo, prestada a la periferia.
///
/// Es una *capacidad* en el sentido estricto del término: quien la tiene no
/// puede obtener un `&mut KernelCore` a partir de ella (no hay método que lo
/// devuelva), y [`KernelRead::capability`] certifica que la escritura está
/// denegada.
#[derive(Debug, Clone, Copy)]
pub struct KernelRead<'k> {
    core: &'k KernelCore,
}

impl<'k> KernelRead<'k> {
    /// Permiso efectivo: siempre [`Capability::ReadOnly`].
    pub const fn capability(&self) -> Capability {
        Capability::ReadOnly
    }

    /// Etiqueta del núcleo prestado.
    pub fn label(&self) -> &'k str {
        self.core.label()
    }

    /// AST prestado.
    pub fn ast(&self) -> &'k ShoreshAst {
        self.core.ast()
    }

    /// Nodos prestados.
    pub fn nodes(&self) -> &'k [ShoreshNode] {
        self.core.nodes()
    }

    /// ADN prestado.
    pub fn dna(&self) -> &'k AstDna {
        self.core.dna()
    }

    /// Revisión observada.
    pub fn revision(&self) -> u64 {
        self.core.revision()
    }

    /// Huella observada (referencia del CAS).
    pub fn digest(&self) -> [u8; 32] {
        self.core.digest()
    }

    /// ¿El núcleo prestado verifica su ADN?
    pub fn verified(&self) -> bool {
        self.core.verify()
    }

    /// Nodo por índice, de forma total.
    pub fn node(&self, index: usize) -> Option<&'k ShoreshNode> {
        self.core.nodes().get(index)
    }

    /// Número de nodos prestados.
    pub fn len(&self) -> usize {
        self.core.nodes().len()
    }

    /// ¿El núcleo prestado está vacío?
    pub fn is_empty(&self) -> bool {
        self.core.nodes().is_empty()
    }
}
// ─────────────────────────────────────────────────────────────────────────
// FASE 1.2 · Canal IPC firmado (Synapse)
// ─────────────────────────────────────────────────────────────────────────

/// Tipo fuerte de un marco del canal Synapse.
///
/// El tipo es un dato del protocolo, no un adorno: sólo viaja su código estable
/// y la traducción inversa es total (un código desconocido **no** es un tipo
/// válido, de modo que un mensaje ambiguo no puede colarse como otro).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// Petición de mutación: el núcleo manda ejecutar en una célula *sandbox*.
    MutationRequest,
    /// Consulta de sólo lectura sobre el núcleo desde una célula.
    KernelQuery,
    /// Informe de una célula (estado, fallos, sello).
    CellReport,
    /// Aviso de fusión consumada (núcleo → periferia).
    FusionNotice,
}

impl FrameKind {
    /// Código estable del tipo (lo único que viaja por el cable).
    pub const fn code(self) -> u8 {
        match self {
            FrameKind::MutationRequest => 1,
            FrameKind::KernelQuery => 2,
            FrameKind::CellReport => 3,
            FrameKind::FusionNotice => 4,
        }
    }

    /// Traducción inversa total.
    pub const fn from_code(code: u8) -> Option<FrameKind> {
        match code {
            1 => Some(FrameKind::MutationRequest),
            2 => Some(FrameKind::KernelQuery),
            3 => Some(FrameKind::CellReport),
            4 => Some(FrameKind::FusionNotice),
            _ => None,
        }
    }

    /// Nombre canónico del tipo.
    pub const fn label(self) -> &'static str {
        match self {
            FrameKind::MutationRequest => "peticion-de-mutacion",
            FrameKind::KernelQuery => "consulta-de-nucleo",
            FrameKind::CellReport => "informe-de-celula",
            FrameKind::FusionNotice => "aviso-de-fusion",
        }
    }
}

/// Marco del canal: secuencia monotónica + tipo fuerte + cuerpo opaco.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Secuencia monotónica del emisor (defensa contra *replay*).
    pub sequence: u64,
    /// Tipo fuerte del mensaje.
    pub kind: FrameKind,
    /// Cuerpo del mensaje: bytes opacos, nunca confiables hasta la traducción.
    pub body: Vec<u8>,
}

impl Frame {
    /// Construye un marco.
    pub fn new(sequence: u64, kind: FrameKind, body: &[u8]) -> Self {
        Self {
            sequence,
            kind,
            body: body.to_vec(),
        }
    }

    /// Enunciado firmado: dominio ‖ secuencia ‖ tipo ‖ longitud ‖ cuerpo.
    ///
    /// La longitud entra **dentro** del enunciado para que la firma cubra la
    /// forma del mensaje y no sólo su contenido.
    fn statement(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(IPC_DOMAIN.len() + 17 + self.body.len());
        out.extend_from_slice(IPC_DOMAIN);
        out.extend_from_slice(&self.sequence.to_le_bytes());
        out.push(self.kind.code());
        out.extend_from_slice(&(self.body.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.body);
        out
    }

    /// Huella del marco completo.
    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.statement())
    }

    /// ¿El cuerpo va vacío?
    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
    }

    /// Representación legible.
    pub fn label(&self) -> String {
        format!(
            "marco #{} {} ({} bytes)",
            self.sequence,
            self.kind.label(),
            self.body.len()
        )
    }
}
/// Codificación hexadecimal minúscula, sin dependencias externas.
fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// Decodificación hexadecimal estricta: longitud par y dígitos válidos.
fn bytes_of_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let nibbles: Option<Vec<u8>> = text
        .bytes()
        .map(|byte| char::from(byte).to_digit(16).map(|digit| digit as u8))
        .collect();
    let nibbles = nibbles?;
    let mut out = Vec::with_capacity(nibbles.len() / 2);
    for pair in nibbles.chunks(2) {
        match pair {
            [high, low] => out.push((high << 4) | low),
            _ => return None,
        }
    }
    Some(out)
}

/// Marco firmado: el cuerpo viaja opaco y la firma lo ata a tipo y orden.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedFrame {
    /// Marco transportado.
    pub frame: Frame,
    /// `HMAC-SHA-256` de la clave soberana sobre el enunciado del marco.
    pub mac: [u8; 32],
}

impl SignedFrame {
    /// Sella un marco con la clave soberana.
    pub fn seal(frame: Frame, key: &[u8; 32]) -> Self {
        let mac = hmac_sha256(key, &frame.statement());
        Self { frame, mac }
    }

    /// ¿La firma corresponde a esta clave?
    pub fn verify(&self, key: &[u8; 32]) -> bool {
        digest_eq(&hmac_sha256(key, &self.frame.statement()), &self.mac)
    }

    /// Serializa al cable: `BARA-IPC/1|secuencia|código|hex(cuerpo)|hex(firma)`.
    pub fn bytes(&self) -> Vec<u8> {
        format!(
            "{}|{}|{}|{}|{}",
            WIRE_MARKER,
            self.frame.sequence,
            self.frame.kind.code(),
            hex_of(&self.frame.body),
            hex_of(&self.mac)
        )
        .into_bytes()
    }

    /// Traduce del cable de forma estricta: cinco campos exactos, ni uno más.
    pub fn parse(raw: &[u8]) -> Option<SignedFrame> {
        let text = std::str::from_utf8(raw).ok()?;
        let mut parts = text.split('|');
        let marker = parts.next()?;
        let sequence = parts.next()?;
        let kind = parts.next()?;
        let body = parts.next()?;
        let mac = parts.next()?;
        if parts.next().is_some() || marker != WIRE_MARKER {
            return None;
        }
        let frame = Frame {
            sequence: sequence.parse::<u64>().ok()?,
            kind: FrameKind::from_code(kind.parse::<u8>().ok()?)?,
            body: bytes_of_hex(body)?,
        };
        let mac_bytes = bytes_of_hex(mac)?;
        let mac: [u8; 32] = <[u8; 32]>::try_from(mac_bytes.as_slice()).ok()?;
        Some(SignedFrame { frame, mac })
    }
}
/// Contadores de la puerta: una puerta que descarta en silencio no es auditable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GatewayCounters {
    /// Marcos traducidos y entregados.
    pub accepted: usize,
    /// Marcos descartados por cualquier motivo.
    pub rejected: usize,
    /// Marcos con firma inválida o secuencia regresiva (hostiles).
    pub tampered: usize,
    /// Marcos que excedieron [`MAX_FRAME`].
    pub oversized: usize,
}

/// Puerta de enlace: traducción estricta de bytes no confiables a marcos
/// verificados.
///
/// Orden de comprobaciones (normativo): **tamaño → forma → firma → secuencia**.
/// El orden importa: se mide antes de interpretar (una bomba de tamaño no debe
/// llegar al analizador de forma), se verifica la forma antes que la firma (no
/// se calcula un `HMAC` sobre lo que ni siquiera es un marco) y la firma antes
/// que la secuencia (un *replay* manipulado se clasifica como manipulación).
#[derive(Debug)]
pub struct SynapseGateway {
    key: [u8; 32],
    expected: u64,
    counters: GatewayCounters,
}

impl SynapseGateway {
    /// Puerta para una clave soberana: espera la secuencia 0.
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            expected: 0,
            counters: GatewayCounters::default(),
        }
    }

    /// Identificador público de la clave de la puerta.
    pub fn key_id(&self) -> u64 {
        ast_dna::key_id(&self.key)
    }

    /// Secuencia que la puerta exigirá a continuación.
    pub fn next_sequence(&self) -> u64 {
        self.expected
    }

    /// Sellado rápido (firma + serialización) para el lado emisor.
    pub fn seal(&self, sequence: u64, kind: FrameKind, body: &[u8]) -> Vec<u8> {
        SignedFrame::seal(Frame::new(sequence, kind, body), &self.key).bytes()
    }

    /// Traduce bytes externos: nada entra al árbol *Shoresh* sin pasar aquí.
    ///
    /// Los cuatro rechazos posibles quedan además en la caja negra con un
    /// [`ViolationCode`] distinto: el incidente es reproducible sin la carga.
    pub fn translate(&mut self, raw: &[u8]) -> Result<Frame, KernelError> {
        if raw.len() > MAX_FRAME {
            self.counters.oversized = self.counters.oversized.saturating_add(1);
            self.counters.rejected = self.counters.rejected.saturating_add(1);
            flight_recorder::record_fingerprint(
                EventKind::VerdictRejected,
                ViolationCode::FrameTooLarge,
                flight_recorder::fingerprint(raw),
            );
            return Err(KernelError::FrameTooLarge {
                found: raw.len(),
                limit: MAX_FRAME,
            });
        }
        let signed = match SignedFrame::parse(raw) {
            Some(signed) => signed,
            None => {
                self.counters.rejected = self.counters.rejected.saturating_add(1);
                flight_recorder::record_fingerprint(
                    EventKind::VerdictRejected,
                    ViolationCode::MalformedFrame,
                    flight_recorder::fingerprint(raw),
                );
                return Err(KernelError::MalformedFrame { marker: "forma" });
            }
        };
        if !signed.verify(&self.key) {
            self.counters.tampered = self.counters.tampered.saturating_add(1);
            self.counters.rejected = self.counters.rejected.saturating_add(1);
            flight_recorder::record_fingerprint(
                EventKind::VerdictRejected,
                ViolationCode::SignatureMismatch,
                flight_recorder::fingerprint(raw),
            );
            return Err(KernelError::SignatureMismatch);
        }
        if signed.frame.sequence < self.expected {
            self.counters.tampered = self.counters.tampered.saturating_add(1);
            self.counters.rejected = self.counters.rejected.saturating_add(1);
            flight_recorder::record_fingerprint(
                EventKind::VerdictRejected,
                ViolationCode::SequenceRegression,
                flight_recorder::fingerprint(raw),
            );
            return Err(KernelError::SequenceRegression {
                expected: self.expected,
                found: signed.frame.sequence,
            });
        }
        self.expected = signed.frame.sequence.saturating_add(1);
        self.counters.accepted = self.counters.accepted.saturating_add(1);
        Ok(signed.frame)
    }

    /// Contadores acumulados de la puerta.
    pub fn counters(&self) -> GatewayCounters {
        self.counters
    }

    /// Etiqueta legible del estado de la puerta.
    pub fn label(&self) -> String {
        format!(
            "puerta Synapse · clave {:016x} · siguiente secuencia {} · aceptados {} · rechazados {} (manipulados {}, excesivos {})",
            self.key_id(),
            self.expected,
            self.counters.accepted,
            self.counters.rejected,
            self.counters.tampered,
            self.counters.oversized
        )
    }
}

/// Canal tipado en proceso entre el núcleo y las células *sandbox*.
///
/// El transporte es un canal `std` de bytes en memoria dinámica y **cada** marco
/// pasa por [`SynapseGateway`]: el tipo lo fija [`FrameKind`] y la firma impide
/// que un proceso vecino inyecte órdenes. El canal no evalúa nada: sólo pone el
/// mensaje verificado a disposición del receptor.
#[derive(Debug)]
pub struct SynapseLink {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
    gateway: SynapseGateway,
    sent: u64,
}

impl SynapseLink {
    /// Abre el canal para una clave soberana.
    pub fn open(key: [u8; 32]) -> Self {
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        Self {
            tx,
            rx,
            gateway: SynapseGateway::new(key),
            sent: 0,
        }
    }

    /// Envía un mensaje tipado: lo firma, le asigna secuencia y lo encola.
    pub fn send(&mut self, kind: FrameKind, body: &[u8]) -> Result<u64, KernelError> {
        let sequence = self.sent;
        let wire = self.gateway.seal(sequence, kind, body);
        self.tx
            .send(wire)
            .map_err(|_| KernelError::MalformedFrame {
                marker: "canal cerrado",
            })?;
        self.sent = self.sent.saturating_add(1);
        Ok(sequence)
    }

    /// Inyecta bytes crudos en el canal (traductor externo y forense).
    ///
    /// Devuelve `false` si el canal ya está cerrado. Lo inyectado **no** es de
    /// confianza: lo verificará la puerta al recibirlo.
    pub fn inject(&self, raw: &[u8]) -> bool {
        self.tx.send(raw.to_vec()).is_ok()
    }

    /// Recibe un marco verificado; `None` si el canal está vacío o cerrado.
    ///
    /// Un marco hostil nunca se devuelve: se cuenta en la puerta y se descarta.
    pub fn receive(&mut self) -> Result<Option<Frame>, KernelError> {
        match self.rx.try_recv() {
            Ok(raw) => self.gateway.translate(&raw).map(Some),
            Err(mpsc::TryRecvError::Empty) | Err(mpsc::TryRecvError::Disconnected) => Ok(None),
        }
    }

    /// Drena el canal: marcos verificados en orden de llegada.
    ///
    /// Cada iteración consume un mensaje, así que el bucle progresa siempre y un
    /// flujo hostil no puede bloquear el drenaje.
    pub fn drain(&mut self) -> Vec<Frame> {
        let mut frames = Vec::new();
        loop {
            match self.receive() {
                Ok(Some(frame)) => frames.push(frame),
                Ok(None) => return frames,
                Err(_) => continue,
            }
        }
    }

    /// Puerta del canal (contadores y clave).
    pub fn gateway(&self) -> &SynapseGateway {
        &self.gateway
    }

    /// Número de marcos emitidos por este extremo.
    pub fn sent(&self) -> u64 {
        self.sent
    }
}
/// Fallo de la autopoiesis: siempre **contenido** dentro de una célula.
///
/// Ningún fallo de este tipo puede alcanzar al núcleo —el núcleo no tiene API de
/// escritura—, pero la célula los clasifica para decidir si se aísla, si se
/// sella o si simplemente rechaza la operación.
#[derive(Debug, Clone, PartialEq)]
pub enum MutatorError {
    /// Fallo de la frontera (puerta IPC, ADN o concurrencia optimista).
    Kernel(KernelError),
    /// No existe la célula indicada.
    CellUnknown {
        /// Identificador pedido.
        id: u64,
    },
    /// La célula fue aislada por un fallo anterior: está en cuarentena.
    CellPoisoned {
        /// Identificador de la célula.
        id: u64,
    },
    /// La célula ya está sellada: su propuesta quedó congelada.
    CellSealed {
        /// Identificador de la célula.
        id: u64,
    },
    /// La célula alcanzó su techo de nodos.
    CellCapacity {
        /// Nodos en uso.
        used: usize,
        /// Techo admitido.
        limit: usize,
    },
    /// El plan de mutación está vacío: no hay nada que proponer.
    CellEmptyPlan,
    /// La célula agotó su presupuesto de operaciones.
    CellOpBudget {
        /// Operaciones ya aplicadas.
        used: usize,
        /// Presupuesto admitido.
        limit: usize,
    },
    /// No existe el nodo indicado.
    NoSuchNode {
        /// Índice pedido.
        index: usize,
        /// Nodos disponibles.
        nodes: usize,
    },
    /// La aridad pedida excede el tope.
    ArityOverflow {
        /// Aridad pedida.
        arity: usize,
        /// Tope admitido.
        limit: usize,
    },
    /// Una masa o un riesgo quedó fuera de `[0, 1]` o no es finito.
    MassOutOfRange {
        /// Campo afectado.
        field: &'static str,
        /// Valor recibido.
        value: f64,
    },
    /// La raíz del nodo nuevo es vacía.
    EmptyRoot,
    /// No existe la propuesta indicada.
    ProposalUnknown {
        /// Identificador pedido.
        id: u64,
    },
    /// El juicio tetravalente no admite la fusión.
    VerdictRejected {
        /// Periferia juzgada.
        periferia: BelnapValue,
        /// Unión informativa con el testigo del núcleo.
        union: BelnapValue,
    },
    /// La auditoría estática *Shoresh* no pasa.
    AuditFailed {
        /// Número de comprobaciones fallidas.
        failed: usize,
    },
    /// El ADN del parche no corresponde a la clave soberana.
    DnaMismatch {
        /// Etiqueta del parche.
        label: String,
    },
    /// El núcleo base ya no es el que se auditó (CAS optimista).
    FusionStale {
        /// Revisión auditada.
        expected: u64,
        /// Revisión observada.
        found: u64,
    },
    /// El núcleo base no verifica su propio ADN.
    CoreBroken,
}

impl fmt::Display for MutatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MutatorError::Kernel(inner) => write!(f, "frontera: {}", inner),
            MutatorError::CellUnknown { id } => write!(f, "célula {} desconocida", id),
            MutatorError::CellPoisoned { id } => {
                write!(f, "célula {} en cuarentena: no admite más operaciones", id)
            }
            MutatorError::CellSealed { id } => {
                write!(f, "célula {} sellada: su propuesta está congelada", id)
            }
            MutatorError::CellCapacity { used, limit } => {
                write!(f, "célula llena: {} nodos (tope {})", used, limit)
            }
            MutatorError::CellEmptyPlan => {
                write!(f, "plan de mutación vacío: no hay nada que proponer")
            }
            MutatorError::CellOpBudget { used, limit } => {
                write!(
                    f,
                    "presupuesto agotado: {} operaciones (tope {})",
                    used, limit
                )
            }
            MutatorError::NoSuchNode { index, nodes } => {
                write!(f, "nodo {} inexistente (hay {})", index, nodes)
            }
            MutatorError::ArityOverflow { arity, limit } => {
                write!(f, "aridad {} por encima del tope {}", arity, limit)
            }
            MutatorError::MassOutOfRange { field, value } => {
                write!(f, "{}({}) fuera de [0,1]", field, value)
            }
            MutatorError::EmptyRoot => {
                write!(f, "raíz vacía: un nodo sin raíz no es Shoresh")
            }
            MutatorError::ProposalUnknown { id } => write!(f, "propuesta {} desconocida", id),
            MutatorError::VerdictRejected { periferia, union } => write!(
                f,
                "juicio {} con unión {}: la fusión no se admite",
                periferia.glyph(),
                union.glyph()
            ),
            MutatorError::AuditFailed { failed } => {
                write!(
                    f,
                    "auditoría estática con {} comprobaciones fallidas",
                    failed
                )
            }
            MutatorError::DnaMismatch { label } => {
                write!(
                    f,
                    "el ADN de «{}» no corresponde a la clave soberana",
                    label
                )
            }
            MutatorError::FusionStale { expected, found } => write!(
                f,
                "fusión caducada: se auditó la revisión {} y el núcleo está en {}",
                expected, found
            ),
            MutatorError::CoreBroken => {
                write!(f, "el núcleo base no verifica su propio ADN")
            }
        }
    }
}

impl std::error::Error for MutatorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MutatorError::Kernel(inner) => Some(inner),
            _ => None,
        }
    }
}

impl From<KernelError> for MutatorError {
    fn from(error: KernelError) -> Self {
        MutatorError::Kernel(error)
    }
}
/// Estado de una célula *sandbox*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellState {
    /// Abierta: admite mutaciones.
    Open,
    /// Sellada: la propuesta está congelada y firmada.
    Sealed,
    /// En cuarentena: un fallo quedó atrapado y la célula fue aislada.
    Quarantined,
}

impl CellState {
    /// Nombre canónico.
    pub const fn label(self) -> &'static str {
        match self {
            CellState::Open => "abierta",
            CellState::Sealed => "sellada",
            CellState::Quarantined => "cuarentena",
        }
    }

    /// Glifo.
    pub const fn glyph(self) -> &'static str {
        match self {
            CellState::Open => "○",
            CellState::Sealed => "◉",
            CellState::Quarantined => "⊘",
        }
    }

    /// ¿Admite operaciones?
    pub const fn is_open(self) -> bool {
        matches!(self, CellState::Open)
    }
}

/// Registro de una operación aplicada dentro de una célula.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationRecord {
    /// Índice de la operación dentro del plan (0 = la primera).
    pub op: usize,
    /// Resumen legible de lo sucedido.
    pub summary: String,
    /// Huella de la rama **después** de la operación.
    pub digest: [u8; 32],
}

/// Fallo atrapado en una célula: se registra en lugar de propagarse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellFault {
    /// Operación que falló.
    pub op: usize,
    /// Descripción del fallo.
    pub error: String,
}

/// Resultado de intentar una operación: aplicada o atrapada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CellOutcome {
    /// Operación aplicada en la rama del *sandbox*.
    Applied(MutationRecord),
    /// Fallo atrapado: la célula se aísla y el núcleo ni se entera.
    Trapped(CellFault),
}

impl CellOutcome {
    /// ¿La operación se aplicó?
    pub fn is_applied(&self) -> bool {
        matches!(self, CellOutcome::Applied(_))
    }

    /// ¿El fallo quedó atrapado?
    pub fn is_trapped(&self) -> bool {
        matches!(self, CellOutcome::Trapped(_))
    }

    /// Registro aplicado, si lo hay.
    pub fn record(&self) -> Option<&MutationRecord> {
        match self {
            CellOutcome::Applied(record) => Some(record),
            CellOutcome::Trapped(_) => None,
        }
    }

    /// Fallo atrapado, si lo hay.
    pub fn fault(&self) -> Option<&CellFault> {
        match self {
            CellOutcome::Applied(_) => None,
            CellOutcome::Trapped(fault) => Some(fault),
        }
    }

    /// Representación legible.
    pub fn label(&self) -> String {
        match self {
            CellOutcome::Applied(record) => {
                format!("op #{} aplicada · {}", record.op, record.summary)
            }
            CellOutcome::Trapped(fault) => {
                format!("op #{} atrapada · {}", fault.op, fault.error)
            }
        }
    }
}

/// Informe del aislamiento de una célula.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationReport {
    /// Célula aislada.
    pub cell: u64,
    /// Operaciones descartadas al aislar.
    pub ops_discarded: usize,
    /// Fallos atrapados acumulados.
    pub faults: usize,
    /// Descripción legible.
    pub label: String,
}

impl IsolationReport {
    /// ¿El aislamiento fue limpio (sin fallos acumulados)?
    pub fn is_clean(&self) -> bool {
        self.faults == 0
    }
}
// ─────────────────────────────────────────────────────────────────────────
// FASE 3.1 · Plan de mutación
// ─────────────────────────────────────────────────────────────────────────

/// Operación estructural sobre un árbol *Shoresh*, ejecutada en una célula.
///
/// El repertorio es deliberadamente pequeño y **finito**: cada operación es una
/// transformación determinista y acotada del AST, de modo que el conjunto de
/// parches posibles es enumerable y auditable (no hay «cualquier cosa»).
#[derive(Debug, Clone, PartialEq)]
pub enum Mutation {
    /// Injerta un nodo nuevo al final de la rama.
    Add {
        /// Raíz triconsonántica del nodo.
        root: String,
        /// Nombre original de la función legada.
        original: String,
        /// Aridad del nodo.
        arity: usize,
        /// Tipo de retorno declarado.
        ret: BaraType,
        /// Riesgo en `[0, 1]`.
        hazard: f64,
        /// Masa de verdad en `[0, 1]`.
        truth: f64,
        /// Masa de falsedad en `[0, 1]`.
        falsity: f64,
    },
    /// Cambia el tipo de retorno de un nodo existente.
    Retarget {
        /// Índice del nodo.
        index: usize,
        /// Tipo nuevo.
        ret: BaraType,
    },
    /// Cambia la aridad (número de parámetros) de un nodo.
    Rewire {
        /// Índice del nodo.
        index: usize,
        /// Aridad nueva.
        arity: usize,
    },
    /// Sella el nodo bajo guarda `שמר` (lo marca como saneado).
    Seal {
        /// Índice del nodo.
        index: usize,
    },
    /// Refuerza el nodo reduciendo su riesgo y elevando su masa de verdad.
    Harden {
        /// Índice del nodo.
        index: usize,
        /// Reducción de riesgo en `[0, 1]`.
        delta: f64,
    },
    /// Niega la valencia paraconsistente del nodo (intercambia masas).
    Negate {
        /// Índice del nodo.
        index: usize,
    },
    /// Retira un nodo de la rama (baja explícita).
    ///
    /// Es la única operación que reduce el árbol: si deja el parche vacío, la
    /// auditoría rechazará la propuesta (`plan.no-vacio`).
    Remove {
        /// Índice del nodo.
        index: usize,
    },
}

impl Mutation {
    /// Aplica la operación sobre un AST y devuelve el resumen de lo sucedido.
    ///
    /// Es **total**: toda entrada inadmisible se convierte en [`MutatorError`]
    /// (que la célula atrapará) en lugar de abortar nada.
    pub fn apply(&self, ast: &mut ShoreshAst) -> Result<String, MutatorError> {
        match self {
            Mutation::Add {
                root,
                original,
                arity,
                ret,
                hazard,
                truth,
                falsity,
            } => {
                if root.is_empty() {
                    return Err(MutatorError::EmptyRoot);
                }
                if *arity > MAX_ARITY {
                    return Err(MutatorError::ArityOverflow {
                        arity: *arity,
                        limit: MAX_ARITY,
                    });
                }
                let risk = mass_of("riesgo", *hazard)?;
                let positive = mass_of("verdad", *truth)?;
                let negative = mass_of("falsedad", *falsity)?;
                let sanitized = risk > SEAL_THRESHOLD;
                ast.nodes.push(ShoreshNode {
                    root: root.clone(),
                    original: original.clone(),
                    arity: *arity,
                    ret: *ret,
                    hazard: risk,
                    valence: QuantumState::paraconsistent(positive, negative),
                    sanitized,
                });
                Ok(format!(
                    "alta «{}» ← «{}» · aridad {} · ret {} · riesgo {:.3} · {}",
                    root,
                    original,
                    arity,
                    ret.label(),
                    risk,
                    if sanitized {
                        "sellado al nacer (שמר)"
                    } else {
                        "sin sello"
                    }
                ))
            }
            Mutation::Retarget { index, ret } => {
                let node = node_mut(ast, *index)?;
                let before = node.ret;
                node.ret = *ret;
                Ok(format!(
                    "nodo {} «{}»: ret {} → {}",
                    index,
                    node.root,
                    before.label(),
                    ret.label()
                ))
            }
            Mutation::Rewire { index, arity } => {
                if *arity > MAX_ARITY {
                    return Err(MutatorError::ArityOverflow {
                        arity: *arity,
                        limit: MAX_ARITY,
                    });
                }
                let node = node_mut(ast, *index)?;
                let before = node.arity;
                node.arity = *arity;
                Ok(format!(
                    "nodo {} «{}»: aridad {} → {}",
                    index, node.root, before, arity
                ))
            }
            Mutation::Seal { index } => {
                let node = node_mut(ast, *index)?;
                let repeat = node.sanitized;
                node.sanitized = true;
                Ok(format!(
                    "nodo {} «{}» sellado bajo guarda שמר{}",
                    index,
                    node.root,
                    if repeat { " (ya lo estaba)" } else { "" }
                ))
            }
            Mutation::Harden { index, delta } => {
                let reduction = mass_of("refuerzo", *delta)?;
                let node = node_mut(ast, *index)?;
                let before = node.hazard;
                let after = (before - reduction).max(0.0);
                let (positive, negative) = node.valence.belnap();
                node.hazard = after;
                node.valence =
                    QuantumState::paraconsistent(positive.max(1.0 - after), negative.min(after));
                Ok(format!(
                    "nodo {} «{}»: riesgo {:.3} → {:.3} · ⊤={:.3} ⊥={:.3}",
                    index,
                    node.root,
                    before,
                    after,
                    node.valence.truth_mass(),
                    node.valence.falsity_mass()
                ))
            }
            Mutation::Negate { index } => {
                let node = node_mut(ast, *index)?;
                let previous = node.valence.clone();
                node.valence = previous.negate();
                Ok(format!(
                    "nodo {} «{}»: valencia {} → {}",
                    index,
                    node.root,
                    previous.label(),
                    node.valence.label()
                ))
            }
            Mutation::Remove { index } => {
                let total = ast.nodes.len();
                if *index >= total {
                    return Err(MutatorError::NoSuchNode {
                        index: *index,
                        nodes: total,
                    });
                }
                let removed = ast.nodes.remove(*index);
                Ok(format!(
                    "baja «{}» · quedan {} nodos",
                    removed.root,
                    ast.nodes.len()
                ))
            }
        }
    }
}

/// Valida una masa o un riesgo: finito y dentro de `[0, 1]`.
fn mass_of(field: &'static str, value: f64) -> Result<f64, MutatorError> {
    if value.is_finite() && (0.0..=1.0).contains(&value) {
        Ok(value)
    } else {
        Err(MutatorError::MassOutOfRange { field, value })
    }
}

/// Nodo mutable por índice, de manera total.
fn node_mut(ast: &mut ShoreshAst, index: usize) -> Result<&mut ShoreshNode, MutatorError> {
    let nodes = ast.nodes.len();
    ast.nodes
        .get_mut(index)
        .ok_or(MutatorError::NoSuchNode { index, nodes })
}
// ─────────────────────────────────────────────────────────────────────────
// FASE 3.1 · Célula *sandbox*
// ─────────────────────────────────────────────────────────────────────────

/// Célula de aislamiento temporal: contenedor con su **propia** rama del AST.
///
/// La rama vive en memoria dinámica del *sandbox* y el núcleo queda intacto por
/// construcción: la célula sólo recibió una copia y no conserva ninguna
/// referencia —ni mutable ni compartida— al núcleo. Por eso un fallo dentro de
/// la célula no puede corromper nada del núcleo: no hay camino.
#[derive(Debug, Clone)]
pub struct SandboxCell {
    id: u64,
    base_label: String,
    base_revision: u64,
    base_digest: [u8; 32],
    branch: ShoreshAst,
    records: Vec<MutationRecord>,
    faults: Vec<CellFault>,
    state: CellState,
    seal: Option<AstDna>,
    seal_label: String,
}

impl SandboxCell {
    /// Abre una célula a partir del núcleo: copia su AST a memoria propia.
    pub fn fork(id: u64, kernel: KernelRead<'_>) -> Self {
        Self {
            id,
            base_label: kernel.label().to_string(),
            base_revision: kernel.revision(),
            base_digest: kernel.digest(),
            branch: ShoreshAst {
                nodes: kernel.nodes().to_vec(),
            },
            records: Vec::new(),
            faults: Vec::new(),
            state: CellState::Open,
            seal: None,
            seal_label: String::new(),
        }
    }

    /// Identificador de la célula.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Estado actual.
    pub fn state(&self) -> CellState {
        self.state
    }

    /// ¿Admite operaciones?
    pub fn is_open(&self) -> bool {
        self.state.is_open()
    }

    /// ¿Está en cuarentena por un fallo atrapado?
    pub fn is_poisoned(&self) -> bool {
        matches!(self.state, CellState::Quarantined)
    }

    /// Etiqueta del núcleo del que se bifurcó.
    pub fn base_label(&self) -> &str {
        &self.base_label
    }

    /// Revisión del núcleo del que se bifurcó (referencia del CAS).
    pub fn base_revision(&self) -> u64 {
        self.base_revision
    }

    /// Huella del núcleo del que se bifurcó (referencia del CAS).
    pub fn base_digest(&self) -> [u8; 32] {
        self.base_digest
    }

    /// Rama mutada (sólo lectura: se muta por [`SandboxCell::apply`]).
    pub fn ast(&self) -> &ShoreshAst {
        &self.branch
    }

    /// Nodos de la rama.
    pub fn nodes(&self) -> &[ShoreshNode] {
        &self.branch.nodes
    }

    /// Nodos existentes en la rama.
    pub fn node_count(&self) -> usize {
        self.branch.nodes.len()
    }

    /// Operaciones aplicadas.
    pub fn op_count(&self) -> usize {
        self.records.len()
    }

    /// Registros de las operaciones aplicadas.
    pub fn records(&self) -> &[MutationRecord] {
        &self.records
    }

    /// Fallos atrapados.
    pub fn faults(&self) -> &[CellFault] {
        &self.faults
    }

    /// Sello (ADN firmado) del parche, si la célula ya se selló.
    pub fn seal(&self) -> Option<&AstDna> {
        self.seal.as_ref()
    }

    /// Etiqueta con la que se selló el parche.
    pub fn seal_label(&self) -> &str {
        &self.seal_label
    }

    /// Techo de riesgo de la rama.
    pub fn hazard_ceiling(&self) -> f64 {
        self.branch.hazard_ceiling()
    }
}

impl SandboxCell {
    /// Huella de la rama: dominio ‖ base ‖ huellas de nodo ‖ huellas de registro.
    ///
    /// Cambia con **cada** operación (la cadena de registros entra en el
    /// enunciado), de modo que la rama tiene una identidad verificable en todo
    /// momento y no sólo al final.
    pub fn branch_digest(&self) -> [u8; 32] {
        let mut statement = Vec::with_capacity(
            BRANCH_DOMAIN.len() + 32 + self.branch.nodes.len() * 32 + self.records.len() * 32,
        );
        statement.extend_from_slice(BRANCH_DOMAIN);
        statement.extend_from_slice(&self.base_digest);
        for node in &self.branch.nodes {
            statement.extend_from_slice(&ast_dna::node_dna(node).digest);
        }
        for record in &self.records {
            statement.extend_from_slice(&record.digest);
        }
        sha256(&statement)
    }

    /// Aplica una operación en la rama y devuelve su registro.
    ///
    /// Devuelve el fallo tal cual: quien decide **atraparlo** es
    /// [`SandboxCell::attempt`]; el núcleo jamás ve este `Result`.
    pub fn apply(&mut self, mutation: &Mutation) -> Result<MutationRecord, MutatorError> {
        match self.state {
            CellState::Open => {}
            CellState::Sealed => return Err(MutatorError::CellSealed { id: self.id }),
            CellState::Quarantined => return Err(MutatorError::CellPoisoned { id: self.id }),
        }
        if self.records.len() >= MAX_CELL_OPS {
            return Err(MutatorError::CellOpBudget {
                used: self.records.len(),
                limit: MAX_CELL_OPS,
            });
        }
        if matches!(mutation, Mutation::Add { .. }) && self.branch.nodes.len() >= MAX_CELL_NODES {
            return Err(MutatorError::CellCapacity {
                used: self.branch.nodes.len(),
                limit: MAX_CELL_NODES,
            });
        }
        let summary = mutation.apply(&mut self.branch)?;
        let record = MutationRecord {
            op: self.records.len(),
            summary,
            digest: self.branch_digest(),
        };
        self.records.push(record.clone());
        Ok(record)
    }

    /// Intenta una operación **atrapando** cualquier fallo.
    ///
    /// Un fallo no sale de la célula: se registra como [`CellFault`], la célula
    /// pasa a cuarentena (aislamiento automático) y el núcleo —que nunca tuvo
    /// referencia a esta rama— sigue exactamente igual. La rama se conserva
    /// congelada para el análisis forense; liberarla es cosa de
    /// [`AutopoieticMutator::release`].
    pub fn attempt(&mut self, mutation: &Mutation) -> CellOutcome {
        match self.apply(mutation) {
            Ok(record) => CellOutcome::Applied(record),
            Err(error) => {
                let fault = CellFault {
                    op: self.records.len(),
                    error: error.to_string(),
                };
                self.faults.push(fault.clone());
                self.state = CellState::Quarantined;
                CellOutcome::Trapped(fault)
            }
        }
    }

    /// Aísla la célula explícitamente y devuelve el informe del aislamiento.
    pub fn isolate(&mut self) -> IsolationReport {
        let report = IsolationReport {
            cell: self.id,
            ops_discarded: self.records.len(),
            faults: self.faults.len(),
            label: format!(
                "celda {} aislada (⊘): {} operaciones descartadas, {} fallos atrapados",
                self.id,
                self.records.len(),
                self.faults.len()
            ),
        };
        self.state = CellState::Quarantined;
        report
    }

    /// Sella la célula con el ADN firmado de su rama (sólo la propuesta sella).
    fn attach_seal(&mut self, label: String, dna: AstDna) {
        self.seal_label = label;
        self.seal = Some(dna);
        self.state = CellState::Sealed;
    }

    /// Representación legible del estado de la célula.
    pub fn label(&self) -> String {
        format!(
            "celda {} {} · base {} rev {} · {} nodos · {} ops · {} fallos · rama {}",
            self.id,
            self.state.glyph(),
            self.base_label,
            self.base_revision,
            self.branch.nodes.len(),
            self.records.len(),
            self.faults.len(),
            hex_of(&self.branch_digest()[..4])
        )
    }
}
// ─────────────────────────────────────────────────────────────────────────
// FASE 2 · Autoevaluación estática (Shoresh)
// ─────────────────────────────────────────────────────────────────────────

/// Resultado de una comprobación estática del parche.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditCheck {
    /// Identificador estable de la regla.
    pub label: &'static str,
    /// ¿Se cumple?
    pub passed: bool,
    /// Detalle legible (incluye el nodo infractor cuando lo hay).
    pub detail: String,
}

/// Auditoría estática de un parche: nueve reglas que se pueden evaluar sin
/// ejecutar nada.
///
/// Es la autoevaluación *Shoresh* de la FASE 2: el árbol se examina a sí mismo
/// ([`audit_ast`]) antes de que nada llegue a compilarse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticAudit {
    /// Comprobaciones, en orden normativo.
    pub checks: Vec<AuditCheck>,
}

impl StaticAudit {
    /// ¿Pasa todas las reglas?
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|check| check.passed)
    }

    /// Recuento `(cumplidas, total)`.
    pub fn score(&self) -> (usize, usize) {
        let passed = self.checks.iter().filter(|check| check.passed).count();
        (passed, self.checks.len())
    }

    /// Reglas incumplidas.
    pub fn failed(&self) -> Vec<&AuditCheck> {
        self.checks.iter().filter(|check| !check.passed).collect()
    }

    /// Comprobación por identificador.
    pub fn check(&self, label: &str) -> Option<&AuditCheck> {
        self.checks.iter().find(|check| check.label == label)
    }

    /// Representación legible.
    pub fn label(&self) -> String {
        let (passed, total) = self.score();
        format!(
            "auditoría Shoresh · {}/{} {}",
            passed,
            total,
            if self.passed() { "✓" } else { "✗" }
        )
    }
}

/// ¿El valor es un riesgo o una masa válida (finito y dentro de `[0, 1]`)?
fn in_unit_interval(value: f64) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}

/// Huellas de nodo de un AST, en orden.
fn node_digests(ast: &ShoreshAst) -> Vec<[u8; 32]> {
    ast.nodes
        .iter()
        .map(|node| ast_dna::node_dna(node).digest)
        .collect()
}

/// Ejecuta las nueve comprobaciones estáticas sobre un parche candidato.
///
/// Reglas (orden normativo):
/// 1. `plan.no-vacio` — un parche sin nodos no es un parche.
/// 2. `aridad.acotada` — aridad `≤` [`MAX_ARITY`] en todos los nodos.
/// 3. `raiz.triconsonantal` — toda raíz es triconsonántica hebrea
///    ([`triconsonantal`], la misma noción que usa el lienzo del IDE).
/// 4. `raiz.unica` — no hay raíces repetidas: un árbol es un conjunto de raíces.
/// 5. `masas.en-rango` — verdad y falsedad de cada valencia en `[0, 1]`.
/// 6. `riesgo.en-rango` — riesgo de cada nodo en `[0, 1]`.
/// 7. `tipo.declarado` — ningún nodo se queda en [`BaraType::Unknown`].
/// 8. `guarda.sello-coherente` — riesgo sobre [`SEAL_THRESHOLD`] obliga a sellar.
/// 9. `huella.determinista` — la raíz de Merkle se reproduce igual dos veces.
pub fn audit_ast(ast: &ShoreshAst) -> StaticAudit {
    let total = ast.nodes.len();

    let (plan_ok, plan_detail) = if total == 0 {
        (false, "el parche no aporta ningún nodo".to_string())
    } else {
        (true, format!("{} nodos en el parche", total))
    };

    let arity_offender = ast
        .nodes
        .iter()
        .enumerate()
        .find(|(_, node)| node.arity > MAX_ARITY);
    let (arity_ok, arity_detail) = match arity_offender {
        Some((index, node)) => (
            false,
            format!(
                "nodo {} «{}» con aridad {} (tope {})",
                index, node.root, node.arity, MAX_ARITY
            ),
        ),
        None => (true, format!("aridad ≤ {} en todos los nodos", MAX_ARITY)),
    };

    let root_offender = ast
        .nodes
        .iter()
        .enumerate()
        .find(|(_, node)| !triconsonantal(&node.root));
    let (root_ok, root_detail) = match root_offender {
        Some((index, node)) => (
            false,
            format!("nodo {} con raíz «{}» no triconsonántica", index, node.root),
        ),
        None => (true, "todas las raíces son triconsonánticas".to_string()),
    };

    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let duplicate = ast
        .nodes
        .iter()
        .enumerate()
        .find(|(_, node)| !seen.insert(node.root.as_str()));
    let (unique_ok, unique_detail) = match duplicate {
        Some((index, node)) => (
            false,
            format!("nodo {} repite la raíz «{}»", index, node.root),
        ),
        None => (true, format!("{} raíces distintas", seen.len())),
    };

    let mass_offender = ast.nodes.iter().enumerate().find(|(_, node)| {
        !in_unit_interval(node.valence.truth_mass())
            || !in_unit_interval(node.valence.falsity_mass())
    });
    let (masses_ok, masses_detail) = match mass_offender {
        Some((index, node)) => (
            false,
            format!(
                "nodo {} «{}» con ⊤={} ⊥={}",
                index,
                node.root,
                node.valence.truth_mass(),
                node.valence.falsity_mass()
            ),
        ),
        None => (true, "todas las valencias están en [0,1]".to_string()),
    };

    let risk_offender = ast
        .nodes
        .iter()
        .enumerate()
        .find(|(_, node)| !in_unit_interval(node.hazard));
    let (risk_ok, risk_detail) = match risk_offender {
        Some((index, node)) => (
            false,
            format!("nodo {} «{}» con riesgo {}", index, node.root, node.hazard),
        ),
        None => (true, "todos los riesgos están en [0,1]".to_string()),
    };

    let type_offender = ast
        .nodes
        .iter()
        .enumerate()
        .find(|(_, node)| node.ret == BaraType::Unknown);
    let (type_ok, type_detail) = match type_offender {
        Some((index, node)) => (
            false,
            format!("nodo {} «{}» sin tipo declarado", index, node.root),
        ),
        None => (true, "todos los nodos declaran tipo de retorno".to_string()),
    };

    let guard_offender = ast
        .nodes
        .iter()
        .enumerate()
        .find(|(_, node)| node.hazard > SEAL_THRESHOLD && !node.sanitized);
    let (guard_ok, guard_detail) = match guard_offender {
        Some((index, node)) => (
            false,
            format!(
                "nodo {} «{}» con riesgo {:.3} sobre el umbral {} y sin sello",
                index, node.root, node.hazard, SEAL_THRESHOLD
            ),
        ),
        None => (true, "los nodos de riesgo alto están sellados".to_string()),
    };

    let first = ast_dna::merkle_root(&node_digests(ast));
    let second = ast_dna::merkle_root(&node_digests(ast));
    let (deterministic_ok, deterministic_detail) = if digest_eq(&first, &second) {
        (
            true,
            format!("raíz de Merkle estable {}", hex_of(&first[..4])),
        )
    } else {
        (false, "la raíz de Merkle no se reproduce igual".to_string())
    };

    StaticAudit {
        checks: vec![
            AuditCheck {
                label: "plan.no-vacio",
                passed: plan_ok,
                detail: plan_detail,
            },
            AuditCheck {
                label: "aridad.acotada",
                passed: arity_ok,
                detail: arity_detail,
            },
            AuditCheck {
                label: "raiz.triconsonantal",
                passed: root_ok,
                detail: root_detail,
            },
            AuditCheck {
                label: "raiz.unica",
                passed: unique_ok,
                detail: unique_detail,
            },
            AuditCheck {
                label: "masas.en-rango",
                passed: masses_ok,
                detail: masses_detail,
            },
            AuditCheck {
                label: "riesgo.en-rango",
                passed: risk_ok,
                detail: risk_detail,
            },
            AuditCheck {
                label: "tipo.declarado",
                passed: type_ok,
                detail: type_detail,
            },
            AuditCheck {
                label: "guarda.sello-coherente",
                passed: guard_ok,
                detail: guard_detail,
            },
            AuditCheck {
                label: "huella.determinista",
                passed: deterministic_ok,
                detail: deterministic_detail,
            },
        ],
    }
}
// ─────────────────────────────────────────────────────────────────────────
// FASE 3.2 · Compuerta paraconsistente (Belnap FOUR)
// ─────────────────────────────────────────────────────────────────────────

/// Valor de la retícula `FOUR` de Belnap: verdadero, falso, ambos o ninguno.
///
/// `FOUR` no es una escala lineal: tiene **dos** órdenes que sirven para cosas
/// distintas.
/// * Orden de verdad (`⊤ > ⊤∧⊥ > ⊥`, con `∅` en el fondo): gobierna `¬`, `∧`, `∨`
///   y la designación (`⊤` y `⊤∧⊥` son designados).
/// * Orden de información (`⊤∧⊥` arriba, `∅` abajo): gobierna el consenso `⊓` y
///   la unión `⊔`, que es como se combinan **testigos independientes**.
///
/// Por eso este tipo no deriva `Ord`: un orden total sería una mentira
/// matemática. Sí deriva `Eq`, porque la igualdad cierta sí es total.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BelnapValue {
    /// `⊥` — determinadamente falso.
    False,
    /// `∅` — ni verdadero ni falso (falta información).
    Neither,
    /// `⊤` — determinadamente verdadero.
    True,
    /// `⊤∧⊥` — contradictorio: verdadero **y** falso a la vez.
    Both,
}

impl BelnapValue {
    /// Los cuatro valores en orden canónico `⊤ ⊥ ⊤∧⊥ ∅`.
    pub const ALL: [BelnapValue; 4] = [
        BelnapValue::True,
        BelnapValue::False,
        BelnapValue::Both,
        BelnapValue::Neither,
    ];

    /// Índice estable en [`BelnapValue::ALL`] (para serializar).
    pub const fn index(self) -> usize {
        match self {
            BelnapValue::True => 0,
            BelnapValue::False => 1,
            BelnapValue::Both => 2,
            BelnapValue::Neither => 3,
        }
    }

    /// Valor a partir de su índice; `None` si el índice no existe.
    pub const fn from_index(index: usize) -> Option<BelnapValue> {
        match index {
            0 => Some(BelnapValue::True),
            1 => Some(BelnapValue::False),
            2 => Some(BelnapValue::Both),
            3 => Some(BelnapValue::Neither),
            _ => None,
        }
    }

    /// Glifo lógico.
    pub const fn glyph(self) -> &'static str {
        match self {
            BelnapValue::True => "⊤",
            BelnapValue::False => "⊥",
            BelnapValue::Both => "⊤∧⊥",
            BelnapValue::Neither => "∅",
        }
    }

    /// Nombre ontológico.
    pub const fn name(self) -> &'static str {
        match self {
            BelnapValue::True => "verdadero",
            BelnapValue::False => "falso",
            BelnapValue::Both => "contradictorio",
            BelnapValue::Neither => "indeterminado",
        }
    }

    /// Masas canónicas del valor: `(verdad, falsedad)` en las esquinas `{0, 1}`.
    ///
    /// Que sean las esquinas **exactas** de su clase no es un detalle: hace que
    /// el mínimo y el máximo componente a componente **sean** la retícula
    /// `FOUR`, tanto en el orden de verdad como en el de información (lo
    /// verifica `belnap.tablas_equivalentes_a_masas`).
    pub const fn corners(self) -> (f64, f64) {
        match self {
            BelnapValue::True => (1.0, 0.0),
            BelnapValue::False => (0.0, 1.0),
            BelnapValue::Both => (1.0, 1.0),
            BelnapValue::Neither => (0.0, 0.0),
        }
    }

    /// Designación por umbral sobre un par de masas continuas.
    pub fn from_masses(truth: f64, falsity: f64) -> BelnapValue {
        match (
            truth >= DESIGNATION_THRESHOLD,
            falsity >= DESIGNATION_THRESHOLD,
        ) {
            (true, true) => BelnapValue::Both,
            (true, false) => BelnapValue::True,
            (false, true) => BelnapValue::False,
            (false, false) => BelnapValue::Neither,
        }
    }

    /// Traduce la observación del runtime sin pérdida.
    pub const fn from_observation(observation: Observation) -> BelnapValue {
        match observation {
            Observation::True => BelnapValue::True,
            Observation::False => BelnapValue::False,
            Observation::Both => BelnapValue::Both,
            Observation::Neither => BelnapValue::Neither,
        }
    }

    /// Observación equivalente del runtime.
    pub const fn to_observation(self) -> Observation {
        match self {
            BelnapValue::True => Observation::True,
            BelnapValue::False => Observation::False,
            BelnapValue::Both => Observation::Both,
            BelnapValue::Neither => Observation::Neither,
        }
    }

    /// Colapsa una valencia paraconsistente de Bara a la retícula `FOUR`.
    pub fn from_state(state: &QuantumState) -> BelnapValue {
        BelnapValue::from_observation(state.observe())
    }

    /// Estado paraconsistente testigo, con masas **exactamente** en su clase.
    pub fn to_state(self) -> QuantumState {
        let (truth, falsity) = self.corners();
        QuantumState::paraconsistent(truth, falsity)
    }

    /// ¿Es designado? (`⊤` o `⊤∧⊥`.)
    pub const fn is_designated(self) -> bool {
        matches!(self, BelnapValue::True | BelnapValue::Both)
    }

    /// ¿Es determinadamente verdadero o falso? (`∅` y `⊤∧⊥` no lo son.)
    pub const fn is_determined(self) -> bool {
        matches!(self, BelnapValue::True | BelnapValue::False)
    }

    /// ¿Es una contradicción tolerada?
    pub const fn is_contradiction(self) -> bool {
        matches!(self, BelnapValue::Both)
    }

    /// ¿Falta información?
    pub const fn is_unknown(self) -> bool {
        matches!(self, BelnapValue::Neither)
    }

    /// Etiqueta legible para las trazas del IDE.
    pub fn label(self) -> String {
        format!("{} {}", self.glyph(), self.name())
    }
}

impl BelnapValue {
    /// Negación (ortocomplemento del orden de verdad): intercambia `⊤` y `⊥` y
    /// deja fijos `⊤∧⊥` y `∅`.
    pub const fn negate(self) -> BelnapValue {
        match self {
            BelnapValue::True => BelnapValue::False,
            BelnapValue::False => BelnapValue::True,
            BelnapValue::Both => BelnapValue::Both,
            BelnapValue::Neither => BelnapValue::Neither,
        }
    }

    /// Complemento: alias de la negación con la notación de retícula.
    pub const fn complement(self) -> BelnapValue {
        self.negate()
    }

    /// Conjunción `∧` (meet del orden de verdad).
    pub const fn conjunction(self, other: BelnapValue) -> BelnapValue {
        match (self, other) {
            (BelnapValue::False, _) | (_, BelnapValue::False) => BelnapValue::False,
            (BelnapValue::True, value) | (value, BelnapValue::True) => value,
            (BelnapValue::Both, BelnapValue::Both) => BelnapValue::Both,
            (BelnapValue::Both, BelnapValue::Neither)
            | (BelnapValue::Neither, BelnapValue::Both) => BelnapValue::False,
            (BelnapValue::Neither, BelnapValue::Neither) => BelnapValue::Neither,
        }
    }

    /// Disyunción `∨` (join del orden de verdad).
    pub const fn disjunction(self, other: BelnapValue) -> BelnapValue {
        match (self, other) {
            (BelnapValue::True, _) | (_, BelnapValue::True) => BelnapValue::True,
            (BelnapValue::False, value) | (value, BelnapValue::False) => value,
            (BelnapValue::Both, BelnapValue::Both) => BelnapValue::Both,
            (BelnapValue::Both, BelnapValue::Neither)
            | (BelnapValue::Neither, BelnapValue::Both) => BelnapValue::True,
            (BelnapValue::Neither, BelnapValue::Neither) => BelnapValue::Neither,
        }
    }

    /// Implicación material `a → b ≜ ¬a ∨ b`.
    pub const fn implication(self, other: BelnapValue) -> BelnapValue {
        self.negate().disjunction(other)
    }

    /// Consenso `⊓` (ínfimo del orden de información): sólo lo que **ambos**
    /// testigos afirman. Cuando dos testigos determinados discrepan (`⊤` frente
    /// a `⊥`) el consenso es `∅`; `⊤∧⊥` es el tope informativo, así que aporta
    /// exactamente lo que afirme el otro testigo.
    pub const fn consensus(self, other: BelnapValue) -> BelnapValue {
        match (self, other) {
            (BelnapValue::Neither, _) | (_, BelnapValue::Neither) => BelnapValue::Neither,
            (BelnapValue::Both, value) | (value, BelnapValue::Both) => value,
            (BelnapValue::True, BelnapValue::True) => BelnapValue::True,
            (BelnapValue::False, BelnapValue::False) => BelnapValue::False,
            (BelnapValue::True, BelnapValue::False) | (BelnapValue::False, BelnapValue::True) => {
                BelnapValue::Neither
            }
        }
    }

    /// Unión `⊔` (join del orden de información): todo lo que **algún** testigo
    /// aporta. Es la operación que combina el juicio de la periferia con el
    /// testigo independiente del núcleo.
    pub const fn union(self, other: BelnapValue) -> BelnapValue {
        match (self, other) {
            (BelnapValue::Both, _) | (_, BelnapValue::Both) => BelnapValue::Both,
            (BelnapValue::True, BelnapValue::False) | (BelnapValue::False, BelnapValue::True) => {
                BelnapValue::Both
            }
            (BelnapValue::True, BelnapValue::Neither)
            | (BelnapValue::Neither, BelnapValue::True) => BelnapValue::True,
            (BelnapValue::False, BelnapValue::Neither)
            | (BelnapValue::Neither, BelnapValue::False) => BelnapValue::False,
            (BelnapValue::True, BelnapValue::True) => BelnapValue::True,
            (BelnapValue::False, BelnapValue::False) => BelnapValue::False,
            (BelnapValue::Neither, BelnapValue::Neither) => BelnapValue::Neither,
        }
    }

    /// Masas resultantes de conjuntar dos valores: `(mín ⊤, máx ⊥)`.
    ///
    /// Como la clase de un par de masas depende sólo de sus indicadores de
    /// umbral, y el mínimo y el máximo distribuyen sobre ellos igual que `∧` y
    /// `∨`, esta función es un **homomorfismo exacto**: para cualquier par de
    /// masas, [`BelnapValue::from_masses`] de aquí devuelve exactamente
    /// [`BelnapValue::conjunction`] de las clases.
    pub fn conjoined_masses(self, other: BelnapValue) -> (f64, f64) {
        let (truth_a, falsity_a) = self.corners();
        let (truth_b, falsity_b) = other.corners();
        (truth_a.min(truth_b), falsity_a.max(falsity_b))
    }

    /// Masas resultantes de la unión informativa de dos valores: `(máx ⊤, máx ⊥)`.
    pub fn united_masses(self, other: BelnapValue) -> (f64, f64) {
        let (truth_a, falsity_a) = self.corners();
        let (truth_b, falsity_b) = other.corners();
        (truth_a.max(truth_b), falsity_a.max(falsity_b))
    }
}

/// ¿El nodo es estructuralmente admisible?
///
/// Es la cara *Shoresh* del juicio: raíz triconsonántica no vacía, aridad
/// acotada, riesgo y masas en `[0, 1]`, tipo declarado y guarda coherente
/// (riesgo alto ⇒ sellado). Un nodo que incumple cualquiera de estas reglas
/// aporta `⊥` al juicio aunque su valencia sea `⊤`.
fn structurally_sound(node: &ShoreshNode) -> bool {
    !node.root.is_empty()
        && triconsonantal(&node.root)
        && node.arity <= MAX_ARITY
        && in_unit_interval(node.hazard)
        && in_unit_interval(node.valence.truth_mass())
        && in_unit_interval(node.valence.falsity_mass())
        && (node.hazard <= SEAL_THRESHOLD || node.sanitized)
        && node.ret != BaraType::Unknown
}

/// Primer código de violación estructural de un nodo, en el orden exacto en que
/// [`structurally_sound`] las comprueba.
///
/// Permite que la caja negra distinga *por qué* se rechazó un nodo: el
/// diagnóstico se lee en el registro sin volver a inspeccionar el AST.
fn structural_violation(node: &ShoreshNode) -> ViolationCode {
    if node.root.is_empty() {
        return ViolationCode::EmptyRoot;
    }
    if !triconsonantal(&node.root) {
        return ViolationCode::RootNotTriconsonantal;
    }
    if node.arity > MAX_ARITY {
        return ViolationCode::ArityExceeded;
    }
    if !in_unit_interval(node.hazard)
        || !in_unit_interval(node.valence.truth_mass())
        || !in_unit_interval(node.valence.falsity_mass())
    {
        return ViolationCode::MassOutOfRange;
    }
    if node.hazard > SEAL_THRESHOLD && !node.sanitized {
        return ViolationCode::HazardUnsealed;
    }
    if node.ret == BaraType::Unknown {
        return ViolationCode::UnknownType;
    }
    ViolationCode::StructuralViolation
}
/// Evidencia de pruebas de la periferia: lo único que puede convertir un plan
/// plausible en un plan fundado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    /// Nombre de la suite (por ejemplo `bara.sandbox.suite`).
    pub suite: String,
    /// Pruebas superadas.
    pub passed: usize,
    /// Pruebas fallidas.
    pub failed: usize,
    /// Duración medida en microsegundos.
    ///
    /// **NO DETERMINISTA**: es un reloj de pared y, por tanto, queda fuera de
    /// toda huella, sello o comparación (igual que `micros` en el resto del
    /// kernel).
    pub elapsed_micros: u128,
}

impl Evidence {
    /// Evidencia con resultado explícito.
    pub fn new(suite: &str, passed: usize, failed: usize) -> Self {
        Self {
            suite: suite.to_string(),
            passed,
            failed,
            elapsed_micros: 0,
        }
    }

    /// Evidencia de una suite en verde.
    pub fn green(suite: &str, passed: usize) -> Self {
        Self::new(suite, passed, 0)
    }

    /// Evidencia de una suite en rojo.
    pub fn red(suite: &str, passed: usize, failed: usize) -> Self {
        Self::new(suite, passed, failed)
    }

    /// Ausencia de evidencia: ni verde ni roja, simplemente nada.
    pub fn none() -> Self {
        Self::new("sin-evidencia", 0, 0)
    }

    /// ¿Verde y con al menos una prueba superada?
    pub fn is_green(&self) -> bool {
        self.failed == 0 && self.passed > 0
    }

    /// Voto tetravalente de la evidencia: verde `⊤`, roja `⊥`, ausente `∅`.
    pub fn vote(&self) -> BelnapValue {
        if self.failed > 0 {
            BelnapValue::False
        } else if self.passed > 0 {
            BelnapValue::True
        } else {
            BelnapValue::Neither
        }
    }

    /// Huella de la evidencia: **excluye** `elapsed_micros` (no determinista).
    pub fn digest(&self) -> [u8; 32] {
        let mut statement = Vec::with_capacity(64 + self.suite.len());
        statement.extend_from_slice(b"bara:aether-omega:evidencia:v1");
        statement.extend_from_slice(&(self.suite.len() as u32).to_le_bytes());
        statement.extend_from_slice(self.suite.as_bytes());
        statement.extend_from_slice(&(self.passed as u64).to_le_bytes());
        statement.extend_from_slice(&(self.failed as u64).to_le_bytes());
        sha256(&statement)
    }

    /// Representación legible (la duración se muestra marcada como volátil).
    pub fn label(&self) -> String {
        format!(
            "evidencia «{}» · {}/{} {} · {} µs (no determinista) · {}",
            self.suite,
            self.passed,
            self.passed.saturating_add(self.failed),
            self.vote().glyph(),
            self.elapsed_micros,
            hex_of(&self.digest()[..4])
        )
    }
}
/// Juicio tetravalente de un parche candidato.
#[derive(Debug, Clone, PartialEq)]
pub struct BelnapVerdict {
    /// Retícula combinada de la periferia: nodos ∧ estructura ∧ evidencia ∧ firma.
    pub periferia: BelnapValue,
    /// Testigo independiente del núcleo (verifica su ADN ⇒ `⊤`).
    pub nucleo: BelnapValue,
    /// Unión informativa de periferia y testigo: el juicio final.
    pub union: BelnapValue,
    /// Masa de verdad de la periferia.
    pub truth: f64,
    /// Masa de falsedad de la periferia.
    pub falsity: f64,
    /// Nodos juzgados.
    pub nodes: usize,
    /// Nodos contradictorios (`⊤∧⊥`).
    pub contradictions: usize,
    /// Nodos indeterminados (`∅`).
    pub unknowns: usize,
    /// Nodos estructuralmente inadmisibles.
    pub violations: usize,
    /// Pruebas superadas que aportó la evidencia.
    pub tests_passed: usize,
    /// Pruebas fallidas que aportó la evidencia.
    pub tests_failed: usize,
    /// ¿La firma del parche es válida?
    pub signature_ok: bool,
    /// ¿El núcleo verifica su propio ADN?
    pub kernel_ok: bool,
}

impl BelnapVerdict {
    /// ¿Se admite la fusión?
    ///
    /// Exige `⊤` determinadamente verdadero **y** unión informativa `⊤`: una
    /// contradicción (`⊤∧⊥`) o una duda (`∅`) **detienen** la fusión en lugar de
    /// propagarse al núcleo.
    pub fn admits_fusion(&self) -> bool {
        self.periferia == BelnapValue::True && self.union == BelnapValue::True
    }

    /// Motivo del juicio, en orden de precedencia.
    pub fn reason(&self) -> &'static str {
        if self.admits_fusion() {
            "fusión admitida: la periferia es ⊤ y concuerda con el testigo del núcleo"
        } else if !self.signature_ok {
            "la firma del parche no corresponde a la clave soberana"
        } else if !self.kernel_ok {
            "el núcleo no verifica su propio ADN"
        } else if self.violations > 0 {
            "hay nodos estructuralmente inadmisibles en la periferia"
        } else if self.tests_failed > 0 {
            "las pruebas de la periferia están en rojo"
        } else if self.tests_passed == 0 {
            "sin evidencia de pruebas: el juicio queda indeterminado"
        } else if self.contradictions > 0 {
            "contradicción no resuelta en la periferia"
        } else if self.unknowns > 0 {
            "información insuficiente en la periferia"
        } else {
            "juicio no concluyente"
        }
    }

    /// ¿Las masas del juicio están en `[0, 1]`? (Siempre deberían estarlo.)
    pub fn is_bounded(&self) -> bool {
        in_unit_interval(self.truth) && in_unit_interval(self.falsity)
    }

    /// Representación legible.
    pub fn label(&self) -> String {
        format!(
            "Belnap ⟦{}⟧ periferia={} núcleo={} unión={} · ⊤={:.3} ⊥={:.3} · {} nodos (contradicciones {}, indeterminados {}, violaciones {}) · pruebas {}/{} · firma {} · {}",
            if self.admits_fusion() { "admitida" } else { "detenida" },
            self.periferia.glyph(),
            self.nucleo.glyph(),
            self.union.glyph(),
            self.truth,
            self.falsity,
            self.nodes,
            self.contradictions,
            self.unknowns,
            self.violations,
            self.tests_passed,
            self.tests_passed.saturating_add(self.tests_failed),
            if self.signature_ok { "⊤" } else { "⊥" },
            self.reason()
        )
    }
}
/// Compuerta tetravalente: convierte un parche candidato en un juicio `FOUR`.
///
/// Combina tres fuentes independientes —valencias y estructura de los nodos,
/// evidencia de pruebas y sello del parche— con el meet del orden de verdad, y
/// después une el resultado con el testigo del núcleo en el orden de
/// información. Las masas se acumulan con mínimo de verdades y máximo de
/// falsedades: exactamente el homomorfismo de [`BelnapValue::conjunction`].
pub struct BelnapMatrix;

impl BelnapMatrix {
    /// Las cuatro esquinas de la retícula con sus masas canónicas.
    pub const fn corners() -> [(BelnapValue, f64, f64); 4] {
        [
            (BelnapValue::True, 1.0, 0.0),
            (BelnapValue::False, 0.0, 1.0),
            (BelnapValue::Both, 1.0, 1.0),
            (BelnapValue::Neither, 0.0, 0.0),
        ]
    }

    /// Voto de un nodo: su valencia paraconsistente ∧ su coherencia estructural.
    pub fn node_vote(node: &ShoreshNode) -> BelnapValue {
        let valence = BelnapValue::from_state(&node.valence);
        let structural = if structurally_sound(node) {
            BelnapValue::True
        } else {
            BelnapValue::False
        };
        valence.conjunction(structural)
    }

    /// Juicio del parche: periferia ∧ evidencia ∧ firma, unido al testigo del núcleo.
    pub fn evaluate(
        kernel: KernelRead<'_>,
        branch: &ShoreshAst,
        evidence: &Evidence,
        signature_ok: bool,
    ) -> BelnapVerdict {
        let mut truth = 1.0_f64;
        let mut falsity = 0.0_f64;
        let mut contradictions = 0usize;
        let mut unknowns = 0usize;
        let mut violations = 0usize;

        for node in &branch.nodes {
            let vote = BelnapMatrix::node_vote(node);
            if vote.is_contradiction() {
                contradictions = contradictions.saturating_add(1);
            }
            if vote.is_unknown() {
                unknowns = unknowns.saturating_add(1);
            }
            let sound = structurally_sound(node);
            let (node_truth, node_falsity) = if sound {
                node.valence.belnap()
            } else {
                violations = violations.saturating_add(1);
                // La causa exacta queda en la caja negra; la huella es la raíz
                // del nodo, nunca su contenido completo.
                flight_recorder::record(
                    EventKind::VerdictRejected,
                    structural_violation(node),
                    node.root.as_bytes(),
                );
                (0.0, 1.0)
            };
            truth = truth.min(node_truth);
            falsity = falsity.max(node_falsity);
        }

        if branch.nodes.is_empty() {
            truth = 0.0;
            falsity = 0.0;
        }

        let (evidence_truth, evidence_falsity) = evidence.vote().corners();
        truth = truth.min(evidence_truth);
        falsity = falsity.max(evidence_falsity);

        let (signature_truth, signature_falsity) =
            if signature_ok { (1.0, 0.0) } else { (0.0, 1.0) };
        truth = truth.min(signature_truth);
        falsity = falsity.max(signature_falsity);

        let periferia = BelnapValue::from_masses(truth, falsity);

        let kernel_ok = kernel.verified();
        let nucleo = if kernel_ok {
            BelnapValue::True
        } else {
            BelnapValue::False
        };
        let (union_truth, union_falsity) = nucleo.united_masses(periferia);
        let union = BelnapValue::from_masses(union_truth, union_falsity);

        // Caja negra: la paradoja no se resuelve, se anota. La huella es la raíz
        // de Merkle de la rama —no el árbol—: el registro no copia el parche.
        if periferia.is_contradiction() {
            flight_recorder::record_digest(
                EventKind::BelnapConflictBoth,
                ViolationCode::ContradictionRetained,
                &ast_dna::merkle_root(&node_digests(branch)),
            );
        } else if periferia.is_unknown() {
            flight_recorder::record_digest(
                EventKind::BelnapConflictNeither,
                ViolationCode::IndeterminateVerdict,
                &ast_dna::merkle_root(&node_digests(branch)),
            );
        }

        BelnapVerdict {
            periferia,
            nucleo,
            union,
            truth,
            falsity,
            nodes: branch.nodes.len(),
            contradictions,
            unknowns,
            violations,
            tests_passed: evidence.passed,
            tests_failed: evidence.failed,
            signature_ok,
            kernel_ok,
        }
    }

    /// Consenso `⊓` entre la periferia y el testigo del núcleo.
    ///
    /// Útil para trazas del IDE: `⊤` significa que ambos testigos coinciden,
    /// `∅` que discrepan y ninguno impone su criterio.
    pub fn agreement(periferia: BelnapValue, nucleo: BelnapValue) -> BelnapValue {
        periferia.consensus(nucleo)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// FASE 3.3 · Diff estructural (API del IDE)
// ─────────────────────────────────────────────────────────────────────────

/// Línea canónica de un nodo *Shoresh*.
///
/// Es el formato compartido por diffs, JSON y consola del IDE: si cambia aquí,
/// cambia en un solo sitio.
pub fn node_line(node: &ShoreshNode) -> String {
    format!(
        "{} · {} · aridad={} · ret={}({}) · riesgo={:.3} · ⊤={:.3} ⊥={:.3} · {}",
        node.root,
        node.original,
        node.arity,
        node.ret.label(),
        node.ret.name(),
        node.hazard,
        node.valence.truth_mass(),
        node.valence.falsity_mass(),
        if node.sanitized { "sellado" } else { "abierto" }
    )
}

/// Huella de un AST candidato: dominio ‖ etiqueta ‖ longitud ‖ raíz de Merkle.
///
/// A diferencia de la huella del núcleo (que incluye la revisión), ésta
/// identifica **un parche**: dos mutadores distintos que producen el mismo
/// árbol con la misma etiqueta obtienen la misma huella, que es justo lo que
/// exige la fusión determinista.
pub fn ast_fingerprint(label: &str, ast: &ShoreshAst) -> [u8; 32] {
    let mut statement = Vec::with_capacity(PATCH_DOMAIN.len() + label.len() + 36);
    statement.extend_from_slice(PATCH_DOMAIN);
    statement.extend_from_slice(&(label.len() as u32).to_le_bytes());
    statement.extend_from_slice(label.as_bytes());
    statement.extend_from_slice(&ast_dna::merkle_root(&node_digests(ast)));
    sha256(&statement)
}

/// Escapa una cadena para JSON, sin dependencias externas.
fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 2);
    for character in input.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if control.is_control() => {
                out.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out
}

/// Línea de un diff estructural entre el núcleo y una rama.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffLine {
    /// Nodo idéntico en ambos árboles (misma posición y misma huella).
    Kept(String),
    /// Nodo presente en ambos pero distinto.
    Changed {
        /// Línea del núcleo.
        before: String,
        /// Línea de la rama.
        after: String,
    },
    /// Nodo que sólo existe en la rama.
    Added(String),
    /// Nodo que sólo existe en el núcleo.
    Removed(String),
}

impl DiffLine {
    /// Marcador textual (`=` `~` `+` `-`).
    pub fn glyph(&self) -> &'static str {
        match self {
            DiffLine::Kept(_) => "=",
            DiffLine::Changed { .. } => "~",
            DiffLine::Added(_) => "+",
            DiffLine::Removed(_) => "-",
        }
    }

    /// ¿La línea representa un cambio?
    pub fn is_change(&self) -> bool {
        !matches!(self, DiffLine::Kept(_))
    }

    /// Render de la línea para el panel del IDE.
    pub fn render(&self) -> String {
        match self {
            DiffLine::Kept(line) => format!("{} {}", self.glyph(), line),
            DiffLine::Changed { before, after } => {
                format!("{} {} → {}", self.glyph(), before, after)
            }
            DiffLine::Added(line) => format!("{} {}", self.glyph(), line),
            DiffLine::Removed(line) => format!("{} {}", self.glyph(), line),
        }
    }
}
/// Diff estructural entre el núcleo base y la rama de una célula.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationDiff {
    /// Célula de la que procede la rama.
    pub cell: u64,
    /// Revisión del núcleo base.
    pub base_revision: u64,
    /// Revisión que tendría el núcleo fusionado.
    pub candidate_revision: u64,
    /// Huella del núcleo base (la que usa el CAS optimista).
    pub base_digest: [u8; 32],
    /// Huella del parche candidato ([`ast_fingerprint`]).
    pub candidate_fingerprint: [u8; 32],
    /// Etiqueta del núcleo base.
    pub base_label: String,
    /// Etiqueta del candidato.
    pub candidate_label: String,
    /// Líneas del diff, en orden (primero lo común, luego altas y bajas).
    pub lines: Vec<DiffLine>,
    /// Nodos idénticos.
    pub kept: usize,
    /// Nodos añadidos.
    pub added: usize,
    /// Nodos eliminados.
    pub removed: usize,
    /// Nodos modificados.
    pub changed: usize,
}

impl MutationDiff {
    /// Calcula el diff de una rama contra el núcleo base.
    ///
    /// El algoritmo es posicional y **total**: compara por índice (huella de
    /// nodo), marca como altas la cola de la rama y como bajas la cola del
    /// núcleo, y nunca indexa fuera de rango (`get(..)` con valor por defecto).
    pub fn compute(
        cell: u64,
        base: KernelRead<'_>,
        candidate: &ShoreshAst,
        candidate_label: &str,
    ) -> Self {
        let base_nodes = base.nodes();
        let mut lines = Vec::with_capacity(candidate.nodes.len().max(base_nodes.len()));
        let mut kept = 0usize;
        let mut changed = 0usize;

        for (before, after) in base_nodes.iter().zip(candidate.nodes.iter()) {
            let same = digest_eq(
                &ast_dna::node_dna(before).digest,
                &ast_dna::node_dna(after).digest,
            );
            if same {
                kept = kept.saturating_add(1);
                lines.push(DiffLine::Kept(node_line(after)));
            } else {
                changed = changed.saturating_add(1);
                lines.push(DiffLine::Changed {
                    before: node_line(before),
                    after: node_line(after),
                });
            }
        }

        let common = base_nodes.len().min(candidate.nodes.len());
        let fresh = candidate.nodes.get(common..).unwrap_or_default();
        let gone = base_nodes.get(common..).unwrap_or_default();
        for node in fresh {
            lines.push(DiffLine::Added(node_line(node)));
        }
        for node in gone {
            lines.push(DiffLine::Removed(node_line(node)));
        }

        Self {
            cell,
            base_revision: base.revision(),
            candidate_revision: base.revision().saturating_add(1),
            base_digest: base.digest(),
            candidate_fingerprint: ast_fingerprint(candidate_label, candidate),
            base_label: base.label().to_string(),
            candidate_label: candidate_label.to_string(),
            lines,
            kept,
            added: fresh.len(),
            removed: gone.len(),
            changed,
        }
    }

    /// ¿La rama no cambia nada respecto al núcleo?
    pub fn is_empty(&self) -> bool {
        self.added == 0 && self.removed == 0 && self.changed == 0
    }

    /// Nodos afectados (altas + bajas + modificaciones).
    pub fn changed_nodes(&self) -> usize {
        self.added
            .saturating_add(self.removed)
            .saturating_add(self.changed)
    }

    /// Líneas que representan cambios.
    pub fn change_lines(&self) -> Vec<&DiffLine> {
        self.lines.iter().filter(|line| line.is_change()).collect()
    }
}
impl MutationDiff {
    /// Resumen de una línea (consola del IDE).
    pub fn summary(&self) -> String {
        format!(
            "diff celda {} · base {} rev {} → candidato rev {} · +{} -{} ~{} ={}",
            self.cell,
            self.base_label,
            self.base_revision,
            self.candidate_revision,
            self.added,
            self.removed,
            self.changed,
            self.kept
        )
    }

    /// Diff unificado (panel de texto del IDE).
    pub fn unified(&self) -> String {
        let mut out = String::with_capacity(self.lines.len() * 48 + 96);
        out.push_str(&format!(
            "--- {} rev {}\n",
            self.base_label, self.base_revision
        ));
        out.push_str(&format!(
            "+++ {} rev {}\n",
            self.candidate_label, self.candidate_revision
        ));
        for line in &self.lines {
            out.push_str(&line.render());
            out.push('\n');
        }
        out
    }

    /// JSON mínimo y estable: es el contrato del lienzo del IDE visual.
    pub fn json(&self) -> String {
        let mut out = String::with_capacity(self.lines.len() * 64 + 256);
        out.push('{');
        out.push_str(&format!("\"cell\":{},", self.cell));
        out.push_str(&format!("\"base_revision\":{},", self.base_revision));
        out.push_str(&format!(
            "\"candidate_revision\":{},",
            self.candidate_revision
        ));
        out.push_str(&format!(
            "\"base_digest\":\"{}\",",
            hex_of(&self.base_digest)
        ));
        out.push_str(&format!(
            "\"candidate_fingerprint\":\"{}\",",
            hex_of(&self.candidate_fingerprint)
        ));
        out.push_str(&format!(
            "\"base_label\":\"{}\",",
            json_escape(&self.base_label)
        ));
        out.push_str(&format!(
            "\"candidate_label\":\"{}\",",
            json_escape(&self.candidate_label)
        ));
        out.push_str(&format!(
            "\"kept\":{},\"added\":{},\"removed\":{},\"changed\":{},",
            self.kept, self.added, self.removed, self.changed
        ));
        out.push_str("\"lines\":[");
        for (index, line) in self.lines.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str(&diff_line_json(line));
        }
        out.push_str("]}");
        out
    }
}

/// Serializa una línea de diff a JSON.
fn diff_line_json(line: &DiffLine) -> String {
    match line {
        DiffLine::Kept(text) => {
            format!("{{\"kind\":\"kept\",\"line\":\"{}\"}}", json_escape(text))
        }
        DiffLine::Added(text) => {
            format!("{{\"kind\":\"added\",\"line\":\"{}\"}}", json_escape(text))
        }
        DiffLine::Removed(text) => format!(
            "{{\"kind\":\"removed\",\"line\":\"{}\"}}",
            json_escape(text)
        ),
        DiffLine::Changed { before, after } => format!(
            "{{\"kind\":\"changed\",\"before\":\"{}\",\"after\":\"{}\"}}",
            json_escape(before),
            json_escape(after)
        ),
    }
}
// ─────────────────────────────────────────────────────────────────────────
// FASE 3.3 · Propuesta y fusión atómica
// ─────────────────────────────────────────────────────────────────────────

/// Propuesta de fusión: parche sellado, auditado y juzgado, listo para el CAS.
#[derive(Debug, Clone)]
pub struct Proposal {
    /// Identificador de la propuesta.
    pub id: u64,
    /// Célula que la produjo.
    pub cell: u64,
    /// Revisión del núcleo sobre la que se construyó.
    pub base_revision: u64,
    /// Huella del núcleo sobre el que se construyó.
    pub base_digest: [u8; 32],
    /// Árbol candidato (ya viene sellado por el ADN del parche).
    pub candidate: ShoreshAst,
    /// Etiqueta del candidato.
    pub candidate_label: String,
    /// ADN firmado del candidato.
    pub dna: AstDna,
    /// Auditoría estática de la FASE 2.
    pub audit: StaticAudit,
    /// Juicio tetravalente de la FASE 3.2.
    pub verdict: BelnapVerdict,
    /// Diff estructural de la FASE 3.3 (API del IDE).
    pub diff: MutationDiff,
    /// Evidencia de pruebas que respalda la propuesta.
    pub evidence: Evidence,
    /// Operaciones aplicadas dentro de la célula.
    pub operations: usize,
}

impl Proposal {
    /// ¿Se admite la fusión? Exige auditoría conforme **y** juicio `⊤`.
    pub fn admits_fusion(&self) -> bool {
        self.audit.passed() && self.verdict.admits_fusion()
    }

    /// Huella del parche propuesto.
    pub fn fingerprint(&self) -> [u8; 32] {
        ast_fingerprint(&self.candidate_label, &self.candidate)
    }

    /// Nodos del candidato.
    pub fn nodes(&self) -> &[ShoreshNode] {
        &self.candidate.nodes
    }

    /// Representación legible.
    pub fn label(&self) -> String {
        format!(
            "propuesta #{} · celda {} · {} ops · {} · {} · {}",
            self.id,
            self.cell,
            self.operations,
            self.audit.label(),
            self.verdict.label(),
            self.diff.summary()
        )
    }

    /// JSON de la propuesta para el IDE: juicio, auditoría y diff en un solo
    /// documento estable (sin dependencias externas, claves fijas).
    pub fn json(&self) -> String {
        let (audit_passed, audit_total) = self.audit.score();
        let mut out = String::with_capacity(768 + self.diff.lines.len() * 64);
        out.push('{');
        out.push_str(&format!("\"id\":{},", self.id));
        out.push_str(&format!("\"cell\":{},", self.cell));
        out.push_str(&format!("\"base_revision\":{},", self.base_revision));
        out.push_str(&format!("\"operations\":{},", self.operations));
        out.push_str(&format!("\"admitida\":{},", self.admits_fusion()));
        out.push_str(&format!(
            "\"candidate_label\":\"{}\",",
            json_escape(&self.candidate_label)
        ));
        out.push_str(&format!(
            "\"fingerprint\":\"{}\",",
            hex_of(&self.fingerprint())
        ));
        out.push_str(&format!(
            "\"dna\":{{\"root\":\"{}\",\"signature\":\"{}\",\"key_id\":{}}},",
            hex_of(&self.dna.root),
            hex_of(&self.dna.signature),
            self.dna.key_id
        ));
        out.push_str(&format!(
            "\"auditoria\":{{\"aprobada\":{},\"cumplidas\":{},\"total\":{},\"reglas\":[",
            self.audit.passed(),
            audit_passed,
            audit_total
        ));
        for (index, check) in self.audit.checks.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"regla\":\"{}\",\"pasa\":{},\"detalle\":\"{}\"}}",
                json_escape(check.label),
                check.passed,
                json_escape(&check.detail)
            ));
        }
        out.push_str("]},");
        out.push_str(&format!(
            "\"juicio\":{{\"periferia\":\"{}\",\"nucleo\":\"{}\",\"union\":\"{}\",\"verdad\":{:.6},\"falsedad\":{:.6},\"contradicciones\":{},\"indeterminados\":{},\"violaciones\":{},\"motivo\":\"{}\"}},",
            self.verdict.periferia.glyph(),
            self.verdict.nucleo.glyph(),
            self.verdict.union.glyph(),
            self.verdict.truth,
            self.verdict.falsity,
            self.verdict.contradictions,
            self.verdict.unknowns,
            self.verdict.violations,
            json_escape(self.verdict.reason())
        ));
        out.push_str(&format!(
            "\"evidencia\":{{\"suite\":\"{}\",\"superadas\":{},\"fallidas\":{},\"huella\":\"{}\"}},",
            json_escape(&self.evidence.suite),
            self.evidence.passed,
            self.evidence.failed,
            hex_of(&self.evidence.digest())
        ));
        out.push_str(&format!("\"diff\":{}", self.diff.json()));
        out.push('}');
        out
    }
}
/// Contadores del mutador: una foto coherente, no una vista viva.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MutatorCounts {
    /// Células vivas en el *sandbox*.
    pub cells: usize,
    /// Propuestas emitidas.
    pub proposals: usize,
    /// Fusiones consumadas.
    pub fusions: usize,
    /// Aislamientos (automáticos o manuales).
    pub isolations: usize,
    /// Fallos atrapados dentro de células.
    pub traps: usize,
    /// Propuestas rechazadas por la auditoría o el juicio.
    pub rejections: usize,
}

/// Entradas del log ontológico del mutador que se conservan.
pub const JOURNAL_LIMIT: usize = 64;

/// Mutador autopoiético en *sandbox*: el único camino legal hacia un núcleo nuevo.
///
/// El mutador no puede escribir en el núcleo —no existe API para ello— y no se
/// fía de sí mismo: cada propuesta pasa por auditoría estática, sellado con ADN,
/// juicio tetravalente y fusión atómica con CAS optimista. Todo lo que aprende
/// queda en el log ontológico, acotado a [`JOURNAL_LIMIT`] entradas.
#[derive(Debug)]
pub struct AutopoieticMutator {
    key: [u8; 32],
    link: SynapseLink,
    cells: BTreeMap<u64, SandboxCell>,
    proposals: BTreeMap<u64, Proposal>,
    journal: VecDeque<String>,
    next_cell: u64,
    next_proposal: u64,
    fusions: usize,
    isolations: usize,
    traps: usize,
    rejections: usize,
}

impl AutopoieticMutator {
    /// Crea un mutador con la clave soberana derivada de la semilla.
    pub fn new(seed: &[u8]) -> Self {
        let key = ast_dna::golden_key(seed);
        Self {
            key,
            link: SynapseLink::open(key),
            cells: BTreeMap::new(),
            proposals: BTreeMap::new(),
            journal: VecDeque::new(),
            next_cell: 1,
            next_proposal: 1,
            fusions: 0,
            isolations: 0,
            traps: 0,
            rejections: 0,
        }
    }

    /// Identificador público de la clave soberana.
    pub fn key_id(&self) -> u64 {
        ast_dna::key_id(&self.key)
    }

    /// Canal IPC del mutador (solo lectura).
    pub fn link(&self) -> &SynapseLink {
        &self.link
    }

    /// Canal IPC del mutador (envío y traducción).
    pub fn link_mut(&mut self) -> &mut SynapseLink {
        &mut self.link
    }

    /// Células vivas, en orden de identificador.
    pub fn cells(&self) -> impl Iterator<Item = &SandboxCell> {
        self.cells.values()
    }

    /// Célula por identificador.
    pub fn cell(&self, id: u64) -> Option<&SandboxCell> {
        self.cells.get(&id)
    }

    /// Propuestas emitidas, en orden de identificador.
    pub fn proposals(&self) -> impl Iterator<Item = &Proposal> {
        self.proposals.values()
    }

    /// Propuesta por identificador.
    pub fn proposal(&self, id: u64) -> Option<&Proposal> {
        self.proposals.get(&id)
    }

    /// Acceso mutable a una propuesta: es la vía de la consola forense del IDE
    /// para anotar un parche (y la que usan las pruebas de manipulación, que
    /// alteran el sello a propósito para comprobar que la fusión lo detecta).
    pub fn proposal_mut(&mut self, id: u64) -> Option<&mut Proposal> {
        self.proposals.get_mut(&id)
    }

    /// Contadores actuales.
    pub fn counters(&self) -> MutatorCounts {
        MutatorCounts {
            cells: self.cells.len(),
            proposals: self.proposals.len(),
            fusions: self.fusions,
            isolations: self.isolations,
            traps: self.traps,
            rejections: self.rejections,
        }
    }

    /// Log ontológico, de la entrada más antigua a la más reciente.
    pub fn journal_lines(&self) -> Vec<String> {
        self.journal.iter().cloned().collect()
    }

    /// Última entrada del log ontológico.
    pub fn journal_tail(&self) -> Option<&str> {
        self.journal.back().map(String::as_str)
    }

    /// Marca de anomalías de la puerta: marcos que no llegaron a traducirse.
    pub fn anomalies(&self) -> usize {
        self.link.gateway().counters().rejected
    }

    /// Anota un peso de atención en el log. No escribe en el núcleo.
    pub fn note_attention(&mut self, fingerprint: u64, weight: u32) {
        self.log(format!("atencion fp={fingerprint:016x} peso={weight}"));
    }

    /// Anota un patrón de repetición en el log. No escribe en el núcleo.
    pub fn note_repetition(&mut self, fingerprint: u64, repetitions: u32) {
        self.log(format!("repeticion fp={fingerprint:016x} n={repetitions}"));
    }

    /// Anota una entrada en el log ontológico, respetando [`JOURNAL_LIMIT`].
    fn log(&mut self, entry: String) {
        if self.journal.len() >= JOURNAL_LIMIT {
            let _ = self.journal.pop_front();
        }
        self.journal.push_back(entry);
    }
}

impl AutopoieticMutator {
    /// Abre una célula *sandbox* a partir del núcleo y devuelve su identificador.
    ///
    /// La copia de los nodos es la memoria dinámica de la célula: a partir de
    /// aquí el núcleo y el *sandbox* comparten tipos pero no estado.
    pub fn open_cell(&mut self, kernel: KernelRead<'_>) -> u64 {
        let id = self.next_cell;
        self.next_cell = self.next_cell.saturating_add(1);
        let cell = SandboxCell::fork(id, kernel);
        let entry = format!(
            "celda {} abierta sobre {} rev {} ({} nodos)",
            id,
            cell.base_label(),
            cell.base_revision(),
            cell.node_count()
        );
        self.cells.insert(id, cell);
        self.log(entry);
        id
    }

    /// Aplica una operación en una célula **atrapando** cualquier fallo.
    ///
    /// El `Result` sólo informa de la célula ausente; todo lo demás —incluidos
    /// los fallos de la operación— vuelve como [`CellOutcome`], de modo que un
    /// error de la periferia nunca sale del *sandbox* como excepción.
    pub fn apply(
        &mut self,
        cell_id: u64,
        mutation: &Mutation,
    ) -> Result<CellOutcome, MutatorError> {
        let (outcome, poisoned, cell_line) = {
            let cell = self
                .cells
                .get_mut(&cell_id)
                .ok_or(MutatorError::CellUnknown { id: cell_id })?;
            let outcome = cell.attempt(mutation);
            let poisoned = cell.is_poisoned();
            let cell_line = cell.label();
            (outcome, poisoned, cell_line)
        };
        if outcome.is_trapped() {
            self.traps = self.traps.saturating_add(1);
            if poisoned {
                self.isolations = self.isolations.saturating_add(1);
            }
        }
        self.log(format!("{} · {}", cell_line, outcome.label()));
        Ok(outcome)
    }

    /// Aísla una célula (o confirma el aislamiento automático) y lo informa.
    pub fn isolate(&mut self, cell_id: u64) -> Result<IsolationReport, MutatorError> {
        let (report, cell_line) = {
            let cell = self
                .cells
                .get_mut(&cell_id)
                .ok_or(MutatorError::CellUnknown { id: cell_id })?;
            let report = cell.isolate();
            let cell_line = cell.label();
            (report, cell_line)
        };
        self.isolations = self.isolations.saturating_add(1);
        self.log(format!("{} · {}", cell_line, report.label));
        Ok(report)
    }

    /// Libera una célula: la rama dinámica se descarta de inmediato.
    ///
    /// Es el *rollback* inmediato del *sandbox*: no hay nada que deshacer en el
    /// núcleo porque nunca se le tocó.
    pub fn release(&mut self, cell_id: u64) -> bool {
        let removed = self.cells.remove(&cell_id).is_some();
        if removed {
            self.log(format!(
                "celda {} liberada: rama dinámica descartada",
                cell_id
            ));
        }
        removed
    }
}
impl AutopoieticMutator {
    /// Sella, audita y juzga la rama de una célula, y emite una propuesta.
    ///
    /// El parche **nace firmado**: el ADN del candidato se calcula con la clave
    /// soberana y se deposita en la célula antes de devolver la propuesta. La
    /// célula queda sellada —plan congelado— y no admite más operaciones.
    pub fn propose(
        &mut self,
        kernel: KernelRead<'_>,
        cell_id: u64,
        evidence: &Evidence,
    ) -> Result<u64, MutatorError> {
        let id = self.next_proposal;
        let key = self.key;
        let (proposal, entry) = {
            let cell = self
                .cells
                .get_mut(&cell_id)
                .ok_or(MutatorError::CellUnknown { id: cell_id })?;
            if cell.is_poisoned() {
                return Err(MutatorError::CellPoisoned { id: cell_id });
            }
            if !cell.is_open() {
                return Err(MutatorError::CellSealed { id: cell_id });
            }
            if cell.op_count() == 0 {
                return Err(MutatorError::CellEmptyPlan);
            }
            if !cell.faults().is_empty() {
                return Err(MutatorError::CellPoisoned { id: cell_id });
            }

            let base_revision = cell.base_revision();
            let base_digest = cell.base_digest();
            let operations = cell.op_count();
            let label = format!("{}.sandbox{}", cell.base_label(), cell_id);
            let candidate = cell.ast().clone();
            let dna = ast_dna::ast_dna(&label, &candidate, &key);
            let signature_ok = ast_dna::verify(&label, &candidate, &dna, &key);
            let audit = audit_ast(&candidate);
            let verdict = BelnapMatrix::evaluate(kernel, &candidate, evidence, signature_ok);
            let diff = MutationDiff::compute(cell_id, kernel, &candidate, &label);
            let entry = format!(
                "propuesta #{} emitida · celda {} · {} ops · {} · {} · {}",
                id,
                cell_id,
                operations,
                audit.label(),
                verdict.label(),
                diff.summary()
            );
            cell.attach_seal(label.clone(), dna.clone());
            (
                Proposal {
                    id,
                    cell: cell_id,
                    base_revision,
                    base_digest,
                    candidate,
                    candidate_label: label,
                    dna,
                    audit,
                    verdict,
                    diff,
                    evidence: evidence.clone(),
                    operations,
                },
                entry,
            )
        };

        self.next_proposal = self.next_proposal.saturating_add(1);
        self.proposals.insert(id, proposal);
        self.log(entry);
        Ok(id)
    }
}

impl AutopoieticMutator {
    /// Fusiona una propuesta **si y sólo si** todo concuerda.
    ///
    /// Orden normativo: núcleo verificado → CAS (revisión y huella) → auditoría
    /// estática → juicio tetravalente → ADN del parche. Sólo entonces se forja
    /// el núcleo siguiente, que es un objeto **nuevo**: el recibido por
    /// referencia no se toca (ni se puede tocar) y sigue siendo válido.
    pub fn commit(
        &mut self,
        kernel: &KernelCore,
        proposal_id: u64,
    ) -> Result<KernelCore, MutatorError> {
        let proposal = self
            .proposals
            .get(&proposal_id)
            .cloned()
            .ok_or(MutatorError::ProposalUnknown { id: proposal_id })?;

        if !kernel.verify() {
            return Err(self.refuse(proposal_id, MutatorError::CoreBroken));
        }
        if kernel.revision() != proposal.base_revision
            || !digest_eq(&kernel.digest(), &proposal.base_digest)
        {
            return Err(self.refuse(
                proposal_id,
                MutatorError::FusionStale {
                    expected: proposal.base_revision,
                    found: kernel.revision(),
                },
            ));
        }
        if !proposal.audit.passed() {
            return Err(self.refuse(
                proposal_id,
                MutatorError::AuditFailed {
                    failed: proposal.audit.failed().len(),
                },
            ));
        }
        if !proposal.verdict.admits_fusion() {
            return Err(self.refuse(
                proposal_id,
                MutatorError::VerdictRejected {
                    periferia: proposal.verdict.periferia,
                    union: proposal.verdict.union,
                },
            ));
        }
        if !ast_dna::verify(
            &proposal.candidate_label,
            &proposal.candidate,
            &proposal.dna,
            &self.key,
        ) {
            return Err(self.refuse(
                proposal_id,
                MutatorError::DnaMismatch {
                    label: proposal.candidate_label.clone(),
                },
            ));
        }

        let next = KernelCore::forge(
            &proposal.candidate_label,
            proposal.candidate.clone(),
            proposal.base_revision.saturating_add(1),
            self.key,
        );
        if !next.verify() {
            return Err(self.refuse(proposal_id, MutatorError::CoreBroken));
        }

        self.fusions = self.fusions.saturating_add(1);
        self.cells.remove(&proposal.cell);
        self.log(format!(
            "fusión consumada · propuesta #{} → núcleo «{}» rev {} ({}) · {}",
            proposal_id,
            next.label(),
            next.revision(),
            hex_of(&next.digest()[..4]),
            proposal.verdict.reason()
        ));
        Ok(next)
    }

    /// Registra el rechazo de una propuesta y devuelve el fallo tal cual.
    ///
    /// El rechazo queda además en la caja negra: motivo clasificado e
    /// identificador de la propuesta, nunca su contenido.
    fn refuse(&mut self, proposal_id: u64, error: MutatorError) -> MutatorError {
        self.rejections = self.rejections.saturating_add(1);
        self.log(format!("propuesta #{} rechazada · {}", proposal_id, error));
        flight_recorder::record_fingerprint(
            EventKind::VerdictRejected,
            mutator_violation(&error),
            proposal_id,
        );
        error
    }
}

/// Clasificación de un fallo de autopoiesis para la caja negra.
///
/// Es total: cualquier variante futura obliga a decidir su código, de modo que
/// el registro nunca hereda un diagnóstico ambiguo.
fn mutator_violation(error: &MutatorError) -> ViolationCode {
    match error {
        MutatorError::Kernel(_) | MutatorError::CellUnknown { .. } => ViolationCode::Unclassified,
        MutatorError::CellPoisoned { .. } | MutatorError::CellSealed { .. } => {
            ViolationCode::CellState
        }
        MutatorError::CellCapacity { .. } => ViolationCode::CellCapacity,
        MutatorError::CellEmptyPlan => ViolationCode::EmptyPatch,
        MutatorError::CellOpBudget { .. } => ViolationCode::BudgetExceeded,
        MutatorError::NoSuchNode { .. } => ViolationCode::UnknownNode,
        MutatorError::ArityOverflow { .. } => ViolationCode::ArityExceeded,
        MutatorError::MassOutOfRange { .. } => ViolationCode::MassOutOfRange,
        MutatorError::EmptyRoot => ViolationCode::EmptyRoot,
        MutatorError::ProposalUnknown { .. } => ViolationCode::UnknownProposal,
        MutatorError::VerdictRejected { .. } => ViolationCode::FusionDenied,
        MutatorError::AuditFailed { .. } => ViolationCode::AuditFailed,
        MutatorError::DnaMismatch { .. } => ViolationCode::DnaMismatch,
        MutatorError::FusionStale { .. } => ViolationCode::StaleCore,
        MutatorError::CoreBroken => ViolationCode::KernelUnverified,
    }
}
impl AutopoieticMutator {
    /// Documento JSON de una propuesta para el lienzo del IDE visual.
    pub fn ide_payload(&self, proposal_id: u64) -> Option<String> {
        self.proposals.get(&proposal_id).map(Proposal::json)
    }

    /// Recibe un marco verificado del canal (o `None` si no hay nada).
    pub fn receive(&mut self) -> Result<Option<Frame>, KernelError> {
        self.link.receive()
    }

    /// Drena el canal y devuelve los marcos verificados en orden de llegada.
    ///
    /// Los marcos hostiles se descartan en la puerta (y se cuentan): nunca
    /// llegan al llamante.
    pub fn pump(&mut self) -> Vec<Frame> {
        let frames = self.link.drain();
        let last = frames.last().map(|frame| frame.kind.label());
        let tail = match last {
            Some(label) => format!(" · último {}", label),
            None => String::new(),
        };
        self.log(format!(
            "canal drenado: {} marcos verificados{}",
            frames.len(),
            tail
        ));
        frames
    }

    /// Etiqueta de una línea del mutador.
    pub fn label(&self) -> String {
        let counts = self.counters();
        format!(
            "AutopoieticMutator · clave {:016x} · células {} · propuestas {} · fusiones {} · aislamientos {}",
            self.key_id(),
            counts.cells,
            counts.proposals,
            counts.fusions,
            counts.isolations
        )
    }

    /// Estado completo del mutador: puerta, contadores, células y log.
    pub fn status(&self) -> String {
        let counts = self.counters();
        let mut out = String::with_capacity(320 + self.journal.len() * 64);
        out.push_str(&format!(
            "mutador autopoiético · clave {:016x} · {}\n",
            self.key_id(),
            self.link.gateway().label()
        ));
        out.push_str(&format!(
            "células {} · propuestas {} · fusiones {} · aislamientos {} · fallos atrapados {} · rechazos {} · anomalías {}\n",
            counts.cells,
            counts.proposals,
            counts.fusions,
            counts.isolations,
            counts.traps,
            counts.rejections,
            self.anomalies()
        ));
        for cell in self.cells.values() {
            out.push_str(&format!("  · {}\n", cell.label()));
        }
        for entry in &self.journal {
            out.push_str(&format!("  ⏺ {}\n", entry));
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Arnés de prueba
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    /// Semilla soberana de las pruebas (determinista: sin aleatoriedad real).
    const SEED: &[u8] = b"bara:pruebas:autopoiesis:v1";

    #[test]
    fn anotar_una_repeticion_no_escribe_en_el_nucleo() {
        let mut mutator = AutopoieticMutator::new(SEED);
        let before = mutator.counters();
        mutator.note_repetition(0xabc, 3);
        assert_eq!(
            mutator.journal_tail(),
            Some("repeticion fp=0000000000000abc n=3")
        );
        assert_eq!(mutator.counters(), before);
    }

    /// Nodo *Shoresh* con valencia `(verdad, falsedad)` explícita.
    fn node(root: &str, arity: usize, hazard: f64, truth: f64, falsity: f64) -> ShoreshNode {
        ShoreshNode {
            root: root.to_string(),
            original: format!("legacy_{}", root),
            arity,
            ret: BaraType::Number,
            hazard,
            valence: QuantumState::paraconsistent(truth, falsity),
            sanitized: false,
        }
    }

    /// Nodo conforme: riesgo bajo y valencia `⊤`.
    fn node_sound(root: &str) -> ShoreshNode {
        node(root, 2, 0.10, 0.90, 0.10)
    }

    /// Raíz triconsonántica distinta para cada índice (base 27 sobre `א..ת`).
    fn root_index(mut index: usize) -> String {
        let letters: Vec<char> = ('\u{05d0}'..='\u{05ea}').collect();
        let size = letters.len();
        let mut out = String::with_capacity(3);
        for _ in 0..3 {
            let slot = index % size;
            index /= size;
            out.push(letters.get(slot).copied().unwrap_or('\u{05d0}'));
        }
        out
    }

    /// AST con `count` nodos conformes y raíces todas distintas.
    fn ast_of(count: usize) -> ShoreshAst {
        ShoreshAst {
            nodes: (0..count)
                .map(|index| node_sound(&root_index(index)))
                .collect(),
        }
    }

    /// AST génesis de dos nodos (אמת y דעת).
    fn ast_genesis() -> ShoreshAst {
        ShoreshAst {
            nodes: vec![node_sound("אמת"), node_sound("דעת")],
        }
    }

    /// Núcleo génesis de pruebas.
    fn genesis() -> KernelCore {
        KernelCore::genesis("pruebas.kernel", ast_genesis(), SEED)
    }

    /// Mutación `Add` conforme con la raíz indicada.
    fn add(root: &str) -> Mutation {
        Mutation::Add {
            root: root.to_string(),
            original: format!("legacy_{}", root),
            arity: 2,
            ret: BaraType::Number,
            hazard: 0.20,
            truth: 0.80,
            falsity: 0.20,
        }
    }

    /// Evidencia en verde.
    fn green() -> Evidence {
        Evidence::green("bara.sandbox.suite", 5)
    }

    /// Aplica exigiendo éxito del contenedor (la trampa se examina aparte).
    fn applied(mutator: &mut AutopoieticMutator, cell: u64, mutation: &Mutation) -> CellOutcome {
        let outcome = mutator.apply(cell, mutation);
        assert!(outcome.is_ok(), "el contenedor debe aceptar la operación");
        match outcome {
            Ok(value) => value,
            Err(_) => CellOutcome::Trapped(CellFault {
                op: 0,
                error: "estado inalcanzable".to_string(),
            }),
        }
    }

    /// Texto del fallo atrapado, si lo hay.
    fn fault_text(outcome: &CellOutcome) -> String {
        outcome
            .fault()
            .map(|fault| fault.error.clone())
            .unwrap_or_default()
    }

    /// Cuerpo hexadecimal del cable (campo 4), para manipularlo a propósito.
    fn wire_body(link: &SynapseLink, sequence: u64, body: &[u8]) -> String {
        let wire = link.gateway().seal(sequence, FrameKind::KernelQuery, body);
        let text = String::from_utf8_lossy(&wire).to_string();
        text.split('|')
            .nth(3)
            .map(str::to_string)
            .unwrap_or_default()
    }

    /// Intercambia el cuerpo del primer marco por el de otro: firma inválida.
    fn swap_body(wire: &[u8], other_body: &str) -> Vec<u8> {
        let text = String::from_utf8_lossy(wire).to_string();
        let mut parts: Vec<String> = text.split('|').map(str::to_string).collect();
        if let Some(slot) = parts.get_mut(3) {
            *slot = other_body.to_string();
        }
        parts.join("|").into_bytes()
    }
    // ─────────────────────────────────────────────────────────────────────
    // FASE 1 · Núcleo inmutable y capacidad de sólo lectura
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn nucleo_inmutable_y_verificable() {
        let kernel = genesis();
        assert!(kernel.verify(), "el génesis debe verificar su propio ADN");
        assert_eq!(kernel.revision(), 0);
        assert_eq!(kernel.label(), "pruebas.kernel");
        assert_eq!(kernel.roots(), 2);
        assert_eq!(kernel.nodes().len(), 2);
        assert_eq!(kernel.key_id(), ast_dna::key_id(&ast_dna::golden_key(SEED)));
        assert_eq!(kernel.dna().key_id, kernel.key_id());
        assert!(kernel.hazard_ceiling() <= SEAL_THRESHOLD);

        let read = kernel.read();
        assert_eq!(read.capability(), Capability::ReadOnly);
        assert!(
            !read.capability().writes(),
            "la capacidad no concede escritura"
        );
        assert_eq!(read.capability().label(), "solo-lectura");
        assert_eq!(read.capability().glyph(), "ר");
        assert_eq!(read.label(), kernel.label());
        assert_eq!(read.len(), 2);
        assert_eq!(read.ast().nodes.len(), read.len());
        assert!(!read.is_empty());
        assert!(read.node(1).is_some());
        assert!(read.node(9).is_none());
        assert!(read.verified());
        assert!(digest_eq(&read.digest(), &kernel.digest()));

        // Determinismo: misma semilla y mismo AST ⇒ misma huella.
        assert!(digest_eq(&genesis().digest(), &kernel.digest()));
        // Otra semilla ⇒ otra clave: el núcleo no es forjable sin el secreto.
        let foreign = KernelCore::genesis("pruebas.kernel", ast_genesis(), b"bara:pruebas:ajena");
        assert_ne!(foreign.key_id(), kernel.key_id());
        assert!(!digest_eq(&foreign.digest(), &kernel.digest()));

        // El ADN cubre el sello y el contenido: cualquier retoque se detecta.
        let mut touched = genesis();
        touched.dna.signature[0] ^= 0x01;
        assert!(!touched.verify(), "un sello manipulado no puede verificar");
        let mut edited = genesis();
        if let Some(first) = edited.ast.nodes.first_mut() {
            first.hazard = 0.9;
        }
        assert!(!edited.verify(), "el ADN debe cubrir los nodos del AST");
    }

    // ─────────────────────────────────────────────────────────────────────
    // FASE 1.2 · Puerta IPC: tamaño, forma, firma y secuencia
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn gateway_firma_valida() {
        let key = ast_dna::golden_key(b"bara:pruebas:canal");
        let mut gateway = SynapseGateway::new(key);
        assert_eq!(gateway.key_id(), ast_dna::key_id(&key));
        assert_eq!(gateway.next_sequence(), 0);
        assert_eq!(gateway.counters(), GatewayCounters::default());
        assert!(gateway.label().contains("puerta Synapse"));

        let body = "alta:אמת".as_bytes();
        let wire = gateway.seal(0, FrameKind::MutationRequest, body);
        let text = String::from_utf8_lossy(&wire).to_string();
        let fields: Vec<&str> = text.split('|').collect();
        assert_eq!(fields.len(), 5, "el cable tiene cinco campos exactos");
        assert_eq!(fields.first().copied(), Some(WIRE_MARKER));
        assert_eq!(fields.get(1).copied(), Some("0"));
        assert_eq!(fields.get(2).copied(), Some("1"));
        let body_hex = hex_of(body);
        assert_eq!(fields.get(3).copied(), Some(body_hex.as_str()));
        assert_eq!(
            fields.get(4).map(|value| value.len()),
            Some(64),
            "firma HMAC-SHA-256"
        );

        let translated = gateway.translate(&wire);
        assert!(translated.is_ok());
        if let Ok(frame) = translated {
            assert_eq!(frame.sequence, 0);
            assert_eq!(frame.kind, FrameKind::MutationRequest);
            assert_eq!(frame.kind.code(), 1);
            assert_eq!(frame.body, body.to_vec());
            assert!(!frame.is_empty());
            assert!(frame.label().contains("marco #0"));
            assert!(digest_eq(
                &frame.digest(),
                &Frame::new(0, FrameKind::MutationRequest, body).digest()
            ));
        }
        assert_eq!(gateway.next_sequence(), 1);
        assert_eq!(gateway.counters().accepted, 1);
        assert_eq!(gateway.counters().rejected, 0);

        // La traducción de tipos es total: un código desconocido no es un tipo.
        assert_eq!(FrameKind::from_code(0), None);
        assert_eq!(FrameKind::from_code(9), None);
        assert_eq!(FrameKind::from_code(3), Some(FrameKind::CellReport));
        assert_eq!(FrameKind::FusionNotice.code(), 4);
        assert_eq!(FrameKind::CellReport.code(), 3);
        assert_eq!(FrameKind::MutationRequest.label(), "peticion-de-mutacion");
        assert_eq!(FrameKind::KernelQuery.label(), "consulta-de-nucleo");
        assert_eq!(FrameKind::FusionNotice.label(), "aviso-de-fusion");
    }

    #[test]
    fn gateway_manipulacion_detectada() {
        let key = ast_dna::golden_key(b"bara:pruebas:canal");
        let mut gateway = SynapseGateway::new(key);
        let wire = gateway.seal(0, FrameKind::KernelQuery, b"consulta");
        let tampered = swap_body(&wire, &hex_of(b"otra-consulta"));
        assert_ne!(tampered, wire);

        let rejected = gateway.translate(&tampered);
        assert!(rejected.is_err());
        if let Err(error) = &rejected {
            assert_eq!(error, &KernelError::SignatureMismatch);
        }
        assert_eq!(gateway.counters().tampered, 1);
        assert_eq!(gateway.counters().rejected, 1);
        assert_eq!(gateway.counters().accepted, 0);
        assert_eq!(
            gateway.next_sequence(),
            0,
            "un marco hostil no avanza la puerta"
        );

        // El mismo mensaje intacto sí entra: el rechazo era la firma, no el cuerpo.
        assert!(gateway.translate(&wire).is_ok());
        assert_eq!(gateway.counters().accepted, 1);
        assert_eq!(gateway.next_sequence(), 1);

        // Una clave ajena tampoco puede hablar en nombre del núcleo.
        let foreign = SynapseGateway::new(ast_dna::golden_key(b"bara:pruebas:ajena"));
        let foreign_wire = foreign.seal(1, FrameKind::KernelQuery, b"consulta");
        assert!(gateway.translate(&foreign_wire).is_err());
        assert_eq!(gateway.counters().tampered, 2);
        assert_eq!(gateway.counters().accepted, 1);
    }

    #[test]
    fn gateway_tamano_y_forma() {
        assert_eq!(MAX_FRAME, immunity_gateway::MAX_PAYLOAD);
        assert_eq!(MAX_FRAME, 64 * 1024);
        let key = ast_dna::golden_key(b"bara:pruebas:canal");
        let mut gateway = SynapseGateway::new(key);

        // Se mide antes de interpretar: la bomba de tamaño ni se analiza.
        let bomb = vec![b'A'; MAX_FRAME + 1];
        let rejected = gateway.translate(&bomb);
        assert!(rejected.is_err());
        if let Err(error) = &rejected {
            assert_eq!(
                error,
                &KernelError::FrameTooLarge {
                    found: MAX_FRAME + 1,
                    limit: MAX_FRAME,
                }
            );
        }
        assert_eq!(gateway.counters().oversized, 1);

        // Forma estricta: cinco campos, marca exacta, códigos y hex válidos.
        let extended = {
            let legit = gateway.seal(0, FrameKind::CellReport, b"x");
            let mut text = String::from_utf8_lossy(&legit).to_string();
            text.push_str("|00");
            text.into_bytes()
        };
        let malformed: [&[u8]; 10] = [
            b"",
            b"BASURA",
            b"BARA-IPC/1|0|1|00",
            b"BARA-IPC/1|0|1|00|",
            b"BARA-IPC/1|0|1|",
            &extended,
            b"OTRA-COSA/1|0|1|00|00",
            b"BARA-IPC/1|0|9|00|00",
            b"BARA-IPC/1|nueve|1|00|00",
            b"BARA-IPC/1|0|1|0g|00",
        ];
        for raw in malformed {
            assert!(gateway.translate(raw).is_err(), "debía rechazar la forma");
        }
        // La firma debe medir exactamente 32 bytes.
        assert!(gateway.translate(b"BARA-IPC/1|0|1|00|ffff").is_err());

        assert_eq!(gateway.counters().accepted, 0);
        assert_eq!(gateway.counters().tampered, 0);
        assert_eq!(gateway.counters().oversized, 1);
        assert_eq!(gateway.counters().rejected, 12);

        // Un marco del tamaño exacto del techo no se rechaza por tamaño (sí por forma).
        let limit_frame = {
            let mut wire = gateway.seal(0, FrameKind::CellReport, b"");
            wire.resize(MAX_FRAME, b'.');
            wire
        };
        assert!(gateway.translate(&limit_frame).is_err());
        assert_eq!(gateway.counters().oversized, 1);
        assert_eq!(gateway.counters().rejected, 13);
    }

    #[test]
    fn gateway_replay_bloqueado() {
        let key = ast_dna::golden_key(b"bara:pruebas:canal");
        let mut gateway = SynapseGateway::new(key);
        let first = gateway.seal(0, FrameKind::MutationRequest, b"uno");
        let second = gateway.seal(1, FrameKind::MutationRequest, b"dos");
        let third = gateway.seal(2, FrameKind::FusionNotice, b"tres");

        assert!(gateway.translate(&first).is_ok());
        assert!(gateway.translate(&second).is_ok());
        // Repetición del primero: firma válida, pero la secuencia retrocede.
        let replay = gateway.translate(&first);
        assert!(replay.is_err());
        if let Err(error) = &replay {
            assert_eq!(
                error,
                &KernelError::SequenceRegression {
                    expected: 2,
                    found: 0,
                }
            );
        }
        // El salto hacia delante es legal: se exige monotonía, no contigüidad.
        assert!(gateway.translate(&third).is_ok());
        assert_eq!(gateway.next_sequence(), 3);
        assert_eq!(gateway.counters().accepted, 3);
        assert_eq!(gateway.counters().tampered, 1);
        assert_eq!(gateway.counters().rejected, 1);
        assert_eq!(gateway.counters().oversized, 0);
    }

    #[test]
    fn canal_tipado_y_verificado() {
        let key = ast_dna::golden_key(b"bara:pruebas:canal");
        let mut link = SynapseLink::open(key);
        assert_eq!(link.sent(), 0);
        assert_eq!(link.gateway().key_id(), ast_dna::key_id(&key));
        assert_eq!(link.send(FrameKind::KernelQuery, b"consulta"), Ok(0));
        assert!(link.send(FrameKind::MutationRequest, b"alta").is_ok());
        assert!(link.send(FrameKind::CellReport, b"informe").is_ok());
        assert_eq!(link.sent(), 3);
        assert!(link.send(FrameKind::FusionNotice, b"aviso").is_ok());
        assert_eq!(link.sent(), 4);

        // Un marco manipulado en tránsito jamás se entrega (pero se cuenta).
        let forged = {
            let other_body = wire_body(&link, 4, b"aviso-falso");
            swap_body(
                &link.gateway().seal(4, FrameKind::FusionNotice, b"aviso"),
                &other_body,
            )
        };
        assert!(link.inject(&forged));

        let frames = link.drain();
        assert_eq!(frames.len(), 4);
        assert_eq!(
            frames.first().map(|frame| frame.kind),
            Some(FrameKind::KernelQuery)
        );
        assert_eq!(frames.get(1).map(|frame| frame.sequence), Some(1));
        assert_eq!(
            frames.get(2).map(|frame| frame.kind),
            Some(FrameKind::CellReport)
        );
        assert_eq!(
            frames.get(3).map(|frame| frame.body.clone()),
            Some(b"aviso".to_vec())
        );
        assert_eq!(link.gateway().counters().accepted, 4);
        assert_eq!(link.gateway().counters().tampered, 1);
        assert_eq!(link.gateway().counters().rejected, 1);
        assert_eq!(
            link.gateway().next_sequence(),
            4,
            "el marco hostil no consume ventana"
        );
        assert!(matches!(link.receive(), Ok(None)));
    }

    // ─────────────────────────────────────────────────────────────────────
    // FASE 3.1 · Célula sandbox: la rama vive fuera del núcleo
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn celda_fork_aislado() {
        let kernel = genesis();
        let base = kernel.digest();
        let mut mutator = AutopoieticMutator::new(SEED);
        let cell = mutator.open_cell(kernel.read());
        assert_eq!(cell, 1, "los identificadores de célula empiezan en 1");
        assert_eq!(mutator.counters().cells, 1);
        assert!(mutator.journal_tail().is_some());

        let before = mutator.cell(cell).map(|found| found.branch_digest());
        assert!(before.is_some());
        let outcome = applied(&mut mutator, cell, &add("חכמ"));
        assert!(outcome.is_applied());
        let after = mutator.cell(cell).map(|found| found.branch_digest());
        assert_ne!(
            before, after,
            "la huella de la rama cambia con cada operación"
        );

        // El núcleo no cambió: ni huella, ni nodos, ni ADN, ni revisión.
        assert!(digest_eq(&kernel.digest(), &base));
        assert_eq!(kernel.nodes().len(), 2);
        assert_eq!(kernel.revision(), 0);
        assert!(kernel.verify());

        if let Some(found) = mutator.cell(cell) {
            assert_eq!(found.id(), cell);
            assert_eq!(found.node_count(), 3);
            assert_eq!(found.op_count(), 1);
            assert_eq!(found.records().len(), 1);
            assert!(found.faults().is_empty());
            assert_eq!(found.state(), CellState::Open);
            assert!(found.is_open());
            assert!(!found.is_poisoned());
            assert_eq!(found.base_revision(), 0);
            assert!(digest_eq(&found.base_digest(), &base));
            assert_eq!(found.base_label(), "pruebas.kernel");
            assert!(found.seal().is_none(), "sin propuesta no hay sello");
            assert!(found.seal_label().is_empty());
            assert!(found.ast().nodes.len() == found.node_count());
            assert!(found.label().contains(CellState::Open.glyph()));
            assert!(found.label().contains("rama "));
            assert_eq!(found.hazard_ceiling(), 0.20);
        }
        assert_eq!(mutator.counters().proposals, 0);
        assert_eq!(mutator.counters().traps, 0);
        assert_eq!(mutator.counters().isolations, 0);
    }

    #[test]
    fn celda_mutaciones_estructurales() {
        let kernel = genesis();
        let mut mutator = AutopoieticMutator::new(SEED);
        let cell = mutator.open_cell(kernel.read());

        // Alta conforme: crece sin sellarse.
        let grow = applied(&mut mutator, cell, &add("חכמ"));
        assert!(grow.is_applied());
        if let Some(record) = grow.record() {
            assert_eq!(record.op, 0);
            assert!(record.summary.contains("חכמ"));
            assert!(record.summary.contains("sin sello"));
        }
        // Alta con riesgo sobre el umbral: nace sellada bajo guarda שמר.
        let hot = applied(
            &mut mutator,
            cell,
            &Mutation::Add {
                root: "רזמ".to_string(),
                original: "legacy_riesgo".to_string(),
                arity: 3,
                ret: BaraType::List,
                hazard: 0.90,
                truth: 0.40,
                falsity: 0.20,
            },
        );
        assert!(hot.is_applied());
        if let Some(record) = hot.record() {
            assert!(record.summary.contains("sellado al nacer"));
        }

        // Operaciones sobre nodos existentes.
        assert!(applied(
            &mut mutator,
            cell,
            &Mutation::Retarget {
                index: 0,
                ret: BaraType::Text
            }
        )
        .is_applied());
        assert!(applied(&mut mutator, cell, &Mutation::Rewire { index: 1, arity: 4 }).is_applied());
        assert!(applied(
            &mut mutator,
            cell,
            &Mutation::Harden {
                index: 1,
                delta: 0.05
            }
        )
        .is_applied());

        assert!(applied(&mut mutator, cell, &Mutation::Negate { index: 1 }).is_applied());
        assert!(applied(&mut mutator, cell, &Mutation::Seal { index: 0 }).is_applied());

        if let Some(found) = mutator.cell(cell) {
            assert_eq!(found.node_count(), 4);
            assert_eq!(found.op_count(), 7);
            assert!(found.faults().is_empty());
            assert!(
                found.is_open(),
                "ninguna operación legal deja la célula en cuarentena"
            );
            let first = found.records().first().map(|record| record.digest);
            let last = found.records().last().map(|record| record.digest);
            assert_ne!(first, last, "cada operación re-huella la rama");
            let texts = found
                .nodes()
                .iter()
                .filter(|node| node.ret == BaraType::Text)
                .count();
            assert_eq!(texts, 1, "Retarget cambió el tipo del primer nodo");
            assert!(found.nodes().iter().any(|node| node.sanitized));
            assert_eq!(found.hazard_ceiling(), 0.90);
            if let Some(node) = found.nodes().get(1) {
                assert_eq!(node.arity, 4, "Rewire ajustó la aridad");
                assert!(
                    node.valence.falsity_mass() > 0.9,
                    "Negate invirtió la valencia"
                );
                assert!(node.hazard < 0.10, "Harden rebajó el riesgo");
            }
        }

        // Un índice inexistente no rompe nada: se convierte en fallo contenido.
        let missing = mutator.apply(
            cell,
            &Mutation::Retarget {
                index: 99,
                ret: BaraType::Text,
            },
        );
        assert!(matches!(&missing, Ok(outcome) if outcome.is_trapped()));
        if let Ok(outcome) = &missing {
            assert!(fault_text(outcome).contains("nodo 99 inexistente"));
        }
    }

    #[test]
    fn celda_fallo_atrapado_no_toca_el_nucleo() {
        let kernel = genesis();
        let base = kernel.digest();
        let mut mutator = AutopoieticMutator::new(SEED);
        let cell = mutator.open_cell(kernel.read());
        assert!(applied(&mut mutator, cell, &add("חכמ")).is_applied());
        let branch_before = mutator.cell(cell).map(|found| found.branch_digest());

        // Índice inexistente: la operación muere dentro de la célula.
        let trapped = mutator.apply(
            cell,
            &Mutation::Retarget {
                index: 9,
                ret: BaraType::Text,
            },
        );
        assert!(trapped.is_ok(), "el contenedor siempre responde");
        if let Ok(outcome) = &trapped {
            assert!(outcome.is_trapped());
            assert!(outcome.record().is_none());
            assert!(fault_text(outcome).contains("nodo 9 inexistente"));
            if let Some(fault) = outcome.fault() {
                assert_eq!(
                    fault.op, 1,
                    "el fallo no consume el registro de operaciones"
                );
            }
        }
        if let Some(found) = mutator.cell(cell) {
            assert!(found.is_poisoned());
            assert_eq!(found.state(), CellState::Quarantined);
            assert_eq!(found.faults().len(), 1);
            assert_eq!(found.op_count(), 1, "la rama se queda como estaba");
            assert_eq!(Some(found.branch_digest()), branch_before);
            assert!(found.seal().is_none());
        }
        assert_eq!(mutator.counters().traps, 1);
        assert_eq!(mutator.counters().isolations, 1);

        // El núcleo no cambió en absoluto: no había camino hacia él.
        assert!(digest_eq(&kernel.digest(), &base));
        assert_eq!(kernel.nodes().len(), 2);
        assert_eq!(kernel.revision(), 0);
        assert!(kernel.verify());

        // La célula en cuarentena ya no admite nada, ni operaciones ni propuestas.
        let again = mutator.apply(cell, &add("עדר"));
        assert!(matches!(&again, Ok(outcome) if outcome.is_trapped()));
        if let Ok(outcome) = &again {
            assert!(fault_text(outcome).contains("cuarentena"));
        }
        assert_eq!(mutator.counters().traps, 2);
        assert_eq!(mutator.counters().isolations, 2);
        let refused = mutator.propose(kernel.read(), cell, &green());
        assert!(matches!(&refused, Err(MutatorError::CellPoisoned { id }) if *id == cell));
        assert_eq!(mutator.counters().proposals, 0);
        assert_eq!(mutator.counters().rejections, 0);
    }

    #[test]
    fn celda_capacidad_y_presupuesto() {
        let capacity_kernel =
            KernelCore::genesis("pruebas.capacidad", ast_of(MAX_CELL_NODES - 2), SEED);
        let mut mutator = AutopoieticMutator::new(SEED);
        let cell = mutator.open_cell(capacity_kernel.read());
        assert!(applied(&mut mutator, cell, &add("חכמ")).is_applied());
        assert!(applied(&mut mutator, cell, &add("עדר")).is_applied());
        assert_eq!(
            mutator.cell(cell).map(|found| found.node_count()),
            Some(MAX_CELL_NODES)
        );
        let overflow = mutator.apply(cell, &add("רזמ"));
        assert!(matches!(&overflow, Ok(outcome) if outcome.is_trapped()));
        if let Ok(outcome) = &overflow {
            assert!(fault_text(outcome).contains("célula llena"));
        }
        assert_eq!(mutator.counters().traps, 1);

        // Presupuesto de operaciones: 64 y ni una más.
        let mut budget = AutopoieticMutator::new(SEED);
        let budget_cell = budget.open_cell(capacity_kernel.read());
        for _ in 0..MAX_CELL_OPS {
            let outcome = applied(
                &mut budget,
                budget_cell,
                &Mutation::Retarget {
                    index: 0,
                    ret: BaraType::Text,
                },
            );
            assert!(outcome.is_applied());
        }
        assert_eq!(
            budget.cell(budget_cell).map(|found| found.op_count()),
            Some(MAX_CELL_OPS)
        );
        let exhausted = budget.apply(budget_cell, &Mutation::Seal { index: 0 });
        assert!(matches!(&exhausted, Ok(outcome) if outcome.is_trapped()));
        if let Ok(outcome) = &exhausted {
            assert!(fault_text(outcome).contains("presupuesto agotado"));
        }
        assert_eq!(budget.counters().traps, 1);
        // El presupuesto no depende del tamaño del árbol: nada se corrompió.
        assert_eq!(
            budget.cell(budget_cell).map(|found| found.node_count()),
            Some(MAX_CELL_NODES - 2)
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // FASE 2 · Autoevaluación estática Shoresh (nueve reglas)
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn auditoria_nueve_reglas() {
        let audit = audit_ast(&ast_genesis());
        assert_eq!(audit.checks.len(), 9);
        assert!(audit.passed());
        assert_eq!(audit.score(), (9, 9));
        assert!(audit.failed().is_empty());
        assert!(audit.label().contains("9/9"));
        assert!(audit.label().contains("✓"));

        let labels = [
            "plan.no-vacio",
            "aridad.acotada",
            "raiz.triconsonantal",
            "raiz.unica",
            "masas.en-rango",
            "riesgo.en-rango",
            "tipo.declarado",
            "guarda.sello-coherente",
            "huella.determinista",
        ];
        for label in labels {
            let found = audit.check(label);
            assert!(found.is_some(), "falta la regla {label}");
            if let Some(check) = found {
                assert!(check.passed, "la regla {label} debería cumplirse");
                assert!(!check.detail.is_empty());
            }
        }
        // La huella no vacía de un parche es reproducible y sensible a la etiqueta.
        assert!(digest_eq(
            &ast_fingerprint("x", &ast_genesis()),
            &ast_fingerprint("x", &ast_genesis())
        ));
        assert!(!digest_eq(
            &ast_fingerprint("x", &ast_genesis()),
            &ast_fingerprint("y", &ast_genesis())
        ));
        assert!(!digest_eq(
            &ast_fingerprint("x", &ast_genesis()),
            &ast_fingerprint("x", &ast_of(3))
        ));
    }

    #[test]
    fn auditoria_detecta_violaciones() {
        // 1. Plan vacío: sin nodos no hay parche.
        let empty = audit_ast(&ShoreshAst { nodes: Vec::new() });
        assert!(!empty.passed());
        assert_eq!(empty.failed().len(), 1);
        assert!(!empty
            .check("plan.no-vacio")
            .map(|check| check.passed)
            .unwrap_or(true));
        assert!(empty.label().contains("✗"));

        // 2. Aridad por encima del tope.
        let wide = audit_ast(&ShoreshAst {
            nodes: vec![node("אמת", MAX_ARITY + 1, 0.1, 0.9, 0.1)],
        });
        assert!(!wide
            .check("aridad.acotada")
            .map(|check| check.passed)
            .unwrap_or(true));

        // 3. Raíz no triconsonántica.
        let foreign = audit_ast(&ShoreshAst {
            nodes: vec![node("abc", 2, 0.1, 0.9, 0.1)],
        });
        assert!(!foreign
            .check("raiz.triconsonantal")
            .map(|check| check.passed)
            .unwrap_or(true));

        // 4. Raíces repetidas: un árbol es un conjunto de raíces.
        let repeated = audit_ast(&ShoreshAst {
            nodes: vec![node_sound("אמת"), node_sound("אמת")],
        });
        assert!(!repeated
            .check("raiz.unica")
            .map(|check| check.passed)
            .unwrap_or(true));

        // 5. Masas fuera de [0, 1] (estado no recortado a propósito).
        let bad_mass = audit_ast(&ShoreshAst {
            nodes: vec![ShoreshNode {
                valence: QuantumState::Superposition {
                    alpha: 2.0,
                    beta: 0.0,
                },
                ..node_sound("אמת")
            }],
        });
        assert!(!bad_mass
            .check("masas.en-rango")
            .map(|check| check.passed)
            .unwrap_or(true));

        // 6. Riesgo fuera de [0, 1].
        let bad_risk = audit_ast(&ShoreshAst {
            nodes: vec![node("אמת", 2, 1.5, 0.9, 0.1)],
        });
        assert!(!bad_risk
            .check("riesgo.en-rango")
            .map(|check| check.passed)
            .unwrap_or(true));

        // 7. Tipo sin declarar.
        let undeclared = audit_ast(&ShoreshAst {
            nodes: vec![ShoreshNode {
                ret: BaraType::Unknown,
                ..node_sound("אמת")
            }],
        });
        assert!(!undeclared
            .check("tipo.declarado")
            .map(|check| check.passed)
            .unwrap_or(true));

        // 8. Guarda שמר: riesgo sobre el umbral obliga a sellar.
        let hot = audit_ast(&ShoreshAst {
            nodes: vec![node("אמת", 2, 0.9, 0.9, 0.1)],
        });
        assert!(hot
            .check("riesgo.en-rango")
            .map(|check| check.passed)
            .unwrap_or(false));
        assert!(!hot
            .check("guarda.sello-coherente")
            .map(|check| check.passed)
            .unwrap_or(true));
        let sealed = audit_ast(&ShoreshAst {
            nodes: vec![ShoreshNode {
                sanitized: true,
                ..node("אמת", 2, 0.9, 0.9, 0.1)
            }],
        });
        assert!(sealed.passed(), "sellado, el mismo riesgo es coherente");

        // La huella determinista nunca falla: se recalcula dos veces.
        for audit in [&empty, &wide, &foreign, &repeated, &bad_mass, &hot] {
            assert!(audit
                .check("huella.determinista")
                .map(|check| check.passed)
                .unwrap_or(false));
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // FASE 3.2 · Retícula FOUR de Belnap: tablas iguales a las masas
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn belnap_tablas_equivalentes_a_masas() {
        // Sobre las cuatro esquinas: la clase de las masas combinadas es la
        // operación del retículo, sin excepciones.
        for left in BelnapValue::ALL {
            for right in BelnapValue::ALL {
                let (truth_a, falsity_a) = left.corners();
                let (truth_b, falsity_b) = right.corners();
                assert_eq!(
                    BelnapValue::from_masses(truth_a.min(truth_b), falsity_a.max(falsity_b)),
                    left.conjunction(right)
                );
                assert_eq!(
                    BelnapValue::from_masses(truth_a.max(truth_b), falsity_a.min(falsity_b)),
                    left.disjunction(right)
                );
                assert_eq!(
                    BelnapValue::from_masses(truth_a.min(truth_b), falsity_a.min(falsity_b)),
                    left.consensus(right)
                );
                assert_eq!(
                    BelnapValue::from_masses(truth_a.max(truth_b), falsity_a.max(falsity_b)),
                    left.union(right)
                );
                // Y lo mismo a través de las masas intermedias de la operación.
                let (truth, falsity) = left.conjoined_masses(right);
                assert_eq!(
                    BelnapValue::from_masses(truth, falsity),
                    left.conjunction(right)
                );
                let (truth, falsity) = left.united_masses(right);
                assert_eq!(BelnapValue::from_masses(truth, falsity), left.union(right));
            }
        }

        // Sobre el continuo: 625 pares de masas (cinco valores por masa).
        let grid = [0.0_f64, 0.25, 0.50, 0.75, 1.0];
        let mut pairs = 0usize;
        for truth_a in grid {
            for falsity_a in grid {
                for truth_b in grid {
                    for falsity_b in grid {
                        let left = BelnapValue::from_masses(truth_a, falsity_a);
                        let right = BelnapValue::from_masses(truth_b, falsity_b);
                        assert_eq!(
                            BelnapValue::from_masses(
                                truth_a.min(truth_b),
                                falsity_a.max(falsity_b)
                            ),
                            left.conjunction(right)
                        );
                        assert_eq!(
                            BelnapValue::from_masses(
                                truth_a.max(truth_b),
                                falsity_a.min(falsity_b)
                            ),
                            left.disjunction(right)
                        );
                        assert_eq!(
                            BelnapValue::from_masses(
                                truth_a.min(truth_b),
                                falsity_a.min(falsity_b)
                            ),
                            left.consensus(right)
                        );
                        assert_eq!(
                            BelnapValue::from_masses(
                                truth_a.max(truth_b),
                                falsity_a.max(falsity_b)
                            ),
                            left.union(right)
                        );
                        pairs = pairs.saturating_add(1);
                    }
                }
            }
        }
        assert_eq!(pairs, 625);

        // El umbral de designación es el mismo en las dos direcciones.
        assert_eq!(BelnapValue::from_masses(0.5, 0.0), BelnapValue::True);
        assert_eq!(BelnapValue::from_masses(0.0, 0.5), BelnapValue::False);
        assert_eq!(BelnapValue::from_masses(0.5, 0.5), BelnapValue::Both);
        assert_eq!(BelnapValue::from_masses(0.49, 0.49), BelnapValue::Neither);
        assert_eq!(DESIGNATION_THRESHOLD, 0.5);
    }

    #[test]
    fn belnap_viaja_al_runtime_sin_perdida() {
        for value in BelnapValue::ALL {
            let state = value.to_state();
            assert_eq!(state.belnap(), value.corners());
            assert_eq!(BelnapValue::from_state(&state), value);
            assert_eq!(BelnapValue::from_observation(value.to_observation()), value);
            assert_eq!(value.to_observation().glyph(), value.glyph());
            assert!(state.label().contains("PARACONSISTENT"));
            assert!(value.label().contains(value.name()));
            assert!(value.glyph().chars().count() > 0);
        }
        // La negación del runtime coincide con la del retículo.
        for value in BelnapValue::ALL {
            assert_eq!(
                BelnapValue::from_state(&value.to_state().negate()),
                value.negate()
            );
            assert_eq!(value.complement(), value.negate());
        }
    }

    #[test]
    fn voto_de_nodo_combina_valencia_y_estructura() {
        // Valencia ⊤ y estructura sana ⇒ ⊤.
        assert_eq!(
            BelnapMatrix::node_vote(&node_sound("אמת")),
            BelnapValue::True
        );
        // Valencia contradictoria con estructura sana ⇒ ⊤∧⊥.
        assert_eq!(
            BelnapMatrix::node_vote(&node("אמת", 2, 0.10, 1.0, 1.0)),
            BelnapValue::Both
        );
        // Valencia indeterminada con estructura sana ⇒ ∅.
        assert_eq!(
            BelnapMatrix::node_vote(&node("אמת", 2, 0.10, 0.20, 0.20)),
            BelnapValue::Neither
        );
        // Valencia ⊤ pero guarda incoherente ⇒ ⊥: la estructura manda.
        let unsound = node("אמת", 2, 0.90, 0.90, 0.10);
        assert!(!unsound.sanitized);
        assert_eq!(BelnapMatrix::node_vote(&unsound), BelnapValue::False);
        // Sin tipo declarado tampoco pasa la estructura.
        let undeclared = ShoreshNode {
            ret: BaraType::Unknown,
            ..node_sound("אמת")
        };
        assert_eq!(BelnapMatrix::node_vote(&undeclared), BelnapValue::False);
        // Raíz no triconsonántica ⇒ ⊥.
        assert_eq!(
            BelnapMatrix::node_vote(&node("abc", 2, 0.10, 0.90, 0.10)),
            BelnapValue::False
        );
        // Las cuatro esquinas declaran sus masas canónicas.
        let corners = BelnapMatrix::corners();
        assert_eq!(corners.len(), 4);
        for (value, truth, falsity) in corners {
            assert_eq!(value.corners(), (truth, falsity));
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // FASE 3.2 · Leyes del retículo y juicio tetravalente
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn belnap_leyes_del_reticulo() {
        for value in BelnapValue::ALL {
            assert_eq!(value.negate().negate(), value, "la negación es involutiva");
            assert_eq!(value.conjunction(value), value, "∧ es idempotente");
            assert_eq!(value.disjunction(value), value, "∨ es idempotente");
            assert_eq!(value.consensus(value), value, "⊓ es idempotente");
            assert_eq!(value.union(value), value, "⊔ es idempotente");
            assert_eq!(
                value.conjunction(BelnapValue::True),
                value,
                "⊤ es neutro de ∧"
            );
            assert_eq!(
                value.disjunction(BelnapValue::False),
                value,
                "⊥ es neutro de ∨"
            );
            assert_eq!(
                value.consensus(BelnapValue::Both),
                value,
                "⊤∧⊥ es neutro de ⊓"
            );
            assert_eq!(value.union(BelnapValue::Neither), value, "∅ es neutro de ⊔");
            assert_eq!(BelnapValue::from_index(value.index()), Some(value));
            assert_eq!(value.index(), BelnapValue::ALL[value.index()].index());
            assert_eq!(
                value.is_determined(),
                value == BelnapValue::True || value == BelnapValue::False
            );
            assert_eq!(
                value.is_designated(),
                value == BelnapValue::True || value == BelnapValue::Both
            );
            assert_eq!(value.is_contradiction(), value == BelnapValue::Both);
            assert_eq!(value.is_unknown(), value == BelnapValue::Neither);
            assert!(value.glyph().chars().count() <= 5);
        }
        assert_eq!(BelnapValue::from_index(4), None);
        assert_eq!(BelnapValue::ALL.len(), 4);
        assert_eq!(BelnapValue::Both.negate(), BelnapValue::Both);
        assert_eq!(BelnapValue::Neither.negate(), BelnapValue::Neither);
        assert_eq!(
            BelnapValue::True.implication(BelnapValue::False),
            BelnapValue::False
        );
        assert_eq!(
            BelnapValue::False.implication(BelnapValue::Both),
            BelnapValue::True
        );

        for left in BelnapValue::ALL {
            for right in BelnapValue::ALL {
                // Conmutatividad de las cuatro operaciones.
                assert_eq!(left.conjunction(right), right.conjunction(left));
                assert_eq!(left.disjunction(right), right.disjunction(left));
                assert_eq!(left.consensus(right), right.consensus(left));
                assert_eq!(left.union(right), right.union(left));
                // Leyes de De Morgan en los dos órdenes.
                assert_eq!(
                    left.negate().conjunction(right.negate()),
                    left.disjunction(right).negate()
                );
                assert_eq!(
                    left.negate().disjunction(right.negate()),
                    left.conjunction(right).negate()
                );
                // La negación **conserva** el orden de información (es su
                // automorfismo): por eso preserva ⊓ y ⊔ sin intercambiarlos.
                assert_eq!(
                    left.negate().consensus(right.negate()),
                    left.consensus(right).negate(),
                    "¬ conserva ⊓"
                );
                assert_eq!(
                    left.negate().union(right.negate()),
                    left.union(right).negate(),
                    "¬ conserva ⊔"
                );
                // ⊤ (ambas polaridades) es neutro de ⊓; ∅ lo es de ⊔.
                assert_eq!(left.consensus(BelnapValue::Both), left);
                assert_eq!(left.union(BelnapValue::Neither), left);
                // ⊤ es neutro de ∧: la designación se preserva.
                assert_eq!(
                    left.conjunction(BelnapValue::True).is_designated(),
                    left.is_designated()
                );
                // El consenso es más exigente que la conjunción (⊓ ≤ ∧).
                let consensus_is_designated = left.consensus(right).is_designated();
                let conjunction_is_designated = left.conjunction(right).is_designated();
                assert!(!consensus_is_designated || conjunction_is_designated);
                // Absorción clásica entre ∧ y ∨.
                assert_eq!(
                    left.conjunction(left.disjunction(right)),
                    left,
                    "∧ absorbe ∨"
                );
                assert_eq!(
                    left.disjunction(left.conjunction(right)),
                    left,
                    "∨ absorbe ∧"
                );
            }
        }

        // Asociatividad de las cuatro operaciones sobre los 64 triples.
        let mut triples = 0usize;
        for first in BelnapValue::ALL {
            for second in BelnapValue::ALL {
                for third in BelnapValue::ALL {
                    assert_eq!(
                        first.conjunction(second).conjunction(third),
                        first.conjunction(second.conjunction(third)),
                        "∧ es asociativa"
                    );
                    assert_eq!(
                        first.disjunction(second).disjunction(third),
                        first.disjunction(second.disjunction(third)),
                        "∨ es asociativa"
                    );
                    assert_eq!(
                        first.consensus(second).consensus(third),
                        first.consensus(second.consensus(third)),
                        "⊓ es asociativa"
                    );
                    assert_eq!(
                        first.union(second).union(third),
                        first.union(second.union(third)),
                        "⊔ es asociativa"
                    );
                    triples = triples.saturating_add(1);
                }
            }
        }
        assert_eq!(triples, 64);
    }

    #[test]
    fn juicio_admite_parche_valido() {
        let kernel = genesis();
        let candidate = ShoreshAst {
            nodes: vec![node_sound("אמת"), node_sound("חכמ")],
        };
        let verdict = BelnapMatrix::evaluate(kernel.read(), &candidate, &green(), true);
        assert_eq!(verdict.periferia, BelnapValue::True);
        assert_eq!(verdict.nucleo, BelnapValue::True);
        assert_eq!(verdict.union, BelnapValue::True);
        assert!(verdict.admits_fusion());
        assert!(verdict.is_bounded());
        assert_eq!(verdict.nodes, 2);
        assert_eq!(verdict.contradictions, 0);
        assert_eq!(verdict.unknowns, 0);
        assert_eq!(verdict.violations, 0);
        assert_eq!(verdict.tests_passed, 5);
        assert_eq!(verdict.tests_failed, 0);
        assert!(verdict.signature_ok);
        assert!(verdict.kernel_ok);
        assert!(verdict.truth > 0.5 && verdict.truth <= 1.0);
        assert!(verdict.falsity < 0.5);
        assert!(verdict.reason().contains("admitida"));
        assert!(verdict.label().contains("Belnap"));
        assert_eq!(
            BelnapMatrix::agreement(verdict.periferia, verdict.nucleo),
            BelnapValue::True
        );
    }

    #[test]
    fn juicio_detiene_contradiccion() {
        let kernel = genesis();
        let candidate = ShoreshAst {
            nodes: vec![node_sound("אמת"), node("דעת", 2, 0.10, 1.0, 1.0)],
        };
        let verdict = BelnapMatrix::evaluate(kernel.read(), &candidate, &green(), true);
        assert_eq!(verdict.periferia, BelnapValue::Both);
        assert!(
            !verdict.admits_fusion(),
            "una contradicción detiene la fusión"
        );
        assert_eq!(verdict.contradictions, 1);
        assert_eq!(verdict.unknowns, 0);
        assert_eq!(verdict.violations, 0);
        assert_eq!(verdict.union, BelnapValue::Both);
        assert!(verdict.reason().contains("contradicci"));
        assert!(verdict.is_bounded());
        assert_eq!(verdict.union, BelnapValue::Both);
    }

    #[test]
    fn juicio_detiene_evidencia_ausente_o_roja() {
        let kernel = genesis();
        let candidate = ShoreshAst {
            nodes: vec![node_sound("אמת")],
        };

        let without = BelnapMatrix::evaluate(kernel.read(), &candidate, &Evidence::none(), true);
        assert_eq!(without.periferia, BelnapValue::Neither);
        assert!(!without.admits_fusion());
        assert_eq!(without.tests_passed, 0);
        assert_eq!(without.tests_failed, 0);
        assert!(without.reason().contains("sin evidencia"));
        assert_eq!(Evidence::none().vote(), BelnapValue::Neither);
        assert!(!Evidence::none().is_green());

        let red = Evidence::red("bara.sandbox.suite", 1, 2);
        assert_eq!(red.vote(), BelnapValue::False);
        let rejected = BelnapMatrix::evaluate(kernel.read(), &candidate, &red, true);
        assert_eq!(rejected.periferia, BelnapValue::False);
        assert!(!rejected.admits_fusion());
        assert_eq!(rejected.tests_failed, 2);
        assert!(rejected.reason().contains("rojo"));

        // El sello roto detiene la fusión aunque todo lo demás sea ⊤.
        let unsigned = BelnapMatrix::evaluate(kernel.read(), &candidate, &green(), false);
        assert!(!unsigned.signature_ok);
        assert!(!unsigned.admits_fusion());
        assert_eq!(unsigned.periferia, BelnapValue::False);
        assert!(unsigned.reason().contains("firma"));

        // La evidencia es determinista en su huella y en su voto.
        assert!(digest_eq(&green().digest(), &green().digest()));
        assert!(green().is_green());
        assert_eq!(green().vote(), BelnapValue::True);
        assert!(green().label().contains("no determinista"));
    }

    #[test]
    fn juicio_detiene_violacion_estructural() {
        let kernel = genesis();
        let candidate = ShoreshAst {
            nodes: vec![node_sound("דעת"), node("אמת", 2, 0.90, 0.90, 0.10)],
        };
        let verdict = BelnapMatrix::evaluate(kernel.read(), &candidate, &green(), true);
        assert_eq!(
            verdict.violations, 1,
            "la guarda שמר incumplida viola la estructura"
        );
        assert_eq!(verdict.periferia, BelnapValue::False);
        assert!(!verdict.admits_fusion());
        assert!(verdict.reason().contains("inadmisibles"));
        // El nodo sano sigue aportando su verdad: sólo el infractor resta.
        assert!(verdict.truth < 0.5);
        assert!(verdict.falsity > 0.9);
        // Una rama vacía no puede ser ⊤: la ausencia de nodos es indeterminación.
        let empty = BelnapMatrix::evaluate(
            kernel.read(),
            &ShoreshAst { nodes: Vec::new() },
            &green(),
            true,
        );
        assert_eq!(empty.nodes, 0);
        assert_eq!(empty.periferia, BelnapValue::Neither);
        assert!(!empty.admits_fusion());
    }

    // ─────────────────────────────────────────────────────────────────────
    // FASE 3.3 · Propuesta sellada y fusión atómica (CAS optimista)
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn fusion_atomica_y_determinista() {
        let kernel = genesis();
        let base = kernel.digest();
        let mut mutator = AutopoieticMutator::new(SEED);
        let cell = mutator.open_cell(kernel.read());
        assert!(applied(&mut mutator, cell, &add("חכמ")).is_applied());

        let proposal = mutator.propose(kernel.read(), cell, &green());
        assert!(proposal.is_ok());
        let id = proposal.unwrap_or(0);
        assert_eq!(id, 1, "las propuestas empiezan en 1");
        if let Some(found) = mutator.proposal(id) {
            assert!(found.admits_fusion());
            assert!(found.audit.passed());
            assert!(found.verdict.admits_fusion());
            assert_eq!(found.nodes().len(), 3);
            assert_eq!(found.operations, 1);
            assert_eq!(found.base_revision, 0);
            assert_eq!(found.cell, cell);
            assert!(digest_eq(&found.base_digest, &base));
            assert!(digest_eq(
                &found.fingerprint(),
                &ast_fingerprint(&found.candidate_label, &found.candidate)
            ));
            assert!(found.label().contains("propuesta #1"));
            assert!(found.evidence.is_green());
        }
        // La célula queda sellada: su plan está congelado.
        if let Some(found) = mutator.cell(cell) {
            assert_eq!(found.state(), CellState::Sealed);
            assert!(!found.is_open());
            assert!(found.seal().is_some());
            assert!(found.seal_label().contains("sandbox1"));
        }
        let frozen = mutator.apply(cell, &add("עדר"));
        assert!(matches!(&frozen, Ok(outcome) if outcome.is_trapped()));
        if let Ok(outcome) = &frozen {
            assert!(fault_text(outcome).contains("sellada"));
        }

        let fused = mutator.commit(&kernel, id);
        assert!(fused.is_ok(), "una propuesta conforme debe fusionarse");
        let next = fused.unwrap_or_else(|_| kernel.clone());
        assert_eq!(next.revision(), 1);
        assert!(next.verify());
        assert_eq!(next.nodes().len(), 3);
        assert_eq!(next.key_id(), kernel.key_id());
        assert_eq!(next.label(), "pruebas.kernel.sandbox1");
        assert!(!digest_eq(&next.digest(), &base));
        assert_eq!(mutator.counters().fusions, 1);
        assert_eq!(mutator.counters().rejections, 0);
        assert_eq!(
            mutator.counters().cells,
            0,
            "la célula se cierra al fusionar"
        );

        // El núcleo anterior sigue intacto y válido: la fusión es atómica.
        assert!(digest_eq(&kernel.digest(), &base));
        assert_eq!(kernel.revision(), 0);
        assert_eq!(kernel.nodes().len(), 2);
        assert!(kernel.verify());

        // Determinismo: otra instancia con la misma semilla forja el mismo núcleo.
        let mut twin = AutopoieticMutator::new(SEED);
        let twin_cell = twin.open_cell(genesis().read());
        assert_eq!(twin_cell, cell);
        assert!(applied(&mut twin, twin_cell, &add("חכמ")).is_applied());
        let twin_proposal = twin.propose(genesis().read(), twin_cell, &green());
        assert!(twin_proposal.is_ok());
        let twin_fused = twin_proposal
            .map(|twin_id| twin.commit(&genesis(), twin_id))
            .unwrap_or_else(|_| Err(MutatorError::ProposalUnknown { id: 0 }));
        let twin_next = twin_fused.unwrap_or_else(|_| next.clone());
        assert!(digest_eq(&twin_next.digest(), &next.digest()));
        assert_eq!(twin_next.label(), next.label());
    }

    #[test]
    fn fusion_detecta_adn_manipulado() {
        let kernel = genesis();
        let mut mutator = AutopoieticMutator::new(SEED);
        let cell = mutator.open_cell(kernel.read());
        assert!(applied(&mut mutator, cell, &add("חכמ")).is_applied());
        let id = mutator.propose(kernel.read(), cell, &green()).unwrap_or(0);
        assert_eq!(id, 1);

        // 1. Sello retocado: el ADN deja de verificar.
        if let Some(found) = mutator.proposal_mut(id) {
            found.dna.signature[0] ^= 0x01;
        }
        let broken_seal = mutator.commit(&kernel, id);
        assert!(matches!(
            &broken_seal,
            Err(MutatorError::DnaMismatch { label }) if label.contains("sandbox1")
        ));
        assert_eq!(mutator.counters().rejections, 1);
        assert_eq!(mutator.counters().fusions, 0);

        // 2. Árbol retocado sin volver a sellar: el ADN también lo cubre.
        if let Some(found) = mutator.proposal_mut(id) {
            if let Some(node) = found.candidate.nodes.first_mut() {
                node.hazard = 0.30;
            }
        }
        let broken_tree = mutator.commit(&kernel, id);
        assert!(matches!(
            &broken_tree,
            Err(MutatorError::DnaMismatch { .. })
        ));
        assert_eq!(mutator.counters().rejections, 2);

        // El núcleo nunca se tocó y sigue siendo el de la revisión 0.
        assert!(kernel.verify());
        assert_eq!(kernel.nodes().len(), 2);
        assert_eq!(kernel.revision(), 0);
    }

    #[test]
    fn fusion_cas_y_propuestas_desconocidas() {
        let kernel = genesis();
        let mut mutator = AutopoieticMutator::new(SEED);
        let cell = mutator.open_cell(kernel.read());
        assert!(applied(&mut mutator, cell, &add("חכמ")).is_applied());
        let id = mutator.propose(kernel.read(), cell, &green()).unwrap_or(0);
        assert_eq!(id, 1);

        // Una propuesta que no existe no consume nada.
        let unknown = mutator.commit(&kernel, 999);
        assert!(matches!(
            &unknown,
            Err(MutatorError::ProposalUnknown { id: 999 })
        ));
        assert_eq!(mutator.counters().rejections, 0);
        assert_eq!(mutator.counters().fusions, 0);

        let fused = mutator.commit(&kernel, id);
        assert!(fused.is_ok());
        let next = fused.unwrap_or_else(|_| kernel.clone());
        assert_eq!(mutator.counters().fusions, 1);

        // El CAS es optimista: la propuesta se auditó sobre la revisión 0.
        let stale = mutator.commit(&next, id);
        assert!(matches!(
            &stale,
            Err(MutatorError::FusionStale {
                expected: 0,
                found: 1
            })
        ));
        assert_eq!(mutator.counters().rejections, 1);
        assert_eq!(mutator.counters().fusions, 1);
        assert_eq!(next.revision(), 1);
        assert_eq!(kernel.revision(), 0);
    }

    #[test]
    fn fusion_rechaza_auditoria_y_juicio() {
        let kernel = genesis();

        // 1. Tipo sin declarar: la auditoría detiene la fusión.
        let mut undeclared = AutopoieticMutator::new(SEED);
        let first_cell = undeclared.open_cell(kernel.read());
        let typed = applied(
            &mut undeclared,
            first_cell,
            &Mutation::Add {
                root: "חכמ".to_string(),
                original: "legacy_sin_tipo".to_string(),
                arity: 2,
                ret: BaraType::Unknown,
                hazard: 0.10,
                truth: 0.90,
                falsity: 0.10,
            },
        );
        assert!(typed.is_applied());
        let first = undeclared
            .propose(kernel.read(), first_cell, &green())
            .unwrap_or(0);
        if let Some(found) = undeclared.proposal(first) {
            assert!(!found.audit.passed());
            assert!(!found
                .audit
                .check("tipo.declarado")
                .map(|check| check.passed)
                .unwrap_or(true));
            assert_eq!(
                found.verdict.violations, 1,
                "el nodo sin tipo es inadmisible"
            );
        }
        let refused = undeclared.commit(&kernel, first);
        assert!(matches!(
            &refused,
            Err(MutatorError::AuditFailed { failed: 1 })
        ));
        assert_eq!(undeclared.counters().rejections, 1);
        assert_eq!(undeclared.counters().fusions, 0);

        // 2. Raíz repetida: un árbol es un conjunto de raíces.
        let mut repeated = AutopoieticMutator::new(SEED);
        let second_cell = repeated.open_cell(kernel.read());
        assert!(applied(&mut repeated, second_cell, &add("אמת")).is_applied());
        let second = repeated
            .propose(kernel.read(), second_cell, &green())
            .unwrap_or(0);
        if let Some(found) = repeated.proposal(second) {
            assert!(!found
                .audit
                .check("raiz.unica")
                .map(|check| check.passed)
                .unwrap_or(true));
        }
        let duplicated = repeated.commit(&kernel, second);
        assert!(matches!(
            &duplicated,
            Err(MutatorError::AuditFailed { failed: 1 })
        ));
        assert_eq!(repeated.counters().rejections, 1);

        // Ningún rechazo tocó el núcleo.
        assert!(kernel.verify());
        assert_eq!(kernel.nodes().len(), 2);
        assert_eq!(kernel.revision(), 0);
    }

    #[test]
    fn veto_belnap_both_y_rollback_por_release() {
        let kernel = genesis();
        let digest_before = kernel.digest();
        let revision_before = kernel.revision();
        let mut mutator = AutopoieticMutator::new(SEED);
        let cell = mutator.open_cell(kernel.read());
        // Valencia Both (truth=1, falsity=1): contradicción retenida → veto.
        assert!(applied(
            &mut mutator,
            cell,
            &Mutation::Add {
                root: "שפט".to_string(),
                original: "legacy_both".to_string(),
                arity: 1,
                ret: BaraType::Number,
                hazard: 0.0,
                truth: 1.0,
                falsity: 1.0,
            },
        )
        .is_applied());
        let id = mutator.propose(kernel.read(), cell, &green()).unwrap_or(0);
        if let Some(found) = mutator.proposal(id) {
            assert!(
                found.verdict.contradictions > 0 || found.verdict.periferia == BelnapValue::Both,
                "debía verse Both/contradicción"
            );
            assert!(!found.verdict.admits_fusion());
        }
        let refused = mutator.commit(&kernel, id);
        assert!(matches!(
            &refused,
            Err(MutatorError::VerdictRejected { .. })
        ));
        assert!(mutator.release(cell), "rollback: liberar la celda");
        assert_eq!(kernel.digest(), digest_before);
        assert_eq!(kernel.revision(), revision_before);
        assert!(mutator.cell(cell).is_none());
    }

    #[test]
    fn fusion_rechaza_indeterminacion() {
        let kernel = genesis();
        let mut mutator = AutopoieticMutator::new(SEED);
        let cell = mutator.open_cell(kernel.read());
        // Sin evidencia y con una valencia indeterminada: la auditoría pasa, el juicio no.
        let dubious = applied(
            &mut mutator,
            cell,
            &Mutation::Add {
                root: "חכמ".to_string(),
                original: "legacy_dudoso".to_string(),
                arity: 2,
                ret: BaraType::Number,
                hazard: 0.10,
                truth: 0.20,
                falsity: 0.20,
            },
        );
        assert!(dubious.is_applied());
        let id = mutator
            .propose(kernel.read(), cell, &Evidence::none())
            .unwrap_or(0);
        if let Some(found) = mutator.proposal(id) {
            assert!(found.audit.passed(), "la auditoría estática pasa");
            assert_eq!(found.verdict.unknowns, 1);
            assert!(!found.verdict.admits_fusion());
            assert!(found.verdict.reason().contains("sin evidencia"));
            assert!(!found.admits_fusion());
        }
        let indeterminate = mutator.commit(&kernel, id);
        assert!(matches!(
            &indeterminate,
            Err(MutatorError::VerdictRejected { .. })
        ));
        assert_eq!(mutator.counters().rejections, 1);
        assert_eq!(mutator.counters().fusions, 0);

        // Con evidencia en verde, el mismo plan indeterminado sigue sin fusionarse.
        let mut second = AutopoieticMutator::new(SEED);
        let second_cell = second.open_cell(kernel.read());
        assert!(applied(
            &mut second,
            second_cell,
            &Mutation::Add {
                root: "חכמ".to_string(),
                original: "legacy_dudoso".to_string(),
                arity: 2,
                ret: BaraType::Number,
                hazard: 0.10,
                truth: 0.20,
                falsity: 0.20,
            }
        )
        .is_applied());
        let second_id = second
            .propose(kernel.read(), second_cell, &green())
            .unwrap_or(0);
        if let Some(found) = second.proposal(second_id) {
            assert!(found.audit.passed());
            assert!(found.verdict.reason().contains("insuficiente"));
        }
        let still_stopped = second.commit(&kernel, second_id);
        assert!(matches!(
            &still_stopped,
            Err(MutatorError::VerdictRejected { .. })
        ));
        assert!(kernel.verify());
        assert_eq!(kernel.nodes().len(), 2);
    }

    #[test]
    fn plan_vacio_no_es_un_parche() {
        let kernel = genesis();
        let mut mutator = AutopoieticMutator::new(SEED);
        let cell = mutator.open_cell(kernel.read());
        assert!(applied(&mut mutator, cell, &Mutation::Remove { index: 0 }).is_applied());
        assert!(applied(&mut mutator, cell, &Mutation::Remove { index: 0 }).is_applied());
        if let Some(found) = mutator.cell(cell) {
            assert_eq!(found.node_count(), 0);
            assert_eq!(found.op_count(), 2, "la baja es una operación más");
        }
        // Fuera de rango: se atrapa en lugar de propagarse.
        let outside = mutator.apply(cell, &Mutation::Remove { index: 7 });
        assert!(matches!(&outside, Ok(outcome) if outcome.is_trapped()));
        if let Ok(outcome) = &outside {
            assert!(fault_text(outcome).contains("nodo 7 inexistente"));
        }
        assert_eq!(mutator.counters().traps, 1);

        // Propuesta con plan vacío: la auditoría la detiene y el diff la describe.
        let proposal = mutator.propose(kernel.read(), cell, &green());
        assert!(proposal.is_err(), "una célula en cuarentena no propone");
        assert!(matches!(&proposal, Err(MutatorError::CellPoisoned { .. })));

        let mut clean = AutopoieticMutator::new(SEED);
        let clean_cell = clean.open_cell(kernel.read());
        assert!(applied(&mut clean, clean_cell, &Mutation::Remove { index: 0 }).is_applied());
        assert!(applied(&mut clean, clean_cell, &Mutation::Remove { index: 0 }).is_applied());
        let empty = clean.propose(kernel.read(), clean_cell, &green());
        assert!(
            empty.is_ok(),
            "la propuesta se emite: quien decide es la auditoría"
        );
        let empty_id = empty.unwrap_or(0);
        if let Some(found) = clean.proposal(empty_id) {
            assert!(!found.audit.passed());
            assert_eq!(found.audit.score(), (8, 9));
            assert!(!found.admits_fusion());
            assert_eq!(found.diff.removed, 2);
            assert_eq!(found.diff.kept, 0);
            assert_eq!(found.diff.added, 0);
            assert_eq!(found.diff.changed, 0);
            assert!(!found.diff.is_empty());
        }
        let fused = clean.commit(&kernel, empty_id);
        assert!(matches!(
            &fused,
            Err(MutatorError::AuditFailed { failed: 1 })
        ));
        assert_eq!(clean.counters().rejections, 1);
        assert_eq!(clean.counters().fusions, 0);
        assert!(kernel.verify());
        assert_eq!(kernel.nodes().len(), 2);
    }

    // ─────────────────────────────────────────────────────────────────────
    // FASE 3.3 · Diff estructural, payload del IDE y ciclo completo
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn diff_posicional_y_estable() {
        let kernel = genesis();
        let mut mutator = AutopoieticMutator::new(SEED);
        let cell = mutator.open_cell(kernel.read());
        assert!(applied(&mut mutator, cell, &add("חכמ")).is_applied());
        assert!(applied(
            &mut mutator,
            cell,
            &Mutation::Retarget {
                index: 0,
                ret: BaraType::Text
            }
        )
        .is_applied());
        assert!(applied(&mut mutator, cell, &Mutation::Negate { index: 1 }).is_applied());
        let id = mutator.propose(kernel.read(), cell, &green()).unwrap_or(0);
        assert_eq!(id, 1);

        if let Some(found) = mutator.proposal(id) {
            let diff = &found.diff;
            assert_eq!(diff.cell, cell);
            assert_eq!(diff.base_revision, 0);
            assert_eq!(diff.candidate_revision, 1);
            assert_eq!(diff.base_label, "pruebas.kernel");
            assert!(diff.candidate_label.contains("sandbox1"));
            assert_eq!(diff.kept, 0);
            assert_eq!(diff.changed, 2);
            assert_eq!(diff.added, 1);
            assert_eq!(diff.removed, 0);
            assert_eq!(diff.changed_nodes(), 3);
            assert!(!diff.is_empty());
            assert_eq!(diff.lines.len(), 3);
            assert_eq!(diff.change_lines().len(), 3);
            assert!(digest_eq(&diff.base_digest, &kernel.digest()));
            assert!(digest_eq(&diff.candidate_fingerprint, &found.fingerprint()));
            assert!(diff.summary().contains("+1 -0 ~2 =0"));
            assert!(diff.summary().contains("diff celda 1"));

            let unified = diff.unified();
            assert!(unified.starts_with("--- pruebas.kernel rev 0\n"));
            assert!(unified.contains("+++ pruebas.kernel.sandbox1 rev 1"));
            assert!(unified.matches('\n').count() >= 5);
            assert!(unified.contains("\n~ "));
            assert!(unified.contains("\n+ "));
            assert!(!unified.contains("\n- "));

            let json = diff.json();
            assert!(json.starts_with('{'));
            assert!(json.ends_with('}'));
            assert!(json.contains("\"added\":1"));
            assert!(json.contains("\"changed\":2"));
            assert!(json.contains("\"removed\":0"));
            assert!(json.contains("\"kept\":0"));
            assert!(json.contains("\"kind\":\"added\""));
            assert!(json.contains("\"kind\":\"changed\""));
            assert!(json.contains("\"base_label\":\"pruebas.kernel\""));
        }
    }

    #[test]
    fn diff_marca_bajas_y_altas_de_la_cola() {
        let kernel = genesis();
        let mut mutator = AutopoieticMutator::new(SEED);
        let cell = mutator.open_cell(kernel.read());
        assert!(applied(&mut mutator, cell, &Mutation::Remove { index: 1 }).is_applied());
        let id = mutator.propose(kernel.read(), cell, &green()).unwrap_or(0);
        if let Some(found) = mutator.proposal(id) {
            assert_eq!(found.diff.kept, 1, "el primer nodo sigue idéntico");
            assert_eq!(found.diff.changed, 0);
            assert_eq!(found.diff.added, 0);
            assert_eq!(found.diff.removed, 1, "la cola del núcleo desaparece");
            assert!(found.diff.json().contains("\"kind\":\"removed\""));
            assert!(found.diff.unified().contains("\n- "));
        }

        // Una rama idéntica al núcleo no produce diff alguno.
        let same = MutationDiff::compute(
            cell,
            kernel.read(),
            &ast_genesis(),
            "pruebas.kernel.sandbox1",
        );
        assert!(same.is_empty());
        assert_eq!(same.kept, 2);
        assert_eq!(same.changed_nodes(), 0);
        assert!(same.change_lines().is_empty());
        assert!(same.json().contains("\"lines\":["));
    }

    #[test]
    fn payload_del_ide_y_motor_completo() {
        let kernel = genesis();
        let base = kernel.digest();
        let mut mutator = AutopoieticMutator::new(SEED);
        assert_eq!(
            mutator.key_id(),
            ast_dna::key_id(&ast_dna::golden_key(SEED))
        );
        assert!(mutator.label().contains("AutopoieticMutator"));
        let cell = mutator.open_cell(kernel.read());
        assert_eq!(cell, 1);

        // La petición entra por la puerta firmada del canal.
        assert!(mutator
            .link_mut()
            .send(FrameKind::MutationRequest, "alta:חכמ".as_bytes())
            .is_ok());
        let frames = mutator.pump();
        assert_eq!(frames.len(), 1);
        assert_eq!(
            frames.first().map(|frame| frame.kind),
            Some(FrameKind::MutationRequest)
        );
        assert!(matches!(mutator.receive(), Ok(None)));
        assert_eq!(mutator.anomalies(), 0);

        assert!(applied(&mut mutator, cell, &add("חכמ")).is_applied());
        let id = mutator.propose(kernel.read(), cell, &green()).unwrap_or(0);
        let payload = mutator.ide_payload(id);
        assert!(payload.is_some());
        if let Some(json) = payload {
            assert!(json.contains("\"admitida\":true"));
            assert!(json.contains("\"id\":1"));
            assert!(json.contains("\"regla\":\"plan.no-vacio\""));
            assert!(json.contains("\"regla\":\"guarda.sello-coherente\""));
            assert!(json.contains("\"juicio\":{"));
            assert!(json.contains("\"diff\":{"));
            assert!(json.contains("\"evidencia\":{"));
            assert!(json.contains("\"fingerprint\":\""));
            assert!(json.contains("\"dna\":{"));
        }
        assert!(mutator.ide_payload(777).is_none());

        let fused = mutator.commit(&kernel, id);
        assert!(fused.is_ok());
        let next = fused.unwrap_or_else(|_| kernel.clone());
        assert_eq!(next.revision(), 1);
        assert!(
            digest_eq(&kernel.digest(), &base),
            "el núcleo base no se toca"
        );

        let status = mutator.status();
        assert!(status.contains("mutador autopoiético"));
        assert!(status.contains("fusión consumada"));
        assert!(status.contains("rev 1"));
        assert!(status.contains("celda 1 abierta"));
        assert_eq!(mutator.counters().cells, 0);
        assert_eq!(mutator.counters().fusions, 1);
        assert_eq!(mutator.counters().proposals, 1);
        assert_eq!(mutator.counters().traps, 0);
        assert_eq!(mutator.counters().rejections, 0);
        let journal = mutator.journal_lines();
        assert!(
            journal.len() >= 4,
            "apertura, operación, propuesta y fusión"
        );
        assert!(mutator
            .journal_tail()
            .map(|line| line.contains("fusión"))
            .unwrap_or(false));
    }

    #[test]
    fn huella_de_rama_estable() {
        let kernel = genesis();
        let mut first = AutopoieticMutator::new(SEED);
        let mut second = AutopoieticMutator::new(SEED);
        let cell_a = first.open_cell(kernel.read());
        let cell_b = second.open_cell(kernel.read());
        assert!(applied(&mut first, cell_a, &add("חכמ")).is_applied());
        assert!(applied(&mut second, cell_b, &add("חכמ")).is_applied());
        let digest_a = first.cell(cell_a).map(|found| found.branch_digest());
        let digest_b = second.cell(cell_b).map(|found| found.branch_digest());
        assert_eq!(
            digest_a, digest_b,
            "misma semilla y mismo plan ⇒ misma rama"
        );
        assert_eq!(
            first.cell(cell_a).map(|found| found.base_revision()),
            Some(kernel.revision())
        );
        assert_eq!(
            first.cell(cell_a).map(|found| found.node_count()),
            second.cell(cell_b).map(|found| found.node_count())
        );

        // Un plan distinto da una rama distinta.
        assert!(applied(&mut second, cell_b, &Mutation::Negate { index: 0 }).is_applied());
        let digest_c = second.cell(cell_b).map(|found| found.branch_digest());
        assert_ne!(digest_a, digest_c);
        assert!(!digest_eq(
            &digest_a.unwrap_or_default(),
            &digest_c.unwrap_or_default()
        ));

        // La huella del parche no depende de la célula ni del mutador.
        assert!(digest_eq(
            &ast_fingerprint("pruebas.kernel.sandbox1", &ast_genesis()),
            &ast_fingerprint("pruebas.kernel.sandbox1", &ast_genesis())
        ));
        assert_eq!(JOURNAL_LIMIT, 64);
        assert_eq!(MAX_CELL_OPS, 64);
        assert_eq!(MAX_CELL_NODES, 32);
        assert_eq!(MAX_ARITY, 8);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Memoria dinámica acotada, aislamiento manual y anomalías
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn log_ontologico_acotado() {
        let kernel = genesis();
        let mut mutator = AutopoieticMutator::new(SEED);
        let total = JOURNAL_LIMIT + 8;
        for _ in 0..total {
            let _ = mutator.open_cell(kernel.read());
        }
        assert_eq!(mutator.counters().cells, total);
        let journal = mutator.journal_lines();
        assert_eq!(journal.len(), JOURNAL_LIMIT, "el log conserva lo último");
        if let Some(first) = journal.first() {
            assert!(
                first.contains("celda 9 abierta"),
                "las 8 más viejas se descartaron"
            );
        }
        assert!(mutator
            .journal_tail()
            .map(|line| line.contains("celda 72 abierta"))
            .unwrap_or(false));
        assert!(mutator.label().contains("células 72"));
        assert!(mutator.status().contains("anomalías 0"));
        // El núcleo no se movió por abrir células: sólo se copió su AST.
        assert_eq!(kernel.nodes().len(), 2);
        assert_eq!(kernel.revision(), 0);
        assert!(kernel.verify());
    }

    #[test]
    fn aislamiento_manual_y_liberacion() {
        let kernel = genesis();
        let mut mutator = AutopoieticMutator::new(SEED);
        let cell = mutator.open_cell(kernel.read());
        assert!(applied(&mut mutator, cell, &add("חכמ")).is_applied());

        let report = mutator.isolate(cell);
        assert!(report.is_ok());
        if let Ok(found) = &report {
            assert_eq!(found.cell, cell);
            assert_eq!(found.ops_discarded, 1);
            assert_eq!(found.faults, 0);
            assert!(found.is_clean(), "aislar a mano no arrastra fallos");
            assert!(found.label.contains("aislada"));
        }
        assert_eq!(mutator.counters().isolations, 1);
        assert!(mutator
            .cell(cell)
            .map(|found| found.is_poisoned())
            .unwrap_or(false));

        // Células y operaciones inexistentes.
        let unknown_cell = mutator.isolate(999);
        assert!(matches!(
            &unknown_cell,
            Err(MutatorError::CellUnknown { id: 999 })
        ));
        assert_eq!(
            mutator.counters().isolations,
            1,
            "aislar en falso no cuenta"
        );
        let unknown_apply = mutator.apply(999, &add("עדר"));
        assert!(matches!(
            &unknown_apply,
            Err(MutatorError::CellUnknown { id: 999 })
        ));

        assert!(mutator.release(cell), "la liberación descarta la rama");
        assert!(mutator.cell(cell).is_none());
        assert!(!mutator.release(cell), "liberar dos veces no es un éxito");
        assert_eq!(mutator.counters().cells, 0);
        // La rama liberada no dejó rastro alguno en el núcleo.
        assert!(kernel.verify());
        assert_eq!(kernel.nodes().len(), 2);
        assert_eq!(kernel.revision(), 0);
    }

    #[test]
    fn anomalias_del_canal() {
        let mut mutator = AutopoieticMutator::new(SEED);
        assert_eq!(mutator.anomalies(), 0);
        let wire = mutator
            .link()
            .gateway()
            .seal(0, FrameKind::KernelQuery, b"consulta");
        assert!(mutator
            .link()
            .inject(&swap_body(&wire, &hex_of(b"consulta-falsa"))));
        let frames = mutator.pump();
        assert!(frames.is_empty(), "un marco hostil no llega nunca");
        assert_eq!(mutator.anomalies(), 1);
        assert!(mutator.status().contains("anomalías 1"));

        // El canal sigue operativo para lo legítimo.
        assert!(mutator
            .link_mut()
            .send(FrameKind::CellReport, b"informe")
            .is_ok());
        assert_eq!(mutator.pump().len(), 1);
        assert_eq!(mutator.anomalies(), 1);
    }

    #[test]
    fn propuesta_exige_plan_vivo() {
        let kernel = genesis();
        let mut mutator = AutopoieticMutator::new(SEED);

        // Sin operaciones no hay plan que proponer.
        let empty = mutator.open_cell(kernel.read());
        let without_plan = mutator.propose(kernel.read(), empty, &green());
        assert!(matches!(&without_plan, Err(MutatorError::CellEmptyPlan)));
        assert_eq!(mutator.counters().proposals, 0);
        assert_eq!(mutator.counters().rejections, 0);

        // Célula desconocida: ni plan ni propuesta.
        let unknown = mutator.propose(kernel.read(), 42, &green());
        assert!(matches!(
            &unknown,
            Err(MutatorError::CellUnknown { id: 42 })
        ));

        // Una sola propuesta por célula: al sellar, el plan queda congelado.
        let cell = mutator.open_cell(kernel.read());
        assert!(applied(&mut mutator, cell, &add("חכמ")).is_applied());
        assert!(mutator.propose(kernel.read(), cell, &green()).is_ok());
        let again = mutator.propose(kernel.read(), cell, &green());
        assert!(matches!(&again, Err(MutatorError::CellSealed { id }) if *id == cell));
        assert_eq!(mutator.counters().proposals, 1);
        assert_eq!(mutator.counters().cells, 2, "la célula sellada sigue viva");
        assert_eq!(mutator.proposals().count(), 1);
    }
}
