//! # NeuralIT — sincronización semántica entre el Árbol *Shoresh* y la cognición
//!
//! Este módulo acopla el AST *Shoresh* ([`ShoreshAst`]) a un índice semántico de
//! **capacidad fija**: cada raíz triconsonántica ocupa una ranura estática con
//! su valencia de Belnap, riesgo, aridad, sellos y una huella SHA‑256. La
//! consulta es una búsqueda hash con un número **acotado** de sondas
//! ([`MAX_PROBES`]), de modo que nunca recorre el árbol ni reserva memoria.
//!
//! ## Invariantes
//! 1. **Cero `unsafe`** (`#![forbid(unsafe_code)]`).
//! 2. **Totalidad (axioma A1)**: producción sin `unwrap`, `expect`, `panic!` ni
//!    indexación que pueda salirse de rango; todo fallo es un [`Result`].
//! 3. **Cero alucinaciones**: sólo se indexa lo que el AST afirma. Una valencia
//!    desconocida se conserva como `∅`; no se sintetiza ningún hecho.
//! 4. **Cero mutación del árbol**: la sincronización recibe `&ShoreshAst` y
//!    jamás escribe en él. Las reglas axiomáticas se validan con
//!    [`audit_ast`] antes de tocar el índice; un intento de alterarlas se
//!    rechaza completo y el índice queda intacto (aplicación por etapas).
//! 5. **Contradicción tolerada**: dos testigos de la misma raíz se combinan con
//!    la unión `⊔` del retículo de Belnap; `⊤` y `⊥` conviven como `⊤∧⊥` sin
//!    explosión ni pánico.
//! 6. **Caja negra**: cada sincronización y cada consulta deja un billete en el
//!    [`FlightRecorder`] con la huella SHA‑256 del resultado y su marca de
//!    tiempo monotónica.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

use std::fmt;

use crate::ast_dna::short_hex;
use crate::autopoiesis::{hazard_permille, PurposeContract, PurposeViolation};
use crate::autopoietic::{ast_fingerprint, audit_ast, BelnapValue};
use crate::crypto_native::{digest_eq, Sha256};
use crate::ffi_ingest::{BaraType, ShoreshAst, ShoreshNode};
use crate::flight_recorder::{self, EventKind, FlightRecorder, ViolationCode};

/// Ranuras del índice semántico. Fijo en tiempo de compilación: el índice no
/// crece con la carga ni reserva memoria en *runtime*.
pub const CAPACITY: usize = 256;

/// Bytes máximos de una raíz *Shoresh* dentro de la ranura.
///
/// Una raíz triconsonántica hebrea ocupa como mucho 12 bytes (3 letras de 4
/// bytes); 24 bytes dejan margen para variantes con marcas sin perder la
/// comparación exacta y sin reservar `String`.
pub const MAX_ROOT_BYTES: usize = 24;

/// Sondas máximas de la tabla hash. Cota dura: la consulta es O(1) con un
/// factor constante de 16 y jamás recorre las 256 ranuras.
pub const MAX_PROBES: usize = 16;

/// Dominio de la huella de un nodo semántico.
pub const NODE_DOMAIN: &[u8] = b"bara:aether-omega:neural-it:nodo:v1";

/// Dominio de la cadena de testigos de una ranura.
pub const CHAIN_DOMAIN: &[u8] = b"bara:aether-omega:neural-it:cadena:v1";

/// Dominio de la huella de una ranura.
pub const SLOT_DOMAIN: &[u8] = b"bara:aether-omega:neural-it:ranura:v1";

/// Dominio de la huella global del índice.
pub const INDEX_DOMAIN: &[u8] = b"bara:aether-omega:neural-it:indice:v1";

/// Dominio de la huella de una consulta fallida.
pub const QUERY_DOMAIN: &[u8] = b"bara:aether-omega:neural-it:consulta:v1";

// ─────────────────────────────────────────────────────────────────────────
// Errores
// ─────────────────────────────────────────────────────────────────────────

/// Fallo de sincronización o indexación.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeuralItError {
    /// El AST no aporta ningún nodo.
    EmptyAst,
    /// El contrato de propósito rechaza el árbol.
    Contract(PurposeViolation),
    /// La auditoría estática *Shoresh* no pasa.
    Audit {
        /// Reglas superadas.
        passed: usize,
        /// Reglas totales.
        total: usize,
    },
    /// Una raíz no cabe en la ranura estática.
    RootTooLong {
        /// Índice del nodo infractor.
        index: usize,
        /// Bytes de la raíz.
        len: usize,
        /// Techo admitido.
        limit: usize,
    },
    /// Una raíz está vacía.
    EmptyRoot {
        /// Índice del nodo infractor.
        index: usize,
    },
    /// La aridad no cabe en el campo compacto de la ranura.
    ArityOverflow {
        /// Índice del nodo infractor.
        index: usize,
        /// Aridad medida.
        arity: usize,
    },
    /// El índice no admite más ranuras.
    Full {
        /// Techo de ranuras.
        limit: usize,
    },
    /// La tabla hash agotó sus sondas acotadas.
    IndexSaturated {
        /// Sondas intentadas.
        probes: usize,
    },
}

impl fmt::Display for NeuralItError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            NeuralItError::EmptyAst => f.write_str("el AST Shoresh no tiene nodos"),
            NeuralItError::Contract(violation) => {
                write!(f, "contrato de propósito rechazado: {violation}")
            }
            NeuralItError::Audit { passed, total } => {
                write!(f, "auditoría Shoresh en rojo: {passed}/{total} reglas")
            }
            NeuralItError::RootTooLong { index, len, limit } => write!(
                f,
                "el nodo {index} tiene una raíz de {len} bytes; la ranura admite {limit}"
            ),
            NeuralItError::EmptyRoot { index } => {
                write!(f, "el nodo {index} tiene una raíz vacía")
            }
            NeuralItError::ArityOverflow { index, arity } => write!(
                f,
                "el nodo {index} declara aridad {arity}; la ranura admite hasta 255"
            ),
            NeuralItError::Full { limit } => {
                write!(f, "índice semántico lleno: {limit} ranuras")
            }
            NeuralItError::IndexSaturated { probes } => {
                write!(f, "tabla hash saturada tras {probes} sondas")
            }
        }
    }
}

impl std::error::Error for NeuralItError {}

/// Código estable de violación para la caja negra.
fn violation_for(error: NeuralItError) -> ViolationCode {
    match error {
        NeuralItError::EmptyAst => ViolationCode::EmptyPatch,
        NeuralItError::Contract(_) => ViolationCode::FusionDenied,
        NeuralItError::Audit { .. } => ViolationCode::AuditFailed,
        NeuralItError::RootTooLong { .. } => ViolationCode::StructuralViolation,
        NeuralItError::EmptyRoot { .. } => ViolationCode::EmptyRoot,
        NeuralItError::ArityOverflow { .. } => ViolationCode::ArityExceeded,
        NeuralItError::Full { .. } => ViolationCode::CellCapacity,
        NeuralItError::IndexSaturated { .. } => ViolationCode::StructuralViolation,
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Huellas
// ─────────────────────────────────────────────────────────────────────────

/// FNV‑1a de 64 bits: determinista, sin dependencias y sin asignaciones.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Huella SHA‑256 de un nodo con sus metadatos semánticos.
fn node_digest(
    node: &ShoreshNode,
    value: BelnapValue,
    hazard_permille: u16,
    arity: u8,
) -> [u8; 32] {
    let root_len = node.root.len().min(u32::MAX as usize) as u32;
    let mut hasher = Sha256::new();
    hasher.update(NODE_DOMAIN);
    hasher.update(&root_len.to_le_bytes());
    hasher.update(node.root.as_bytes());
    hasher.update(&[
        value.index() as u8,
        arity,
        u8::from(node.sanitized),
        u8::from(node.ret != BaraType::Unknown),
    ]);
    hasher.update(&hazard_permille.to_le_bytes());
    hasher.update(&node.valence.truth_mass().to_bits().to_le_bytes());
    hasher.update(&node.valence.falsity_mass().to_bits().to_le_bytes());
    hasher.finish()
}

/// Huella de una consulta fallida: enlaza la raíz pedida sin inventar datos.
fn query_digest(root: &str) -> [u8; 32] {
    let len = root.len().min(u64::MAX as usize) as u64;
    let mut hasher = Sha256::new();
    hasher.update(QUERY_DOMAIN);
    hasher.update(&len.to_le_bytes());
    hasher.update(root.as_bytes());
    hasher.finish()
}

// ─────────────────────────────────────────────────────────────────────────
// Ranura semántica
// ─────────────────────────────────────────────────────────────────────────
/// Metadatos semánticos de una raíz *Shoresh*, en almacenamiento estático.
///
/// `value` es la **unión** de Belnap de todos los testigos indexados para la
/// raíz; `chain` encadena las huellas de esos testigos y `digest` sella el
/// conjunto. Todo es `Copy`: una ranura no posee memoria dinámica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticSlot {
    /// Raíz en bytes, con relleno cero hasta [`MAX_ROOT_BYTES`].
    root: [u8; MAX_ROOT_BYTES],
    /// Longitud real de `root`.
    root_len: u8,
    /// Unión de Belnap de los testigos.
    pub value: BelnapValue,
    /// Riesgo máximo observado, en milésimas.
    pub hazard_permille: u16,
    /// Aridad máxima observada.
    pub arity: u8,
    /// ¿Todos los testigos estaban sellados?
    pub sanitized: bool,
    /// ¿Todos los testigos declaraban tipo?
    pub typed: bool,
    /// Testigos acumulados para esta raíz.
    pub nodes: u16,
    /// Cadena SHA‑256 de las huellas de los testigos.
    pub chain: [u8; 32],
    /// Sello SHA‑256 de la ranura completa.
    pub digest: [u8; 32],
}

impl SemanticSlot {
    /// Construye una ranura nueva. Devuelve `None` si la raíz no cabe.
    fn new(
        root: &[u8],
        value: BelnapValue,
        hazard_permille: u16,
        arity: u8,
        sanitized: bool,
        typed: bool,
        node_digest: &[u8; 32],
    ) -> Option<Self> {
        if root.is_empty() || root.len() > MAX_ROOT_BYTES {
            return None;
        }
        let mut slot = SemanticSlot {
            root: [0; MAX_ROOT_BYTES],
            root_len: root.len() as u8,
            value,
            hazard_permille,
            arity,
            sanitized,
            typed,
            nodes: 1,
            chain: [0; 32],
            digest: [0; 32],
        };
        for (target, source) in slot.root.iter_mut().zip(root.iter()) {
            *target = *source;
        }
        slot.chain = chain_step(&slot.chain, node_digest);
        slot.digest = slot.recompute_digest();
        Some(slot)
    }

    /// Raíz legible. Es `""` sólo ante bytes corruptos, caso que [`Self::root`]
    /// no puede provocar porque la ranura nace de un `&str` válido.
    pub fn root(&self) -> &str {
        std::str::from_utf8(&self.root[..usize::from(self.root_len)]).unwrap_or_default()
    }

    /// ¿La raíz de la ranura coincide byte a byte con `root`?
    fn root_matches(&self, root: &[u8]) -> bool {
        usize::from(self.root_len) == root.len() && self.root.get(..root.len()) == Some(root)
    }

    /// ¿La valencia acumulada es una contradicción tolerada?
    pub fn is_contradiction(&self) -> bool {
        self.value.is_contradiction()
    }

    /// ¿La valencia acumulada es información insuficiente?
    pub fn is_unknown(&self) -> bool {
        self.value.is_unknown()
    }
    /// Recalcula el sello desde los campos actuales.
    fn recompute_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(SLOT_DOMAIN);
        hasher.update(&self.root);
        hasher.update(&[
            self.root_len,
            self.value.index() as u8,
            self.arity,
            u8::from(self.sanitized),
            u8::from(self.typed),
        ]);
        hasher.update(&self.hazard_permille.to_le_bytes());
        hasher.update(&self.nodes.to_le_bytes());
        hasher.update(&self.chain);
        hasher.finish()
    }

    /// Incorpora un testigo a la ranura con la unión `⊔` de Belnap.
    fn absorb(
        &mut self,
        value: BelnapValue,
        hazard_permille: u16,
        arity: u8,
        sanitized: bool,
        typed: bool,
        node_digest: &[u8; 32],
    ) {
        self.value = self.value.union(value);
        self.hazard_permille = self.hazard_permille.max(hazard_permille);
        self.arity = self.arity.max(arity);
        self.sanitized &= sanitized;
        self.typed &= typed;
        self.nodes = self.nodes.saturating_add(1);
        self.chain = chain_step(&self.chain, node_digest);
        self.digest = self.recompute_digest();
    }
}

/// Encadena una huella de nodo con la cadena previa.
fn chain_step(previous: &[u8; 32], node_digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CHAIN_DOMAIN);
    hasher.update(previous);
    hasher.update(node_digest);
    hasher.finish()
}

// ─────────────────────────────────────────────────────────────────────────
// Informes
// ─────────────────────────────────────────────────────────────────────────

/// Resultado de indexar un AST en el motor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexReport {
    /// Nodos del AST procesados.
    pub nodes: usize,
    /// Raíces nuevas.
    pub indexed: usize,
    /// Testigos absorbidos por una raíz ya presente.
    pub merged: usize,
    /// Ranuras ocupadas tras la operación.
    pub slots: usize,
    /// Techo de ranuras.
    pub capacity: usize,
    /// Huella SHA‑256 del índice completo.
    pub digest: [u8; 32],
}

impl IndexReport {
    /// ¿El recuento cuadra con los nodos y la capacidad?
    pub fn is_coherent(&self) -> bool {
        self.slots <= self.capacity
            && self.nodes > 0
            && self.indexed.saturating_add(self.merged) == self.nodes
    }

    /// Huella hexadecimal del índice.
    pub fn fingerprint(&self) -> String {
        short_hex(&self.digest)
    }
}

/// Resultado de una sincronización blindada por contrato y auditoría.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncReport {
    /// Índice resultante.
    pub index: IndexReport,
    /// Propósito que autorizó la sincronización.
    pub purpose: &'static str,
    /// Reglas de auditoría superadas.
    pub audit_passed: usize,
    /// Reglas de auditoría totales.
    pub audit_total: usize,
    /// Ranuras en contradicción tolerada `⊤∧⊥`.
    pub contradictions: usize,
    /// Ranuras con información insuficiente `∅`.
    pub unknown: usize,
    /// Billete de la caja negra para la sincronización.
    pub ticket: Option<u64>,
}

impl SyncReport {
    /// ¿La auditoría fue completa y el índice cuadra?
    pub fn is_coherent(&self) -> bool {
        self.audit_total > 0 && self.audit_passed == self.audit_total && self.index.is_coherent()
    }

    /// Huella hexadecimal del índice.
    pub fn fingerprint(&self) -> String {
        self.index.fingerprint()
    }
}

/// Foto `Copy` del índice semántico para el panel del IDE.
///
/// Copiar los contadores (en vez de retener un préstamo del motor) permite
/// construir el marco neuronal, soltar el motor y serializar después.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticView {
    /// Ranuras ocupadas.
    pub slots: usize,
    /// Techo de ranuras.
    pub capacity: usize,
    /// Testigos acumulados en todas las sincronizaciones.
    pub nodes: u64,
    /// Censo de ranuras `[⊤, ⊥, ⊤∧⊥, ∅]`.
    pub census: [u64; 4],
    /// Ranuras en `⊤∧⊥`.
    pub contradictions: usize,
    /// Ranuras en `∅`.
    pub unknown: usize,
    /// Huella SHA‑256 del índice.
    pub digest: [u8; 32],
}

// ─────────────────────────────────────────────────────────────────────────
// Motor NeuralIT
// ─────────────────────────────────────────────────────────────────────────

/// Índice semántico *Shoresh* de capacidad fija.
///
/// La tabla `table` guarda `ranura + 1` (cero = libre) y la resolución usa
/// doble hash con [`MAX_PROBES`] sondas. Las ranuras se escriben en orden de
/// inserción y nunca se eliminan, de modo que la huella global es determinista.
#[derive(Debug, Clone)]
pub struct NeuralIt {
    slots: [Option<SemanticSlot>; CAPACITY],
    table: [u16; CAPACITY],
    len: usize,
    nodes: u64,
    last_sync: Option<[u8; 32]>,
}

impl NeuralIt {
    /// Motor vacío, listo para sincronizar.
    pub const fn new() -> Self {
        Self {
            slots: [None; CAPACITY],
            table: [0; CAPACITY],
            len: 0,
            nodes: 0,
            last_sync: None,
        }
    }

    /// Ranuras ocupadas.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Techo de ranuras.
    pub const fn capacity(&self) -> usize {
        CAPACITY
    }

    /// ¿Sin ninguna raíz indexada?
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// ¿El índice alcanzó su techo?
    pub fn is_full(&self) -> bool {
        self.len >= CAPACITY
    }

    /// Testigos acumulados en todas las sincronizaciones.
    pub fn nodes(&self) -> u64 {
        self.nodes
    }

    /// Huella de la última sincronización, si la hubo.
    pub fn last_sync(&self) -> Option<[u8; 32]> {
        self.last_sync
    }

    /// Ranura por orden de inserción.
    pub fn slot_at(&self, index: usize) -> Option<&SemanticSlot> {
        self.slots.get(index).and_then(|slot| slot.as_ref())
    }

    /// Huella SHA‑256 del índice completo.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(INDEX_DOMAIN);
        hasher.update(&(self.len as u64).to_le_bytes());
        hasher.update(&self.nodes.to_le_bytes());
        for slot in self.slots.iter().take(self.len).flatten() {
            hasher.update(&slot.digest);
        }
        hasher.finish()
    }

    /// Censo de ranuras `[⊤, ⊥, ⊤∧⊥, ∅]`.
    pub fn census(&self) -> [u64; 4] {
        let mut counts = [0_u64; 4];
        for slot in self.slots.iter().take(self.len).flatten() {
            if let Some(cell) = counts.get_mut(slot.value.index()) {
                *cell = cell.saturating_add(1);
            }
        }
        counts
    }

    /// Foto `Copy` para el panel del IDE.
    pub fn view(&self) -> SemanticView {
        SemanticView::capture(self)
    }

    /// Consulta pura por raíz: no registra nada y no reserva memoria.
    pub fn lookup(&self, root: &str) -> Option<&SemanticSlot> {
        let bytes = root.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_ROOT_BYTES {
            return None;
        }
        let (home, step) = probe_path(bytes);
        for probe in 0..MAX_PROBES {
            let index = (home + probe * step) % CAPACITY;
            let tag = self.table.get(index).copied()?;
            if tag == 0 {
                return None;
            }
            let slot = self
                .slots
                .get(usize::from(tag - 1))
                .and_then(|slot| slot.as_ref())?;
            if slot.root_matches(bytes) {
                return Some(slot);
            }
        }
        None
    }

    /// Verifica la cadena de hashes y la coherencia de la tabla.
    pub fn verify(&self) -> bool {
        if self.len > CAPACITY {
            return false;
        }
        for slot in self.slots.iter().take(self.len).flatten() {
            if !digest_eq(&slot.digest, &slot.recompute_digest()) {
                return false;
            }
            if slot.root().is_empty() || slot.nodes == 0 {
                return false;
            }
            match self.lookup(slot.root()) {
                Some(found) => {
                    if !digest_eq(&found.digest, &slot.digest) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        self.table
            .iter()
            .all(|&tag| tag == 0 || usize::from(tag) <= self.len)
    }
}

impl NeuralIt {
    /// Indexa un nodo. Devuelve `true` si abrió una ranura nueva y `false` si
    /// se fusionó con una raíz existente mediante la unión de Belnap.
    fn index_node(&mut self, node: &ShoreshNode, index: usize) -> Result<bool, NeuralItError> {
        let root = node.root.as_bytes();
        validate_node(node, index)?;
        let arity = match u8::try_from(node.arity) {
            Ok(value) => value,
            Err(_) => {
                return Err(NeuralItError::ArityOverflow {
                    index,
                    arity: node.arity,
                })
            }
        };
        let value = BelnapValue::from_state(&node.valence);
        let hazard = hazard_permille(node.hazard);
        let typed = node.ret != BaraType::Unknown;
        let digest = node_digest(node, value, hazard, arity);
        let (home, step) = probe_path(root);
        let mut free = None;
        for probe in 0..MAX_PROBES {
            let table_index = (home + probe * step) % CAPACITY;
            let tag = match self.table.get(table_index).copied() {
                Some(tag) => tag,
                None => continue,
            };
            if tag == 0 {
                if free.is_none() {
                    free = Some(table_index);
                }
                break;
            }
            let slot_index = usize::from(tag - 1);
            let matches = match self.slots.get(slot_index).and_then(|slot| slot.as_ref()) {
                Some(slot) => slot.root_matches(root),
                None => false,
            };
            if matches {
                if let Some(slot) = self
                    .slots
                    .get_mut(slot_index)
                    .and_then(|slot| slot.as_mut())
                {
                    slot.absorb(value, hazard, arity, node.sanitized, typed, &digest);
                    self.nodes = self.nodes.saturating_add(1);
                    return Ok(false);
                }
                return Err(NeuralItError::IndexSaturated { probes: MAX_PROBES });
            }
        }
        let target = match free {
            Some(target) => target,
            None => return Err(NeuralItError::IndexSaturated { probes: MAX_PROBES }),
        };
        if self.len >= CAPACITY {
            return Err(NeuralItError::Full { limit: CAPACITY });
        }
        let slot =
            match SemanticSlot::new(root, value, hazard, arity, node.sanitized, typed, &digest) {
                Some(slot) => slot,
                None => {
                    return Err(NeuralItError::RootTooLong {
                        index,
                        len: root.len(),
                        limit: MAX_ROOT_BYTES,
                    })
                }
            };
        let cell = match self.slots.get_mut(self.len) {
            Some(cell) => cell,
            None => return Err(NeuralItError::Full { limit: CAPACITY }),
        };
        *cell = Some(slot);
        if let Some(entry) = self.table.get_mut(target) {
            *entry = (self.len as u16) + 1;
        }
        self.len += 1;
        self.nodes = self.nodes.saturating_add(1);
        Ok(true)
    }

    /// Indexa un AST completo **por etapas**: si un nodo falla, el índice queda
    /// exactamente como estaba. No valida contrato ni auditoría; para la ruta
    /// blindada se usa [`NeuralIt::synchronize`].
    pub fn index_ast(&mut self, ast: &ShoreshAst) -> Result<IndexReport, NeuralItError> {
        if ast.nodes.is_empty() {
            return Err(NeuralItError::EmptyAst);
        }
        if self.len.saturating_add(ast.nodes.len()) > CAPACITY {
            return Err(NeuralItError::Full { limit: CAPACITY });
        }
        for (index, node) in ast.nodes.iter().enumerate() {
            validate_node(node, index)?;
        }
        let mut staged = self.clone();
        let mut indexed = 0_usize;
        let mut merged = 0_usize;
        for (index, node) in ast.nodes.iter().enumerate() {
            match staged.index_node(node, index) {
                Ok(true) => indexed = indexed.saturating_add(1),
                Ok(false) => merged = merged.saturating_add(1),
                Err(error) => return Err(error),
            }
        }
        let digest = staged.digest();
        staged.last_sync = Some(digest);
        let slots = staged.len;
        *self = staged;
        Ok(IndexReport {
            nodes: ast.nodes.len(),
            indexed,
            merged,
            slots,
            capacity: CAPACITY,
            digest,
        })
    }
}

impl Default for NeuralIt {
    fn default() -> Self {
        Self::new()
    }
}

/// Posición inicial y paso de la doble hash, ambos dentro de la tabla.
fn probe_path(root: &[u8]) -> (usize, usize) {
    let hash = fnv1a(root);
    let home = (hash as usize) % CAPACITY;
    let step = (((hash >> 32) as usize) | 1) % CAPACITY;
    (home, if step == 0 { 1 } else { step })
}

/// Comprueba que un nodo cabe en una ranura sin tocar el índice.
fn validate_node(node: &ShoreshNode, index: usize) -> Result<(), NeuralItError> {
    let len = node.root.len();
    if len == 0 {
        return Err(NeuralItError::EmptyRoot { index });
    }
    if len > MAX_ROOT_BYTES {
        return Err(NeuralItError::RootTooLong {
            index,
            len,
            limit: MAX_ROOT_BYTES,
        });
    }
    if node.arity > usize::from(u8::MAX) {
        return Err(NeuralItError::ArityOverflow {
            index,
            arity: node.arity,
        });
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
// Sincronización blindada y consulta trazada
// ─────────────────────────────────────────────────────────────────────────

impl NeuralIt {
    /// Sincroniza con el registro global de la caja negra.
    ///
    /// Es la ruta que usa el kernel: contrato de propósito, auditoría estática,
    /// indexación por etapas y un billete `CognitiveSync` en [`FlightRecorder`].
    pub fn synchronize(
        &mut self,
        ast: &ShoreshAst,
        contract: &PurposeContract,
    ) -> Result<SyncReport, NeuralItError> {
        self.synchronize_with(ast, contract, None)
    }

    /// Sincroniza con un registro explícito (útil para pruebas y diagnósticos).
    ///
    /// Secuencia normativa:
    /// 1. El contrato de propósito evalúa **todos** los nodos.
    /// 2. La auditoría estática comprueba las nueve reglas axiomáticas.
    /// 3. La indexación se aplica a una copia y sólo se publica si es total.
    /// 4. La caja negra recibe la huella SHA‑256 del índice y las anomalías.
    pub fn synchronize_with(
        &mut self,
        ast: &ShoreshAst,
        contract: &PurposeContract,
        recorder: Option<&FlightRecorder>,
    ) -> Result<SyncReport, NeuralItError> {
        let rejection = ast_fingerprint("neural-it", ast);
        if let Err(violation) = contract.evaluate(ast) {
            emit(
                recorder,
                EventKind::VerdictRejected,
                ViolationCode::FusionDenied,
                &rejection,
            );
            return Err(NeuralItError::Contract(violation));
        }
        let audit = audit_ast(ast);
        let (audit_passed, audit_total) = audit.score();
        if !audit.passed() {
            emit(
                recorder,
                EventKind::VerdictRejected,
                ViolationCode::AuditFailed,
                &rejection,
            );
            return Err(NeuralItError::Audit {
                passed: audit_passed,
                total: audit_total,
            });
        }
        let index = match self.index_ast(ast) {
            Ok(index) => index,
            Err(error) => {
                emit(
                    recorder,
                    EventKind::VerdictRejected,
                    violation_for(error),
                    &rejection,
                );
                return Err(error);
            }
        };
        let ticket = emit(
            recorder,
            EventKind::CognitiveSync,
            ViolationCode::None,
            &index.digest,
        );
        let view = self.view();
        if view.contradictions > 0 {
            emit(
                recorder,
                EventKind::BelnapConflictBoth,
                ViolationCode::ContradictionRetained,
                &index.digest,
            );
        }
        if view.unknown > 0 {
            emit(
                recorder,
                EventKind::BelnapConflictNeither,
                ViolationCode::IndeterminateVerdict,
                &index.digest,
            );
        }
        Ok(SyncReport {
            index,
            purpose: contract.name,
            audit_passed,
            audit_total,
            contradictions: view.contradictions,
            unknown: view.unknown,
            ticket: Some(ticket),
        })
    }

    /// Consulta una raíz y deja constancia en el registro global.
    pub fn query(&self, root: &str) -> Option<SemanticSlot> {
        self.query_with(root, None)
    }

    /// Consulta una raíz en un registro explícito.
    ///
    /// Un acierto registra la huella de la ranura; un fallo registra `∅` con la
    /// huella de la consulta. En ambos casos hay marca de tiempo y verificación
    /// de hash.
    pub fn query_with(
        &self,
        root: &str,
        recorder: Option<&FlightRecorder>,
    ) -> Option<SemanticSlot> {
        let found = self.lookup(root).copied();
        let digest = match found {
            Some(slot) => slot.digest,
            None => query_digest(root),
        };
        let violation = match found {
            Some(_) => ViolationCode::None,
            None => ViolationCode::IndeterminateVerdict,
        };
        emit(recorder, EventKind::CognitiveSync, violation, &digest);
        found
    }
}

/// Escribe un billete en la caja negra indicada o en la global.
fn emit(
    recorder: Option<&FlightRecorder>,
    event: EventKind,
    violation: ViolationCode,
    digest: &[u8; 32],
) -> u64 {
    match recorder {
        Some(recorder) => recorder.record_digest(event, violation, digest),
        None => flight_recorder::record_digest(event, violation, digest),
    }
}

impl SemanticView {
    /// Captura los contadores del motor.
    pub fn capture(engine: &NeuralIt) -> Self {
        let census = engine.census();
        Self {
            slots: engine.len(),
            capacity: engine.capacity(),
            nodes: engine.nodes(),
            census,
            contradictions: census[2] as usize,
            unknown: census[3] as usize,
            digest: engine.digest(),
        }
    }

    /// ¿El censo suma las ranuras y respeta la capacidad?
    pub fn is_coherent(&self) -> bool {
        let total = self
            .census
            .iter()
            .fold(0_u64, |acc, count| acc.saturating_add(*count));
        self.slots <= self.capacity && total == self.slots as u64 && self.nodes >= self.slots as u64
    }

    /// Huella hexadecimal del índice.
    pub fn fingerprint(&self) -> String {
        short_hex(&self.digest)
    }

    /// Objeto JSON de la vista semántica.
    pub fn json(&self) -> String {
        format!(
            "{{\"ranuras\":{},\"capacidad\":{},\"nodos\":{},\"censo\":{{\"verdadero\":{},\"falso\":{},\"contradictorio\":{},\"indeterminado\":{}}},\"contradicciones\":{},\"indeterminados\":{},\"huella\":\"{}\"}}",
            self.slots,
            self.capacity,
            self.nodes,
            self.census[0],
            self.census[1],
            self.census[2],
            self.census[3],
            self.contradictions,
            self.unknown,
            self.fingerprint()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Pruebas
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::autopoiesis::PurposeViolation;

    fn node(root: &str, value: BelnapValue, hazard: f64, arity: usize) -> ShoreshNode {
        ShoreshNode {
            root: root.to_string(),
            original: format!("fn_{root}"),
            arity,
            ret: BaraType::Truth,
            hazard,
            valence: value.to_state(),
            sanitized: false,
        }
    }

    fn ast(entries: &[(&str, BelnapValue)]) -> ShoreshAst {
        ShoreshAst {
            nodes: entries
                .iter()
                .map(|(root, value)| node(root, *value, 0.2, 2))
                .collect(),
        }
    }

    #[test]
    fn indexa_y_consulta_una_raiz() {
        let mut engine = NeuralIt::new();
        let tree = ast(&[("שמר", BelnapValue::True)]);
        assert!(engine.index_ast(&tree).is_ok());
        let report = match engine.index_ast(&ast(&[("ברא", BelnapValue::False)])) {
            Ok(report) => report,
            Err(_) => return,
        };
        assert!(report.is_coherent());
        assert_eq!(report.indexed, 1);
        assert_eq!(engine.len(), 2);
        assert!(engine.verify());
        let slot = match engine.lookup("שמר") {
            Some(slot) => slot,
            None => return,
        };
        assert_eq!(slot.root(), "שמר");
        assert_eq!(slot.value, BelnapValue::True);
        assert_eq!(slot.hazard_permille, 200);
        assert_eq!(slot.arity, 2);
        assert_eq!(slot.nodes, 1);
        assert!(!slot.is_contradiction());
        assert!(!slot.is_unknown());
    }

    #[test]
    fn dos_testigos_opuestos_se_unen_en_both() {
        let mut engine = NeuralIt::new();
        assert!(engine
            .index_ast(&ast(&[("שמר", BelnapValue::True)]))
            .is_ok());
        assert!(engine
            .index_ast(&ast(&[("שמר", BelnapValue::False)]))
            .is_ok());
        let slot = match engine.lookup("שמר") {
            Some(slot) => slot,
            None => return,
        };
        assert_eq!(slot.value, BelnapValue::Both);
        assert_eq!(slot.nodes, 2);
        assert!(slot.is_contradiction());
        let view = engine.view();
        assert_eq!(view.slots, 1);
        assert_eq!(view.nodes, 2);
        assert_eq!(view.census, [0, 0, 1, 0]);
        assert_eq!(view.contradictions, 1);
        assert!(view.is_coherent());
        assert!(engine.verify());
    }

    #[test]
    fn el_contrato_rechaza_sin_tocar_el_indice() {
        let mut engine = NeuralIt::new();
        let mut risky = node("שמר", BelnapValue::True, 0.9, 2);
        risky.sanitized = true;
        let tree = ShoreshAst { nodes: vec![risky] };
        let contract = PurposeContract::new("estricto").hazard(100);
        let recorder = FlightRecorder::new();
        let result = engine.synchronize_with(&tree, &contract, Some(&recorder));
        assert!(matches!(
            result,
            Err(NeuralItError::Contract(
                PurposeViolation::HazardCeiling { .. }
            ))
        ));
        assert!(engine.is_empty());
        assert!(engine.verify());
        assert!(recorder.inspect().entries.iter().any(|entry| {
            entry.event == EventKind::VerdictRejected
                && entry.violation == ViolationCode::FusionDenied
        }));
    }

    #[test]
    fn la_auditoria_rechaza_raices_ajenas_al_arbol() {
        let mut engine = NeuralIt::new();
        let tree = ShoreshAst {
            nodes: vec![node("abc", BelnapValue::True, 0.2, 2)],
        };
        let contract = PurposeContract::new("cognicion");
        let result = engine.synchronize_with(&tree, &contract, Some(&FlightRecorder::new()));
        assert!(matches!(result, Err(NeuralItError::Audit { .. })));
        assert!(engine.is_empty());
    }

    #[test]
    fn el_indice_rechaza_ast_vacio_raiz_larga_y_aridad_fuera_de_rango() {
        let mut engine = NeuralIt::new();
        assert!(matches!(
            engine.index_ast(&ShoreshAst::default()),
            Err(NeuralItError::EmptyAst)
        ));

        let long = "א".repeat(MAX_ROOT_BYTES / 2 + 1);
        let tree = ShoreshAst {
            nodes: vec![node(&long, BelnapValue::True, 0.2, 2)],
        };
        assert!(matches!(
            engine.index_ast(&tree),
            Err(NeuralItError::RootTooLong { .. })
        ));

        let tree = ShoreshAst {
            nodes: vec![node("", BelnapValue::True, 0.2, 2)],
        };
        assert!(matches!(
            engine.index_ast(&tree),
            Err(NeuralItError::EmptyRoot { .. })
        ));

        let tree = ShoreshAst {
            nodes: vec![node("שמר", BelnapValue::True, 0.2, 256)],
        };
        assert!(matches!(
            engine.index_ast(&tree),
            Err(NeuralItError::ArityOverflow { .. })
        ));
        assert!(engine.is_empty());
    }

    #[test]
    fn la_huella_es_determinista_entre_motores() {
        let tree = ast(&[("שמר", BelnapValue::True), ("ברא", BelnapValue::False)]);
        let mut first = NeuralIt::new();
        let mut second = NeuralIt::new();
        assert!(first.index_ast(&tree).is_ok());
        assert!(second.index_ast(&tree).is_ok());
        assert_eq!(first.digest(), second.digest());
        assert_eq!(first.view(), second.view());
        assert_eq!(first.last_sync(), second.last_sync());
    }

    #[test]
    fn verify_detecta_una_ranura_manipulada() {
        let mut engine = NeuralIt::new();
        assert!(engine
            .index_ast(&ast(&[("שמר", BelnapValue::True)]))
            .is_ok());
        assert!(engine.verify());
        if let Some(slot) = engine.slots.get_mut(0).and_then(|slot| slot.as_mut()) {
            slot.digest[0] ^= 0xFF;
        }
        assert!(!engine.verify());
    }

    #[test]
    fn la_caja_negra_registra_sincronizacion_y_consulta() {
        let recorder = FlightRecorder::new();
        let mark = recorder.mark();
        let mut engine = NeuralIt::new();
        let contract = PurposeContract::new("cognicion");
        let tree = ast(&[("שמר", BelnapValue::True)]);
        let report = match engine.synchronize_with(&tree, &contract, Some(&recorder)) {
            Ok(report) => report,
            Err(_) => return,
        };
        assert!(report.is_coherent());
        assert!(report.ticket.is_some());
        assert!(engine.query_with("שמר", Some(&recorder)).is_some());
        assert!(engine.query_with("no-existe", Some(&recorder)).is_none());
        let entries = recorder.entries_since(mark);
        let syncs = entries
            .iter()
            .filter(|entry| entry.event == EventKind::CognitiveSync)
            .count();
        assert!(syncs >= 3);
        assert!(entries.iter().any(|entry| {
            entry.event == EventKind::CognitiveSync && entry.violation == ViolationCode::None
        }));
        assert!(entries.iter().any(|entry| {
            entry.event == EventKind::CognitiveSync
                && entry.violation == ViolationCode::IndeterminateVerdict
        }));
    }

    #[test]
    fn la_vista_resume_el_censo_y_serializa_json() {
        let mut engine = NeuralIt::new();
        assert!(engine
            .index_ast(&ast(&[
                ("שמר", BelnapValue::True),
                ("חכם", BelnapValue::Neither)
            ]))
            .is_ok());
        let view = engine.view();
        assert!(view.is_coherent());
        assert_eq!(view.slots, 2);
        assert_eq!(view.census, [1, 0, 0, 1]);
        assert_eq!(view.unknown, 1);
        let json = view.json();
        assert!(json.contains("\"ranuras\":2"));
        assert!(json.contains("\"indeterminado\":1"));
        assert!(json.contains("\"huella\":\""));
        assert_eq!(view.fingerprint().len(), 64);
    }

    #[test]
    fn la_sincronizacion_no_altera_el_ast() {
        let tree = ast(&[("שמר", BelnapValue::True)]);
        let before = tree.nodes.first().map(|node| node.root.clone());
        let mut engine = NeuralIt::new();
        assert!(engine
            .synchronize_with(&tree, &PurposeContract::new("cognicion"), None)
            .is_ok());
        assert_eq!(tree.nodes.first().map(|node| node.root.clone()), before);
        assert_eq!(tree.nodes.len(), 1);
    }
}
