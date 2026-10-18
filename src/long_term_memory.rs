//! # Memoria AST de largo plazo — Bara / AETHER‑Ω (FASE 1)
//!
//! Almacén **inmutable en forma y acotado en tamaño** para los nodos *Shoresh*
//! que el núcleo ya validó. No interpreta el AST ni lo reescribe: conserva una
//! proyección compacta de cada nodo —raíz triconsonántica, capa, valencia de
//! Belnap, riesgo, aridad, sello y padre— y la indexa por `(raíz, capa)`.
//!
//! ## Invariantes
//! 1. **Cero `unsafe`** (`#![forbid(unsafe_code)]`).
//! 2. **Cero asignaciones dinámicas** — toda la memoria vive en arrays fijos
//!    ([`MAX_ENTRIES`] entradas, [`INDEX_SLOTS`] ranuras). Insertar, buscar,
//!    revisar y calcular la huella no piden memoria al *allocator*.
//! 3. **Totalidad** — ninguna entrada provoca un pánico: capacidad, duplicados,
//!    raíces ilegibles y capas fuera de rango vuelven como [`MemoryError`].
//! 4. **Determinismo** — el índice es FNV‑1a y la huella es SHA‑256 sobre el
//!    contenido canónico; no hay reloj ni aleatoriedad.
//! 5. **Sin pérdida silenciosa** — un duplicado se rechaza; para cambiar el
//!    valor de una entrada existente se usa [`LongTermMemory::revise`], que
//!    incrementa su revisión.
//!
//! ## Por qué una raíz fija
//! [`RootKey`] guarda hasta [`crate::inference::MAX_ROOT_BYTES`] bytes en un
//! buffer propio. Una raíz triconsonántica hebrea ocupa seis bytes, así que la
//! entrada completa cabe en unas pocas palabras y la copia nunca reserva.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

use std::fmt;

use crate::ast_dna::short_hex;
use crate::autopoietic::BelnapValue;
use crate::crypto_native::Sha256;
use crate::ffi_ingest::ShoreshNode;
use crate::inference::{RootKey, MAX_LAYERS};

/// Entradas que admite la memoria de largo plazo.
pub const MAX_ENTRIES: usize = 256;

/// Ranuras del índice (potencia de dos y > [`MAX_ENTRIES`], para que la sonda
/// lineal nunca dé la vuelta completa).
pub const INDEX_SLOTS: usize = 512;

/// Profundidad máxima de una cadena de linaje.
pub const MAX_LINEAGE: usize = 64;

/// Ranura vacía del índice.
const EMPTY_SLOT: u16 = u16::MAX;

/// Dominio de la huella (separa estas digests de las del resto del kernel).
pub const MEMORY_DOMAIN: &[u8] = b"bara:aether-omega:memoria-largo-plazo:v1";

// ─────────────────────────────────────────────────────────────────────────
// Identificador
// ─────────────────────────────────────────────────────────────────────────

/// Identificador estable de una entrada (índice en el array fijo).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemoryId(u16);

impl MemoryId {
    /// Índice interno.
    pub const fn index(self) -> usize {
        self.0 as usize
    }

    /// Código crudo (para serialización).
    pub const fn raw(self) -> u16 {
        self.0
    }

    /// Reconstruye un identificador desde su código crudo.
    ///
    /// No garantiza que la entrada exista: [`LongTermMemory::get`] devuelve
    /// `None` si el código no apunta a la región viva.
    pub const fn from_raw(raw: u16) -> Self {
        Self(raw)
    }
}

impl fmt::Display for MemoryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "memoria#{}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Errores
// ─────────────────────────────────────────────────────────────────────────

/// Fallo tipado de la memoria de largo plazo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryError {
    /// La memoria ya no admite entradas.
    Full {
        /// Techo de entradas.
        limit: usize,
    },
    /// Ya existe una entrada para esa `(raíz, capa)`.
    Duplicate {
        /// Entrada que ocupa la clave.
        existing: MemoryId,
    },
    /// El índice no pudo alojar la clave (situación imposible con las cotas
    /// actuales, pero tratada como fallo en lugar de como pánico).
    IndexSaturated {
        /// Ranuras del índice.
        slots: usize,
    },
    /// Identificador fuera de la región viva.
    Unknown {
        /// Índice pedido.
        index: usize,
        /// Entradas vivas.
        entries: usize,
    },
    /// La raíz no cabe en el buffer fijo.
    RootTooLong {
        /// Bytes medidos.
        len: usize,
        /// Bytes admitidos.
        limit: usize,
    },
    /// La raíz está vacía.
    EmptyRoot,
    /// La capa no pertenece al rango del motor.
    LayerOutOfRange {
        /// Capa pedida.
        layer: usize,
        /// Capas admitidas.
        limit: usize,
    },
    /// La aridad no cabe en el campo compacto de la entrada.
    ArityOutOfRange {
        /// Aridad medida.
        arity: usize,
        /// Aridad máxima representable.
        limit: usize,
    },
    /// El linaje excede la capacidad del buffer de salida.
    LineageTruncated {
        /// Ancestros que no cupieron.
        missing: usize,
    },
    /// Un nodo se declaró padre de sí mismo.
    SelfParent,
    /// El linaje se muerde la cola (cadena cíclica).
    LineageCycle {
        /// Entrada en la que se detectó la repetición.
        at: MemoryId,
    },
}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoryError::Full { limit } => {
                write!(f, "memoria llena: ya hay {} entradas", limit)
            }
            MemoryError::Duplicate { existing } => {
                write!(f, "la clave ya está ocupada por {}", existing)
            }
            MemoryError::IndexSaturated { slots } => {
                write!(f, "índice saturado: {} ranuras ocupadas", slots)
            }
            MemoryError::Unknown { index, entries } => {
                write!(f, "entrada {} fuera de la región viva ({})", index, entries)
            }
            MemoryError::RootTooLong { len, limit } => {
                write!(f, "raíz de {} bytes: el buffer admite {}", len, limit)
            }
            MemoryError::EmptyRoot => write!(f, "la raíz está vacía"),
            MemoryError::LayerOutOfRange { layer, limit } => {
                write!(f, "capa {} fuera de rango (admitidas 0..{})", layer, limit)
            }
            MemoryError::ArityOutOfRange { arity, limit } => {
                write!(f, "aridad de {}: el campo admite hasta {}", arity, limit)
            }
            MemoryError::LineageTruncated { missing } => {
                write!(f, "linaje truncado: faltan {} ancestros", missing)
            }
            MemoryError::SelfParent => {
                write!(f, "un nodo no puede ser padre de sí mismo")
            }
            MemoryError::LineageCycle { at } => {
                write!(f, "linaje cíclico detectado en {}", at)
            }
        }
    }
}

impl std::error::Error for MemoryError {}

// ─────────────────────────────────────────────────────────────────────────
// Entrada
// ─────────────────────────────────────────────────────────────────────────

/// Proyección compacta de un nodo *Shoresh*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryEntry {
    root: RootKey,
    layer: u8,
    value: BelnapValue,
    hazard_permille: u16,
    arity: u8,
    parent: Option<u16>,
    revision: u16,
    sanitized: bool,
}

impl MemoryEntry {
    /// Raíz triconsonántica.
    pub const fn root(&self) -> RootKey {
        self.root
    }

    /// Capa del grafo.
    pub const fn layer(&self) -> u8 {
        self.layer
    }

    /// Valencia de Belnap vigente.
    pub const fn value(&self) -> BelnapValue {
        self.value
    }

    /// Riesgo en milésimas (`0..=1000`), entero y determinista.
    pub const fn hazard_permille(&self) -> u16 {
        self.hazard_permille
    }

    /// Aridad declarada.
    pub const fn arity(&self) -> u8 {
        self.arity
    }

    /// Entrada padre en el linaje.
    pub fn parent(&self) -> Option<MemoryId> {
        self.parent.map(MemoryId)
    }

    /// Revisión (0 al insertar; +1 por cada [`LongTermMemory::revise`]).
    pub const fn revision(&self) -> u16 {
        self.revision
    }

    /// ¿El nodo venía sellado?
    pub const fn sanitized(&self) -> bool {
        self.sanitized
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Borrador de entrada
// ─────────────────────────────────────────────────────────────────────────

/// Datos con los que se pide una inserción.
///
/// Agrupa los campos en un solo valor —la insersión no admite ocho argumentos
/// sueltos— y permite construir la petición de forma legible:
///
/// ```
/// use bara::autopoietic::BelnapValue;
/// use bara::long_term_memory::{LongTermMemory, MemoryDraft};
///
/// let mut memoria = LongTermMemory::new();
/// let borrador = MemoryDraft::new("אמת", 0, BelnapValue::True)
///     .hazard(250)
///     .arity(2)
///     .sanitized(true);
/// assert!(memoria.insert(borrador).is_ok());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryDraft<'a> {
    /// Raíz triconsonántica.
    pub root: &'a str,
    /// Capa del grafo.
    pub layer: u8,
    /// Valencia de Belnap.
    pub value: BelnapValue,
    /// Riesgo en milésimas.
    pub hazard_permille: u16,
    /// Aridad.
    pub arity: u8,
    /// ¿Nodo sellado?
    pub sanitized: bool,
    /// Entrada padre del linaje.
    pub parent: Option<MemoryId>,
}

impl<'a> MemoryDraft<'a> {
    /// Borrador mínimo: sin riesgo, aridad cero, sin sello ni padre.
    pub const fn new(root: &'a str, layer: u8, value: BelnapValue) -> Self {
        Self {
            root,
            layer,
            value,
            hazard_permille: 0,
            arity: 0,
            sanitized: false,
            parent: None,
        }
    }

    /// Fija el riesgo en milésimas.
    pub const fn hazard(mut self, permille: u16) -> Self {
        self.hazard_permille = permille;
        self
    }

    /// Fija la aridad.
    pub const fn arity(mut self, arity: u8) -> Self {
        self.arity = arity;
        self
    }

    /// Marca el sello del nodo.
    pub const fn sanitized(mut self, sanitized: bool) -> Self {
        self.sanitized = sanitized;
        self
    }

    /// Encadena la entrada a un padre ya presente.
    pub const fn parent(mut self, parent: MemoryId) -> Self {
        self.parent = Some(parent);
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Memoria
// ─────────────────────────────────────────────────────────────────────────

/// Almacén fijo de nodos *Shoresh* con índice `(raíz, capa)`.
///
/// La región viva es siempre `0..len`: no hay huecos ni borrados, de modo que
/// el índice guarda posiciones estables y la huella depende sólo del contenido.
#[derive(Debug, Clone)]
pub struct LongTermMemory {
    entries: [Option<MemoryEntry>; MAX_ENTRIES],
    slots: [u16; INDEX_SLOTS],
    len: usize,
    writes: u64,
}

impl LongTermMemory {
    /// Memoria vacía.
    pub fn new() -> Self {
        Self {
            entries: [None; MAX_ENTRIES],
            slots: [EMPTY_SLOT; INDEX_SLOTS],
            len: 0,
            writes: 0,
        }
    }

    /// Entradas vivas.
    pub fn len(&self) -> usize {
        self.len
    }

    /// ¿Está vacía?
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Techo de entradas.
    pub const fn capacity(&self) -> usize {
        MAX_ENTRIES
    }

    /// ¿No admite más entradas?
    pub fn is_full(&self) -> bool {
        self.len >= MAX_ENTRIES
    }

    /// Escrituras acumuladas (inserciones y revisiones).
    pub fn writes(&self) -> u64 {
        self.writes
    }

    /// Entradas vivas en orden de inserción.
    pub fn entries(&self) -> impl Iterator<Item = &MemoryEntry> {
        self.entries.iter().take(self.len).flatten()
    }

    /// Entrada por identificador, de forma total.
    pub fn get(&self, id: MemoryId) -> Option<&MemoryEntry> {
        self.entries.get(id.index())?.as_ref()
    }

    /// Inserta un nodo nuevo.
    ///
    /// Rechaza duplicados de `(raíz, capa)` en lugar de sobrescribirlos: un
    /// segundo hecho sobre el mismo nodo debe pasar por [`Self::revise`], que
    /// deja rastro en la revisión.
    pub fn insert(&mut self, draft: MemoryDraft<'_>) -> Result<MemoryId, MemoryError> {
        let key = self.validate(draft.root, draft.layer)?;
        if let Some(existing) = self.find(key, draft.layer) {
            return Err(MemoryError::Duplicate { existing });
        }
        if let Some(parent) = draft.parent {
            if parent.index() >= self.len {
                return Err(MemoryError::Unknown {
                    index: parent.index(),
                    entries: self.len,
                });
            }
        }
        if self.len >= MAX_ENTRIES {
            return Err(MemoryError::Full { limit: MAX_ENTRIES });
        }
        let index = self.len;
        let id = u16::try_from(index)
            .ok()
            .map(MemoryId)
            .ok_or(MemoryError::Full { limit: MAX_ENTRIES })?;
        let entry = MemoryEntry {
            root: key,
            layer: draft.layer,
            value: draft.value,
            hazard_permille: draft.hazard_permille.min(1_000),
            arity: draft.arity,
            parent: draft.parent.map(MemoryId::raw),
            revision: 0,
            sanitized: draft.sanitized,
        };
        match self.entries.get_mut(index) {
            Some(slot) => *slot = Some(entry),
            None => return Err(MemoryError::Full { limit: MAX_ENTRIES }),
        }
        let slot = Self::slot_index(key, draft.layer);
        let mut placed = false;
        for offset in 0..INDEX_SLOTS {
            let position = slot.wrapping_add(offset) % INDEX_SLOTS;
            match self.slots.get(position).copied() {
                Some(EMPTY_SLOT) => {
                    if let Some(target) = self.slots.get_mut(position) {
                        *target = id.0;
                        placed = true;
                    }
                    break;
                }
                Some(_) => continue,
                None => break,
            }
        }
        if !placed {
            if let Some(slot) = self.entries.get_mut(index) {
                *slot = None;
            }
            return Err(MemoryError::IndexSaturated { slots: INDEX_SLOTS });
        }
        self.len = self.len.saturating_add(1);
        self.writes = self.writes.saturating_add(1);
        Ok(id)
    }

    /// Copia un nodo *Shoresh* validado a la memoria.
    ///
    /// El riesgo continuo se cuantiza a milésimas (`round`, acotado a
    /// `0..=1000`) para que la huella sea entera y reproducible. La aridad se
    /// rechaza si no cabe en un byte: truncarla falsearía el nodo.
    pub fn ingest(&mut self, node: &ShoreshNode, layer: u8) -> Result<MemoryId, MemoryError> {
        let arity = u8::try_from(node.arity).map_err(|_| MemoryError::ArityOutOfRange {
            arity: node.arity,
            limit: usize::from(u8::MAX),
        })?;
        let hazard = if node.hazard.is_finite() {
            (node.hazard.clamp(0.0, 1.0) * 1_000.0).round() as u16
        } else {
            1_000
        };
        let value = BelnapValue::from_state(&node.valence);
        let draft = MemoryDraft::new(&node.root, layer, value)
            .hazard(hazard)
            .arity(arity)
            .sanitized(node.sanitized);
        self.insert(draft)
    }

    /// Busca la entrada de una `(raíz, capa)`.
    pub fn lookup(&self, root: &str, layer: u8) -> Option<MemoryId> {
        let key = RootKey::new(root)?;
        if usize::from(layer) >= MAX_LAYERS {
            return None;
        }
        self.find(key, layer)
    }

    /// Cambia la valencia de una entrada y sube su revisión.
    pub fn revise(&mut self, id: MemoryId, value: BelnapValue) -> Result<MemoryEntry, MemoryError> {
        let index = id.index();
        if index >= self.len {
            return Err(MemoryError::Unknown {
                index,
                entries: self.len,
            });
        }
        let entry = match self.entries.get_mut(index).and_then(Option::as_mut) {
            Some(entry) => entry,
            None => {
                return Err(MemoryError::Unknown {
                    index,
                    entries: self.len,
                })
            }
        };
        if entry.value != value {
            entry.value = value;
            entry.revision = entry.revision.saturating_add(1);
            self.writes = self.writes.saturating_add(1);
        }
        Ok(*entry)
    }

    /// Escribe en `out` la cadena de ancestros (del padre hacia la raíz) y
    /// devuelve cuántos escribió.
    ///
    /// Acepta cualquier tamaño de buffer: si el linaje no cabe, devuelve
    /// [`MemoryError::LineageTruncated`] sin escribir más allá del final. La
    /// caminata se detiene además tras `len` pasos, de modo que una cadena
    /// cíclica devuelve [`MemoryError::LineageCycle`] en lugar de colgar el hilo.
    pub fn lineage(&self, id: MemoryId, out: &mut [MemoryId]) -> Result<usize, MemoryError> {
        if self.get(id).is_none() {
            return Err(MemoryError::Unknown {
                index: id.index(),
                entries: self.len,
            });
        }
        let mut written = 0usize;
        let mut steps = 0usize;
        let mut cursor = self.get(id).and_then(MemoryEntry::parent);
        while let Some(parent) = cursor {
            if parent == id {
                return Err(MemoryError::SelfParent);
            }
            if steps >= self.len {
                return Err(MemoryError::LineageCycle { at: parent });
            }
            if parent.index() >= self.len {
                return Err(MemoryError::Unknown {
                    index: parent.index(),
                    entries: self.len,
                });
            }
            match out.get_mut(written) {
                Some(slot) => *slot = parent,
                None => return Err(MemoryError::LineageTruncated { missing: 1 }),
            }
            written = written.saturating_add(1);
            steps = steps.saturating_add(1);
            cursor = self.get(parent).and_then(MemoryEntry::parent);
        }
        Ok(written)
    }

    /// Censo en el orden canónico `[⊤, ⊥, ⊤∧⊥, ∅]`.
    pub fn census(&self) -> [usize; 4] {
        let mut census = [0usize; 4];
        for entry in self.entries() {
            if let Some(slot) = census.get_mut(entry.value.index()) {
                *slot = slot.saturating_add(1);
            }
        }
        census
    }

    /// Suma de riesgos en milésimas (cota superior para contratos de propósito).
    pub fn hazard_total(&self) -> u64 {
        self.entries()
            .map(|entry| u64::from(entry.hazard_permille))
            .sum()
    }

    /// Huella determinista de toda la región viva.
    ///
    /// Recorre el contenido en orden de inserción con un SHA‑256 incremental:
    /// no construye ningún buffer intermedio.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(MEMORY_DOMAIN);
        hasher.update(b":memoria:");
        hasher.update(&(self.len as u64).to_le_bytes());
        for entry in self.entries() {
            let root = entry.root.as_str().as_bytes();
            hasher.update(&(root.len() as u16).to_le_bytes());
            hasher.update(root);
            hasher.update(&[entry.layer]);
            hasher.update(&[entry.value.index() as u8]);
            hasher.update(&entry.hazard_permille.to_le_bytes());
            hasher.update(&[entry.arity]);
            hasher.update(&entry.parent.unwrap_or(EMPTY_SLOT).to_le_bytes());
            hasher.update(&entry.revision.to_le_bytes());
            hasher.update(&[u8::from(entry.sanitized)]);
        }
        hasher.finish()
    }

    /// Huella corta en hexadecimal (paneles y log).
    pub fn fingerprint(&self) -> String {
        short_hex(&self.digest())
    }

    /// Vacía la memoria conservando la capacidad.
    pub fn clear(&mut self) {
        self.entries = [None; MAX_ENTRIES];
        self.slots = [EMPTY_SLOT; INDEX_SLOTS];
        self.len = 0;
        self.writes = 0;
    }

    fn validate(&self, root: &str, layer: u8) -> Result<RootKey, MemoryError> {
        if usize::from(layer) >= MAX_LAYERS {
            return Err(MemoryError::LayerOutOfRange {
                layer: usize::from(layer),
                limit: MAX_LAYERS,
            });
        }
        if root.is_empty() {
            return Err(MemoryError::EmptyRoot);
        }
        RootKey::new(root).ok_or(MemoryError::RootTooLong {
            len: root.len(),
            limit: crate::inference::MAX_ROOT_BYTES,
        })
    }

    fn find(&self, key: RootKey, layer: u8) -> Option<MemoryId> {
        let start = Self::slot_index(key, layer);
        for offset in 0..INDEX_SLOTS {
            let position = start.wrapping_add(offset) % INDEX_SLOTS;
            let raw = *self.slots.get(position)?;
            if raw == EMPTY_SLOT {
                return None;
            }
            let entry = self.entries.get(usize::from(raw))?.as_ref()?;
            if entry.root == key && entry.layer == layer {
                return Some(MemoryId(raw));
            }
        }
        None
    }

    fn slot_index(key: RootKey, layer: u8) -> usize {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in key.as_str().as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash ^= u64::from(layer).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        (hash as usize) & (INDEX_SLOTS - 1)
    }
}

impl Default for LongTermMemory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi_ingest::BaraType;
    use crate::inference::MAX_ROOT_BYTES;
    use crate::runtime::QuantumState;

    /// Desempaqueta un `Result` de prueba; un fallo es un fallo del test.
    fn must<T>(result: Result<T, MemoryError>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("operación rechazada inesperadamente: {error}"),
        }
    }

    fn node(root: &str, arity: usize, hazard: f64, truth: f64, falsity: f64) -> ShoreshNode {
        ShoreshNode {
            root: root.to_string(),
            original: format!("legacy_{root}"),
            arity,
            ret: BaraType::Void,
            hazard,
            valence: QuantumState::paraconsistent(truth, falsity),
            sanitized: true,
        }
    }

    #[test]
    fn new_memory_is_empty_and_deterministic() {
        let a = LongTermMemory::new();
        let b = LongTermMemory::default();

        assert_eq!(a.len(), 0);
        assert!(a.is_empty());
        assert!(!a.is_full());
        assert_eq!(a.capacity(), MAX_ENTRIES);
        assert_eq!(a.writes(), 0);
        assert_eq!(a.census(), [0, 0, 0, 0]);
        assert_eq!(a.hazard_total(), 0);
        assert_eq!(a.entries().count(), 0);
        assert_eq!(a.digest(), b.digest());
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_eq!(a.fingerprint().len(), 64);
        assert_eq!(a.fingerprint(), short_hex(&a.digest()));
    }

    #[test]
    fn insert_and_lookup_roundtrip() {
        let mut memory = LongTermMemory::new();
        let id = must(
            memory.insert(
                MemoryDraft::new("אמת", 1, BelnapValue::True)
                    .hazard(125)
                    .arity(2)
                    .sanitized(true),
            ),
        );

        assert_eq!(id.index(), 0);
        assert_eq!(id.to_string(), "memoria#0");
        assert_eq!(memory.len(), 1);
        assert_eq!(memory.writes(), 1);
        assert_eq!(memory.lookup("אמת", 1), Some(id));
        assert_eq!(memory.lookup("אמת", 2), None);
        assert_eq!(memory.lookup("שקר", 1), None);

        let entry = match memory.get(id) {
            Some(entry) => entry,
            None => panic!("la entrada recién insertada no se encuentra"),
        };
        assert_eq!(entry.root().as_str(), "אמת");
        assert_eq!(entry.layer(), 1);
        assert_eq!(entry.value(), BelnapValue::True);
        assert_eq!(entry.hazard_permille(), 125);
        assert_eq!(entry.arity(), 2);
        assert!(entry.sanitized());
        assert_eq!(entry.revision(), 0);
        assert_eq!(entry.parent(), None);
        assert_eq!(memory.entries().count(), 1);
        assert_eq!(memory.census(), [1, 0, 0, 0]);
        assert_eq!(memory.hazard_total(), 125);
    }

    #[test]
    fn duplicate_keys_are_rejected_per_layer() {
        let mut memory = LongTermMemory::new();
        let id = must(memory.insert(MemoryDraft::new("אמת", 1, BelnapValue::True)));

        assert_eq!(
            memory.insert(MemoryDraft::new("אמת", 1, BelnapValue::False)),
            Err(MemoryError::Duplicate { existing: id })
        );
        assert!(memory
            .insert(MemoryDraft::new("אמת", 2, BelnapValue::False))
            .is_ok());
        assert_eq!(memory.len(), 2);
        assert_eq!(memory.writes(), 2);
    }

    #[test]
    fn invalid_inputs_return_typed_errors() {
        let mut memory = LongTermMemory::new();
        let too_long = "a".repeat(MAX_ROOT_BYTES + 1);

        assert_eq!(
            memory.insert(MemoryDraft::new("", 0, BelnapValue::True)),
            Err(MemoryError::EmptyRoot)
        );
        assert_eq!(
            memory.insert(MemoryDraft::new(&too_long, 0, BelnapValue::True)),
            Err(MemoryError::RootTooLong {
                len: MAX_ROOT_BYTES + 1,
                limit: MAX_ROOT_BYTES,
            })
        );
        assert_eq!(
            memory.insert(MemoryDraft::new("אמת", MAX_LAYERS as u8, BelnapValue::True)),
            Err(MemoryError::LayerOutOfRange {
                layer: MAX_LAYERS,
                limit: MAX_LAYERS,
            })
        );
        assert_eq!(
            memory.insert(
                MemoryDraft::new("אמת", 0, BelnapValue::True).parent(MemoryId::from_raw(7))
            ),
            Err(MemoryError::Unknown {
                index: 7,
                entries: 0,
            })
        );
        assert!(memory.is_empty());
        assert_eq!(memory.lookup(&too_long, 0), None);
        assert_eq!(memory.lookup("אמת", MAX_LAYERS as u8), None);
        assert!(memory.get(MemoryId::from_raw(0)).is_none());
    }

    #[test]
    fn capacity_is_enforced_without_panic() {
        let mut memory = LongTermMemory::new();
        for index in 0..MAX_ENTRIES {
            let root = format!("r{index}");
            assert!(memory
                .insert(MemoryDraft::new(&root, 0, BelnapValue::Neither))
                .is_ok());
        }

        assert!(memory.is_full());
        assert_eq!(memory.len(), MAX_ENTRIES);
        assert_eq!(
            memory.insert(MemoryDraft::new("extra", 0, BelnapValue::True)),
            Err(MemoryError::Full { limit: MAX_ENTRIES })
        );
        assert_eq!(memory.len(), MAX_ENTRIES);
        assert_eq!(memory.lookup("r0", 0).map(MemoryId::index), Some(0));
        assert_eq!(
            memory
                .lookup(&format!("r{}", MAX_ENTRIES - 1), 0)
                .map(MemoryId::index),
            Some(MAX_ENTRIES - 1)
        );
    }

    #[test]
    fn revise_bumps_revision_only_on_change() {
        let mut memory = LongTermMemory::new();
        let id = must(
            memory.insert(
                MemoryDraft::new("אמת", 0, BelnapValue::True)
                    .hazard(300)
                    .arity(1),
            ),
        );

        let same = must(memory.revise(id, BelnapValue::True));
        assert_eq!(same.revision(), 0);
        assert_eq!(memory.writes(), 1);

        let changed = must(memory.revise(id, BelnapValue::Both));
        assert_eq!(changed.value(), BelnapValue::Both);
        assert_eq!(changed.revision(), 1);
        assert_eq!(memory.writes(), 2);
        assert_eq!(memory.census(), [0, 0, 1, 0]);

        let again = must(memory.revise(id, BelnapValue::Neither));
        assert_eq!(again.revision(), 2);
        assert_eq!(
            memory.revise(MemoryId::from_raw(9), BelnapValue::True),
            Err(MemoryError::Unknown {
                index: 9,
                entries: 1,
            })
        );
        assert_eq!(memory.len(), 1);
        assert_eq!(memory.hazard_total(), 300);
    }

    #[test]
    fn lineage_walks_parents_and_reports_truncation() {
        let mut memory = LongTermMemory::new();
        let a = must(memory.insert(MemoryDraft::new("אב", 0, BelnapValue::True)));
        let b = must(memory.insert(MemoryDraft::new("בן", 1, BelnapValue::True).parent(a)));
        let c = must(memory.insert(MemoryDraft::new("גד", 2, BelnapValue::True).parent(b)));

        assert_eq!(memory.get(c).and_then(MemoryEntry::parent), Some(b));
        assert_eq!(memory.get(b).and_then(MemoryEntry::parent), Some(a));
        assert_eq!(memory.get(a).and_then(MemoryEntry::parent), None);

        let mut buffer = [MemoryId::from_raw(0); 4];
        assert_eq!(memory.lineage(c, &mut buffer), Ok(2));
        assert_eq!(&buffer[..2], &[b, a]);

        let mut empty: [MemoryId; 0] = [];
        assert_eq!(
            memory.lineage(c, &mut empty),
            Err(MemoryError::LineageTruncated { missing: 1 })
        );
        let mut tiny = [MemoryId::from_raw(0); 1];
        assert_eq!(memory.lineage(a, &mut tiny), Ok(0));
        assert_eq!(
            memory.lineage(MemoryId::from_raw(9), &mut buffer),
            Err(MemoryError::Unknown {
                index: 9,
                entries: 3,
            })
        );
    }

    #[test]
    fn census_digest_and_clone_are_deterministic() {
        let mut memory = LongTermMemory::new();
        let id = must(
            memory.insert(
                MemoryDraft::new("אב", 0, BelnapValue::True)
                    .hazard(100)
                    .sanitized(true),
            ),
        );
        must(
            memory.insert(
                MemoryDraft::new("בן", 0, BelnapValue::False)
                    .hazard(200)
                    .arity(1),
            ),
        );
        must(
            memory.insert(
                MemoryDraft::new("גד", 1, BelnapValue::Both)
                    .hazard(300)
                    .arity(2)
                    .sanitized(true)
                    .parent(id),
            ),
        );
        must(
            memory.insert(
                MemoryDraft::new("דה", 2, BelnapValue::Neither)
                    .hazard(400)
                    .arity(3),
            ),
        );

        assert_eq!(memory.census(), [1, 1, 1, 1]);
        assert_eq!(memory.hazard_total(), 1_000);
        assert_eq!(memory.len(), 4);

        let digest = memory.digest();
        let fingerprint = memory.fingerprint();
        assert_eq!(fingerprint.len(), 64);
        assert_eq!(fingerprint, short_hex(&digest));
        assert_eq!(memory.clone().digest(), digest);

        must(memory.revise(id, BelnapValue::Both));
        assert_ne!(memory.digest(), digest, "la revisión entra en la huella");
        assert_eq!(memory.entries().count(), 4);

        memory.clear();
        assert!(memory.is_empty());
        assert_eq!(memory.writes(), 0);
        assert_eq!(memory.digest(), LongTermMemory::new().digest());
        assert!(memory.lookup("אב", 0).is_none());
        assert!(memory.get(id).is_none());
    }

    #[test]
    fn ingest_projects_shoresh_nodes() {
        let mut memory = LongTermMemory::new();
        let id = must(memory.ingest(&node("אמת", 2, 0.125_4, 1.0, 0.0), 3));

        let entry = match memory.get(id) {
            Some(entry) => entry,
            None => panic!("la ingesta no dejó entrada"),
        };
        assert_eq!(entry.root().as_str(), "אמת");
        assert_eq!(entry.layer(), 3);
        assert_eq!(entry.value(), BelnapValue::True);
        assert_eq!(entry.hazard_permille(), 125);
        assert_eq!(entry.arity(), 2);
        assert!(entry.sanitized());
        assert_eq!(entry.parent(), None);

        // Riesgo fuera de rango o no finito: se acota en lugar de desbordar.
        must(memory.ingest(&node("שקר", 0, 7.5, 0.0, 1.0), 0));
        must(memory.ingest(&node("גבול", 1, f64::NAN, 1.0, 1.0), 1));
        let hazards: Vec<u16> = memory.entries().map(MemoryEntry::hazard_permille).collect();
        assert_eq!(hazards, vec![125, 1_000, 1_000]);
        assert_eq!(memory.census(), [1, 1, 1, 0]);

        let contradictory = memory.lookup("גבול", 1).and_then(|id| memory.get(id));
        assert_eq!(
            contradictory.map(|entry| entry.value()),
            Some(BelnapValue::Both)
        );

        let too_wide = node("רחב", usize::from(u8::MAX) + 1, 0.0, 0.0, 0.0);
        assert_eq!(
            memory.ingest(&too_wide, 0),
            Err(MemoryError::ArityOutOfRange {
                arity: usize::from(u8::MAX) + 1,
                limit: usize::from(u8::MAX),
            })
        );
        assert_eq!(
            memory.ingest(&node("כפול", 0, 0.0, 0.0, 0.0), MAX_LAYERS as u8),
            Err(MemoryError::LayerOutOfRange {
                layer: MAX_LAYERS,
                limit: MAX_LAYERS,
            })
        );
        assert_eq!(
            memory.ingest(&node("אמת", 2, 0.0, 0.0, 0.0), 3),
            Err(MemoryError::Duplicate { existing: id })
        );
    }
}
