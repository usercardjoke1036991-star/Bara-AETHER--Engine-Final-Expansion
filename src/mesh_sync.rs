//! # Global Memory Mesh Sync — `mesh_sync.rs`
//!
//! Malla de sincronización **peer-to-peer** del estado holográfico de Bara.
//! Propaga las regiones de memoria entre nodos (hilos obreros locales o, por
//! su formato *wire*, fronteras de red) **sin sockets**: el medio de
//! transporte es un bus en proceso ([`MeshBus`]) o canales `std::sync::mpsc`
//! entre hilos.
//!
//! ## Propiedades
//! * **Holográfica** — la huella de un nodo es el **XOR** de las huellas de
//!   sus entradas. El XOR es conmutativo, asociativo e idempotente: cada parte
//!   contribuye al todo, el orden de llegada no altera el resultado y reenviar
//!   un fotograma no añade entropía.
//! * **Causal** — cada fotograma transporta un [`VectorClock`]; los fotogramas
//!   dominados (obsoletos) se descartan y los concurrentes se fusionan.
//! * **Paraconsistente** — dos nodos que afirman valores distintos para la
//!   misma clave **no** provocan un conflicto fatal: se combinan con la
//!   disyunción de Belnap (join) y el valor resultante es una contradicción
//!   tolerada `⊤∧⊥`.
//! * **Transportable** — [`MeshFrame::to_wire`] / [`from_wire`] serializan el
//!   fotograma a bytes (`std` puro), listo para cualquier transporte externo.

use crate::memory_region::RegionId;
use crate::runtime::QuantumState;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, VecDeque};
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

// ─────────────────────────────────────────────────────────────────────────
// Identidad de nodo y tiempo causal
// ─────────────────────────────────────────────────────────────────────────

/// Identificador de un nodo (peer) de la malla.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId(pub usize);

impl PeerId {
    /// Etiqueta legible `peer-03`.
    pub fn label(&self) -> String {
        format!("peer-{:02}", self.0)
    }
}

/// Reloj vectorial: orden causal sin reloj global ni coordenación.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VectorClock {
    ticks: Vec<u64>,
}

impl VectorClock {
    /// Reloj vectorial virgen para `peers` nodos.
    pub fn new(peers: usize) -> Self {
        VectorClock {
            ticks: vec![0; peers],
        }
    }

    /// Número de nodos contemplados por el reloj.
    pub fn len(&self) -> usize {
        self.ticks.len()
    }

    /// ¿Reloj sin nodos?
    pub fn is_empty(&self) -> bool {
        self.ticks.is_empty()
    }

    /// Lectura del contador de un peer.
    pub fn get(&self, peer: PeerId) -> u64 {
        self.ticks.get(peer.0).copied().unwrap_or(0)
    }

    /// Avanza el contador local de `peer` y devuelve el nuevo valor.
    pub fn tick(&mut self, peer: PeerId) -> u64 {
        if self.ticks.len() <= peer.0 {
            self.ticks.resize(peer.0 + 1, 0);
        }
        let slot = &mut self.ticks[peer.0];
        *slot = slot.saturating_add(1);
        *slot
    }

    /// Escribe el contador de un peer (usado por el decodificador *wire*).
    pub fn set(&mut self, peer: PeerId, value: u64) {
        if self.ticks.len() <= peer.0 {
            self.ticks.resize(peer.0 + 1, 0);
        }
        self.ticks[peer.0] = value;
    }

    /// Fusiona el reloj recibido (máximo componente a componente).
    /// Devuelve `true` si el reloj local cambió.
    pub fn merge(&mut self, other: &VectorClock) -> bool {
        if other.ticks.len() > self.ticks.len() {
            self.ticks.resize(other.ticks.len(), 0);
        }
        let mut changed = false;
        for (index, value) in other.ticks.iter().enumerate() {
            if *value > self.ticks[index] {
                self.ticks[index] = *value;
                changed = true;
            }
        }
        changed
    }

    /// ¿`self` está dominado por `other` (es anterior o igual, componente a
    /// componente)?
    pub fn dominated_by(&self, other: &VectorClock) -> bool {
        for index in 0..self.ticks.len() {
            let mine = self.ticks[index];
            let theirs = other.ticks.get(index).copied().unwrap_or(0);
            if mine > theirs {
                return false;
            }
        }
        true
    }

    /// ¿Los dos relojes son estrictamente causales (`self` antes que `other`)?
    pub fn happens_before(&self, other: &VectorClock) -> bool {
        self.dominated_by(other) && self != other
    }

    /// ¿Los dos relojes son concurrentes (ni uno domina al otro)?
    pub fn concurrent_with(&self, other: &VectorClock) -> bool {
        !self.dominated_by(other) && !other.dominated_by(self)
    }

    /// Suma de todos los contadores.
    pub fn total(&self) -> u64 {
        self.ticks.iter().sum()
    }

    /// Representación `(1,0,2,0)`.
    pub fn label(&self) -> String {
        let parts: Vec<String> = self.ticks.iter().map(|t| t.to_string()).collect();
        format!("({})", parts.join(","))
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Entradas y fotogramas
// ─────────────────────────────────────────────────────────────────────────

/// Entrada del almacén holográfico de un nodo.
///
/// La clave (`key`) y la huella (`digest`) derivan del contenido, por lo que
/// reescribir lo mismo es una no-operación: entropía cero.
#[derive(Debug, Clone)]
pub struct MeshEntry {
    /// Clave topológica (hash FNV-1a del nombre de la región).
    pub key: u64,
    /// Región de memoria compartida.
    pub region: RegionId,
    /// Nombre simbólico de la región.
    pub name: String,
    /// Huella del contenido (`key ⊕ huella(estado)`).
    pub digest: u64,
    /// Estado retenido (cuántico o paraconsistente).
    pub state: QuantumState,
    /// Época lógica de la última escritura.
    pub epoch: u64,
    /// Número de escrituras acumuladas (una fusión la incrementa).
    pub revision: u32,
}

impl MeshEntry {
    /// Construye una entrada con clave y huella derivadas del contenido.
    pub fn new(name: &str, region: RegionId, state: QuantumState, epoch: u64) -> Self {
        let key = fnv1a(name.as_bytes());
        let digest = key ^ fingerprint(&state);
        MeshEntry {
            key,
            region,
            name: name.to_string(),
            digest,
            state,
            epoch,
            revision: 1,
        }
    }

    /// ¿Dos entradas coinciden en contenido?
    pub fn matches(&self, other: &MeshEntry) -> bool {
        self.key == other.key && self.digest == other.digest
    }

    /// Fusión paraconsistente de dos entradas divergentes (join de Belnap).
    pub fn merge_with(&mut self, other: &MeshEntry) {
        self.state = self.state.disjunction(&other.state);
        self.digest = self.key ^ fingerprint(&self.state);
        self.epoch = self.epoch.max(other.epoch);
        self.revision += 1;
    }
}

/// Fotograma de sincronización: la unidad de transporte de la malla.
#[derive(Debug, Clone)]
pub struct MeshFrame {
    /// Nodo emisor.
    pub origin: PeerId,
    /// Época lógica del emisor.
    pub epoch: u64,
    /// Reloj vectorial del emisor.
    pub clock: VectorClock,
    /// Entradas transportadas.
    pub entries: Vec<MeshEntry>,
    /// Huella holográfica (XOR de las huellas de las entradas).
    pub digest: u64,
}

impl MeshFrame {
    /// Construye un fotograma a partir de sus entradas.
    pub fn new(origin: PeerId, epoch: u64, clock: VectorClock, entries: Vec<MeshEntry>) -> Self {
        let digest = hologram_of(&entries);
        MeshFrame {
            origin,
            epoch,
            clock,
            entries,
            digest,
        }
    }

    /// Número de entradas transportadas.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// ¿Fotograma vacío?
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Recuento de escrituras efectivas del fotograma.
    pub fn revisions(&self) -> u32 {
        self.entries.iter().map(|e| e.revision).sum()
    }
}

/// Huella holográfica de un conjunto de entradas (`XOR`, conmutativo e
/// idempotente: el orden no importa y repetir no añade información).
pub fn hologram_of(entries: &[MeshEntry]) -> u64 {
    entries.iter().fold(0_u64, |acc, e| acc ^ e.digest)
}

/// Huella de un estado: hash determinista de su forma canónica.
pub fn fingerprint(state: &QuantumState) -> u64 {
    let (truth, falsity) = state.belnap();
    let tag = match state {
        QuantumState::Classical(_) => 0_u8,
        QuantumState::Superposition { .. } => 1,
        QuantumState::Paraconsistent { .. } => 2,
    };
    let mut bytes = Vec::with_capacity(17);
    bytes.push(tag);
    bytes.extend_from_slice(&truth.to_bits().to_le_bytes());
    bytes.extend_from_slice(&falsity.to_bits().to_le_bytes());
    fnv1a(&bytes)
}

// ─────────────────────────────────────────────────────────────────────────
// Códec *wire* (serialización sin dependencias)
// ─────────────────────────────────────────────────────────────────────────

/// Offset del emisor dentro del fotograma serializado.
const WIRE_MAGIC: u8 = 0x4D; // 'M' de *mesh*

impl MeshFrame {
    /// Serializa el fotograma a bytes (formato propio, `std` puro).
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.entries.len() * 64);
        out.push(WIRE_MAGIC);
        out.extend_from_slice(&(self.origin.0 as u32).to_le_bytes());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&(self.clock.len() as u32).to_le_bytes());
        for tick in 0..self.clock.len() {
            out.extend_from_slice(&self.clock.get(PeerId(tick)).to_le_bytes());
        }
        out.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for entry in &self.entries {
            out.extend_from_slice(&entry.key.to_le_bytes());
            out.extend_from_slice(&(entry.region.0 as u32).to_le_bytes());
            out.extend_from_slice(&entry.revision.to_le_bytes());
            out.extend_from_slice(&entry.epoch.to_le_bytes());
            let name = entry.name.as_bytes();
            out.extend_from_slice(&(name.len() as u32).to_le_bytes());
            out.extend_from_slice(name);
            match &entry.state {
                QuantumState::Classical(b) => {
                    out.push(0);
                    out.push(u8::from(*b));
                }
                QuantumState::Superposition { alpha, beta } => {
                    out.push(1);
                    out.extend_from_slice(&alpha.to_le_bytes());
                    out.extend_from_slice(&beta.to_le_bytes());
                }
                QuantumState::Paraconsistent { truth, falsity } => {
                    out.push(2);
                    out.extend_from_slice(&truth.to_le_bytes());
                    out.extend_from_slice(&falsity.to_le_bytes());
                }
            }
        }
        out.extend_from_slice(&self.digest.to_le_bytes());
        out
    }

    /// Reconstruye un fotograma desde bytes.
    ///
    /// Es **tolerante**: cualquier truncamiento o corrupción de la huella
    /// holográfica devuelve `None` en lugar de un pánico.
    pub fn from_wire(bytes: &[u8]) -> Option<MeshFrame> {
        let mut reader = WireReader::new(bytes);
        if reader.u8()? != WIRE_MAGIC {
            return None;
        }
        let origin = PeerId(reader.u32()? as usize);
        let epoch = reader.u64()?;
        let clock_len = reader.u32()? as usize;
        if clock_len > 4_096 {
            return None;
        }
        let mut clock = VectorClock::new(clock_len);
        for tick in 0..clock_len {
            let value = reader.u64()?;
            clock.set(PeerId(tick), value);
        }
        let entry_count = reader.u32()? as usize;
        if entry_count > 65_536 {
            return None;
        }
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            let key = reader.u64()?;
            let region = RegionId(reader.u32()? as usize);
            let revision = reader.u32()?;
            let entry_epoch = reader.u64()?;
            let name_len = reader.u32()? as usize;
            if name_len > 4_096 {
                return None;
            }
            let name = String::from_utf8(reader.bytes(name_len)?.to_vec()).ok()?;
            let tag = reader.u8()?;
            let state = match tag {
                0 => QuantumState::classical(reader.u8()? != 0),
                1 => QuantumState::superposition(reader.f64()?, reader.f64()?),
                2 => QuantumState::paraconsistent(reader.f64()?, reader.f64()?),
                _ => return None,
            };
            let mut entry = MeshEntry::new(&name, region, state, entry_epoch);
            entry.key = key;
            entry.revision = revision;
            entries.push(entry);
        }
        let digest = reader.u64()?;
        // Verificación de integridad: la huella debe reproducirse.
        if digest != hologram_of(&entries) {
            return None;
        }
        Some(MeshFrame {
            origin,
            epoch,
            clock,
            entries,
            digest,
        })
    }
}

/// Lector secuencial tolerante sobre un *buffer* de bytes.
struct WireReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> WireReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        WireReader { data, pos: 0 }
    }

    fn bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let slice = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.bytes(1)?[0])
    }

    fn u32(&mut self) -> Option<u32> {
        let mut buf = [0_u8; 4];
        buf.copy_from_slice(self.bytes(4)?);
        Some(u32::from_le_bytes(buf))
    }

    fn u64(&mut self) -> Option<u64> {
        let mut buf = [0_u8; 8];
        buf.copy_from_slice(self.bytes(8)?);
        Some(u64::from_le_bytes(buf))
    }

    fn f64(&mut self) -> Option<f64> {
        Some(f64::from_bits(self.u64()?))
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Nodos de la malla
// ─────────────────────────────────────────────────────────────────────────

/// Resultado de aplicar un fotograma a un nodo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestOutcome {
    /// Entradas nuevas incorporadas.
    Merged(usize),
    /// Entradas divergentes fusionadas paraconsistentemente.
    Conflicts(usize),
    /// Fotograma obsoleto: época o reloj dominados por el nodo local.
    Stale,
    /// Nada que hacer: el contenido ya estaba presente (entropía cero).
    NoOp,
}

/// Nodo de la malla: almacén holográfico local + reloj causal.
#[derive(Debug, Clone, Default)]
pub struct MeshNode {
    /// Índice del nodo dentro de la malla.
    pub id: usize,
    /// Nombre simbólico (`worker-01`).
    pub name: String,
    entries: BTreeMap<u64, MeshEntry>,
    clock: VectorClock,
    epoch: u64,
    applied: u64,
    rejected: u64,
}

impl MeshNode {
    /// Crea un nodo virgen dentro de una malla de `peers` nodos.
    pub fn new(id: usize, peers: usize) -> Self {
        MeshNode {
            id,
            name: PeerId(id).label(),
            entries: BTreeMap::new(),
            clock: VectorClock::new(peers),
            epoch: 0,
            applied: 0,
            rejected: 0,
        }
    }

    /// Número de entradas retenidas.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// ¿Almacén vacío?
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Época lógica actual.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Reloj vectorial del nodo.
    pub fn clock(&self) -> &VectorClock {
        &self.clock
    }

    /// Entradas incorporadas desde otros nodos.
    pub fn applied(&self) -> u64 {
        self.applied
    }

    /// Fotogramas obsoletos descartados.
    pub fn rejected(&self) -> u64 {
        self.rejected
    }

    /// Itinerario sobre las entradas, en orden de clave.
    pub fn entries(&self) -> impl Iterator<Item = &MeshEntry> {
        self.entries.values()
    }

    /// Recupera una entrada por clave.
    pub fn get(&self, key: u64) -> Option<&MeshEntry> {
        self.entries.get(&key)
    }

    /// Huella holográfica del nodo (`XOR` de sus entradas).
    pub fn hologram(&self) -> u64 {
        self.entries.values().fold(0_u64, |acc, e| acc ^ e.digest)
    }

    /// Escribe una entrada. Devuelve `(clave, ¿cambió?)`.
    pub fn insert(
        &mut self,
        name: &str,
        region: RegionId,
        state: QuantumState,
    ) -> (u64, bool) {
        let candidate = MeshEntry::new(name, region, state, self.epoch);
        if let Some(existing) = self.entries.get(&candidate.key) {
            if existing.matches(&candidate) {
                return (candidate.key, false);
            }
        }
        let key = candidate.key;
        self.entries.insert(key, candidate);
        (key, true)
    }

    /// Avanza la época lógica y marca el tiempo causal local.
    pub fn advance(&mut self, epoch: u64) {
        self.epoch = epoch;
        self.clock.tick(PeerId(self.id));
    }

    /// Captura un fotograma con todas las entradas locales.
    pub fn snapshot(&self) -> MeshFrame {
        let entries: Vec<MeshEntry> = self.entries.values().cloned().collect();
        MeshFrame::new(PeerId(self.id), self.epoch, self.clock.clone(), entries)
    }

    /// Aplica un fotograma remoto.
    ///
    /// Fotogramas de época anterior se descartan; las entradas divergentes se
    /// **fusionan** con el join paraconsistente en vez de provocar un error.
    pub fn ingest(&mut self, frame: &MeshFrame) -> IngestOutcome {
        if frame.origin.0 == self.id {
            return IngestOutcome::NoOp;
        }
        if frame.epoch < self.epoch {
            self.rejected += 1;
            return IngestOutcome::Stale;
        }

        let mut merged = 0;
        let mut conflicts = 0;
        for incoming in &frame.entries {
            match self.entries.entry(incoming.key) {
                Entry::Vacant(slot) => {
                    slot.insert(incoming.clone());
                    merged += 1;
                }
                Entry::Occupied(mut slot) => {
                    let existing = slot.get_mut();
                    if existing.digest != incoming.digest {
                        existing.merge_with(incoming);
                        conflicts += 1;
                    }
                }
            }
        }

        self.clock.merge(&frame.clock);
        self.epoch = self.epoch.max(frame.epoch);
        self.applied += merged as u64;

        if conflicts > 0 {
            IngestOutcome::Conflicts(conflicts)
        } else if merged > 0 {
            IngestOutcome::Merged(merged)
        } else {
            IngestOutcome::NoOp
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Bus en proceso
// ─────────────────────────────────────────────────────────────────────────

/// Informe de un ciclo de enrutado del bus.
#[derive(Debug, Clone, Default)]
pub struct RouteReport {
    /// Fotogramas enrutados.
    pub frames: usize,
    /// Entregas intentadas (nodo × fotograma).
    pub deliveries: usize,
    /// Entradas nuevas incorporadas.
    pub merged: usize,
    /// Entradas fusionadas por divergencia.
    pub conflicts: usize,
    /// Fotogramas obsoletos descartados.
    pub stale: usize,
    /// Entregas sin efecto.
    pub noop: usize,
}

/// Bus de la malla: enrutado **en proceso**, sin sockets ni driver.
#[derive(Debug, Default)]
pub struct MeshBus {
    pending: VecDeque<(PeerId, MeshFrame)>,
    delivered: u64,
    dropped: u64,
}

impl MeshBus {
    /// Bus vacío.
    pub fn new() -> Self {
        Self::default()
    }

    /// Encola un fotograma para su difusión.
    pub fn enqueue(&mut self, origin: PeerId, frame: MeshFrame) {
        self.pending.push_back((origin, frame));
    }

    /// Fotogramas pendientes de enrutar.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Fotogramas que produjeron algún cambio en algún nodo.
    pub fn delivered(&self) -> u64 {
        self.delivered
    }

    /// Fotogramas que no aportaron nada (idempotencia).
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Entrega cada fotograma pendiente a todos los nodos salvo su emisor.
    pub fn route(&mut self, nodes: &mut [MeshNode]) -> RouteReport {
        let mut report = RouteReport::default();
        while let Some((origin, frame)) = self.pending.pop_front() {
            report.frames += 1;
            let mut useful = false;
            for node in nodes.iter_mut() {
                if node.id == origin.0 {
                    continue;
                }
                report.deliveries += 1;
                match node.ingest(&frame) {
                    IngestOutcome::Merged(n) => {
                        report.merged += n;
                        useful = true;
                    }
                    IngestOutcome::Conflicts(n) => {
                        report.conflicts += n;
                        useful = true;
                    }
                    IngestOutcome::Stale => report.stale += 1,
                    IngestOutcome::NoOp => report.noop += 1,
                }
            }
            if useful {
                self.delivered += 1;
            } else {
                self.dropped += 1;
            }
        }
        report
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Informe y acumuladores de sincronización
// ─────────────────────────────────────────────────────────────────────────

/// Acumulador interno de contadores de una sincronización.
#[derive(Debug, Clone, Copy, Default)]
struct Tally {
    merged: usize,
    conflicts: usize,
    stale: usize,
    noop: usize,
    deliveries: u64,
    wire_bytes: usize,
}

/// Informe de una sincronización de la malla.
#[derive(Debug, Clone)]
pub struct SyncReport {
    /// Rondas ejecutadas.
    pub rounds: usize,
    /// Número de nodos.
    pub peers: usize,
    /// Entradas presentes en el nodo más rico.
    pub entries: usize,
    /// Entradas nuevas incorporadas.
    pub merged: usize,
    /// Entradas divergentes fusionadas (paraconsistencia).
    pub conflicts: usize,
    /// Fotogramas obsoletos descartados.
    pub stale: usize,
    /// Entregas sin efecto (idempotencia holográfica).
    pub noop: usize,
    /// Entregas totales intentadas.
    pub deliveries: u64,
    /// Bytes intercambiados por el formato *wire*.
    pub wire_bytes: usize,
    /// Huella holográfica global tras la sincronización.
    pub digest: u64,
    /// ¿Todos los nodos comparten la misma huella?
    pub converged: bool,
    /// Fracción de entradas en desacuerdo con la mayoría, en `[0,1]`.
    pub drift: f64,
    /// Duración de la sincronización en microsegundos.
    pub micros: u128,
    /// `true` si se usaron hilos obreros (`std::thread` + `mpsc`).
    pub threaded: bool,
}

impl SyncReport {
    /// Descripción compacta para el log ontológico.
    pub fn label(&self) -> String {
        format!(
            "{} peers · {} ronda(s) · entradas={} · fusión={} · conflicto={} · obsoleto={} · no-op={} · {} entregas · {} B wire · digest=0x{:016X} · deriva={:.4} · convergido={} · {} µs · vía={}",
            self.peers,
            self.rounds,
            self.entries,
            self.merged,
            self.conflicts,
            self.stale,
            self.noop,
            self.deliveries,
            self.wire_bytes,
            self.digest,
            self.drift,
            self.converged,
            self.micros,
            if self.threaded { "hilos std" } else { "bus en proceso" }
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Malla
// ─────────────────────────────────────────────────────────────────────────

/// Malla completa: varios nodos más el bus que los une.
#[derive(Debug, Default)]
pub struct MeshCluster {
    nodes: Vec<MeshNode>,
    bus: MeshBus,
    epoch: u64,
    wire_bytes: usize,
}

impl MeshCluster {
    /// Crea una malla con `peers` nodos (mínimo uno).
    pub fn new(peers: usize) -> Self {
        let peers = peers.max(1);
        MeshCluster {
            nodes: (0..peers).map(|id| MeshNode::new(id, peers)).collect(),
            bus: MeshBus::new(),
            epoch: 0,
            wire_bytes: 0,
        }
    }

    /// Nodos de la malla.
    pub fn nodes(&self) -> &[MeshNode] {
        &self.nodes
    }

    /// Recupera un nodo por su identificador.
    pub fn node(&self, peer: PeerId) -> Option<&MeshNode> {
        self.nodes.iter().find(|n| n.id == peer.0)
    }

    /// Número de nodos.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// ¿Malla sin nodos?
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Época lógica global alcanzada.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Bytes acumulados por el formato *wire*.
    pub fn wire_bytes(&self) -> usize {
        self.wire_bytes
    }

    /// Entradas del nodo más rico.
    pub fn entries(&self) -> usize {
        self.nodes.iter().map(|n| n.len()).max().unwrap_or(0)
    }

    /// Siembra una región en **todos** los nodos (condición inicial común).
    pub fn seed(
        &mut self,
        name: &str,
        region: RegionId,
        state: QuantumState,
    ) -> (PeerId, u64) {
        let mut key = 0;
        for node in self.nodes.iter_mut() {
            let (k, _) = node.insert(name, region, state.clone());
            key = k;
        }
        (PeerId(0), key)
    }

    /// Introduce una escritura en **un solo** nodo, creando divergencia.
    pub fn diverge(
        &mut self,
        peer: PeerId,
        name: &str,
        region: RegionId,
        state: QuantumState,
    ) -> bool {
        match self.nodes.get_mut(peer.0) {
            Some(node) => node.insert(name, region, state).1,
            None => false,
        }
    }

    /// Huella holográfica global: `XOR` de las huellas de cada nodo, mezcladas
    /// con su índice para que nodos idénticos **no se cancelen** entre sí.
    pub fn hologram(&self) -> u64 {
        self.nodes
            .iter()
            .fold(0_u64, |acc, node| acc ^ mix64(node.hologram(), node.id as u64))
    }

    /// ¿Todos los nodos comparten la misma huella (y hay contenido)?
    pub fn converged(&self) -> bool {
        match self.nodes.first() {
            Some(first) => {
                !first.is_empty()
                    && self.nodes.iter().all(|n| n.hologram() == first.hologram())
            }
            None => false,
        }
    }

    /// Fracción de entradas en desacuerdo con la mayoría, en `[0,1]`.
    pub fn drift(&self) -> f64 {
        let mut tally: BTreeMap<u64, BTreeMap<u64, usize>> = BTreeMap::new();
        let mut pairs = 0_usize;
        for node in &self.nodes {
            for entry in node.entries() {
                *tally
                    .entry(entry.key)
                    .or_default()
                    .entry(entry.digest)
                    .or_insert(0) += 1;
                pairs += 1;
            }
        }
        if pairs == 0 {
            return 0.0;
        }
        let mut aligned = 0_usize;
        for digests in tally.values() {
            aligned += digests.values().copied().max().unwrap_or(0);
        }
        1.0 - (aligned as f64) / (pairs as f64)
    }

    /// Ensambla el informe final a partir del acumulador interno.
    fn finish(&self, rounds: usize, tally: Tally, threaded: bool, start: Instant) -> SyncReport {
        SyncReport {
            rounds,
            peers: self.nodes.len(),
            entries: self.entries(),
            merged: tally.merged,
            conflicts: tally.conflicts,
            stale: tally.stale,
            noop: tally.noop,
            deliveries: tally.deliveries,
            wire_bytes: tally.wire_bytes,
            digest: self.hologram(),
            converged: self.converged(),
            drift: self.drift(),
            micros: start.elapsed().as_micros(),
            threaded,
        }
    }

    /// Sincroniza la malla a través del bus en proceso (determinista).
    pub fn synchronize(&mut self, rounds: usize) -> SyncReport {
        let start = Instant::now();
        let mut tally = Tally::default();
        for _ in 0..rounds {
            self.epoch += 1;
            let epoch = self.epoch;
            for node in self.nodes.iter_mut() {
                node.advance(epoch);
            }
            for node in self.nodes.iter() {
                let frame = node.snapshot();
                tally.wire_bytes += frame.to_wire().len();
                self.bus.enqueue(PeerId(node.id), frame);
            }
            let routed = self.bus.route(&mut self.nodes);
            tally.merged += routed.merged;
            tally.conflicts += routed.conflicts;
            tally.stale += routed.stale;
            tally.noop += routed.noop;
            tally.deliveries += routed.deliveries as u64;
        }
        self.wire_bytes += tally.wire_bytes;
        self.finish(rounds, tally, false, start)
    }

    /// Sincroniza la malla con **hilos obreros** (`std::thread` + `mpsc`).
    ///
    /// Cada nodo vive en su propio hilo y se comunica por canales en memoria:
    /// no hay sockets, ni *loops* de red, ni llamadas al driver del sistema
    /// operativo. Un hub central recolecta un fotograma por obrero y ronda y lo
    /// difunde al resto; el hilo principal recompone la malla con los estados
    /// finales, de modo que el resultado es **determinista** pese al
    /// paralelismo.
    pub fn synchronize_threaded(&mut self, rounds: usize) -> SyncReport {
        let start = Instant::now();
        let peers = self.nodes.len();
        if peers == 0 || rounds == 0 {
            return self.finish(rounds, Tally::default(), true, start);
        }

        let (announce_tx, announce_rx) = mpsc::channel::<(usize, MeshFrame)>();
        let (done_tx, done_rx) = mpsc::channel::<(usize, usize, usize, usize, usize, MeshNode)>();
        let mut broadcast = Vec::with_capacity(peers);
        let mut inboxes = Vec::with_capacity(peers);
        for _ in 0..peers {
            let (tx, rx) = mpsc::channel::<MeshFrame>();
            broadcast.push(tx);
            inboxes.push(rx);
        }

        let base_epoch = self.epoch;
        // Hub: recolecta `peers` fotogramas por ronda y los difunde a todos.
        let hub = thread::spawn(move || {
            for _ in 0..rounds {
                let mut frames = Vec::with_capacity(peers);
                for _ in 0..peers {
                    match announce_rx.recv() {
                        Ok((_, frame)) => frames.push(frame),
                        Err(_) => return,
                    }
                }
                for frame in &frames {
                    for tx in &broadcast {
                        if tx.send(frame.clone()).is_err() {
                            return;
                        }
                    }
                }
            }
        });

        let mut handles = Vec::with_capacity(peers);
        let node_seeds: Vec<MeshNode> = self.nodes.to_vec();
        for (id, (rx, mut node)) in inboxes.into_iter().zip(node_seeds).enumerate() {
            let announce = announce_tx.clone();
            let done = done_tx.clone();
            handles.push(thread::spawn(move || {
                let mut merged = 0_usize;
                let mut conflicts = 0_usize;
                let mut stale = 0_usize;
                let mut noop = 0_usize;
                let mut wire = 0_usize;
                let mut epoch = base_epoch;
                for round in 0..rounds {
                    if round > 0 {
                        for _ in 0..peers {
                            match rx.recv() {
                                Ok(frame) => match node.ingest(&frame) {
                                    IngestOutcome::Merged(n) => merged += n,
                                    IngestOutcome::Conflicts(n) => conflicts += n,
                                    IngestOutcome::Stale => stale += 1,
                                    IngestOutcome::NoOp => noop += 1,
                                },
                                Err(_) => break,
                            }
                        }
                    }
                    epoch += 1;
                    node.advance(epoch);
                    let frame = node.snapshot();
                    wire += frame.to_wire().len();
                    let _ = announce.send((id, frame));
                }
                let _ = done.send((id, merged, conflicts, stale, noop, node));
                wire
            }));
        }

        drop(announce_tx);
        drop(done_tx);

        let mut results = Vec::with_capacity(peers);
        for _ in 0..peers {
            if let Ok(item) = done_rx.recv() {
                results.push(item);
            }
        }
        let mut wire_bytes = 0_usize;
        for handle in handles {
            if let Ok(wire) = handle.join() {
                wire_bytes += wire;
            }
        }
        let _ = hub.join();

        let mut tally = Tally {
            wire_bytes,
            ..Tally::default()
        };
        for (id, merged, conflicts, stale, noop, node) in results {
            tally.merged += merged;
            tally.conflicts += conflicts;
            tally.stale += stale;
            tally.noop += noop;
            if let Some(slot) = self.nodes.get_mut(id) {
                *slot = node;
            }
        }
        tally.deliveries = (peers * rounds) as u64
            + (peers as u64) * (peers as u64 - 1) * rounds.saturating_sub(1) as u64;
        self.epoch = base_epoch + rounds as u64;
        self.wire_bytes += tally.wire_bytes;
        self.finish(rounds, tally, true, start)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Utilidades internas
// ─────────────────────────────────────────────────────────────────────────

/// Hash FNV-1a de 64 bits. Determinista y sin dependencias externas.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Mezcla de avalancha de 64 bits (SplitMix64) usada para desambiguar huellas.
fn mix64(value: u64, salt: u64) -> u64 {
    let mut hash = value ^ salt.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    hash ^= hash >> 30;
    hash = hash.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    hash ^= hash >> 27;
    hash = hash.wrapping_mul(0x94D0_49BB_1331_11EB);
    hash ^ (hash >> 31)
}
