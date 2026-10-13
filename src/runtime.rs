//! # Bara Runtime — Núcleo Paraconsistente, Autopoiético y Holográfico
//!
//! Este módulo implementa el corazón del sistema Bara:
//!
//! * [`QuantumState`] — valor de verdad que unifica lógica clásica,
//!   superposición cuántica y lógica **paraconsistente** (Belnap `FOUR` /
//!   *Logic of Paradox*). Una contradicción (`⊤ ∧ ⊥`) es un *valor*, no un
//!   fallo: el runtime jamás se derrumba ante ella.
//! * [`AutopoieticMutator`] — motor de auto-evolución. Ante una raíz
//!   desconocida no lanza un error fatal: **sintetiza un nuevo axioma**.
//! * [`HolographicMemory`] — memoria direccionada por contenido, de
//!   entropía cero por construcción (escrituras idempotentes).
//! * [`BaraRuntime`] — evaluador de la secuencia de tokens con pila de
//!   estados y log ontológico.

use crate::ffi_ingest::{self, IngestedDecl, ShoreshNode};
use crate::fractal_geometry::FractalLayout;
use crate::lexer::{Keyword, Token, TokenKind};
use crate::memory_region::{Device, RegionKind, RegionTable};
use crate::mesh_sync::{MeshCluster, SyncReport};
use crate::metal_ir::{MetalMapper, MetalProgram};
use crate::quantum_native::{Amplitude, BellPhase, QuantumNative};
use crate::temporal_rollback::{self, TemporalEngine};
use crate::zk_proof::{ConstraintSystem, ZkCertificate};
use std::collections::BTreeMap;

/// Umbral de designación: convierte masa continua de verdad/falsedad en una
/// valoración discreta (la verdad como proceso, no como bit).
const DESIGNATION_THRESHOLD: f64 = 0.5;

/// Referencia del "haz de reconstrucción" holográfico (afinidad topológica).
const HOLOGRAPHIC_REFERENCE: u64 = 0xAAAA_AAAA_AAAA_AAAA;

// ─────────────────────────────────────────────────────────────────────────
// Observación discreta
// ─────────────────────────────────────────────────────────────────────────

/// Resultado discreto de observar (colapsar) un [`QuantumState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    /// Verdadero designado (`⊤`).
    True,
    /// Falso designado (`⊥`).
    False,
    /// Contradicción: verdadero **y** falso (`⊤ ∧ ⊥`).
    Both,
    /// Indeterminado: ni verdadero ni falso (`∅`).
    Neither,
}

impl Observation {
    /// Símbolo lógico canónico.
    pub fn glyph(&self) -> &'static str {
        match self {
            Observation::True => "⊤",
            Observation::False => "⊥",
            Observation::Both => "⊤∧⊥",
            Observation::Neither => "∅",
        }
    }

    /// Nombre ontológico.
    pub fn name(&self) -> &'static str {
        match self {
            Observation::True => "verdadero",
            Observation::False => "falso",
            Observation::Both => "contradicción tolerada",
            Observation::Neither => "indeterminado",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Estado cuántico / paraconsistente
// ─────────────────────────────────────────────────────────────────────────

/// Valor de verdad de Bara: clásico, en superposición o paraconsistente.
///
/// Los estados paraconsistentes se interpretan como un par de Belnap
/// `(truth, falsity)` donde ambas masas pueden ser positivas a la vez.
#[derive(Debug, Clone, PartialEq)]
pub enum QuantumState {
    /// Bit clásico determinista.
    Classical(bool),
    /// Superposición de amplitudes `alpha` (`⊤`) y `beta` (`⊥`).
    Superposition { alpha: f64, beta: f64 },
    /// Par `(truth, falsity)` de la lógica paraconsistente.
    Paraconsistent { truth: f64, falsity: f64 },
}

impl QuantumState {
    /// Construye un estado clásico.
    pub fn classical(b: bool) -> Self {
        QuantumState::Classical(b)
    }

    /// Construye una superposición normalizada (regla de Born).
    pub fn superposition(alpha: f64, beta: f64) -> Self {
        let norm = (alpha * alpha + beta * beta).sqrt();
        if norm == 0.0 {
            QuantumState::Superposition {
                alpha: std::f64::consts::FRAC_1_SQRT_2,
                beta: std::f64::consts::FRAC_1_SQRT_2,
            }
        } else {
            QuantumState::Superposition {
                alpha: alpha / norm,
                beta: beta / norm,
            }
        }
    }

    /// Construye un estado paraconsistente (masas recortadas a `[0,1]`).
    pub fn paraconsistent(truth: f64, falsity: f64) -> Self {
        QuantumState::Paraconsistent {
            truth: clamp01(truth),
            falsity: clamp01(falsity),
        }
    }

    /// Masa de verdad en `[0,1]`.
    pub fn truth_mass(&self) -> f64 {
        match self {
            QuantumState::Classical(b) => {
                if *b {
                    1.0
                } else {
                    0.0
                }
            }
            QuantumState::Superposition { alpha, .. } => alpha * alpha,
            QuantumState::Paraconsistent { truth, .. } => *truth,
        }
    }

    /// Masa de falsedad en `[0,1]`.
    pub fn falsity_mass(&self) -> f64 {
        match self {
            QuantumState::Classical(b) => {
                if *b {
                    0.0
                } else {
                    1.0
                }
            }
            QuantumState::Superposition { beta, .. } => beta * beta,
            QuantumState::Paraconsistent { falsity, .. } => *falsity,
        }
    }

    /// Proyección al par de Belnap `(truth, falsity)`.
    pub fn belnap(&self) -> (f64, f64) {
        (self.truth_mass(), self.falsity_mass())
    }

    /// Colapsa a una observación discreta. Nunca entra en pánico.
    pub fn observe(&self) -> Observation {
        let (t, f) = self.belnap();
        match (t >= DESIGNATION_THRESHOLD, f >= DESIGNATION_THRESHOLD) {
            (true, true) => Observation::Both,
            (true, false) => Observation::True,
            (false, true) => Observation::False,
            (false, false) => Observation::Neither,
        }
    }

    /// ¿El estado viola el principio de no-contradicción? (es decir, es `⊤∧⊥`)
    pub fn is_contradiction(&self) -> bool {
        self.observe() == Observation::Both
    }

    /// Negación paraconsistente: intercambia las masas.
    pub fn negate(&self) -> QuantumState {
        match self {
            QuantumState::Classical(b) => QuantumState::Classical(!b),
            QuantumState::Superposition { alpha, beta } => {
                QuantumState::superposition(*beta, *alpha)
            }
            QuantumState::Paraconsistent { truth, falsity } => {
                QuantumState::paraconsistent(*falsity, *truth)
            }
        }
    }

    /// Conjunción paraconsistente (meet de Belnap: `∧`).
    pub fn conjunction(&self, other: &QuantumState) -> QuantumState {
        let (t1, f1) = self.belnap();
        let (t2, f2) = other.belnap();
        QuantumState::paraconsistent(t1.min(t2), f1.max(f2))
    }

    /// Disyunción paraconsistente (join de Belnap: `∨`).
    pub fn disjunction(&self, other: &QuantumState) -> QuantumState {
        let (t1, f1) = self.belnap();
        let (t2, f2) = other.belnap();
        QuantumState::paraconsistent(t1.max(t2), f1.min(f2))
    }

    /// ¿Es un estado puramente clásico?
    pub fn is_classical(&self) -> bool {
        matches!(self, QuantumState::Classical(_))
    }

    /// Representación legible para el log ontológico.
    pub fn label(&self) -> String {
        match self {
            QuantumState::Classical(b) => format!("CLASSICAL({})", b),
            QuantumState::Superposition { alpha, beta } => format!(
                "SUPERPOSITION(|α|²={:.3}, |β|²={:.3})",
                alpha * alpha,
                beta * beta
            ),
            QuantumState::Paraconsistent { truth, falsity } => {
                format!("PARACONSISTENT(⊤={:.3}, ⊥={:.3})", truth, falsity)
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Mutador autopoiético (auto-evolución)
// ─────────────────────────────────────────────────────────────────────────

/// Axioma sintetizado dinámicamente a partir de una raíz desconocida.
#[derive(Debug, Clone)]
pub struct Axiom {
    /// Raíz que originó el axioma.
    pub root: String,
    /// Generación evolutiva en la que nació.
    pub generation: usize,
    /// Regla lógica generada.
    pub rule: String,
    /// Valencia paraconsistente asociada al axioma.
    pub valence: QuantumState,
}

/// Motor autopoiético: el lenguaje se reescribe a sí mismo.
///
/// Cuando el evaluador encuentra una raíz que no reconoce, no aborta:
/// invoca [`AutopoieticMutator::synthesize`], que **inventa** un axioma
/// determinista pero nuevo a partir de los puntos de código de la raíz.
#[derive(Debug, Clone, Default)]
pub struct AutopoieticMutator {
    generation: usize,
    axioms: BTreeMap<String, Axiom>,
}

impl AutopoieticMutator {
    /// Crea un mutador vacío (generación 0).
    pub fn new() -> Self {
        Self::default()
    }

    /// Número de la generación actual.
    pub fn generation(&self) -> usize {
        self.generation
    }

    /// ¿Ya existe un axioma para esta raíz?
    pub fn knows(&self, root: &str) -> bool {
        self.axioms.contains_key(root)
    }

    /// Recupera el axioma asociado a una raíz.
    pub fn axiom(&self, root: &str) -> Option<&Axiom> {
        self.axioms.get(root)
    }

    /// Itera sobre todos los axiomas sintetizados.
    pub fn axioms(&self) -> impl Iterator<Item = &Axiom> {
        self.axioms.values()
    }

    /// Sintetiza (o recupera) el axioma de una raíz desconocida.
    ///
    /// La generación se incrementa una sola vez por raíz: la síntesis es
    /// idempotente, coherente con el principio de entropía cero.
    pub fn synthesize(&mut self, root: &str) -> Axiom {
        if let Some(existing) = self.axioms.get(root) {
            return existing.clone();
        }

        self.generation += 1;
        let seed = fnv1a(root);

        let modality = ["⊤-estable", "⊥-disolvente", "⊤⊢⊥ metaestable"][(seed % 3) as usize];
        let invariant = [
            "(x ∧ ¬x) → x",
            "(x ∨ ¬x) → ⊤",
            "(x → y) → (¬y → ¬x)",
            "◇x ∧ □¬x → ⊥",
        ][((seed >> 3) % 4) as usize];
        let truth = 0.5 + ((seed >> 7) % 50) as f64 / 100.0;
        let falsity = 0.5 + ((seed >> 11) % 50) as f64 / 100.0;

        let axiom = Axiom {
            root: root.to_string(),
            generation: self.generation,
            rule: format!("⟦{}⟧ ≜ {} : {}", root, modality, invariant),
            valence: QuantumState::paraconsistent(truth, falsity),
        };
        self.axioms.insert(root.to_string(), axiom.clone());
        axiom
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Memoria holográfica de entropía cero
// ─────────────────────────────────────────────────────────────────────────

/// Nodo almacenado en la memoria holográfica.
#[derive(Debug, Clone)]
pub struct MemoryNode {
    /// Etiqueta lógica del nodo.
    pub label: String,
    /// Clave topológica (hash FNV-1a del contenido).
    pub key: u64,
    /// Estado cuántico retenido.
    pub state: QuantumState,
    /// Afinidad con el haz de reconstrucción holográfico, en `[0,1]`.
    pub affinity: f64,
}

/// Ancho lógico del registro de un nodo holográfico, en bytes.
///
/// Suma del tamaño fijo del registro —clave topológica (`u64`, 8 B) y afinidad
/// (`f64`, 8 B)— más el cuerpo del estado (1 B si es clásico, 16 B si lleva dos
/// masas `f64`) y la etiqueta en UTF‑8. Es una medida **lógica**: el kernel no
/// direcciona memoria física, sólo decide cómo repartir nodos sin fragmentar
/// (retícula áurea de [`crate::fractal_geometry`]).
pub fn node_width(label: &str, state: &QuantumState) -> usize {
    const FIXED: usize = 8 + 8;
    let body = match state {
        QuantumState::Classical(_) => 1,
        QuantumState::Superposition { .. } | QuantumState::Paraconsistent { .. } => 16,
    };
    FIXED + body + label.len()
}

/// Memoria holográfica **direccionada por contenido**.
///
/// La clave de cada nodo se deriva del contenido (FNV-1a). Al ser una
/// función determinista, escribir dos veces lo mismo es una **no-operación**
/// y, por tanto, la entropía acumulada es exactamente `0.0`. La memoria se
/// organiza además por *afinidad topológica*: la distancia de Hamming frente
/// al haz de reconstrucción mide cuán "cerca" está cada nodo del todo.
///
/// El **reparto espacial** de los nodos es una retícula áurea: pasos de
/// Fibonacci y orden `i·φ` (véase [`HolographicMemory::layout`]).
#[derive(Debug, Clone, Default)]
pub struct HolographicMemory {
    nodes: BTreeMap<u64, MemoryNode>,
    index: BTreeMap<String, u64>,
    writes: u64,
    /// Retícula áurea: `(clave topológica, ancho lógico)` en orden de escritura.
    grid: Vec<(u64, usize)>,
}

impl HolographicMemory {
    /// Crea una memoria holográfica vacía.
    pub fn new() -> Self {
        Self::default()
    }

    /// Número de nodos retenidos.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// ¿La memoria está vacía?
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Número de escrituras físicas efectivas (idempotentes).
    pub fn writes(&self) -> u64 {
        self.writes
    }

    /// Entropía acumulada. Por construcción, **siempre cero**.
    pub fn entropy(&self) -> f64 {
        0.0
    }

    /// Almacena un estado bajo una etiqueta.
    ///
    /// Devuelve la clave topológica. Si la etiqueta ya existía, es una
    /// no-operación (no incrementa escrituras ni entropía).
    pub fn store(&mut self, label: &str, state: QuantumState) -> u64 {
        let key = fnv1a(label);
        if self.nodes.contains_key(&key) {
            return key;
        }
        // Ancho lógico calculado **antes** de mover el estado: alimenta la
        // retícula áurea que reparte los nodos en el espacio.
        let width = node_width(label, &state);
        let node = MemoryNode {
            label: label.to_string(),
            key,
            state,
            affinity: affinity_to_hologram(key),
        };
        self.nodes.insert(key, node);
        self.index.insert(label.to_string(), key);
        self.grid.push((key, width));
        self.writes += 1;
        key
    }

    /// Recupera un nodo por su etiqueta.
    pub fn recall(&self, label: &str) -> Option<&MemoryNode> {
        self.index.get(label).and_then(|k| self.nodes.get(k))
    }

    /// Recupera un nodo por su clave topológica.
    pub fn recall_by_key(&self, key: u64) -> Option<&MemoryNode> {
        self.nodes.get(&key)
    }

    /// Itera sobre todos los nodos almacenados.
    pub fn nodes(&self) -> impl Iterator<Item = &MemoryNode> {
        self.nodes.values()
    }

    /// Afinidad topológica entre dos claves, en `[0,1]`.
    pub fn topological_affinity_to(&self, a: u64, b: u64) -> f64 {
        let hamming = (a ^ b).count_ones();
        1.0 - (hamming as f64) / 64.0
    }

    /// Reparto espacial (**retícula áurea**) de los nodos retenidos.
    ///
    /// Cada nodo recibe una ranura —desplazamiento lógico en bytes— cuyo paso
    /// es el Fibonacci inmediatamente mayor que su ancho de registro, y el
    /// orden de ocupación es la secuencia de *phyllotaxis* `i·φ`: nodos
    /// consecutivos en el tiempo de escritura quedan **lejos** en el espacio
    /// (propiedad holográfica: el vecino lógico no es el vecino físico). La
    /// fragmentación resultante queda acotada por `1 − 1/φ ≈ 38.2 %`, frente
    /// al `50 %` de los cubos potencia de dos.
    pub fn layout(&self) -> FractalLayout {
        let widths: Vec<usize> = self.grid.iter().map(|(_, width)| *width).collect();
        FractalLayout::plan_from(&widths)
    }

    /// Fragmentación medida de la retícula, en `[0,1)`.
    pub fn fragmentation(&self) -> f64 {
        self.layout().fragmentation
    }

    /// Anchos de registro retenidos, en orden de escritura `(clave, bytes)`.
    pub fn grid(&self) -> &[(u64, usize)] {
        &self.grid
    }

    /// Ranuras áureas de todos los nodos: `(clave topológica, desplazamiento)`.
    pub fn slots(&self) -> Vec<(u64, u64)> {
        let layout = self.layout();
        self.grid
            .iter()
            .enumerate()
            .map(|(position, (key, _))| (*key, layout.slot_of(position).unwrap_or(0)))
            .collect()
    }

    /// Ranura áurea del nodo con esta etiqueta, si existe.
    pub fn slot_of(&self, label: &str) -> Option<u64> {
        let key = *self.index.get(label)?;
        self.slot_of_key(key)
    }

    /// Ranura áurea del nodo con esta clave topológica, si existe.
    pub fn slot_of_key(&self, key: u64) -> Option<u64> {
        let position = self.grid.iter().position(|(k, _)| *k == key)?;
        self.layout().slot_of(position)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Eventos del log ontológico
// ─────────────────────────────────────────────────────────────────────────

/// Evento emitido por el runtime durante la ejecución del génesis.
#[derive(Debug, Clone)]
pub enum ExecutionEvent {
    /// Se reconoció (o no) una raíz.
    Root {
        /// Glifo hebreo.
        glyph: String,
        /// Palabra clave asociada, o `None` si es desconocida.
        keyword: Option<Keyword>,
    },
    /// Manifestación ex nihilo.
    Manifest { state: QuantumState },
    /// Superposición heurística.
    Superpose { state: QuantumState },
    /// Guarda / aislamiento de día-cero.
    Guard { sealed: bool },
    /// Colapso observacional.
    Collapse { from: QuantumState, to: Observation },
    /// Emisión de un estado.
    Emit { text: String },
    /// Axiogénesis: nuevo axioma sintetizado.
    Axiogenesis { axiom: Axiom },
    /// Pliegue (conjunción/disyunción paraconsistente).
    Fold { state: QuantumState },
    /// Escritura en la memoria holográfica.
    Hologram { label: String, key: u64 },
    /// Operación tolerada (nunca fatal).
    Tolerated { reason: String },
    /// Región de memoria introducida (inferencia de regiones).
    Region {
        /// Nombre de la región.
        name: String,
        /// Clase de región.
        kind: RegionKind,
        /// Extensión en bytes.
        bytes: usize,
    },
    /// Certificado ZK emitido por la etapa de compilación.
    ZkVerified {
        /// Etiqueta del enunciado certificado.
        label: String,
        /// Veredicto de la verificación.
        verified: bool,
        /// Número de invariantes comprometidos.
        constraints: usize,
    },
    /// Rollback temporal `Δ⁻¹` de estado (rollback atómico).
    Rollback {
        /// Número de deltas revertidos.
        reverted: usize,
        /// Duración del rollback en microsegundos.
        micros: u128,
        /// Paradoja interceptada que lo motivó.
        paradox: String,
    },
    /// Nodo legado ingerido y saneado (ingesta FFI omnívora).
    Ingested {
        /// Nombre original de la función.
        name: String,
        /// Raíz triconsonántica asignada.
        root: String,
        /// Riesgo detectado.
        hazard: f64,
        /// ¿Fue saneado?
        sanitized: bool,
    },
    /// Qubit nativo materializado en superposición (`Qubit<|ψ⟩>`).
    QuantumSuperposed {
        /// Nombre del qubit.
        name: String,
        /// Estados base del espacio de Hilbert.
        states: usize,
        /// Probabilidad del estado más probable.
        top_probability: f64,
        /// Entropía de la distribución, en bits.
        entropy_bits: f64,
    },
    /// Enlace de entrelazamiento entre dos qubits nativos.
    Entangled {
        /// Primer qubit.
        left: String,
        /// Segundo qubit.
        right: String,
        /// Convención de fase del par de Bell.
        phase: String,
        /// Correlación `⟨Z⊗Z⟩`.
        correlation: f64,
    },
    /// Colapso de un qubit nativo por la regla de Born.
    QuantumCollapsed {
        /// Nombre del qubit.
        name: String,
        /// Estado base observado.
        outcome: String,
        /// Probabilidad del resultado.
        probability: f64,
    },
    /// Sincronización de un nodo de la malla global de memoria.
    MeshSynced {
        /// Nodo (peer) sincronizado.
        region: String,
        /// Número de peers de la malla.
        peers: usize,
        /// Huella holográfica del nodo.
        digest: u64,
        /// ¿La malla quedó convergida?
        converged: bool,
    },
    /// Traducción del AST a Metal-IR y a un *layout* abstracto de registros.
    MetalMapped {
        /// Etiqueta del programa de metal.
        program: String,
        /// Número de instrucciones emitidas.
        ops: usize,
        /// Registros físicos asignados.
        registers: usize,
        /// Derrames a ranuras estáticas.
        spills: usize,
    },
    /// Turno del oráculo REPL (compilación dinámica).
    Oracle {
        /// Consulta original.
        input: String,
        /// Programa *Shoresh* compilado.
        roots: String,
        /// Resumen de la respuesta.
        reply: String,
    },
}

impl ExecutionEvent {
    /// Formatea el evento para el log ontológico.
    pub fn describe(&self) -> String {
        match self {
            ExecutionEvent::Root { glyph, keyword } => match keyword {
                Some(k) => format!("⟐ léxico     raíz {} reconocida ⇒ {}", glyph, k.meaning()),
                None => format!(
                    "⟐ léxico     raíz {} desconocida ⇒ activando autopoiesis",
                    glyph
                ),
            },
            ExecutionEvent::Manifest { state } => {
                format!("⊕ génesis    manifestación ex nihilo ⇒ {}", state.label())
            }
            ExecutionEvent::Superpose { state } => {
                format!("≈ heurística superposición adaptativa ⇒ {}", state.label())
            }
            ExecutionEvent::Guard { sealed } => {
                format!("⛨ guarda     aislamiento de día-cero (sellado={})", sealed)
            }
            ExecutionEvent::Collapse { from, to } => format!(
                "⊙ colapso    {} ⊳ observación {} ({})",
                from.label(),
                to.glyph(),
                to.name()
            ),
            ExecutionEvent::Emit { text } => format!("🗣 emisión    {}", text),
            ExecutionEvent::Axiogenesis { axiom } => format!(
                "✦ autopoiesis gen#{} {} ⇒ {}",
                axiom.generation, axiom.root, axiom.rule
            ),
            ExecutionEvent::Fold { state } => {
                format!("⊗ pliegue    conjunción/disyunción ⇒ {}", state.label())
            }
            ExecutionEvent::Hologram { label, key } => {
                format!("❖ holograma  «{}» key=0x{:016X}", label, key)
            }
            ExecutionEvent::Tolerated { reason } => format!("∅ tolerado   {}", reason),
            ExecutionEvent::Region { name, kind, bytes } => format!(
                "▤ región     «{}» {} {} bytes (liberación estática)",
                name,
                kind.label(),
                bytes
            ),
            ExecutionEvent::ZkVerified {
                label,
                verified,
                constraints,
            } => format!(
                "🔐 ZK-proof   certificado «{}» · {} invariantes ⇒ verificado={}",
                label, constraints, verified
            ),
            ExecutionEvent::Rollback {
                reverted,
                micros,
                paradox,
            } => format!(
                "⧗ Δ⁻¹ rollback «{}» ⊳ {} deltas revertidos en {} µs",
                paradox, reverted, micros
            ),
            ExecutionEvent::Ingested {
                name,
                root,
                hazard,
                sanitized,
            } => format!(
                "⇄ ingesta FFI «{}» ⇒ raíz {} · riesgo={:.2} · saneado={}",
                name, root, hazard, sanitized
            ),
            ExecutionEvent::QuantumSuperposed {
                name,
                states,
                top_probability,
                entropy_bits,
            } => format!(
                "⌬ qubit      «{}» {} estado(s) · p★={:.3} · S={:.3} bits",
                name, states, top_probability, entropy_bits
            ),
            ExecutionEvent::Entangled {
                left,
                right,
                phase,
                correlation,
            } => format!(
                "⧉ entrelaza  «{}» ⊗ «{}» {} · ⟨Z⊗Z⟩={:+.0} ⇒ ⊤∧⊥ tolerado",
                left, right, phase, correlation
            ),
            ExecutionEvent::QuantumCollapsed {
                name,
                outcome,
                probability,
            } => format!(
                "◉ colapso-q  «{}» ⇒ {} (p={:.3}) · Born determinista",
                name, outcome, probability
            ),
            ExecutionEvent::MeshSynced {
                region,
                peers,
                digest,
                converged,
            } => format!(
                "⬡ malla      «{}» {} peer(s) · hológrafo=0x{:016X} · convergido={}",
                region, peers, digest, converged
            ),
            ExecutionEvent::MetalMapped {
                program,
                ops,
                registers,
                spills,
            } => format!(
                "⛭ metal-IR   «{}» {} op(s) · {} registro(s) · {} derrame(s) · bypass del driver",
                program, ops, registers, spills
            ),
            ExecutionEvent::Oracle {
                input,
                roots,
                reply,
            } => format!("🔮 oráculo    «{}» ⇒ shoresh: {} ⇒ {}", input, roots, reply),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Runtime / evaluador
// ─────────────────────────────────────────────────────────────────────────

/// Evaluador del lenguaje Bara.
///
/// Mantiene una pila de [`QuantumState`], la memoria holográfica, el mutador
/// autopoiético y el log de eventos. **No existe una ruta de error fatal**:
/// toda situación anómala produce un [`ExecutionEvent::Tolerated`].
#[derive(Debug, Default)]
pub struct BaraRuntime {
    /// Pila de estados en evaluación.
    pub stack: Vec<QuantumState>,
    /// Memoria holográfica asociada.
    pub memory: HolographicMemory,
    /// Motor autopoiético.
    pub mutator: AutopoieticMutator,
    /// Tabla de regiones de memoria inferidas.
    pub regions: RegionTable,
    /// Motor de navegación temporal y rollback `Δ⁻¹`.
    pub timeline: TemporalEngine,
    /// Certificado ZK del AST (si la etapa de compilación se ejecutó).
    pub certificate: Option<ZkCertificate>,
    /// Registro de qubits nativos (`Qubit<|ψ⟩>`) y entrelazamientos.
    pub qubits: QuantumNative,
    /// Malla global de memoria holográfica sincronizada.
    pub mesh: MeshCluster,
    /// Último programa Metal-IR emitido (bypass del driver).
    pub metal: Option<MetalProgram>,
    log: Vec<ExecutionEvent>,
}

impl BaraRuntime {
    /// Crea un runtime virgen.
    pub fn new() -> Self {
        Self::default()
    }

    /// Acceso al log ontológico acumulado.
    pub fn log(&self) -> &[ExecutionEvent] {
        &self.log
    }

    /// Apila un estado.
    pub fn push(&mut self, state: QuantumState) {
        self.stack.push(state);
    }

    /// Desapila un estado.
    pub fn pop(&mut self) -> Option<QuantumState> {
        self.stack.pop()
    }

    /// Observa la cumbre de la pila sin extraerla.
    pub fn peek(&self) -> Option<&QuantumState> {
        self.stack.last()
    }

    /// Ejecuta la etapa de compilación ZK y certifica los invariantes del AST.
    ///
    /// Construye el sistema de restricciones a partir de los axiomas
    /// autopoiéticos y de los invariantes paraconsistentes del runtime,
    /// emite la prueba y la verifica independientemente.
    ///
    /// Es total **por construcción**: no hay ninguna ruta de fallo que cubrir
    /// y por tanto sin `expect()` ni `unwrap()`, y sin `Option` que degradar
    /// (A1 · totalidad sin excepciones).
    pub fn certify(&mut self) -> &ZkCertificate {
        let mut invariants: Vec<String> = self.mutator.axioms().map(|a| a.rule.clone()).collect();
        invariants.push("∀s ∈ pila · 0 ≤ ⊤(s) ≤ 1 ∧ 0 ≤ ⊥(s) ≤ 1".to_string());
        invariants.push("¬(⊤ ∧ ⊥) ⇒ contradicción retenida, jamás explosión".to_string());
        invariants.push("memoria holográfica idempotente ⇒ entropía = 0".to_string());

        let system = ConstraintSystem::from_invariants(&invariants);
        let statement = system.statement("AST-Bara-génesis", &invariants);
        let certificate = ZkCertificate::certify(&system, statement);

        self.record(ExecutionEvent::ZkVerified {
            label: certificate.statement.label.clone(),
            verified: certificate.result.verified,
            constraints: certificate.statement.n_constraints,
        });
        // `Option::insert` almacena el certificado **y** devuelve el préstamo
        // del valor recién guardado (`&mut ZkCertificate`, que en la posición
        // de retorno re-coerciona a `&ZkCertificate`). El préstamo nace del
        // propio `insert`, así que la función es total por construcción: no
        // queda ninguna ruta de fallo capaz de abortar el proceso (A1).
        self.certificate.insert(certificate)
    }

    /// Ingiere una cabecera C y sanea sus declaraciones hacia el AST *Shoresh*.
    pub fn ingest_c(&mut self, source: &str) -> Vec<ShoreshNode> {
        self.ingest_decls(ffi_ingest::ingest_c(source))
    }

    /// Ingiere un módulo Python y sanea sus funciones hacia el AST *Shoresh*.
    pub fn ingest_python(&mut self, source: &str) -> Vec<ShoreshNode> {
        self.ingest_decls(ffi_ingest::ingest_python(source))
    }

    /// Materializa una región `SHARED` por cada nodo ingerido y lo registra.
    fn ingest_decls(&mut self, decls: Vec<IngestedDecl>) -> Vec<ShoreshNode> {
        let ast = ffi_ingest::to_shoresh(&decls);
        for node in &ast.nodes {
            let bytes = node.arity * 8 + 8;
            let name = format!("ffi:{}", node.root);
            self.regions
                .introduce(name.clone(), RegionKind::Shared, bytes, None);
            self.record(ExecutionEvent::Region {
                name,
                kind: RegionKind::Shared,
                bytes,
            });
            self.record(ExecutionEvent::Ingested {
                name: node.original.clone(),
                root: node.root.clone(),
                hazard: node.hazard,
                sanitized: node.sanitized,
            });
        }
        ast.nodes
    }

    /// Registra un evento externo en el log ontológico.
    ///
    /// Lo usan el oráculo REPL y los subsistemas de la fase AETHER‑Ω para
    /// dejar constancia de sus operaciones en el diario del runtime.
    pub fn note(&mut self, event: ExecutionEvent) {
        self.record(event);
    }

    /// Materializa un qubit nativo en superposición y lo evalúa.
    ///
    /// `alpha` y `beta` son las amplitudes complejas de `|⊤⟩` y `|⊥⟩`; el
    /// vector se normaliza por la regla de Born. La valencia resultante se
    /// apila en el runtime paraconsistente.
    pub fn superpose_native(
        &mut self,
        name: &str,
        alpha: Amplitude,
        beta: Amplitude,
    ) -> QuantumState {
        let evaluation = self.qubits.superpose(name, alpha, beta);
        let states = self.qubits.get(name).map(|qubit| qubit.dim()).unwrap_or(0);
        self.record(ExecutionEvent::QuantumSuperposed {
            name: name.to_string(),
            states,
            top_probability: evaluation.probability,
            entropy_bits: evaluation.entropy_bits,
        });
        self.push(evaluation.valence.clone());
        evaluation.valence
    }

    /// Entrelaza dos qubits nativos con una fase de Bell.
    ///
    /// La descripción local de cada mitad es la traza parcial del par: se
    /// obtiene una contradicción `⊤∧⊥` que el runtime **tolera** (no explota,
    /// no colapsa). Devuelve `None` si algún qubit no existe.
    pub fn entangle_native(
        &mut self,
        left: &str,
        right: &str,
        phase: BellPhase,
    ) -> Option<QuantumState> {
        let evaluation = self.qubits.entangle(left, right, phase)?;
        self.record(ExecutionEvent::Entangled {
            left: left.to_string(),
            right: right.to_string(),
            phase: phase.label().to_string(),
            correlation: phase.correlation(),
        });
        self.push(evaluation.valence.clone());
        Some(evaluation.valence)
    }

    /// Colapsa un qubit nativo (regla de Born) con propagación **no local** a
    /// sus socios entrelazados. Devuelve `None` si el qubit no existe.
    pub fn collapse_native(&mut self, name: &str) -> Option<QuantumState> {
        let evaluation = self.qubits.collapse(name)?;
        let outcome = evaluation
            .measured
            .map(|index| format!("|{}⟩", index))
            .unwrap_or_else(|| "∅".to_string());
        self.record(ExecutionEvent::QuantumCollapsed {
            name: name.to_string(),
            outcome,
            probability: evaluation.probability,
        });
        self.push(evaluation.valence.clone());
        Some(evaluation.valence)
    }

    /// Sincroniza la **malla global de memoria** a partir de las regiones vivas
    /// del runtime.
    ///
    /// La primera llamada siembra cada región (con su estado holográfico, si lo
    /// hay) en todos los nodos; las siguientes propagan únicamente los cambios,
    /// de modo que la sincronización es idempotente. El transporte es el bus en
    /// proceso o **hilos obreros** (`std::thread` + `mpsc`), nunca sockets.
    pub fn mesh_sync(&mut self, peers: usize, rounds: usize, threaded: bool) -> SyncReport {
        if self.mesh.is_empty() {
            self.mesh = MeshCluster::new(peers);
        }
        if self.mesh.entries() == 0 {
            for region in self.regions.regions() {
                let name = region.name.clone();
                let id = region.id;
                let state = self
                    .memory
                    .recall(&name)
                    .map(|node| node.state.clone())
                    .unwrap_or_else(|| QuantumState::classical(true));
                self.mesh.seed(&name, id, state);
            }
        }

        let report = if threaded {
            self.mesh.synchronize_threaded(rounds)
        } else {
            self.mesh.synchronize(rounds)
        };

        let peers_online = self.mesh.len();
        let snapshot: Vec<(String, u64)> = self
            .mesh
            .nodes()
            .iter()
            .map(|node| (node.name.clone(), node.hologram()))
            .collect();
        for (name, digest) in snapshot {
            self.record(ExecutionEvent::MeshSynced {
                region: name,
                peers: peers_online,
                digest,
                converged: report.converged,
            });
        }
        report
    }

    /// Traduce el AST a **Metal-IR** y a un *layout* abstracto de registros,
    /// con la ruta de bypass del driver ya calculada.
    pub fn lower_metal(&mut self, label: &str, device: Device, tokens: &[Token]) -> MetalProgram {
        let program = MetalMapper::lower(label, device, tokens);
        self.record(ExecutionEvent::MetalMapped {
            program: program.label.clone(),
            ops: program.len(),
            registers: program.allocation.allocated(),
            spills: program.allocation.spilled(),
        });
        self.metal = Some(program.clone());
        program
    }

    fn record(&mut self, event: ExecutionEvent) {
        self.log.push(event);
    }

    /// Ejecuta una secuencia de tokens. **Nunca falla.**
    pub fn execute(&mut self, tokens: &[Token]) -> &[ExecutionEvent] {
        for token in tokens {
            self.step(&token.kind);
        }
        &self.log
    }

    /// Un paso de evaluación sobre un token.
    fn step(&mut self, kind: &TokenKind) {
        match kind {
            TokenKind::Root { letters, keyword } => self.eval_root(letters, *keyword),
            TokenKind::Number(n) => self.push(QuantumState::classical(*n != 0.0)),
            TokenKind::Str(s) => {
                let label = format!("str:{}", s);
                let key = self.memory.store(&label, QuantumState::classical(true));
                self.record(ExecutionEvent::Hologram { label, key });
            }
            TokenKind::BangBang => self.fuse(),
            TokenKind::Bang | TokenKind::Question => self.collapse(),
            TokenKind::Star => self.binary(false),
            TokenKind::Plus => self.binary(true),
            TokenKind::Newline | TokenKind::Eof => {}
            _ => {}
        }
    }

    /// Evalúa una raíz triconsonántica según su palabra clave.
    fn eval_root(&mut self, letters: &str, keyword: Option<Keyword>) {
        if letters.is_empty() {
            return;
        }
        self.record(ExecutionEvent::Root {
            glyph: letters.to_string(),
            keyword,
        });

        match keyword {
            Some(Keyword::Manifest) => {
                let state = QuantumState::classical(true);
                let label = format!("genesis:{}", self.memory.len() + 1);
                let key = self.memory.store(&label, state.clone());
                self.record(ExecutionEvent::Hologram { label, key });
                // Región de génesis: inmortal, ex nihilo (liberación estática).
                let region_bytes = 64 * (self.regions.len() + 1);
                let region_name = format!("bereshit:{}", self.regions.len() + 1);
                self.regions.introduce(
                    region_name.clone(),
                    RegionKind::Genesis,
                    region_bytes,
                    None,
                );
                self.record(ExecutionEvent::Region {
                    name: region_name,
                    kind: RegionKind::Genesis,
                    bytes: region_bytes,
                });
                self.record(ExecutionEvent::Manifest {
                    state: state.clone(),
                });
                self.push(state);
            }
            Some(Keyword::Synthesize) => {
                let state = QuantumState::superposition(0.8, 0.6);
                self.record(ExecutionEvent::Superpose {
                    state: state.clone(),
                });
                self.push(state);
            }
            Some(Keyword::Guard) => match self.pop() {
                Some(top) => {
                    let (truth, _falsity) = top.belnap();
                    // Se sella la falsedad a cero: el estado queda aislado
                    // contra la explosión lógica (ex falso quodlibet).
                    self.push(QuantumState::paraconsistent(truth, 0.0));
                    self.record(ExecutionEvent::Guard { sealed: true });
                }
                None => self.record(ExecutionEvent::Tolerated {
                    reason: "שמר sobre pila vacía (tolerado)".to_string(),
                }),
            },
            Some(Keyword::Execute) => self.collapse(),
            Some(Keyword::Emit) => {
                let text = self
                    .peek()
                    .map(|s| s.label())
                    .unwrap_or_else(|| "<pila vacía>".to_string());
                self.record(ExecutionEvent::Emit { text });
            }
            Some(Keyword::Judge) => self.binary(false),
            None => {
                let axiom = self.mutator.synthesize(letters);
                let valence = axiom.valence.clone();
                self.record(ExecutionEvent::Axiogenesis { axiom });
                self.push(valence);
            }
        }
    }

    /// Colapsa la cumbre de la pila a una observación clásica.
    fn collapse(&mut self) {
        match self.pop() {
            Some(from) => {
                let to = from.observe();
                let collapsed =
                    QuantumState::classical(matches!(to, Observation::True | Observation::Both));
                self.record(ExecutionEvent::Collapse { from, to });
                self.push(collapsed);
            }
            None => self.record(ExecutionEvent::Tolerated {
                reason: "colapso sobre pila vacía (tolerado)".to_string(),
            }),
        }
    }

    /// Aplica una operación binaria paraconsistente sobre los dos estados
    /// superiores de la pila.
    fn binary(&mut self, disjunction: bool) {
        let b = self.pop();
        let a = self.pop();
        match (a, b) {
            (Some(a), Some(b)) => {
                let state = if disjunction {
                    a.disjunction(&b)
                } else {
                    a.conjunction(&b)
                };
                self.record(ExecutionEvent::Fold {
                    state: state.clone(),
                });
                self.push(state);
            }
            (a, b) => {
                if let Some(a) = a {
                    self.push(a);
                }
                if let Some(b) = b {
                    self.push(b);
                }
                self.record(ExecutionEvent::Tolerated {
                    reason: "operación binaria con operandos insuficientes (tolerado)".to_string(),
                });
            }
        }
    }

    /// Fusión paraconsistente `!!`: confluye la cumbre con el valor
    /// contradictorio `⊤∧⊥`. Si se intercepta una **paradoja irresoluble**
    /// (verdad y falsedad máximas), el motor temporal ejecuta un rollback
    /// atómico `Δ⁻¹` y se preserva el estado previo en lugar de colapsar.
    fn fuse(&mut self) {
        match self.pop() {
            Some(top) => {
                // Instantánea temporal antes de la operación riesgosa.
                let marker = self.timeline.mark();
                self.timeline.push(top.clone());

                let contradiction = QuantumState::paraconsistent(1.0, 1.0);
                let state = top.conjunction(&contradiction);
                self.timeline.push(state.clone());
                self.record(ExecutionEvent::Fold {
                    state: state.clone(),
                });

                if let Some(paradox) = temporal_rollback::detect_paradox(&state) {
                    let report = self.timeline.rollback_paradox(marker, &paradox);
                    self.record(ExecutionEvent::Rollback {
                        reverted: report.reverted,
                        micros: report.micros,
                        paradox: paradox.description,
                    });
                    // El estado anterior sobrevive: la paradoja se disuelve.
                    self.push(top);
                } else {
                    self.push(state);
                }
            }
            None => self.record(ExecutionEvent::Tolerated {
                reason: "fusión !! sobre pila vacía (tolerado)".to_string(),
            }),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Utilidades internas
// ─────────────────────────────────────────────────────────────────────────

/// Recorta un valor al intervalo `[0, 1]`.
fn clamp01(x: f64) -> f64 {
    x.clamp(0.0, 1.0)
}

/// Hash FNV-1a de 64 bits. Determinista y sin dependencias externas.
fn fnv1a(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in s.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Afinidad topológica de una clave respecto al haz holográfico.
///
/// Se mide la distancia de Hamming normalizada frente a
/// [`HOLOGRAPHIC_REFERENCE`]; `1.0` significa coincidencia total.
fn affinity_to_hologram(key: u64) -> f64 {
    let hamming = (key ^ HOLOGRAPHIC_REFERENCE).count_ones();
    1.0 - (hamming as f64) / 64.0
}
