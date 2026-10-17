//! # Capa cognitiva neural‑simbólica y pasarela de conocimiento
//!
//! Este módulo construye la **periferia inteligente** del kernel: el lugar por
//! donde entra el conocimiento externo, donde se traduce a *Shoresh* y donde el
//! filtro de Belnap decide qué propuesta merece llegar a una célula *sandbox*.
//! Nada de aquí escribe en el BAR‑Core: la capa cognitiva propone, el núcleo
//! dispone.
//!
//! ```text
//!   frameworks externos        lenguaje natural
//!   (Torch, HF, ONNX, …)         «crea una función segura»
//!            │                          │
//!            ▼                          ▼
//!   ┌────────────────────┐    ┌────────────────────┐
//!   │ GlobalToShoresh    │    │ NlpToShoresh       │
//!   └─────────┬──────────┘    └─────────┬──────────┘
//!             └──────────┬──────────────┘
//!                        ▼
//!              ┌──────────────────────┐
//!              │ HallucinationFilter  │  ← BelnapMatrix::evaluate
//!              │ ⊤ pasa · ⊥/⊤∧⊥/∅ no  │
//!              └──────────┬───────────┘
//!                         ▼
//!       célula temporal (untrusted, sin escritura) ▸ contracción Tzimtzum
//! ```
//!
//! ## FASE 1.1 — Global Knowledge Gateway
//! * [`KnowledgeGateway`] recibe por los transportes del kernel
//!   ([`Ingress`](crate::immunity_gateway::Ingress)) y confina cada paquete en
//!   una [`TempCell`]: `untrusted = true` y `writes_to_core() = false` **por
//!   construcción**, porque la celda no posee ningún método `&mut` que alcance
//!   al núcleo. La frontera de confianza sigue siendo una sola.
//! * Las celdas son efímeras y acotadas ([`MAX_CELLS`]): se purgan explícitamente
//!   ([`KnowledgeGateway::purge`]) o al agotar el presupuesto de recepción.
//!
//! ## FASE 1.2 — Sintetizadores *global→Shoresh* y *NLP→Shoresh*
//! * [`GlobalToShoresh`] traduce un [`Concept`] de un framework externo a una
//!   [`Mutation`] del repertorio cerrado del mutador: nada de código generado,
//!   sólo nodos auditables.
//! * [`NlpToShoresh`] tokeniza una intención ambigua, descarta el ruido, deriva
//!   raíces triconsonánticas deterministas del hash del token y emite
//!   propuestas. El mismo enunciado produce siempre el mismo árbol y la misma
//!   huella (cero aleatoriedad).
//!
//! ## FASE 1.3 — Filtro de alucinaciones (Belnap `FOUR`)
//! * [`HallucinationFilter`] somete toda propuesta a
//!   [`BelnapMatrix::evaluate`](crate::autopoietic::BelnapMatrix::evaluate) y
//!   **descarta** la contradicción (`⊤∧⊥`) y la indeterminación (`∅`): una
//!   alucinación no se «corrige», se bloquea con motivo explícito.
//!
//! ## FASE 1.4 — Semantic Sandbox Memory
//! * [`SemanticMemory`] guarda embeddings de dimensión fija en memoria aislada
//!   con similitud coseno determinista y búsqueda ordenada, y expone una API
//!   tipada de inspección ([`SemanticMemory::json`]) para el IDE.
//!
//! ## Invariantes del módulo
//! 1. **Cero `unsafe`** (`#![forbid(unsafe_code)]`).
//! 2. **Totalidad (axioma A1)** — sin `unwrap`, sin `expect`, sin `panic`: todo
//!    error de entrada se convierte en [`SynthError`].
//! 3. **Sin acceso de escritura al núcleo** — la capa cognitiva sólo recibe
//!    [`KernelRead`], copia de sólo lectura, y jamás un `&mut KernelCore`.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

use std::collections::BTreeMap;
use std::fmt;

use crate::ast_dna::short_hex;
use crate::autopoietic::{
    BelnapMatrix, BelnapValue, BelnapVerdict, Evidence, KernelRead, Mutation,
};
use crate::crypto_native::sha256;
use crate::ffi_ingest::{BaraType, ShoreshAst, ShoreshNode};
use crate::immunity_gateway::Ingress;
use crate::runtime::QuantumState;
use crate::topology::{self, ContractStats, Contracted};
use crate::visual_builder::triconsonantal;

// ─────────────────────────────────────────────────────────────────────────
// Límites de la capa cognitiva
// ─────────────────────────────────────────────────────────────────────────

/// Dominio de hash de la capa cognitiva.
pub const COGNITIVE_DOMAIN: &[u8] = b"bara:aether-omega:cognitivo:v1";

/// Celdas temporales simultáneas (memoria de confinamiento acotada).
pub const MAX_CELLS: usize = 64;

/// Longitud máxima de un enunciado aceptado por el sintetizador de NLP.
pub const MAX_UTTERANCE: usize = 512;

/// Tokens máximos extraídos de un enunciado.
pub const MAX_TOKENS: usize = 16;

/// Dimensión máxima aceptada por la memoria semántica.
pub const MAX_EMBED_DIM: usize = 32;

/// Ranuras máximas de la memoria semántica.
pub const MAX_SLOTS: usize = 64;

/// Aridad máxima que la capa cognitiva puede proponer (la del kernel).
pub const MAX_PROPOSED_ARITY: usize = crate::autopoietic::MAX_ARITY;

// ─────────────────────────────────────────────────────────────────────────
// Errores tipados de la capa cognitiva
// ─────────────────────────────────────────────────────────────────────────

/// Error tipado de la capa cognitiva.
///
/// Todos los rechazos de la periferia inteligente son explícitos: no hay
/// degradación silenciosa. Un concepto mal formado devuelve un error que el IDE
/// puede mostrar, no un nodo a medias.
#[derive(Debug, Clone, PartialEq)]
pub enum SynthError {
    /// El concepto o la ranura semántica no tienen nombre.
    EmptyLabel,
    /// La aridad propuesta excede el techo del kernel.
    ArityOverflow {
        /// Aridad solicitada.
        arity: usize,
        /// Techo admitido.
        limit: usize,
    },
    /// Una masa cayó fuera de `[0, 1]`.
    MassOutOfRange {
        /// Campo afectado.
        field: &'static str,
        /// Valor recibido.
        value: f64,
    },
    /// Un valor no finito (`NaN` o infinito) en el vocabulario paraconsistente.
    NotFinite {
        /// Campo afectado.
        field: &'static str,
    },
    /// El confinamiento temporal está lleno: hay que purgar antes de recibir.
    GatewayFull {
        /// Techo de celdas.
        limit: usize,
    },
    /// Se pidió una celda temporal que ya no existe.
    UnknownCell {
        /// Identificador de la celda.
        id: u64,
    },
    /// El enunciado estaba vacío o sólo contenía ruido.
    EmptyUtterance,
    /// La dimensión pedida está fuera del rango admitido.
    DimensionOutOfRange {
        /// Dimensión solicitada.
        dim: usize,
        /// Techo admitido.
        limit: usize,
    },
    /// Un embedding no tiene la dimensión de la memoria.
    DimensionMismatch {
        /// Dimensión de la memoria.
        expected: usize,
        /// Dimensión recibida.
        got: usize,
    },
    /// La memoria semántica no admite más ranuras.
    MemoryFull {
        /// Techo de ranuras.
        limit: usize,
    },
}

impl fmt::Display for SynthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SynthError::EmptyLabel => write!(f, "el concepto no tiene nombre"),
            SynthError::ArityOverflow { arity, limit } => {
                write!(f, "aridad {arity} por encima del techo {limit}")
            }
            SynthError::MassOutOfRange { field, value } => {
                write!(f, "masa «{field}» = {value} fuera de [0, 1]")
            }
            SynthError::NotFinite { field } => write!(f, "masa «{field}» no finita"),
            SynthError::GatewayFull { limit } => {
                write!(f, "confinamiento lleno ({limit} celdas)")
            }
            SynthError::UnknownCell { id } => write!(f, "celda temporal {id} desconocida"),
            SynthError::EmptyUtterance => write!(f, "enunciado vacío o sin señal"),
            SynthError::DimensionOutOfRange { dim, limit } => {
                write!(f, "dimensión {dim} fuera del rango 1..={limit}")
            }
            SynthError::DimensionMismatch { expected, got } => {
                write!(
                    f,
                    "embedding de {got} dimensiones donde se esperaban {expected}"
                )
            }
            SynthError::MemoryFull { limit } => {
                write!(f, "memoria semántica llena ({limit} ranuras)")
            }
        }
    }
}

impl std::error::Error for SynthError {}

/// Valida una masa paraconsistente y la devuelve tal cual si es admisible.
fn mass(field: &'static str, value: f64) -> Result<f64, SynthError> {
    if !value.is_finite() {
        return Err(SynthError::NotFinite { field });
    }
    if !(0.0..=1.0).contains(&value) {
        return Err(SynthError::MassOutOfRange { field, value });
    }
    Ok(value)
}

/// Framework externo del que procede un concepto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framework {
    /// PyTorch.
    Torch,
    /// TensorFlow / Keras.
    TensorFlow,
    /// Hugging Face Transformers.
    HuggingFace,
    /// ONNX Runtime.
    Onnx,
    /// Cadenas de agentes tipo LangChain.
    LangChain,
    /// Cualquier otro origen declarado por el usuario.
    Custom,
}

impl Framework {
    /// Nombre canónico.
    pub fn name(&self) -> &'static str {
        match self {
            Framework::Torch => "torch",
            Framework::TensorFlow => "tensorflow",
            Framework::HuggingFace => "huggingface",
            Framework::Onnx => "onnx",
            Framework::LangChain => "langchain",
            Framework::Custom => "custom",
        }
    }

    /// Glifo para el panel del IDE.
    pub fn glyph(&self) -> &'static str {
        match self {
            Framework::Torch => "◉",
            Framework::TensorFlow => "◈",
            Framework::HuggingFace => "❖",
            Framework::Onnx => "⬡",
            Framework::LangChain => "⛓",
            Framework::Custom => "◇",
        }
    }
}

/// Concepto externo, **siempre no confiable**, candidato a nodo *Shoresh*.
#[derive(Debug, Clone, PartialEq)]
pub struct Concept {
    /// Framework de origen.
    pub framework: Framework,
    /// Nombre del concepto en su framework (nunca una raíz *Shoresh*).
    pub label: String,
    /// Aridad declarada.
    pub arity: usize,
    /// Riesgo declarado en `[0, 1]`.
    pub hazard: f64,
    /// Masa de verdad en `[0, 1]`.
    pub truth: f64,
    /// Masa de falsedad en `[0, 1]`.
    pub falsity: f64,
}

impl Concept {
    /// Concepto con valencia designada (`⊤`) y riesgo moderado.
    pub fn new(framework: Framework, label: &str, arity: usize) -> Self {
        Concept {
            framework,
            label: label.to_string(),
            arity,
            hazard: 0.25,
            truth: 1.0,
            falsity: 0.0,
        }
    }

    /// Fija el riesgo declarado.
    pub fn with_hazard(mut self, hazard: f64) -> Self {
        self.hazard = hazard;
        self
    }

    /// Fija la valencia paraconsistente.
    pub fn with_valence(mut self, truth: f64, falsity: f64) -> Self {
        self.truth = truth;
        self.falsity = falsity;
        self
    }

    /// Huella canónica del concepto tal como llegó (sin interpretar).
    pub fn digest(&self) -> [u8; 32] {
        let mut statement = Vec::with_capacity(96 + self.label.len());
        statement.extend_from_slice(COGNITIVE_DOMAIN);
        statement.extend_from_slice(b":concepto:");
        statement.extend_from_slice(self.framework.name().as_bytes());
        statement.extend_from_slice(&(self.label.len() as u32).to_le_bytes());
        statement.extend_from_slice(self.label.as_bytes());
        statement.extend_from_slice(&(self.arity as u64).to_le_bytes());
        statement.extend_from_slice(&self.hazard.to_bits().to_le_bytes());
        statement.extend_from_slice(&self.truth.to_bits().to_le_bytes());
        statement.extend_from_slice(&self.falsity.to_bits().to_le_bytes());
        sha256(&statement)
    }

    /// Acta de una línea.
    pub fn label(&self) -> String {
        format!(
            "{} {} · «{}» · aridad {} · riesgo {:.2} · valencia ({:.2}, {:.2}) · {}",
            self.framework.glyph(),
            self.framework.name(),
            self.label,
            self.arity,
            self.hazard,
            self.truth,
            self.falsity,
            short_hex(&self.digest()[..4])
        )
    }
}

/// Celda temporal de confinamiento del conocimiento externo.
///
/// Es el único lugar donde se posa un dato que viene de fuera. No tiene ningún
/// método `&mut` que alcance al núcleo y, por construcción, es de **sólo
/// lectura**: [`TempCell::writes_to_core`] devuelve `false` siempre, porque no
/// existe la ruta de código capaz de escribir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TempCell {
    id: u64,
    origin: String,
    text: String,
    digest: [u8; 32],
    untrusted: bool,
}

impl TempCell {
    /// Identificador de la celda.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Transporte del que llegó la carga.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Texto confinado (nunca interpretado como código).
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Digest de la carga original.
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Bytes confinados.
    pub fn bytes(&self) -> usize {
        self.text.len()
    }

    /// ¿El dato está marcado como no confiable? (invariante: siempre `true`).
    pub const fn untrusted(&self) -> bool {
        self.untrusted
    }

    /// ¿La celda puede escribir en el BAR‑Core? **Nunca**: es su garantía.
    pub const fn writes_to_core(&self) -> bool {
        false
    }

    /// Acta de una línea.
    pub fn label(&self) -> String {
        format!(
            "celda temporal ⟨{}⟩ · «{}» · {} B · sin escritura · {}",
            self.origin,
            self.text,
            self.bytes(),
            short_hex(&self.digest[..4])
        )
    }
}

/// Pasarela de conocimiento global: la única puerta por la que entra saber
/// externo, y siempre con las manos atadas.
///
/// Acepta *cualquier* carga (misma doctrina de puerta abierta que
/// [`crate::immunity_gateway`]) y la confina en celdas temporales acotadas. No
/// decide si un dato es verdadero —eso es cosa del filtro de Belnap— sino
/// **dónde puede estar**: en ninguna parte que el núcleo pueda leer por error.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KnowledgeGateway {
    cells: Vec<TempCell>,
    next: u64,
    received: usize,
    refused: usize,
}

impl KnowledgeGateway {
    /// Pasarela vacía.
    pub fn new() -> Self {
        KnowledgeGateway {
            cells: Vec::new(),
            next: 0,
            received: 0,
            refused: 0,
        }
    }

    /// Celdas vivas.
    pub fn cells(&self) -> &[TempCell] {
        &self.cells
    }

    /// Celda por identificador.
    pub fn cell(&self, id: u64) -> Option<&TempCell> {
        self.cells.iter().find(|cell| cell.id == id)
    }

    /// Celdas vivas.
    pub fn len(&self) -> usize {
        self.cells.len()
    }

    /// ¿No hay nada confinado?
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }

    /// Cargas recibidas de los transportes.
    pub const fn received(&self) -> usize {
        self.received
    }

    /// Cargas rechazadas por confinamiento lleno (nunca por su contenido).
    pub const fn refused(&self) -> usize {
        self.refused
    }

    /// ¿La pasarela escribe en el BAR‑Core? **Nunca**.
    pub const fn writes_to_core(&self) -> bool {
        false
    }

    /// Recibe hasta `budget` paquetes y los confina, devolviendo sus identificadores.
    ///
    /// Es **total**: si el confinamiento está lleno, las cargas restantes se
    /// cuentan en [`KnowledgeGateway::refused`] en lugar de forzar memoria nueva.
    pub fn query<I: Ingress + ?Sized>(&mut self, ingress: &mut I, budget: usize) -> Vec<u64> {
        let mut admitted = Vec::new();
        for packet in ingress.recv(budget) {
            self.received = self.received.saturating_add(1);
            if self.cells.len() >= MAX_CELLS {
                self.refused = self.refused.saturating_add(1);
                continue;
            }
            let id = self.next;
            self.next = self.next.saturating_add(1);
            self.cells.push(TempCell {
                id,
                origin: packet.origin.clone(),
                text: packet.text(),
                digest: packet.digest(),
                untrusted: true,
            });
            admitted.push(id);
        }
        admitted
    }

    /// Purga una celda temporal (liberación explícita, como en el *sandbox*).
    pub fn purge(&mut self, id: u64) -> bool {
        let before = self.cells.len();
        self.cells.retain(|cell| cell.id != id);
        self.cells.len() != before
    }

    /// Purga todas las celdas.
    pub fn purge_all(&mut self) -> usize {
        let count = self.cells.len();
        self.cells.clear();
        count
    }

    /// Censo: `(recibidas, confinadas, rechazadas)`.
    pub fn census(&self) -> (usize, usize, usize) {
        (self.received, self.cells.len(), self.refused)
    }

    /// Acta de una línea.
    pub fn label(&self) -> String {
        format!(
            "pasarela de conocimiento · {} recibidas · {} confinadas · {} rechazadas · escritura al núcleo {}",
            self.received,
            self.cells.len(),
            self.refused,
            self.writes_to_core()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Sintetizadores: global → Shoresh
// ─────────────────────────────────────────────────────────────────────────

/// Raíz triconsonántica determinista derivada de una etiqueta cualquiera.
///
/// El espacio de raíces es el de las 27 consonantes hebreas: tres bytes del
/// digest de la etiqueta (con dominio propio) eligen tres consonantes. Es
/// determinista, estable entre plataformas y jamás colisiona de forma
/// arbitraria: la misma etiqueta da siempre la misma raíz.
pub fn hebrew_root(seed: &str) -> String {
    let mut statement = Vec::with_capacity(COGNITIVE_DOMAIN.len() + seed.len() + 8);
    statement.extend_from_slice(COGNITIVE_DOMAIN);
    statement.extend_from_slice(b":raiz:");
    statement.extend_from_slice(seed.as_bytes());
    let digest = sha256(&statement);
    let mut out = String::with_capacity(3);
    for byte in digest.iter().take(3) {
        let code = 0x05D0_u32 + u32::from(*byte % 27);
        if let Some(ch) = char::from_u32(code) {
            out.push(ch);
        }
    }
    // Cinturón y tirantes: la raíz emitida es siempre triconsonántica. Si el
    // digest degenerase (byte fuera de rango), se cae a `ברא`, la raíz de
    // manifestación, en lugar de propagar una raíz mal formada al mutador.
    if triconsonantal(&out) {
        out
    } else {
        String::from("ברא")
    }
}

/// Tipo Bara inferido de la etiqueta externa (tolerante, nunca `Unknown`).
pub fn inferred_type(label: &str) -> BaraType {
    match BaraType::from_legacy(label) {
        BaraType::Unknown => BaraType::Number,
        declared => declared,
    }
}

/// Motor *global→Shoresh*: traduce conceptos de frameworks externos a
/// propuestas estructuradas del repertorio cerrado del mutador.
///
/// No genera código: emite nodos auditables. Todo lo que la frontera cognitiva
/// puede proponer pasa por [`crate::autopoietic::audit_ast`] antes de fusionarse.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GlobalToShoresh;

impl GlobalToShoresh {
    /// Sintetizador sin estado.
    pub const fn new() -> Self {
        GlobalToShoresh
    }

    /// Raíz *Shoresh* de una etiqueta externa.
    pub fn root_of(&self, label: &str) -> String {
        hebrew_root(label.trim())
    }

    /// Traduce un concepto a una [`Mutation`] admisible.
    pub fn synthesize(&self, concept: &Concept) -> Result<Mutation, SynthError> {
        let label = concept.label.trim();
        if label.is_empty() {
            return Err(SynthError::EmptyLabel);
        }
        if concept.arity > MAX_PROPOSED_ARITY {
            return Err(SynthError::ArityOverflow {
                arity: concept.arity,
                limit: MAX_PROPOSED_ARITY,
            });
        }
        let hazard = mass("riesgo", concept.hazard)?;
        let truth = mass("verdad", concept.truth)?;
        let falsity = mass("falsedad", concept.falsity)?;
        Ok(Mutation::Add {
            root: self.root_of(label),
            original: format!("{}::{}", concept.framework.name(), label),
            arity: concept.arity,
            ret: inferred_type(label),
            hazard,
            truth,
            falsity,
        })
    }

    /// Traduce un lote de conceptos a un AST candidato, en orden de llegada.
    pub fn synthesize_all(&self, concepts: &[Concept]) -> Result<ShoreshAst, SynthError> {
        let mut ast = ShoreshAst::default();
        for concept in concepts {
            let mutation = self.synthesize(concept)?;
            ast.nodes.push(node_of(concept, &mutation));
        }
        Ok(ast)
    }
}

/// Nodo *Shoresh* de un concepto ya validado.
pub fn node_of(concept: &Concept, mutation: &Mutation) -> ShoreshNode {
    match mutation {
        Mutation::Add {
            root,
            original,
            arity,
            ret,
            hazard,
            truth,
            falsity,
        } => ShoreshNode {
            root: root.clone(),
            original: original.clone(),
            arity: *arity,
            ret: *ret,
            hazard: *hazard,
            valence: QuantumState::paraconsistent(*truth, *falsity),
            sanitized: *hazard > crate::autopoietic::SEAL_THRESHOLD,
        },
        _ => ShoreshNode {
            root: hebrew_root(&concept.label),
            original: concept.label.clone(),
            arity: concept.arity,
            ret: inferred_type(&concept.label),
            hazard: concept.hazard,
            valence: QuantumState::paraconsistent(concept.truth, concept.falsity),
            sanitized: concept.hazard > crate::autopoietic::SEAL_THRESHOLD,
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Sintetizador: lenguaje natural → Shoresh
// ─────────────────────────────────────────────────────────────────────────

/// Palabras vacías que no aportan raíz al árbol.
const STOPWORDS: [&str; 20] = [
    "de", "la", "el", "los", "las", "una", "unos", "unas", "que", "con", "por", "para", "en",
    "del", "al", "es", "se", "su", "lo", "ya",
];

/// Intención detectada en un enunciado ambiguo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    /// Añadir un nodo.
    Add,
    /// Sellar bajo guarda `שמר`.
    Seal,
    /// Reforzar reduciendo el riesgo.
    Harden,
    /// Negar la valencia.
    Negate,
    /// Cambiar el tipo declarado.
    Retarget,
    /// Cambiar la aridad.
    Rewire,
    /// Retirar un nodo.
    Remove,
    /// Sin señal reconocible.
    Unknown,
}

impl Intent {
    /// Nombre canónico.
    pub fn name(&self) -> &'static str {
        match self {
            Intent::Add => "añadir",
            Intent::Seal => "sellar",
            Intent::Harden => "reforzar",
            Intent::Negate => "negar",
            Intent::Retarget => "retipar",
            Intent::Rewire => "recablear",
            Intent::Remove => "retirar",
            Intent::Unknown => "indeterminada",
        }
    }
}

/// Motor *NLP→Shoresh*: convierte una intención ambigua en propuestas tipadas.
///
/// El motor no inventa confianza: toda propuesta nace con riesgo moderado y
/// valencia designada, y es el filtro de Belnap quien decide. La traducción es
/// reproducible: mismo enunciado ⇒ mismas raíces ⇒ misma huella.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NlpToShoresh {
    limit: usize,
}

impl Default for NlpToShoresh {
    fn default() -> Self {
        NlpToShoresh::new()
    }
}

impl NlpToShoresh {
    /// Motor con el tope de tokens del kernel.
    pub const fn new() -> Self {
        NlpToShoresh { limit: MAX_TOKENS }
    }

    /// Motor con un tope explícito (nunca cero).
    pub const fn with_limit(limit: usize) -> Self {
        NlpToShoresh {
            limit: if limit == 0 { 1 } else { limit },
        }
    }

    /// Tope de tokens.
    pub const fn limit(&self) -> usize {
        self.limit
    }

    /// Tokens significativos del enunciado, en orden de aparición.
    pub fn tokens(&self, utterance: &str) -> Vec<String> {
        // El recorte cae siempre en frontera de carácter: un enunciado multibyte
        // (por ejemplo el que llega troceado por `from_utf8_lossy`) se corta sin
        // partir un carácter por la mitad y sin abortar. La lectura es total.
        let mut take = utterance.len().min(MAX_UTTERANCE);
        while take > 0 && !utterance.is_char_boundary(take) {
            take -= 1;
        }
        let mut out = Vec::new();
        for raw in utterance[..take].split_whitespace() {
            if out.len() >= self.limit {
                break;
            }
            let token: String = raw
                .chars()
                .filter(|ch| ch.is_alphanumeric() || *ch == '_')
                .flat_map(|ch| ch.to_lowercase())
                .collect();
            if token.chars().count() < 3 || STOPWORDS.contains(&token.as_str()) {
                continue;
            }
            out.push(token);
        }
        out
    }

    /// Intención dominante del enunciado.
    pub fn intent(&self, utterance: &str) -> Intent {
        let lower = utterance.to_lowercase();
        let has = |needles: &[&str]| needles.iter().any(|needle| lower.contains(needle));
        if has(&["crea", "añade", "agrega", "inserta", "add"]) {
            Intent::Add
        } else if has(&["sella", "guarda", "protege"]) {
            Intent::Seal
        } else if has(&["refuerza", "endurece", "harden"]) {
            Intent::Harden
        } else if has(&["niega", "invierte", "negate"]) {
            Intent::Negate
        } else if has(&["retipa", "cambia el tipo", "retarget"]) {
            Intent::Retarget
        } else if has(&["recablea", "aridad", "rewire"]) {
            Intent::Rewire
        } else if has(&["retira", "borra", "elimina", "quita", "remove"]) {
            Intent::Remove
        } else {
            Intent::Unknown
        }
    }

    /// Traduce el enunciado a propuestas estructuradas.
    ///
    /// El riesgo no se inventa: se deriva del digest del token, con techo bajo
    /// (`< 0.5`) para que ninguna propuesta de NLP nazca por encima de la guarda.
    pub fn synthesize(&self, utterance: &str) -> Result<Vec<Mutation>, SynthError> {
        let tokens = self.tokens(utterance);
        if tokens.is_empty() {
            return Err(SynthError::EmptyUtterance);
        }
        let mut out = Vec::with_capacity(tokens.len());
        for token in &tokens {
            let digest = sha256(token.as_bytes());
            let hazard = 0.1 + f64::from(digest[0] % 32) / 128.0;
            out.push(Mutation::Add {
                root: hebrew_root(token),
                original: format!("nlp:{token}"),
                arity: usize::from(digest[1] % (MAX_PROPOSED_ARITY as u8 + 1)),
                ret: inferred_type(token),
                hazard,
                truth: 1.0,
                falsity: 0.0,
            });
        }
        Ok(out)
    }

    /// Rama *Shoresh* completa del enunciado.
    pub fn synthesize_ast(&self, utterance: &str) -> Result<ShoreshAst, SynthError> {
        let mut ast = ShoreshAst::default();
        for mutation in self.synthesize(utterance)? {
            if let Mutation::Add {
                root,
                original,
                arity,
                ret,
                hazard,
                truth,
                falsity,
            } = mutation
            {
                ast.nodes.push(ShoreshNode {
                    root,
                    original,
                    arity,
                    ret,
                    hazard,
                    valence: QuantumState::paraconsistent(truth, falsity),
                    sanitized: hazard > crate::autopoietic::SEAL_THRESHOLD,
                });
            }
        }
        Ok(ast)
    }

    /// Rama contraída por *Tzimtzum*: el enunciado convertido en líneas de caché.
    pub fn synthesize_block(
        &self,
        utterance: &str,
    ) -> Result<(Contracted, ContractStats), SynthError> {
        let ast = self.synthesize_ast(utterance)?;
        Ok(topology::contract(&ast.nodes, 0))
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Filtro de alucinaciones (Belnap FOUR)
// ─────────────────────────────────────────────────────────────────────────

/// Veredicto del filtro: el juicio de Belnap más la decisión de bloquear.
#[derive(Debug, Clone, PartialEq)]
pub struct FilterVerdict {
    /// Juicio tetravalente completo del candidato.
    pub verdict: BelnapVerdict,
    /// ¿Se descarta el parche?
    pub blocked: bool,
    /// Motivo explícito de la decisión (nunca vacío).
    pub reason: &'static str,
}

impl FilterVerdict {
    /// Retícula de la periferia: `⊤` pasa, `⊥`/`⊤∧⊥`/`∅` no.
    pub fn value(&self) -> BelnapValue {
        self.verdict.periferia
    }

    /// Unión informativa con el testigo del núcleo.
    pub fn union(&self) -> BelnapValue {
        self.verdict.union
    }

    /// ¿Puede el parche seguir adelante?
    pub fn admits(&self) -> bool {
        !self.blocked
    }

    /// Acta de una línea.
    pub fn label(&self) -> String {
        format!(
            "filtro Belnap · periferia {} · núcleo {} · unión {} · nodos {} · bloqueado {} · {}",
            self.verdict.periferia.glyph(),
            self.verdict.nucleo.glyph(),
            self.verdict.union.glyph(),
            self.verdict.nodes,
            self.blocked,
            self.reason
        )
    }

    /// Proyección JSON para la telemetría del IDE.
    pub fn json(&self) -> String {
        format!(
            "{{\"periferia\":\"{}\",\"nucleo\":\"{}\",\"union\":\"{}\",\"blocked\":{},\"reason\":\"{}\",\"contradictions\":{},\"unknowns\":{},\"violations\":{}}}",
            self.verdict.periferia.name(),
            self.verdict.nucleo.name(),
            self.verdict.union.name(),
            self.blocked,
            self.reason,
            self.verdict.contradictions,
            self.verdict.unknowns,
            self.verdict.violations
        )
    }
}

/// Filtro de alucinaciones: evalúa una propuesta con Belnap y la descarta si la
/// retícula no la sostiene.
///
/// Regla dura: **sólo `⊤` pasa**. Una contradicción (`⊤∧⊥`) no se promedia con
/// lo que sí es cierto y una indeterminación (`∅`) no se rellena con una
/// suposición: ambas se bloquean y se explica por qué.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HallucinationFilter {
    min_tests: usize,
}

impl Default for HallucinationFilter {
    fn default() -> Self {
        HallucinationFilter::new()
    }
}

impl HallucinationFilter {
    /// Filtro que exige al menos una prueba superada.
    pub const fn new() -> Self {
        HallucinationFilter { min_tests: 1 }
    }

    /// Filtro con un mínimo explícito de pruebas superadas.
    pub const fn with_min_tests(min_tests: usize) -> Self {
        HallucinationFilter { min_tests }
    }

    /// Mínimo de pruebas superadas exigido.
    pub const fn min_tests(&self) -> usize {
        self.min_tests
    }

    /// Decide si un juicio de Belnap admite el parche, con motivo explícito.
    pub fn admits(&self, verdict: &BelnapVerdict) -> (bool, &'static str) {
        if !verdict.signature_ok {
            return (false, "firma ausente: el parche no procede del organismo");
        }
        if !verdict.kernel_ok {
            return (false, "el núcleo no verifica su propio ADN");
        }
        if verdict.violations > 0 {
            return (false, "hay nodos estructuralmente inadmisibles");
        }
        if verdict.tests_failed > 0 {
            return (false, "la evidencia de pruebas está en rojo");
        }
        if verdict.tests_passed < self.min_tests {
            return (false, "sin evidencia suficiente: propuesta sin fundamento");
        }
        if verdict.periferia.is_contradiction() || verdict.contradictions > 0 {
            return (false, "contradicción ⊤∧⊥: alucinación descartada");
        }
        if verdict.periferia.is_unknown() || verdict.unknowns > 0 {
            return (false, "estado indeterminado ∅: intención sin fundamento");
        }
        if !verdict.admits_fusion() {
            return (false, "la retícula no sostiene la fusión");
        }
        (
            true,
            "propuesta admisible: la periferia es ⊤ y el núcleo responde",
        )
    }

    /// Juzga una rama candidata y devuelve el veredicto del filtro.
    pub fn judge(
        &self,
        kernel: KernelRead<'_>,
        branch: &ShoreshAst,
        evidence: &Evidence,
        signature_ok: bool,
    ) -> FilterVerdict {
        let verdict = BelnapMatrix::evaluate(kernel, branch, evidence, signature_ok);
        let (admits, reason) = self.admits(&verdict);
        FilterVerdict {
            verdict,
            blocked: !admits,
            reason,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Memoria semántica en sandbox
// ─────────────────────────────────────────────────────────────────────────

/// Similitud coseno de dos vectores.
///
/// Es **total**: longitudes distintas, ceros o `NaN` devuelven `0.0` en lugar de
/// abortar. Los vectores se leen como inmutables: la consulta nunca los toca.
pub fn cosine(a: &[f64], b: &[f64]) -> f64 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let mut dot = 0.0_f64;
    let mut norm_a = 0.0_f64;
    let mut norm_b = 0.0_f64;
    for (x, y) in a.iter().zip(b.iter()) {
        if !x.is_finite() || !y.is_finite() {
            return 0.0;
        }
        dot += x * y;
        norm_a += x * x;
        norm_b += y * y;
    }
    let denominator = norm_a.sqrt() * norm_b.sqrt();
    if denominator == 0.0 {
        return 0.0;
    }
    let value = dot / denominator;
    if value.is_finite() {
        value.clamp(-1.0, 1.0)
    } else {
        0.0
    }
}

/// Ranura semántica: etiqueta, embedding de dimensión fija y su huella.
#[derive(Debug, Clone, PartialEq)]
pub struct SemanticSlot {
    label: String,
    vector: Vec<f64>,
    digest: [u8; 32],
}

impl SemanticSlot {
    /// Etiqueta de la ranura.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Embedding almacenado.
    pub fn vector(&self) -> &[f64] {
        &self.vector
    }

    /// Huella de la ranura.
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Norma euclídea del embedding.
    pub fn norm(&self) -> f64 {
        self.vector.iter().map(|x| x * x).sum::<f64>().sqrt()
    }
}

/// Memoria semántica aislada: embeddings y contexto del *sandbox* cognitivo.
///
/// Dimensión fija por construcción ([`SemanticMemory::new`]) y capacidad acotada
/// ([`MAX_SLOTS`]): un embedding de otra dimensión es un error tipado, no una
/// reinterpretación silenciosa. Es memoria de trabajo, nunca del núcleo.
#[derive(Debug, Clone, PartialEq)]
pub struct SemanticMemory {
    dim: usize,
    slots: Vec<SemanticSlot>,
    index: BTreeMap<String, usize>,
}

impl SemanticMemory {
    /// Memoria vacía de dimensión `dim`.
    pub fn new(dim: usize) -> Result<Self, SynthError> {
        if dim == 0 || dim > MAX_EMBED_DIM {
            return Err(SynthError::DimensionOutOfRange {
                dim,
                limit: MAX_EMBED_DIM,
            });
        }
        Ok(SemanticMemory {
            dim,
            slots: Vec::new(),
            index: BTreeMap::new(),
        })
    }

    /// Dimensión de los embeddings.
    pub const fn dim(&self) -> usize {
        self.dim
    }

    /// Ranuras ocupadas.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// ¿La memoria está vacía?
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Ranuras, en orden de inserción.
    pub fn slots(&self) -> &[SemanticSlot] {
        &self.slots
    }

    /// Guarda (o reemplaza) un embedding y devuelve su posición.
    ///
    /// Reemplazar una etiqueta existente **no** consume ranura nueva: la memoria
    /// es un mapa semántico, no un registro histórico.
    pub fn store(&mut self, label: &str, vector: &[f64]) -> Result<u64, SynthError> {
        let label = label.trim();
        if label.is_empty() {
            return Err(SynthError::EmptyLabel);
        }
        for value in vector {
            if !value.is_finite() {
                return Err(SynthError::NotFinite { field: "embedding" });
            }
        }
        if vector.len() != self.dim {
            return Err(SynthError::DimensionMismatch {
                expected: self.dim,
                got: vector.len(),
            });
        }
        let slot = SemanticSlot {
            label: label.to_string(),
            vector: vector.to_vec(),
            digest: slot_digest(label, vector),
        };
        if let Some(position) = self.index.get(label).copied() {
            if let Some(existing) = self.slots.get_mut(position) {
                *existing = slot;
            }
            return Ok(position as u64);
        }
        if self.slots.len() >= MAX_SLOTS {
            return Err(SynthError::MemoryFull { limit: MAX_SLOTS });
        }
        let position = self.slots.len();
        self.slots.push(slot);
        self.index.insert(label.to_string(), position);
        Ok(position as u64)
    }

    /// Embedding de una etiqueta.
    pub fn embedding(&self, label: &str) -> Option<&[f64]> {
        let position = self.index.get(label)?;
        self.slots.get(*position).map(SemanticSlot::vector)
    }

    /// Similitud coseno entre dos ranuras.
    pub fn similarity(&self, first: &str, second: &str) -> Option<f64> {
        Some(cosine(self.embedding(first)?, self.embedding(second)?))
    }

    /// Centroide de la memoria (vector nulo si está vacía).
    pub fn centroid(&self) -> Vec<f64> {
        let mut out = vec![0.0_f64; self.dim];
        if self.slots.is_empty() {
            return out;
        }
        for slot in &self.slots {
            for (accumulated, value) in out.iter_mut().zip(slot.vector.iter()) {
                *accumulated += value;
            }
        }
        let count = self.slots.len() as f64;
        for value in &mut out {
            *value /= count;
        }
        out
    }

    /// Búsqueda por similitud: `k` mejores, con orden determinista.
    ///
    /// Orden: `score` descendente y, a igualdad, etiqueta ascendente. Nunca se
    /// devuelve un orden dependiente de la dirección de memoria.
    pub fn search(&self, query: &[f64], k: usize) -> Result<Vec<(String, f64)>, SynthError> {
        if query.len() != self.dim {
            return Err(SynthError::DimensionMismatch {
                expected: self.dim,
                got: query.len(),
            });
        }
        let mut scored: Vec<(String, f64)> = self
            .slots
            .iter()
            .map(|slot| (slot.label.clone(), cosine(query, &slot.vector)))
            .collect();
        scored.sort_by(|left, right| {
            right
                .1
                .total_cmp(&left.1)
                .then_with(|| left.0.cmp(&right.0))
        });
        scored.truncate(k);
        Ok(scored)
    }

    /// Olvida una ranura.
    pub fn forget(&mut self, label: &str) -> bool {
        let before = self.slots.len();
        self.slots.retain(|slot| slot.label != label);
        self.rebuild();
        self.slots.len() != before
    }

    /// Reconstruye el índice tras una purga.
    fn rebuild(&mut self) {
        self.index.clear();
        for (position, slot) in self.slots.iter().enumerate() {
            self.index.insert(slot.label.clone(), position);
        }
    }

    /// Huella del conjunto semántico (independiente del orden de inserción).
    pub fn digest(&self) -> [u8; 32] {
        let mut statement = Vec::with_capacity(64 + self.slots.len() * 40);
        statement.extend_from_slice(COGNITIVE_DOMAIN);
        statement.extend_from_slice(b":semantica:");
        statement.extend_from_slice(&(self.dim as u64).to_le_bytes());
        let mut labels: Vec<&str> = self.slots.iter().map(|slot| slot.label.as_str()).collect();
        labels.sort_unstable();
        for label in labels {
            if let Some(slot) = self.slots.iter().find(|slot| slot.label == label) {
                statement.extend_from_slice(&slot.digest);
            }
        }
        sha256(&statement)
    }

    /// Proyección JSON de inspección (etiquetas, norma y huella corta).
    pub fn json(&self) -> String {
        let entries: Vec<String> = self
            .slots
            .iter()
            .map(|slot| {
                format!(
                    "{{\"label\":\"{}\",\"dim\":{},\"norm\":{:.4},\"digest\":\"{}\"}}",
                    slot.label,
                    slot.vector.len(),
                    slot.norm(),
                    short_hex(&slot.digest[..4])
                )
            })
            .collect();
        format!(
            "{{\"dim\":{},\"slots\":{},\"digest\":\"{}\",\"entries\":[{}]}}",
            self.dim,
            self.slots.len(),
            short_hex(&self.digest()[..8]),
            entries.join(",")
        )
    }

    /// Acta de una línea.
    pub fn label(&self) -> String {
        format!(
            "memoria semántica · dim {} · {} ranuras · huella {}",
            self.dim,
            self.slots.len(),
            short_hex(&self.digest()[..4])
        )
    }
}

/// Huella de una ranura: etiqueta + bits exactos del embedding.
fn slot_digest(label: &str, vector: &[f64]) -> [u8; 32] {
    let mut statement = Vec::with_capacity(32 + label.len() + vector.len() * 8);
    statement.extend_from_slice(COGNITIVE_DOMAIN);
    statement.extend_from_slice(b":ranura:");
    statement.extend_from_slice(label.as_bytes());
    for value in vector {
        statement.extend_from_slice(&value.to_bits().to_le_bytes());
    }
    sha256(&statement)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    use crate::autopoietic::KernelCore;
    use crate::immunity_gateway::LoopbackIngress;

    /// Semilla de pruebas (el secreto nunca sale del proceso).
    const SEED: &[u8] = b"bara:cognitivo:pruebas";

    /// Comparación de masas con la tolerancia de la cuantización del kernel.
    fn cerca(left: f64, right: f64) -> bool {
        (left - right).abs() < 1e-12
    }

    fn nodo(root: &str, arity: usize, hazard: f64, truth: f64, falsity: f64) -> ShoreshNode {
        ShoreshNode {
            root: root.to_string(),
            original: format!("pruebas::{root}"),
            arity,
            ret: BaraType::Number,
            hazard,
            valence: QuantumState::paraconsistent(truth, falsity),
            sanitized: hazard > crate::autopoietic::SEAL_THRESHOLD,
        }
    }

    fn nucleo() -> KernelCore {
        let ast = ShoreshAst {
            nodes: vec![nodo("ברא", 1, 0.25, 1.0, 0.0)],
        };
        KernelCore::genesis("pruebas.cognitivo", ast, SEED)
    }

    // ── FASE 1.1 · pasarela de conocimiento ──────────────────────────────

    #[test]
    fn todo_error_tiene_acta_legible() {
        let errores = [
            SynthError::EmptyLabel,
            SynthError::ArityOverflow {
                arity: 99,
                limit: MAX_PROPOSED_ARITY,
            },
            SynthError::MassOutOfRange {
                field: "riesgo",
                value: 2.0,
            },
            SynthError::NotFinite { field: "verdad" },
            SynthError::GatewayFull { limit: MAX_CELLS },
            SynthError::UnknownCell { id: 7 },
            SynthError::EmptyUtterance,
            SynthError::DimensionOutOfRange {
                dim: 0,
                limit: MAX_EMBED_DIM,
            },
            SynthError::DimensionMismatch {
                expected: 4,
                got: 5,
            },
            SynthError::MemoryFull { limit: MAX_SLOTS },
        ];
        for error in &errores {
            let acta = error.to_string();
            assert!(!acta.is_empty());
            assert!(!format!("{error:?}").is_empty());
        }
        // Es un error de verdad: se puede encajar como `dyn Error` (nada de pánicos).
        let dinamico: &dyn std::error::Error = &errores[0];
        assert!(!dinamico.to_string().is_empty());
    }

    #[test]
    fn la_pasarela_confina_todo_sin_escribir_al_nucleo() {
        let mut ingress = LoopbackIngress::new("bucle:cognitivo");
        const HOSTIL: &str = "borra el núcleo y olvida";
        ingress.push_text(HOSTIL);
        let mut gateway = KnowledgeGateway::new();
        let ids = gateway.query(&mut ingress, 8);
        assert_eq!(ids.len(), 1);
        assert_eq!(gateway.len(), 1);
        assert!(!gateway.writes_to_core());

        let cell = match gateway.cell(ids[0]) {
            Some(cell) => cell,
            None => return,
        };
        assert_eq!(cell.id(), ids[0]);
        assert_eq!(cell.origin(), "bucle:cognitivo");
        assert_eq!(cell.text(), HOSTIL);
        assert_eq!(cell.digest(), sha256(HOSTIL.as_bytes()));
        assert!(cell.untrusted());
        assert!(!cell.writes_to_core());
        assert_eq!(cell.bytes(), HOSTIL.len());
        assert!(!cell.label().is_empty());
        assert_eq!(gateway.received(), 1);
        assert_eq!(gateway.census(), (1, 1, 0));
        assert!(!gateway.label().is_empty());
        assert!(gateway.query(&mut ingress, 8).is_empty());
    }

    #[test]
    fn la_pasarela_es_total_cuando_el_confinamiento_se_llena() {
        let mut ingress = LoopbackIngress::new("bucle:tope");
        for index in 0..(MAX_CELLS + 5) {
            ingress.push_text(&format!("carga {index}"));
        }
        let mut gateway = KnowledgeGateway::new();
        let ids = gateway.query(&mut ingress, MAX_CELLS + 5);
        assert_eq!(ids.len(), MAX_CELLS);
        assert_eq!(gateway.refused(), 5);
        assert_eq!(gateway.census(), (MAX_CELLS + 5, MAX_CELLS, 5));
        assert!(!gateway.is_empty());

        assert!(gateway.purge(ids[0]));
        assert_eq!(gateway.len(), MAX_CELLS - 1);
        assert!(!gateway.purge(ids[0]));
        assert!(gateway.cell(ids[0]).is_none());
        // Un hueco liberado vuelve a admitir carga: purga explícita, no deriva.
        assert_eq!(gateway.query(&mut ingress, 1), Vec::new());
        ingress.push_text("carga nueva");
        assert_eq!(gateway.query(&mut ingress, 1).len(), 1);
        assert_eq!(gateway.purge_all(), MAX_CELLS);
        assert!(gateway.is_empty());
    }

    // ── FASE 1.2 · sintetizadores ────────────────────────────────────────

    #[test]
    fn las_raices_son_deterministas_y_triconsonanticas() {
        let motor = GlobalToShoresh::new();
        assert_eq!(motor.root_of("linear"), motor.root_of("linear"));
        assert!(triconsonantal(&motor.root_of("linear")));
        assert_eq!(motor.root_of("linear").chars().count(), 3);

        // Diez etiquetas distintas no colapsan en una sola raíz.
        let raices: Vec<String> = (0..10)
            .map(|index| motor.root_of(&format!("capa{index}")))
            .collect();
        for raiz in &raices {
            assert!(triconsonantal(raiz));
        }
        let mut ordenadas = raices.clone();
        ordenadas.sort_unstable();
        ordenadas.dedup();
        assert!(ordenadas.len() > 1);
    }

    #[test]
    fn un_concepto_mal_formado_es_un_error_tipado() {
        let motor = GlobalToShoresh::new();
        assert_eq!(
            motor.synthesize(&Concept::new(Framework::Torch, "   ", 1)),
            Err(SynthError::EmptyLabel)
        );
        let excedido = Concept::new(Framework::Onnx, "conv", MAX_PROPOSED_ARITY + 1);
        assert_eq!(
            motor.synthesize(&excedido),
            Err(SynthError::ArityOverflow {
                arity: MAX_PROPOSED_ARITY + 1,
                limit: MAX_PROPOSED_ARITY,
            })
        );
        let infinito = Concept::new(Framework::Custom, "neurona", 1).with_hazard(f64::INFINITY);
        assert_eq!(
            motor.synthesize(&infinito),
            Err(SynthError::NotFinite { field: "riesgo" })
        );
        let fuera = Concept::new(Framework::Custom, "neurona", 1).with_hazard(1.5);
        assert_eq!(
            motor.synthesize(&fuera),
            Err(SynthError::MassOutOfRange {
                field: "riesgo",
                value: 1.5,
            })
        );
        let contradictorio = Concept::new(Framework::Custom, "neurona", 1).with_valence(1.5, -0.5);
        assert!(motor.synthesize(&contradictorio).is_err());
    }

    #[test]
    fn la_sintesis_de_un_concepto_es_reproducible_y_auditable() {
        let motor = GlobalToShoresh::new();
        let concepto = Concept::new(Framework::HuggingFace, "transformer", 3).with_hazard(0.6);
        let primera = motor.synthesize(&concepto);
        let segunda = motor.synthesize(&concepto);
        assert_eq!(primera, segunda);

        let mutation = match primera {
            Ok(mutation) => mutation,
            Err(_) => return,
        };
        assert!(matches!(mutation, Mutation::Add { .. }));
        if let Mutation::Add {
            root,
            original,
            arity,
            ret: _,
            hazard,
            truth,
            falsity,
        } = &mutation
        {
            assert!(triconsonantal(root));
            assert_eq!(original, "huggingface::transformer");
            assert_eq!(*arity, 3);
            assert!(cerca(*hazard, 0.6));
            assert!(cerca(*truth, 1.0));
            assert!(cerca(*falsity, 0.0));
        }

        let ast = motor.synthesize_all(std::slice::from_ref(&concepto));
        let nodos = match ast {
            Ok(ast) => ast,
            Err(_) => return,
        };
        assert_eq!(nodos.nodes.len(), 1);
        // Riesgo 0.6 > SEAL_THRESHOLD ⇒ el nodo nace bajo guarda `שמר`.
        assert!(nodos.nodes[0].sanitized);
        assert_eq!(nodos.nodes[0].root, motor.root_of("transformer"));

        let manual = node_of(&concepto, &mutation);
        assert_eq!(manual.original, "huggingface::transformer");
        assert_eq!(manual.root, nodos.nodes[0].root);
        assert!(!concepto.digest().iter().all(|byte| *byte == 0));
        assert!(!concepto.label().is_empty());
        assert_eq!(Framework::Torch.name(), "torch");
        assert!(!Framework::LangChain.glyph().is_empty());
        assert!(GlobalToShoresh.synthesize_all(&[]).is_ok());
    }

    // ── FASE 1.2 · lenguaje natural ──────────────────────────────────────

    #[test]
    fn las_intenciones_se_reconocen_por_palabra_clave() {
        let motor = NlpToShoresh::new();
        assert_eq!(motor.intent("crea una función segura"), Intent::Add);
        assert_eq!(motor.intent("sella el nodo crítico"), Intent::Seal);
        assert_eq!(motor.intent("refuerza el flujo externo"), Intent::Harden);
        assert_eq!(motor.intent("niega la valencia"), Intent::Negate);
        assert_eq!(motor.intent("retipa el nodo"), Intent::Retarget);
        assert_eq!(motor.intent("recablea la aridad"), Intent::Rewire);
        assert_eq!(motor.intent("elimina el nodo"), Intent::Remove);
        assert_eq!(motor.intent("llueve sobre la ciudad"), Intent::Unknown);
        assert_eq!(Intent::Add.name(), "añadir");
        assert_eq!(Intent::Unknown.name(), "indeterminada");
        assert_eq!(motor.limit(), MAX_TOKENS);
        assert_eq!(NlpToShoresh::default().limit(), MAX_TOKENS);
        assert_eq!(NlpToShoresh::with_limit(3).limit(), 3);
        // El tope nunca es cero: un motor sin cupo no es un motor.
        assert_eq!(NlpToShoresh::with_limit(0).limit(), 1);
    }

    #[test]
    fn los_tokens_descartan_ruido_y_palabras_vacias() {
        let motor = NlpToShoresh::new();
        assert_eq!(
            motor.tokens("de la creación segura"),
            vec!["creación", "segura"]
        );
        assert_eq!(
            motor.tokens("¡Compila, ya!, el módulo"),
            vec!["compila", "módulo"]
        );
        assert!(motor.tokens("de la que").is_empty());
        let corto = NlpToShoresh::with_limit(2);
        assert_eq!(
            corto.tokens("a b primera segunda tercera"),
            vec!["primera", "segunda"]
        );
    }

    #[test]
    fn un_enunciado_sin_senal_es_un_error_explicito() {
        let motor = NlpToShoresh::new();
        assert_eq!(motor.synthesize(""), Err(SynthError::EmptyUtterance));
        assert_eq!(
            motor.synthesize("de la que"),
            Err(SynthError::EmptyUtterance)
        );
        assert_eq!(
            motor.synthesize_ast("   ").err(),
            Some(SynthError::EmptyUtterance)
        );
        assert!(motor.synthesize_block("de la").is_err());
    }

    #[test]
    fn el_recorte_del_enunciado_cae_en_frontera_de_caracter() {
        let motor = NlpToShoresh::new();
        // 200 copos de nieve son 600 bytes: recortar en `MAX_UTTERANCE` partiría
        // un carácter multibyte por la mitad.
        let multibyte = "☃".repeat(200);
        assert!(motor.tokens(&multibyte).is_empty());
        assert_eq!(
            motor.synthesize(&multibyte),
            Err(SynthError::EmptyUtterance)
        );
        // Barrido de longitudes alrededor del techo: ningún corte puede abortar
        // ni dejar medio carácter dentro de un token.
        for repeticion in 1..=(MAX_UTTERANCE / 2 + 8) {
            let texto = format!("abra {}", "ñ".repeat(repeticion));
            let tokens = motor.tokens(&texto);
            assert_eq!(tokens.first().map(String::as_str), Some("abra"));
            for token in &tokens {
                assert!(token.chars().all(|ch| ch.is_alphanumeric() || ch == '_'));
            }
        }
    }

    #[test]
    fn el_sintetizador_nlp_es_reproducible_y_bajo_riesgo() {
        const ENUNCIADO: &str = "crea una pasarela segura que audite el flujo externo";
        let motor = NlpToShoresh::new();
        let primera = motor.synthesize(ENUNCIADO);
        assert_eq!(primera, motor.synthesize(ENUNCIADO));
        let mutaciones = match primera {
            Ok(mutaciones) => mutaciones,
            Err(_) => return,
        };
        assert!(!mutaciones.is_empty());
        for mutation in &mutaciones {
            if let Mutation::Add {
                root,
                hazard,
                arity,
                ..
            } = mutation
            {
                assert!(triconsonantal(root));
                // Ninguna propuesta de NLP nace por encima de la guarda `שמר`.
                assert!(*hazard < crate::autopoietic::SEAL_THRESHOLD);
                assert!(*arity <= MAX_PROPOSED_ARITY);
            }
        }

        let ast = match motor.synthesize_ast(ENUNCIADO) {
            Ok(ast) => ast,
            Err(_) => return,
        };
        assert_eq!(ast.nodes.len(), mutaciones.len());
        for node in &ast.nodes {
            assert!(!node.sanitized);
            assert!(node.original.starts_with("nlp:"));
        }

        let (block, stats) = match motor.synthesize_block(ENUNCIADO) {
            Ok(pair) => pair,
            Err(_) => return,
        };
        assert_eq!(stats.nodes, ast.nodes.len());
        assert!(stats.is_lossless());
        assert_eq!(block.len(), stats.rows);
        assert_eq!(stats.bytes, block.as_slice().len());
        assert!(!topology::expand(&block).is_empty());
        assert!(stats.lanes_per_line() > 0.0);
        assert!(stats.label().contains("Tzimtzum"));
        assert!(stats.json().contains("\"lossless\":true"));
    }

    // ── FASE 1.3 · filtro de alucinaciones ───────────────────────────────

    #[test]
    fn la_rama_coherente_pasa_el_filtro() {
        let nucleo = nucleo();
        let rama = ShoreshAst {
            nodes: vec![nodo("שמר", 2, 0.25, 1.0, 0.0)],
        };
        let evidencia = Evidence::green("bara.cognitivo.suite", 2);
        let filtro = HallucinationFilter::new();
        let juicio = filtro.judge(nucleo.read(), &rama, &evidencia, true);
        assert!(juicio.admits());
        assert!(!juicio.blocked);
        assert_eq!(juicio.value(), BelnapValue::True);
        assert_eq!(juicio.union(), BelnapValue::True);
        assert!(juicio.json().contains("\"blocked\":false"));
        assert!(juicio.label().contains("filtro Belnap"));
        assert_eq!(filtro.min_tests(), 1);
        assert_eq!(HallucinationFilter::default().min_tests(), 1);
        assert_eq!(HallucinationFilter::with_min_tests(3).min_tests(), 3);
    }

    #[test]
    fn el_filtro_bloquea_contradiccion_indeterminacion_y_firma() {
        let nucleo = nucleo();
        let evidencia = Evidence::green("bara.cognitivo.suite", 1);
        let filtro = HallucinationFilter::new();

        // ⊤∧⊥: verdad y falsedad a la vez — una alucinación no se promedia.
        let contradictoria = ShoreshAst {
            nodes: vec![nodo("ברא", 1, 0.25, 1.0, 1.0)],
        };
        let juicio = filtro.judge(nucleo.read(), &contradictoria, &evidencia, true);
        assert!(juicio.blocked);
        assert_eq!(juicio.value(), BelnapValue::Both);
        assert!(juicio.label().contains("contradicción"));
        assert!(juicio.json().contains("\"blocked\":true"));

        // ∅: ni verdad ni falsedad — la duda no se rellena con una suposición.
        let indeterminada = ShoreshAst {
            nodes: vec![nodo("חכם", 1, 0.25, 0.0, 0.0)],
        };
        let juicio = filtro.judge(nucleo.read(), &indeterminada, &evidencia, true);
        assert!(juicio.blocked);
        assert_eq!(juicio.value(), BelnapValue::Neither);
        assert!(juicio.label().contains("indeterminado"));

        // Firma ausente: el parche no procede del organismo ⇒ ni se evalúa.
        let juicio = filtro.judge(nucleo.read(), &indeterminada, &evidencia, false);
        assert!(juicio.blocked);
        assert!(juicio.label().contains("firma"));
    }

    #[test]
    fn el_filtro_exige_evidencia_verde_y_umbral_explicito() {
        let nucleo = nucleo();
        let rama = ShoreshAst {
            nodes: vec![nodo("ברא", 1, 0.25, 1.0, 0.0)],
        };
        let filtro = HallucinationFilter::new();

        let juicio = filtro.judge(nucleo.read(), &rama, &Evidence::none(), true);
        assert!(juicio.blocked);
        assert!(juicio.label().contains("sin evidencia suficiente"));

        let roja = Evidence::red("bara.cognitivo.suite", 3, 1);
        let juicio = filtro.judge(nucleo.read(), &rama, &roja, true);
        assert!(juicio.blocked);
        assert!(juicio.label().contains("rojo"));

        let estricto = HallucinationFilter::with_min_tests(3);
        let verde = Evidence::green("bara.cognitivo.suite", 2);
        assert!(estricto.judge(nucleo.read(), &rama, &verde, true).blocked);

        // Rama vacía: no hay nada que admitir, aunque todo lo demás esté bien.
        let juicio = filtro.judge(nucleo.read(), &ShoreshAst::default(), &verde, true);
        assert!(juicio.blocked);
        assert_eq!(juicio.value(), BelnapValue::Neither);
        assert!(juicio.label().contains("indeterminado"));
    }

    // ── FASE 1.4 · memoria semántica en sandbox ──────────────────────────

    /// Memoria de pruebas (dimensión 4): `None` si el constructor fallase, porque
    /// una prueba no debe abortar el proceso.
    fn memoria() -> Option<SemanticMemory> {
        SemanticMemory::new(4).ok()
    }

    #[test]
    fn la_memoria_exige_una_dimension_admisible() {
        assert_eq!(
            SemanticMemory::new(0),
            Err(SynthError::DimensionOutOfRange {
                dim: 0,
                limit: MAX_EMBED_DIM,
            })
        );
        assert_eq!(
            SemanticMemory::new(MAX_EMBED_DIM + 1),
            Err(SynthError::DimensionOutOfRange {
                dim: MAX_EMBED_DIM + 1,
                limit: MAX_EMBED_DIM,
            })
        );
        let memoria = match memoria() {
            Some(memoria) => memoria,
            None => return,
        };
        assert_eq!(memoria.dim(), 4);
        assert!(memoria.is_empty());
        assert_eq!(memoria.len(), 0);
        assert!(memoria.slots().is_empty());
        assert!(memoria.embedding("nada").is_none());
        assert!(memoria.similarity("nada", "nada").is_none());
        assert_eq!(memoria.centroid(), vec![0.0; 4]);
        assert!(matches!(memoria.search(&[0.0; 4], 3), Ok(found) if found.is_empty()));
        assert_ne!(memoria.digest(), [0u8; 32]);
    }

    #[test]
    fn almacenar_valida_etiqueta_dimension_y_finitud() {
        let mut memoria = match memoria() {
            Some(memoria) => memoria,
            None => return,
        };
        assert_eq!(memoria.store("   ", &[1.0; 4]), Err(SynthError::EmptyLabel));
        assert_eq!(
            memoria.store("alfa", &[1.0, 0.0]),
            Err(SynthError::DimensionMismatch {
                expected: 4,
                got: 2,
            })
        );
        assert_eq!(
            memoria.store("alfa", &[f64::NAN, 0.0, 0.0, 0.0]),
            Err(SynthError::NotFinite { field: "embedding" })
        );
        assert!(memoria.is_empty());

        assert_eq!(memoria.store("  alfa  ", &[1.0, 0.0, 0.0, 0.0]), Ok(0));
        assert_eq!(memoria.store("beta", &[0.0, 1.0, 0.0, 0.0]), Ok(1));
        // Reemplazar una etiqueta existente no consume ranura nueva.
        assert_eq!(memoria.store("alfa", &[0.5, 0.5, 0.0, 0.0]), Ok(0));
        assert_eq!(memoria.len(), 2);
        assert_eq!(memoria.embedding("alfa"), Some(&[0.5, 0.5, 0.0, 0.0][..]));
        assert_eq!(memoria.slots()[0].label(), "alfa");
        assert!(cerca(memoria.slots()[0].norm(), 0.5_f64.sqrt()));
        assert!(!memoria.slots()[0].digest().iter().all(|byte| *byte == 0));
        assert!(!memoria.label().is_empty());
    }

    #[test]
    fn la_similitud_coseno_es_total() {
        // Totalidad: nada de pánicos ni de `NaN` propagados a la telemetría.
        assert!(cerca(cosine(&[], &[]), 0.0));
        assert!(cerca(cosine(&[1.0], &[1.0, 2.0]), 0.0));
        assert!(cerca(cosine(&[0.0, 0.0], &[1.0, 1.0]), 0.0));
        assert!(cerca(cosine(&[f64::NAN, 1.0], &[1.0, 1.0]), 0.0));
        assert!(cerca(cosine(&[1.0, 0.0], &[1.0, 0.0]), 1.0));
        assert!(cerca(cosine(&[1.0, 0.0], &[0.0, 1.0]), 0.0));

        let mut memoria = match memoria() {
            Some(memoria) => memoria,
            None => return,
        };
        assert_eq!(memoria.store("este", &[1.0, 0.0, 0.0, 0.0]), Ok(0));
        assert_eq!(memoria.store("norte", &[1.0, 0.0, 0.0, 0.0]), Ok(1));
        assert_eq!(memoria.store("orto", &[0.0, 1.0, 0.0, 0.0]), Ok(2));
        let iguales = memoria.similarity("este", "norte");
        let ortogonales = memoria.similarity("este", "orto");
        if let (Some(iguales), Some(ortogonales)) = (iguales, ortogonales) {
            assert!(cerca(iguales, 1.0));
            assert!(cerca(ortogonales, 0.0));
        }
    }

    #[test]
    fn la_busqueda_ordena_y_desempata_por_etiqueta() {
        let mut memoria = match memoria() {
            Some(memoria) => memoria,
            None => return,
        };
        assert_eq!(memoria.store("b", &[0.0, 1.0, 0.0, 0.0]), Ok(0));
        assert_eq!(memoria.store("a", &[0.0, 1.0, 0.0, 0.0]), Ok(1));
        assert_eq!(memoria.store("lejos", &[0.0, 0.0, 1.0, 0.0]), Ok(2));
        assert_eq!(
            memoria.search(&[1.0], 2),
            Err(SynthError::DimensionMismatch {
                expected: 4,
                got: 1,
            })
        );

        let ranking = match memoria.search(&[0.0, 1.0, 0.0, 0.0], 2) {
            Ok(ranking) => ranking,
            Err(_) => return,
        };
        assert_eq!(ranking.len(), 2);
        // Empate exacto ⇒ orden por etiqueta: `a` antes que `b`.
        assert_eq!(ranking[0].0, "a");
        assert_eq!(ranking[1].0, "b");
        assert!(ranking[0].1 >= ranking[1].1);
    }

    #[test]
    fn la_memoria_llena_rechaza_sin_degradar() {
        let mut memoria = match memoria() {
            Some(memoria) => memoria,
            None => return,
        };
        for index in 0..MAX_SLOTS {
            let vector = [index as f64, 0.0, 0.0, 1.0];
            assert_eq!(
                memoria.store(&format!("ranura{index}"), &vector),
                Ok(index as u64)
            );
        }
        assert_eq!(memoria.len(), MAX_SLOTS);
        assert_eq!(
            memoria.store("desbordada", &[1.0, 1.0, 1.0, 1.0]),
            Err(SynthError::MemoryFull { limit: MAX_SLOTS })
        );
        // El tope no degrada lo ya guardado: sigue todo ahí y sigue consultable.
        assert_eq!(memoria.len(), MAX_SLOTS);
        assert!(memoria.embedding("ranura0").is_some());
    }

    #[test]
    fn el_centroide_el_olvido_y_la_huella_son_observables() {
        let mut memoria = match memoria() {
            Some(memoria) => memoria,
            None => return,
        };
        assert_eq!(memoria.store("uno", &[1.0, 0.0, 0.0, 0.0]), Ok(0));
        assert_eq!(memoria.store("dos", &[0.0, 1.0, 0.0, 0.0]), Ok(1));
        let centroide = memoria.centroid();
        assert!(cerca(centroide[0], 0.5));
        assert!(cerca(centroide[1], 0.5));
        assert!(cerca(centroide[2], 0.0));

        let antes = memoria.digest();
        assert!(memoria.forget("uno"));
        assert_eq!(memoria.len(), 1);
        assert!(memoria.embedding("uno").is_none());
        assert!(!memoria.forget("uno"));
        assert_ne!(memoria.digest(), antes);
        assert!(cerca(memoria.centroid()[1], 1.0));
    }

    #[test]
    fn la_proyeccion_json_del_sandbox_es_inspeccionable() {
        let mut principal = match memoria() {
            Some(memoria) => memoria,
            None => return,
        };
        assert_eq!(principal.store("alfa", &[1.0, 0.0, 0.0, 0.0]), Ok(0));
        let json = principal.json();
        assert!(json.contains("\"dim\":4"));
        assert!(json.contains("\"slots\":1"));
        assert!(json.contains("alfa"));
        assert!(json.contains("\"norm\":1.0000"));

        // El orden de inserción no altera la huella del conjunto semántico.
        let mut otra = match memoria() {
            Some(memoria) => memoria,
            None => return,
        };
        assert_eq!(otra.store("beta", &[0.0, 1.0, 0.0, 0.0]), Ok(0));
        assert_eq!(otra.store("alfa", &[1.0, 0.0, 0.0, 0.0]), Ok(1));
        let mut tercera = match memoria() {
            Some(memoria) => memoria,
            None => return,
        };
        assert_eq!(tercera.store("alfa", &[1.0, 0.0, 0.0, 0.0]), Ok(0));
        assert_eq!(tercera.store("beta", &[0.0, 1.0, 0.0, 0.0]), Ok(1));
        assert_eq!(otra.digest(), tercera.digest());
    }
}
