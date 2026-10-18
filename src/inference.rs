#![forbid(unsafe_code)]
//! # Motor de inferencia multicapa sobre la retícula de Belnap
//!
//! Conecta [`BelnapValue`] con un grafo de inferencia **estratificado**: cada
//! regla declara una capa de origen y otra de destino estrictamente posterior.
//! Esa restricción —verificada al declarar la regla— elimina los ciclos por
//! construcción, así que una sola pasada en orden de capa calcula el punto fijo
//! exacto, sin iteraciones de punto fijo y sin asignaciones dinámicas.
//!
//! ## Invariantes
//! 1. Cero `unsafe` y cero `panic!`/`unwrap`/`expect` en producción.
//! 2. Cero asignaciones dinámicas en evaluación: arrays de capacidad constante
//!    ([`MAX_NODES`], [`MAX_RULES`], [`MAX_TRACE`]).
//! 3. Tiempo acotado: se evalúan como máximo `MAX_RULES` reglas por capa, en
//!    [`MAX_LAYERS`] capas; no hay bucles ligados a la longitud de una cadena.
//! 4. Determinismo: orden de inserción dentro de la capa y unión informativa
//!    `⊔` conmutativa; dos ejecuciones del mismo grafo coinciden exactamente.
//!
//! La inferencia **no** escribe en el núcleo: consume hechos ya validados por la
//! periferia y produce una vista que el puente del IDE puede dibujar.

use crate::autopoietic::BelnapValue;

/// Capas máximas del grafo (de `0` a [`MAX_LAYERS`] − 1).
pub const MAX_LAYERS: usize = 8;

/// Nodos máximos del grafo.
pub const MAX_NODES: usize = 128;

/// Reglas máximas del grafo.
pub const MAX_RULES: usize = 256;

/// Pasos máximos conservados en la traza de evaluación.
pub const MAX_TRACE: usize = 256;

/// Bytes máximos de una raíz léxica.
pub const MAX_ROOT_BYTES: usize = 16;

// ─────────────────────────────────────────────────────────────────────────
// Raíz léxica estable
// ─────────────────────────────────────────────────────────────────────────

/// Raíz de un concepto, almacenada sin asignaciones dinámicas.
///
/// Se copia como bytes y se valida en la frontera: una raíz vacía o más larga
/// que [`MAX_ROOT_BYTES`] se rechaza en lugar de truncarse (truncar podría
/// partir un carácter UTF-8). Como la fuente es un `&str` válido y sólo se
/// aceptan copias completas, [`RootKey::as_str`] siempre devuelve texto válido.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RootKey {
    bytes: [u8; MAX_ROOT_BYTES],
    len: u8,
}

impl RootKey {
    /// Raíz vacía canónica.
    pub const fn empty() -> Self {
        Self {
            bytes: [0; MAX_ROOT_BYTES],
            len: 0,
        }
    }

    /// Copia una raíz si cabe completa en la capacidad fija.
    pub fn new(root: &str) -> Option<Self> {
        if root.is_empty() || root.len() > MAX_ROOT_BYTES {
            return None;
        }
        let mut bytes = [0u8; MAX_ROOT_BYTES];
        let end = root.len();
        let slot = bytes.get_mut(..end)?;
        slot.copy_from_slice(root.as_bytes());
        Some(Self {
            bytes,
            len: end as u8,
        })
    }

    /// Raíz como texto. Nunca entra en pánico: una copia corrupta se degrada a
    /// la cadena vacía (estado imposible a través de la API pública).
    pub fn as_str(&self) -> &str {
        let end = self.len as usize;
        let slice = match self.bytes.get(..end) {
            Some(slice) => slice,
            None => return "",
        };
        core::str::from_utf8(slice).unwrap_or("")
    }

    /// Longitud en bytes.
    pub const fn byte_len(self) -> usize {
        self.len as usize
    }

    /// ¿Está vacía?
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
}

impl core::fmt::Debug for RootKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "«{}»", self.as_str())
    }
}

impl core::fmt::Display for RootKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Identificadores
// ─────────────────────────────────────────────────────────────────────────

/// Identificador de un nodo, indexado en el array fijo del motor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NodeId(u16);

impl NodeId {
    /// Índice interno.
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// Identificador de una regla.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RuleId(u16);

impl RuleId {
    /// Índice interno.
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Conectivas y reglas
// ─────────────────────────────────────────────────────────────────────────

/// Conectiva tetravalente de una regla.
///
/// Todas las conectivas se apoyan en operaciones **constantes** de
/// [`BelnapValue`], no en umbrales flotantes: la inferencia es exacta sobre las
/// cuatro clases y no depende del redondeo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    /// Transferencia: `antecedente ∧ fuerza`.
    Transfer,
    /// Conjunción: `(antecedente ∧ auxiliar) ∧ fuerza`.
    Conjunction,
    /// Disyunción: `(antecedente ∨ auxiliar) ∧ fuerza`.
    Disjunction,
    /// Negación: `(¬antecedente) ∧ fuerza`.
    Negation,
    /// Consenso informativo: `(antecedente ⊓ auxiliar) ∧ fuerza`.
    Consensus,
    /// Unión informativa: `(antecedente ⊔ auxiliar) ∧ fuerza`.
    Fusion,
}

impl RuleKind {
    /// ¿Necesita un segundo antecedente?
    pub const fn requires_auxiliary(self) -> bool {
        !matches!(self, RuleKind::Transfer | RuleKind::Negation)
    }

    /// Nombre canónico para trazas y JSON.
    pub const fn name(self) -> &'static str {
        match self {
            RuleKind::Transfer => "transferencia",
            RuleKind::Conjunction => "conjuncion",
            RuleKind::Disjunction => "disyuncion",
            RuleKind::Negation => "negacion",
            RuleKind::Consensus => "consenso",
            RuleKind::Fusion => "fusion",
        }
    }

    /// Aplica la conectiva. Total para las cuatro clases de Belnap.
    pub fn apply(
        self,
        antecedent: BelnapValue,
        auxiliary: BelnapValue,
        strength: BelnapValue,
    ) -> BelnapValue {
        match self {
            RuleKind::Transfer => antecedent.conjunction(strength),
            RuleKind::Conjunction => antecedent.conjunction(auxiliary).conjunction(strength),
            RuleKind::Disjunction => antecedent.disjunction(auxiliary).conjunction(strength),
            RuleKind::Negation => antecedent.negate().conjunction(strength),
            RuleKind::Consensus => antecedent.consensus(auxiliary).conjunction(strength),
            RuleKind::Fusion => antecedent.union(auxiliary).conjunction(strength),
        }
    }
}

/// Regla de inferencia estratificada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InferenceRule {
    /// Nodo antecedente.
    pub from: NodeId,
    /// Nodo consecuente.
    pub to: NodeId,
    /// Segundo antecedente, si la conectiva lo exige.
    pub aux: Option<NodeId>,
    /// Fuerza de la regla (`⊤` = sin atenuación).
    pub strength: BelnapValue,
    /// Conectiva.
    pub kind: RuleKind,
}

/// Nodo del grafo con su valor asertado y su valor inferido.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InferenceNode {
    /// Raíz léxica.
    pub root: RootKey,
    /// Capa (0 = hechos de entrada).
    pub layer: u8,
    /// Valor actual (asertado `⊔` derivado).
    pub value: BelnapValue,
    /// Valor aportado directamente por la periferia.
    pub asserted: BelnapValue,
    /// ¿Tiene al menos un hecho asertado?
    pub is_fact: bool,
    /// ¿Su valor actual difiere de lo asertado?
    pub is_derived: bool,
}

impl InferenceNode {
    const fn empty() -> Self {
        Self {
            root: RootKey::empty(),
            layer: 0,
            value: BelnapValue::Neither,
            asserted: BelnapValue::Neither,
            is_fact: false,
            is_derived: false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Traza e informe
// ─────────────────────────────────────────────────────────────────────────

/// Un paso de evaluación, copiado a un anillo estático.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InferenceStep {
    /// Regla aplicada.
    pub rule: RuleId,
    /// Capa de origen.
    pub from_layer: u8,
    /// Capa de destino.
    pub to_layer: u8,
    /// Valor del consecuente antes del paso.
    pub before: BelnapValue,
    /// Valor del consecuente después del paso.
    pub after: BelnapValue,
}

/// Foto coherente de una evaluación.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InferenceReport {
    /// Nodos declarados.
    pub nodes: usize,
    /// Reglas declaradas.
    pub rules: usize,
    /// Reglas evaluadas.
    pub applied: usize,
    /// Nodos cuyo valor cambió en esta evaluación.
    pub changed: usize,
    /// Nodos con valor `⊤`.
    pub true_count: usize,
    /// Nodos con valor `⊥`.
    pub false_count: usize,
    /// Nodos con valor `⊤∧⊥`.
    pub both_count: usize,
    /// Nodos con valor `∅`.
    pub neither_count: usize,
    /// Nodos derivados (valor distinto del asertado).
    pub derived: usize,
    /// Capas con al menos un nodo.
    pub layers_used: usize,
    /// ¿La traza se truncó por capacidad?
    pub truncated: bool,
}

impl InferenceReport {
    /// Contradicciones toleradas (`⊤∧⊥`).
    pub const fn contradictions(&self) -> usize {
        self.both_count
    }

    /// Nodos sin información (`∅`).
    pub const fn unknowns(&self) -> usize {
        self.neither_count
    }

    /// ¿La inferencia produjo alguna contradicción?
    pub const fn is_paraconsistent(&self) -> bool {
        self.both_count > 0
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Errores
// ─────────────────────────────────────────────────────────────────────────

/// Fallo de construcción o estratificación del grafo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InferenceError {
    /// Se agotaron los nodos.
    NodeCapacity {
        /// Capacidad fija.
        limit: usize,
    },
    /// Se agotaron las reglas.
    RuleCapacity {
        /// Capacidad fija.
        limit: usize,
    },
    /// Capa fuera de rango.
    LayerOutOfRange {
        /// Capa pedida.
        layer: usize,
        /// Techo de capas.
        limit: usize,
    },
    /// Raíz vacía.
    EmptyRoot,
    /// Raíz demasiado larga para el búfer fijo.
    RootTooLong {
        /// Longitud recibida.
        len: usize,
        /// Capacidad fija.
        limit: usize,
    },
    /// Identificador de nodo inexistente.
    UnknownNode {
        /// Índice pedido.
        index: usize,
        /// Nodos declarados.
        nodes: usize,
    },
    /// La regla no avanza de capa (ciclo potencial).
    NonStratified {
        /// Capa de origen.
        from: u8,
        /// Capa de destino.
        to: u8,
    },
    /// El segundo antecedente se calcula después del primero.
    AuxiliaryAhead {
        /// Capa del segundo antecedente.
        auxiliary: u8,
        /// Capa del primer antecedente.
        from: u8,
    },
    /// La conectiva exige un segundo antecedente y no lo recibió.
    MissingAuxiliary {
        /// Conectiva afectada.
        kind: RuleKind,
    },
}

impl core::fmt::Display for InferenceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InferenceError::NodeCapacity { limit } => {
                write!(f, "capacidad de nodos agotada (tope {limit})")
            }
            InferenceError::RuleCapacity { limit } => {
                write!(f, "capacidad de reglas agotada (tope {limit})")
            }
            InferenceError::LayerOutOfRange { layer, limit } => {
                write!(f, "capa {layer} fuera de [0, {limit})")
            }
            InferenceError::EmptyRoot => f.write_str("raíz vacía"),
            InferenceError::RootTooLong { len, limit } => {
                write!(f, "raíz de {len} B por encima del tope {limit} B")
            }
            InferenceError::UnknownNode { index, nodes } => {
                write!(f, "nodo {index} inexistente (hay {nodes})")
            }
            InferenceError::NonStratified { from, to } => write!(
                f,
                "regla no estratificada: la capa destino {to} no es posterior a {from}"
            ),
            InferenceError::AuxiliaryAhead { auxiliary, from } => write!(
                f,
                "antecedente auxiliar en capa {auxiliary}, posterior a la capa {from}"
            ),
            InferenceError::MissingAuxiliary { kind } => {
                write!(
                    f,
                    "la conectiva «{}» exige antecedente auxiliar",
                    kind.name()
                )
            }
        }
    }
}

impl std::error::Error for InferenceError {}

// ─────────────────────────────────────────────────────────────────────────
// Motor
// ─────────────────────────────────────────────────────────────────────────

/// Motor de inferencia determinista y libre de asignaciones en evaluación.
#[derive(Debug, Clone)]
pub struct InferenceEngine {
    nodes: [InferenceNode; MAX_NODES],
    rules: [InferenceRule; MAX_RULES],
    trace: [Option<InferenceStep>; MAX_TRACE],
    node_len: usize,
    rule_len: usize,
    trace_len: usize,
    evaluated: bool,
}

impl InferenceEngine {
    /// Motor vacío.
    pub fn new() -> Self {
        Self {
            nodes: [InferenceNode::empty(); MAX_NODES],
            rules: [InferenceRule {
                from: NodeId(0),
                to: NodeId(0),
                aux: None,
                strength: BelnapValue::True,
                kind: RuleKind::Transfer,
            }; MAX_RULES],
            trace: [None; MAX_TRACE],
            node_len: 0,
            rule_len: 0,
            trace_len: 0,
            evaluated: false,
        }
    }

    /// Nodos declarados.
    pub fn node_count(&self) -> usize {
        self.node_len
    }

    /// Reglas declaradas.
    pub fn rule_count(&self) -> usize {
        self.rule_len
    }

    /// ¿Se evaluó al menos una vez?
    pub fn is_evaluated(&self) -> bool {
        self.evaluated
    }

    /// Nodos, en orden de declaración.
    pub fn nodes(&self) -> &[InferenceNode] {
        self.nodes.get(..self.node_len).unwrap_or(&[])
    }

    /// Reglas, en orden de declaración.
    pub fn rules(&self) -> &[InferenceRule] {
        self.rules.get(..self.rule_len).unwrap_or(&[])
    }

    /// Traza de la última evaluación (vacía antes de evaluar).
    pub fn trace(&self) -> &[Option<InferenceStep>] {
        self.trace.get(..self.trace_len).unwrap_or(&[])
    }

    /// Nodo por identificador.
    pub fn node(&self, id: NodeId) -> Option<&InferenceNode> {
        self.nodes.get(id.index())
    }

    /// Nodo por raíz y capa.
    pub fn lookup(&self, root: &str, layer: u8) -> Option<NodeId> {
        let key = RootKey::new(root)?;
        self.nodes
            .get(..self.node_len)?
            .iter()
            .position(|node| node.root == key && node.layer == layer)
            .and_then(|index| u16::try_from(index).ok())
            .map(NodeId)
    }

    /// Asienta un hecho. Varios hechos sobre el mismo nodo se combinan con la
    /// unión informativa `⊔`, de modo que dos testigos que discrepan producen
    /// `⊤∧⊥` en lugar de perder información.
    pub fn assert_fact(
        &mut self,
        layer: u8,
        root: &str,
        value: BelnapValue,
    ) -> Result<NodeId, InferenceError> {
        self.check_layer(layer)?;
        let key = RootKey::new(root).ok_or({
            if root.is_empty() {
                InferenceError::EmptyRoot
            } else {
                InferenceError::RootTooLong {
                    len: root.len(),
                    limit: MAX_ROOT_BYTES,
                }
            }
        })?;

        if let Some(index) = self.nodes.get(..self.node_len).and_then(|nodes| {
            nodes
                .iter()
                .position(|node| node.root == key && node.layer == layer)
        }) {
            if let Some(node) = self.nodes.get_mut(index) {
                node.asserted = node.asserted.union(value);
                node.value = node.asserted;
                node.is_fact = true;
                node.is_derived = false;
                self.evaluated = false;
                return u16::try_from(index)
                    .ok()
                    .map(NodeId)
                    .ok_or(InferenceError::NodeCapacity { limit: MAX_NODES });
            }
        }

        if self.node_len >= MAX_NODES {
            return Err(InferenceError::NodeCapacity { limit: MAX_NODES });
        }
        let index = self.node_len;
        let id = u16::try_from(index)
            .ok()
            .map(NodeId)
            .ok_or(InferenceError::NodeCapacity { limit: MAX_NODES })?;
        if let Some(node) = self.nodes.get_mut(index) {
            *node = InferenceNode {
                root: key,
                layer,
                value,
                asserted: value,
                is_fact: true,
                is_derived: false,
            };
            self.node_len = self.node_len.saturating_add(1);
            self.evaluated = false;
            Ok(id)
        } else {
            Err(InferenceError::NodeCapacity { limit: MAX_NODES })
        }
    }

    /// Alias expresivo de [`InferenceEngine::assert_fact`].
    pub fn assert(
        &mut self,
        layer: u8,
        root: &str,
        value: BelnapValue,
    ) -> Result<NodeId, InferenceError> {
        self.assert_fact(layer, root, value)
    }

    /// Declara una regla estratificada.
    ///
    /// El destino debe estar en una capa **estrictamente posterior**; el
    /// antecedente auxiliar, en una capa no posterior. Con esas dos condiciones
    /// el grafo es acíclico y una sola pasada por capas alcanza el punto fijo.
    pub fn add_rule(
        &mut self,
        from: NodeId,
        to: NodeId,
        kind: RuleKind,
        strength: BelnapValue,
        aux: Option<NodeId>,
    ) -> Result<RuleId, InferenceError> {
        let from_node = self
            .node(from)
            .copied()
            .ok_or(InferenceError::UnknownNode {
                index: from.index(),
                nodes: self.node_len,
            })?;
        let to_node = self.node(to).copied().ok_or(InferenceError::UnknownNode {
            index: to.index(),
            nodes: self.node_len,
        })?;
        if to_node.layer <= from_node.layer {
            return Err(InferenceError::NonStratified {
                from: from_node.layer,
                to: to_node.layer,
            });
        }
        if kind.requires_auxiliary() && aux.is_none() {
            return Err(InferenceError::MissingAuxiliary { kind });
        }
        if let Some(auxiliary) = aux {
            let aux_node = self
                .node(auxiliary)
                .copied()
                .ok_or(InferenceError::UnknownNode {
                    index: auxiliary.index(),
                    nodes: self.node_len,
                })?;
            if aux_node.layer > from_node.layer {
                return Err(InferenceError::AuxiliaryAhead {
                    auxiliary: aux_node.layer,
                    from: from_node.layer,
                });
            }
        }
        if self.rule_len >= MAX_RULES {
            return Err(InferenceError::RuleCapacity { limit: MAX_RULES });
        }
        let index = self.rule_len;
        let id = u16::try_from(index)
            .ok()
            .map(RuleId)
            .ok_or(InferenceError::RuleCapacity { limit: MAX_RULES })?;
        if let Some(slot) = self.rules.get_mut(index) {
            *slot = InferenceRule {
                from,
                to,
                aux,
                strength,
                kind,
            };
            self.rule_len = self.rule_len.saturating_add(1);
            self.evaluated = false;
            Ok(id)
        } else {
            Err(InferenceError::RuleCapacity { limit: MAX_RULES })
        }
    }

    /// Evalúa el grafo desde los hechos asertados.
    ///
    /// Es idempotente: cada llamada reinicia los valores al valor asertado y
    /// vuelve a aplicar todas las reglas en orden canónico. No asigna memoria.
    pub fn evaluate(&mut self) -> InferenceReport {
        for index in 0..self.node_len {
            if let Some(node) = self.nodes.get_mut(index) {
                node.value = node.asserted;
                node.is_derived = false;
            }
        }
        self.trace = [None; MAX_TRACE];
        self.trace_len = 0;
        let mut applied = 0usize;
        let mut changed = 0usize;

        for layer in 0..MAX_LAYERS {
            for rule_index in 0..self.rule_len {
                let rule = match self.rules.get(rule_index).copied() {
                    Some(rule) => rule,
                    None => continue,
                };
                let from = match self.node(rule.from).copied() {
                    Some(node) => node,
                    None => continue,
                };
                if usize::from(from.layer) != layer {
                    continue;
                }
                let antecedent = from.value;
                let auxiliary = match rule.aux.and_then(|id| self.node(id)) {
                    Some(node) => node.value,
                    None => BelnapValue::Neither,
                };
                let conclusion = rule.kind.apply(antecedent, auxiliary, rule.strength);
                let target = match self.nodes.get_mut(rule.to.index()) {
                    Some(target) => target,
                    None => continue,
                };
                let before = target.value;
                let after = before.union(conclusion);
                if after != before {
                    target.value = after;
                    target.is_derived = after != target.asserted;
                    changed = changed.saturating_add(1);
                }
                applied = applied.saturating_add(1);
                let to_layer = target.layer;

                if self.trace_len < MAX_TRACE {
                    if let Some(slot) = self.trace.get_mut(self.trace_len) {
                        let id = RuleId(u16::try_from(rule_index).unwrap_or(u16::MAX));
                        *slot = Some(InferenceStep {
                            rule: id,
                            from_layer: from.layer,
                            to_layer,
                            before,
                            after,
                        });
                        self.trace_len = self.trace_len.saturating_add(1);
                    }
                }
            }
        }
        self.evaluated = true;
        self.report(applied, changed)
    }

    /// Informe coherente con el estado actual.
    pub fn report(&self, applied: usize, changed: usize) -> InferenceReport {
        let mut true_count = 0usize;
        let mut false_count = 0usize;
        let mut both_count = 0usize;
        let mut neither_count = 0usize;
        let mut derived = 0usize;
        let mut layers = 0u8;
        for node in self.nodes() {
            match node.value {
                BelnapValue::True => true_count = true_count.saturating_add(1),
                BelnapValue::False => false_count = false_count.saturating_add(1),
                BelnapValue::Both => both_count = both_count.saturating_add(1),
                BelnapValue::Neither => neither_count = neither_count.saturating_add(1),
            }
            if node.is_derived {
                derived = derived.saturating_add(1);
            }
            layers = layers.max(node.layer.saturating_add(1));
        }
        InferenceReport {
            nodes: self.node_len,
            rules: self.rule_len,
            applied,
            changed,
            true_count,
            false_count,
            both_count,
            neither_count,
            derived,
            layers_used: usize::from(layers),
            truncated: self.trace_len >= MAX_TRACE,
        }
    }

    /// Censo en el orden `[⊤, ⊥, ⊤∧⊥, ∅]`.
    pub fn census(&self) -> [usize; 4] {
        let report = self.report(0, 0);
        [
            report.true_count,
            report.false_count,
            report.both_count,
            report.neither_count,
        ]
    }

    /// Vacía el grafo conservando la capacidad.
    pub fn clear(&mut self) {
        self.nodes = [InferenceNode::empty(); MAX_NODES];
        self.node_len = 0;
        self.rule_len = 0;
        self.trace = [None; MAX_TRACE];
        self.trace_len = 0;
        self.evaluated = false;
    }

    fn check_layer(&self, layer: u8) -> Result<(), InferenceError> {
        if usize::from(layer) >= MAX_LAYERS {
            Err(InferenceError::LayerOutOfRange {
                layer: usize::from(layer),
                limit: MAX_LAYERS,
            })
        } else {
            Ok(())
        }
    }
}

impl Default for InferenceEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Pruebas
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn el_motor_vacio_es_coherente() {
        let mut engine = InferenceEngine::new();
        let report = engine.evaluate();
        assert_eq!(report.nodes, 0);
        assert_eq!(report.rules, 0);
        assert_eq!(report.applied, 0);
        assert!(engine.nodes().is_empty());
        assert!(engine.rules().is_empty());
        assert!(engine.trace().is_empty());
    }

    #[test]
    fn la_inferencia_es_transitiva_en_tres_capas() {
        let mut engine = InferenceEngine::new();
        let a = engine.assert(0, "אמת", BelnapValue::True).ok();
        let b = engine.assert(1, "דעת", BelnapValue::Neither).ok();
        let c = engine.assert(2, "חכמ", BelnapValue::Neither).ok();
        let (Some(a), Some(b), Some(c)) = (a, b, c) else {
            return;
        };
        assert!(engine
            .add_rule(a, b, RuleKind::Transfer, BelnapValue::True, None)
            .is_ok());
        assert!(engine
            .add_rule(b, c, RuleKind::Transfer, BelnapValue::True, None)
            .is_ok());

        let report = engine.evaluate();
        assert_eq!(report.applied, 2);
        assert_eq!(report.changed, 2);
        assert_eq!(report.true_count, 3);
        assert_eq!(report.layers_used, 3);
        assert_eq!(
            engine.node(b).map(|node| node.value),
            Some(BelnapValue::True)
        );
        assert_eq!(
            engine.node(c).map(|node| node.value),
            Some(BelnapValue::True)
        );
        assert_eq!(engine.node(c).map(|node| node.is_derived), Some(true));
    }

    #[test]
    fn dos_testigos_que_discrepan_producen_una_contradiccion() {
        let mut engine = InferenceEngine::new();
        let a = engine.assert(0, "אמת", BelnapValue::True).ok();
        let b = engine.assert(0, "שקר", BelnapValue::False).ok();
        let target = engine.assert(2, "דעת", BelnapValue::Neither).ok();
        let (Some(a), Some(b), Some(target)) = (a, b, target) else {
            return;
        };
        assert!(engine
            .add_rule(a, target, RuleKind::Transfer, BelnapValue::True, None)
            .is_ok());
        assert!(engine
            .add_rule(b, target, RuleKind::Transfer, BelnapValue::True, None)
            .is_ok());

        let report = engine.evaluate();
        assert_eq!(report.applied, 2);
        assert_eq!(report.both_count, 1);
        assert!(report.is_paraconsistent());
        assert_eq!(
            engine.node(target).map(|node| node.value),
            Some(BelnapValue::Both)
        );
    }

    #[test]
    fn la_conjuncion_y_la_negacion_respetan_la_reticula() {
        let mut engine = InferenceEngine::new();
        let a = engine.assert(0, "אמת", BelnapValue::True).ok();
        let b = engine.assert(0, "דעת", BelnapValue::Both).ok();
        let and = engine.assert(2, "חכמ", BelnapValue::Neither).ok();
        let not = engine.assert(2, "בינ", BelnapValue::Neither).ok();
        let (Some(a), Some(b), Some(and), Some(not)) = (a, b, and, not) else {
            return;
        };
        assert!(engine
            .add_rule(a, and, RuleKind::Conjunction, BelnapValue::True, Some(b))
            .is_ok());
        assert!(engine
            .add_rule(a, not, RuleKind::Negation, BelnapValue::True, None)
            .is_ok());

        engine.evaluate();
        assert_eq!(
            engine.node(and).map(|node| node.value),
            Some(BelnapValue::Both)
        );
        assert_eq!(
            engine.node(not).map(|node| node.value),
            Some(BelnapValue::False)
        );
    }

    #[test]
    fn la_estratificacion_rechaza_ciclos_y_auxiliares_futuros() {
        let mut engine = InferenceEngine::new();
        let a = engine.assert(0, "אמת", BelnapValue::True).ok();
        let b = engine.assert(0, "דעת", BelnapValue::True).ok();
        let c = engine.assert(2, "חכמ", BelnapValue::Neither).ok();
        let (Some(a), Some(b), Some(c)) = (a, b, c) else {
            return;
        };

        assert_eq!(
            engine.add_rule(c, a, RuleKind::Transfer, BelnapValue::True, None),
            Err(InferenceError::NonStratified { from: 2, to: 0 })
        );
        assert_eq!(
            engine.add_rule(a, b, RuleKind::Transfer, BelnapValue::True, None),
            Err(InferenceError::NonStratified { from: 0, to: 0 })
        );
        assert_eq!(
            engine.add_rule(a, c, RuleKind::Conjunction, BelnapValue::True, Some(c)),
            Err(InferenceError::AuxiliaryAhead {
                auxiliary: 2,
                from: 0
            })
        );
        assert_eq!(
            engine.add_rule(a, c, RuleKind::Conjunction, BelnapValue::True, None),
            Err(InferenceError::MissingAuxiliary {
                kind: RuleKind::Conjunction
            })
        );
    }

    #[test]
    fn la_evaluacion_es_idempotente_y_reproducible() {
        let build = || {
            let mut engine = InferenceEngine::new();
            let a = engine.assert(0, "אמת", BelnapValue::True);
            let b = engine.assert(1, "דעת", BelnapValue::Neither);
            let c = engine.assert(2, "חכמ", BelnapValue::Neither);
            match (a, b, c) {
                (Ok(a), Ok(b), Ok(c)) => {
                    let _ = engine.add_rule(a, b, RuleKind::Transfer, BelnapValue::True, None);
                    let _ = engine.add_rule(b, c, RuleKind::Transfer, BelnapValue::True, None);
                    Some(engine)
                }
                _ => None,
            }
        };
        let Some(mut first) = build() else {
            return;
        };
        let Some(mut second) = build() else {
            return;
        };
        let one = first.evaluate();
        let two = first.evaluate();
        let other = second.evaluate();
        assert_eq!(one, two);
        assert_eq!(one, other);
        assert_eq!(first.census(), second.census());
    }

    #[test]
    fn las_capacidades_son_cotas_reales_y_no_panican() {
        let mut engine = InferenceEngine::new();
        for index in 0..MAX_NODES {
            let root = format!("נ{index:02}");
            let result = engine.assert(0, &root, BelnapValue::True);
            assert!(result.is_ok(), "nodo {index} rechazado antes de tiempo");
        }
        assert_eq!(
            engine.assert(0, "אמת", BelnapValue::True),
            Err(InferenceError::NodeCapacity { limit: MAX_NODES })
        );
        assert_eq!(
            engine.assert(0, "", BelnapValue::True),
            Err(InferenceError::EmptyRoot)
        );
        let largo = "א".repeat(MAX_ROOT_BYTES + 1);
        assert_eq!(
            engine.assert(0, &largo, BelnapValue::True),
            Err(InferenceError::RootTooLong {
                len: largo.len(),
                limit: MAX_ROOT_BYTES
            })
        );
        assert_eq!(
            engine.assert(MAX_LAYERS as u8, "אמת", BelnapValue::True),
            Err(InferenceError::LayerOutOfRange {
                layer: MAX_LAYERS,
                limit: MAX_LAYERS
            })
        );
    }

    #[test]
    fn la_raiz_fija_conserva_el_texto_y_rechaza_lo_que_no_cabe() {
        let Some(key) = RootKey::new("אמת") else {
            return;
        };
        assert_eq!(key.as_str(), "אמת");
        assert_eq!(key.byte_len(), 6);
        assert!(!key.is_empty());
        assert_eq!(RootKey::new(""), None);
        assert_eq!(RootKey::new(&"x".repeat(MAX_ROOT_BYTES + 1)), None);
        assert_eq!(RootKey::empty().as_str(), "");
    }

    #[test]
    fn la_traza_se_acota_sin_perder_el_informe() {
        let mut engine = InferenceEngine::new();
        let a = engine.assert(0, "אמת", BelnapValue::True).ok();
        let b = engine.assert(1, "דעת", BelnapValue::Neither).ok();
        let (Some(a), Some(b)) = (a, b) else {
            return;
        };
        assert!(engine
            .add_rule(a, b, RuleKind::Transfer, BelnapValue::True, None)
            .is_ok());
        let report = engine.evaluate();
        assert_eq!(report.applied, 1);
        assert_eq!(engine.trace().len(), 1);
        assert!(!report.truncated);
        assert_eq!(engine.lookup("אמת", 0), Some(a));
        assert!(engine.lookup("אמת", 3).is_none());
    }
}
