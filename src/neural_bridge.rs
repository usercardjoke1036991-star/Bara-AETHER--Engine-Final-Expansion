//! # Puente neuronal — Bara / AETHER‑Ω (FASE 4)
//!
//! Serializa la cognición del kernel al **formato de sección del IDE**
//! ([`Section`]): un cuerpo JSON acotado, determinista y de sólo lectura que un
//! panel dibuja sin hablar con el motor.
//!
//! El puente **no añade secciones**: el manifiesto canónico sigue teniendo
//! exactamente las cuatro secciones de [`crate::ide_bridge::SectionKind`], con
//! la misma huella de contrato. La cognición viaja dentro de la sección
//! `nucleo`, bajo la clave `neuronal`, de modo que un panel antiguo que ignore
//! esa clave sigue leyendo el documento sin romperse y un panel nuevo la
//! encuentra sin que el manifiesto cambie.
//!
//! ## Invariantes
//! 1. **Cero `unsafe`** y cero `panic!`/`unwrap`/`expect` en producción.
//! 2. **Sólo lectura**: el puente copia contadores, nunca toca el motor, la
//!    memoria ni el núcleo.
//! 3. **Determinismo**: el cuerpo y su huella sólo dependen de los datos
//!    recibidos; no hay reloj, azar ni orden de mapa.
//! 4. **Coherencia verificable**: el censo tetravalente debe sumar exactamente
//!    los nodos del informe, el censo de memoria sus entradas y un ciclo
//!    fusionado debe estar auditado. Un marco incoherente se marca
//!    (`coherente:false`) en lugar de mentir.
//! 5. **Estabilidad del contrato**: [`crate::ide_bridge::section_identity`] no
//!    cambia; lo fija [`IDENTITY_FINGERPRINT`].

#![forbid(unsafe_code)]
#![deny(clippy::all)]

use std::fmt;

use crate::ast_dna::{embed_root, short_hex, SymbolicEmbedding};
use crate::autopoiesis::CycleReport;
use crate::autopoietic::BelnapValue;
use crate::crypto_native::Sha256;
use crate::ide_bridge::{BridgeError, Section, SectionKind};
use crate::inference::{InferenceReport, ResolutionAdvice, RootKey};
use crate::long_term_memory::LongTermMemory;
use crate::neural_it::{NeuralIt, SemanticView};
use crate::topology::{AstChart, MetricPoint, METRIC_CAP};

/// Dominio de hash del puente neuronal.
pub const NEURAL_DOMAIN: &[u8] = b"bara:aether-omega:puente-neuronal:v1";

/// Esquema del marco neuronal.
pub const NEURAL_SCHEMA: &str = "aether-omega/neural/1";

/// Sección del IDE que transporta la cognición.
///
/// Es una de las cuatro canónicas: el puente no crea secciones nuevas.
pub const NEURAL_SECTION: SectionKind = SectionKind::Nucleo;

/// Clave del objeto neuronal dentro del cuerpo de la sección.
pub const NEURAL_KEY: &str = "neuronal";

/// Huella del manifiesto canónico del puente.
///
/// Se fija aquí como **candado de compatibilidad**: si alguien añade, quita o
/// reordena una sección del IDE, la prueba `el_contrato_del_ide_no_cambia`
/// falla y obliga a versionar el esquema en lugar de romper paneles en
/// silencio.
pub const IDENTITY_FINGERPRINT: &str =
    "cdf1a04bf051725173bf873cc7b1d2f3648955f98d4f9425a596f72c651e975c";

// ─────────────────────────────────────────────────────────────────────────
// Censo tetravalente
// ─────────────────────────────────────────────────────────────────────────

/// Recuento de las cuatro clases de Belnap.
///
/// Se indexa con [`BelnapValue::index`], así que el orden es el canónico
/// `⊤ ⊥ ⊤∧⊥ ∅` y no depende de cómo se construyó el censo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BelnapCensus {
    counts: [u64; 4],
}

impl BelnapCensus {
    /// Censo vacío.
    pub const fn new() -> Self {
        Self { counts: [0; 4] }
    }

    /// Suma una observación.
    pub fn observe(&mut self, value: BelnapValue) {
        if let Some(slot) = self.counts.get_mut(value.index()) {
            *slot = slot.saturating_add(1);
        }
    }

    /// Censo derivado de un informe de inferencia.
    pub fn from_report(report: &InferenceReport) -> Self {
        Self {
            counts: [
                report.true_count as u64,
                report.false_count as u64,
                report.both_count as u64,
                report.neither_count as u64,
            ],
        }
    }

    /// Censo derivado de un array `[⊤, ⊥, ⊤∧⊥, ∅]`.
    pub fn from_census(census: [usize; 4]) -> Self {
        Self {
            counts: [
                census[0] as u64,
                census[1] as u64,
                census[2] as u64,
                census[3] as u64,
            ],
        }
    }

    /// Recuento de una clase.
    pub const fn get(self, value: BelnapValue) -> u64 {
        self.counts[value.index()]
    }

    /// Observaciones totales.
    pub const fn total(self) -> u64 {
        self.counts[0]
            .saturating_add(self.counts[1])
            .saturating_add(self.counts[2])
            .saturating_add(self.counts[3])
    }

    /// ¿No hay observaciones?
    pub const fn is_empty(self) -> bool {
        self.total() == 0
    }

    /// Clase dominante; en empate gana la primera en orden canónico.
    pub fn dominant(self) -> Option<BelnapValue> {
        let mut best: Option<BelnapValue> = None;
        let mut best_count = 0u64;
        for value in BelnapValue::ALL {
            let count = self.get(value);
            if count > best_count {
                best = Some(value);
                best_count = count;
            }
        }
        best
    }

    /// Recuentos en orden canónico.
    pub const fn counts(self) -> [u64; 4] {
        self.counts
    }

    /// Objeto JSON del censo.
    pub fn json(&self) -> String {
        format!(
            "{{\"verdadero\":{},\"falso\":{},\"contradictorio\":{},\"indeterminado\":{},\"total\":{}}}",
            self.counts[0],
            self.counts[1],
            self.counts[2],
            self.counts[3],
            self.total()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Vista de la memoria a largo plazo
// ─────────────────────────────────────────────────────────────────────────

/// Foto `Copy` de la memoria a largo plazo.
///
/// Copiar los contadores (en vez de retener un préstamo) permite construir el
/// marco, soltar la memoria y serializar después sin bloquear el motor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryView {
    /// Entradas vivas.
    pub entries: usize,
    /// Techo de entradas.
    pub capacity: usize,
    /// Censo de clases `[⊤, ⊥, ⊤∧⊥, ∅]`.
    pub census: [usize; 4],
    /// Riesgo acumulado en milésimas.
    pub hazard_total: u64,
    /// Escrituras acumuladas.
    pub writes: u64,
    /// Huella de la memoria.
    pub digest: [u8; 32],
}

impl MemoryView {
    /// Captura los contadores de la memoria.
    pub fn capture(memory: &LongTermMemory) -> Self {
        Self {
            entries: memory.len(),
            capacity: memory.capacity(),
            census: memory.census(),
            hazard_total: memory.hazard_total(),
            writes: memory.writes(),
            digest: memory.digest(),
        }
    }

    /// ¿Memoria vacía?
    pub const fn is_empty(self) -> bool {
        self.entries == 0
    }

    /// ¿Memoria llena?
    pub const fn is_full(self) -> bool {
        self.entries >= self.capacity
    }

    /// ¿El censo suma exactamente las entradas?
    pub fn is_coherent(self) -> bool {
        let total = self.census[0]
            .saturating_add(self.census[1])
            .saturating_add(self.census[2])
            .saturating_add(self.census[3]);
        total == self.entries && self.entries <= self.capacity
    }

    /// Huella hexadecimal de la memoria.
    pub fn fingerprint(self) -> String {
        short_hex(&self.digest)
    }

    /// Objeto JSON de la memoria.
    pub fn json(&self) -> String {
        format!(
            "{{\"entradas\":{},\"capacidad\":{},\"llena\":{},\"censo\":{},\"riesgo\":{},\"escrituras\":{},\"huella\":\"{}\"}}",
            self.entries,
            self.capacity,
            self.is_full(),
            BelnapCensus::from_census(self.census).json(),
            self.hazard_total,
            self.writes,
            self.fingerprint()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Marco neuronal
// ─────────────────────────────────────────────────────────────────────────

/// Marco neuronal: el estado cognitivo que el panel dibuja.
///
/// Es `Copy`: la memoria se guarda ya copiada en [`MemoryView`], así que un
/// marco nunca presta nada del kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeuralFrame {
    /// Generación del kernel a la que pertenece el marco.
    pub generation: u64,
    /// Informe de la última inferencia.
    pub report: InferenceReport,
    /// Censo tetravalente **derivado** del informe.
    pub census: BelnapCensus,
    /// Vista de la memoria a largo plazo, si se capturó.
    pub memory: Option<MemoryView>,
    /// Último ciclo autopoiético, si se capturó.
    pub cycle: Option<CycleReport>,
    /// Vista del índice semántico *Shoresh* (NeuralIT), si se capturó.
    pub semantic: Option<SemanticView>,
    /// Consejos para estados `Both`, como máximo cuatro.
    pub advice: [Option<ResolutionAdvice>; 4],
    /// Embedding del fragmento que el marco está mirando. Cero si no hay nodo.
    pub embedding: SymbolicEmbedding,
    /// Carta topológica del AST que el marco está mirando.
    pub topology: TopoView,
}

impl NeuralFrame {
    /// Marco sin memoria ni ciclo, con el censo derivado del informe.
    pub fn new(generation: u64, report: InferenceReport) -> Self {
        Self {
            generation,
            report,
            census: BelnapCensus::from_report(&report),
            memory: None,
            cycle: None,
            semantic: None,
            advice: [None; 4],
            embedding: SymbolicEmbedding::zero(),
            topology: TopoView::quiet(),
        }
    }

    /// Fija la carta topológica del fragmento activo.
    pub const fn with_topology(mut self, topology: TopoView) -> Self {
        self.topology = topology;
        self
    }

    /// Fija el embedding del fragmento activo.
    pub const fn with_embedding(mut self, embedding: SymbolicEmbedding) -> Self {
        self.embedding = embedding;
        self
    }

    /// Copia hasta cuatro consejos de resolución. El resto se descarta.
    pub fn with_advice(mut self, advice: &[ResolutionAdvice]) -> Self {
        for (index, item) in advice.iter().take(self.advice.len()).enumerate() {
            if let Some(slot) = self.advice.get_mut(index) {
                *slot = Some(*item);
            }
        }
        self
    }

    /// Marco con memoria.
    pub fn capture(generation: u64, report: InferenceReport, memory: &LongTermMemory) -> Self {
        Self::new(generation, report).with_memory(memory)
    }

    /// Añade la vista de una memoria.
    pub fn with_memory(mut self, memory: &LongTermMemory) -> Self {
        self.memory = Some(MemoryView::capture(memory));
        self
    }

    /// Añade una vista ya copiada.
    pub const fn with_view(mut self, view: MemoryView) -> Self {
        self.memory = Some(view);
        self
    }

    /// Añade el último ciclo autopoiético.
    pub const fn with_cycle(mut self, cycle: CycleReport) -> Self {
        self.cycle = Some(cycle);
        self
    }

    /// Añade la vista del índice semántico *Shoresh*.
    pub fn with_semantic(mut self, engine: &NeuralIt) -> Self {
        self.semantic = Some(engine.view());
        self
    }

    /// Añade una vista semántica ya copiada.
    pub const fn with_semantic_view(mut self, view: SemanticView) -> Self {
        self.semantic = Some(view);
        self
    }

    /// ¿El censo del informe suma sus nodos, el de memoria sus entradas y el
    /// ciclo fusionado está auditado?
    pub fn is_coherent(&self) -> bool {
        let nodes = self.report.nodes as u64;
        let inference_ok = self.census.total() == nodes;
        let memory_ok = match self.memory {
            Some(view) => view.is_coherent(),
            None => true,
        };
        let cycle_ok = match self.cycle {
            Some(cycle) => {
                !cycle.is_committed() || (cycle.audit_conforms() && cycle.proposal.is_some())
            }
            None => true,
        };
        let semantic_ok = match self.semantic {
            Some(view) => view.is_coherent(),
            None => true,
        };
        inference_ok && memory_ok && cycle_ok && semantic_ok
    }

    /// Objeto JSON del informe de inferencia.
    fn report_json(&self) -> String {
        format!(
            "{{\"nodos\":{},\"reglas\":{},\"aplicadas\":{},\"cambiadas\":{},\"derivadas\":{},\"capas\":{},\"truncado\":{}}}",
            self.report.nodes,
            self.report.rules,
            self.report.applied,
            self.report.changed,
            self.report.derived,
            self.report.layers_used,
            self.report.truncated
        )
    }

    /// Objeto JSON del ciclo autopoiético.
    fn cycle_json(&self) -> String {
        let cycle = match self.cycle {
            Some(cycle) => cycle,
            None => return String::from("null"),
        };
        let proposal = match cycle.proposal {
            Some(id) => id.to_string(),
            None => String::from("null"),
        };
        let verdict = match cycle.verdict {
            Some(value) => value.index().to_string(),
            None => String::from("null"),
        };
        let violation = match cycle.violation {
            Some(rule) => format!("\"{}\"", escape(rule.code())),
            None => String::from("null"),
        };
        format!(
            "{{\"proposito\":\"{}\",\"celula\":{},\"propuesta\":{},\"revision_base\":{},\"operaciones\":{},\"nodos\":{},\"auditoria\":{{\"superadas\":{},\"totales\":{},\"conforme\":{}}},\"juicio\":{},\"resultado\":\"{}\",\"explicacion\":\"{}\",\"violacion\":{},\"huella\":\"{}\"}}",
            escape(cycle.purpose),
            cycle.cell,
            proposal,
            cycle.base_revision,
            cycle.operations,
            cycle.nodes,
            cycle.audit_passed,
            cycle.audit_total,
            cycle.audit_conforms(),
            verdict,
            cycle.result.code(),
            escape(&cycle.result.label()),
            violation,
            cycle.fingerprint()
        )
    }

    /// Objeto JSON del índice semántico *Shoresh*.
    fn semantic_json(&self) -> String {
        match self.semantic {
            Some(view) => view.json(),
            None => String::from("null"),
        }
    }

    /// Objeto neuronal canónico (clave `neuronal` del panel).
    pub fn json(&self) -> String {
        let memory = match self.memory {
            Some(view) => view.json(),
            None => String::from("null"),
        };
        format!(
            "{{\"esquema\":\"{}\",\"generacion\":{},\"inferencia\":{},\"censo\":{},\"memoria\":{},\"ciclo\":{},\"semantica\":{},\"recomendaciones\":{},\"embedding\":{},\"proximidad_mili\":{},\"topologia\":{},\"coherente\":{}}}",
            NEURAL_SCHEMA,
            self.generation,
            self.report_json(),
            self.census.json(),
            memory,
            self.cycle_json(),
            self.semantic_json(),
            self.advice_json(),
            self.embedding.json(),
            conceptual_milli(self.embedding, embed_root("ברא")),
            self.topology.json(),
            self.is_coherent()
        )
    }

    /// Lista JSON de consejos `Both`. Vacía si la evaluación no encontró ninguno.
    fn advice_json(&self) -> String {
        let mut out = String::from("[");
        let mut first = true;
        for slot in &self.advice {
            let Some(advice) = slot else {
                continue;
            };
            if !first {
                out.push(',');
            }
            first = false;
            out.push_str("{\"raiz\":\"");
            out.push_str(&escape(advice.root.as_str()));
            out.push_str("\",\"tactica\":\"");
            out.push_str(advice.tactic.label());
            out.push_str("\",\"recomendacion\":\"");
            out.push_str(&escape(advice.tactic.recommendation()));
            out.push_str("\"}");
        }
        out.push(']');
        out
    }

    /// Cuerpo completo de la sección: `{"neuronal":{…}}`.
    ///
    /// Sólo depende de los campos del marco, así que sirve para incrustarlo en
    /// el `nucleo` que arme el runtime sin tocar el resto del documento.
    pub fn body(&self) -> String {
        format!("{{\"{}\":{}}}", NEURAL_KEY, self.json())
    }

    /// Huella `sha256` del cuerpo neuronal.
    pub fn digest(&self) -> [u8; 32] {
        let body = self.body();
        let mut hasher = Sha256::new();
        hasher.update(NEURAL_DOMAIN);
        hasher.update(&(body.len() as u64).to_le_bytes());
        hasher.update(body.as_bytes());
        hasher.finish()
    }

    /// Huella del cuerpo en hexadecimal.
    pub fn fingerprint(&self) -> String {
        short_hex(&self.digest())
    }

    /// Sección `nucleo` con la cognición, validada por el puente del IDE.
    pub fn section(&self) -> Result<Section, BridgeError> {
        Section::new(NEURAL_SECTION, &self.body())
    }
}

impl fmt::Display for NeuralFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "neuronal(gen={}, nodos={}, ⊤={}, ⊥={}, ⊤∧⊥={}, ∅={}, huella={})",
            self.generation,
            self.report.nodes,
            self.census.get(BelnapValue::True),
            self.census.get(BelnapValue::False),
            self.census.get(BelnapValue::Both),
            self.census.get(BelnapValue::Neither),
            self.fingerprint()
        )
    }
}

/// Coseno en milésimas `[-1000, 1000]`. Un vector nulo mide cero.
pub fn conceptual_milli(left: SymbolicEmbedding, right: SymbolicEmbedding) -> i32 {
    let mut dot: i64 = 0;
    let mut left_norm: i64 = 0;
    let mut right_norm: i64 = 0;
    for (left_lane, right_lane) in left.lanes.iter().zip(right.lanes.iter()) {
        let l = i64::from(*left_lane);
        let r = i64::from(*right_lane);
        dot += l * r;
        left_norm += l * l;
        right_norm += r * r;
    }
    if dot == 0 || left_norm == 0 || right_norm == 0 {
        return 0;
    }
    let denom = ((left_norm as f64) * (right_norm as f64)).sqrt();
    if denom == 0.0 {
        return 0;
    }
    let milli = (dot as f64) * 1000.0 / denom;
    let quantized = milli.round().clamp(-1000.0, 1000.0);
    if quantized >= 0.0 {
        quantized as i32
    } else {
        -((-quantized) as i32)
    }
}

/// Similitud coseno en `[-1, 1]`, cuantizada a milésimas para que el bit no flote.
pub fn conceptual_cosine(left: SymbolicEmbedding, right: SymbolicEmbedding) -> f32 {
    (conceptual_milli(left, right) as f32) / 1000.0
}

/// Vista topológica copiable: conteos, el par más cercano y la alerta de solape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TopoView {
    /// Puntos que entraron en la carta.
    pub nodes: u16,
    /// Pares con el mismo residuo.
    pub overlaps: u16,
    /// Cohesión en milésimas. `1000` es un documento de un solo punto.
    pub cohesion_milli: u16,
    /// Distancia del par más cercano. `u16::MAX` si no hay par.
    pub nearest: u16,
    /// Nodos que no cupieron en la carta.
    pub omitted: u16,
    /// Raíz de un extremo del par más cercano.
    pub focus: RootKey,
    /// Raíz del otro extremo.
    pub neighbor: RootKey,
    /// Hay al menos un solape de trayectoria.
    pub alert: bool,
}

impl TopoView {
    /// Carta vacía, cohesión plena y sin alerta.
    pub const fn quiet() -> Self {
        Self {
            nodes: 0,
            overlaps: 0,
            cohesion_milli: 1000,
            nearest: u16::MAX,
            omitted: 0,
            focus: RootKey::empty(),
            neighbor: RootKey::empty(),
            alert: false,
        }
    }

    /// Objeto JSON en *snake_case*.
    pub fn json(&self) -> String {
        let distance = if self.nearest == u16::MAX {
            String::from("null")
        } else {
            self.nearest.to_string()
        };
        format!(
            "{{\"nodos\":{},\"solapes\":{},\"cohesion_mili\":{},\"distancia\":{},\"omitidos\":{},\"foco\":\"{}\",\"vecino\":\"{}\",\"alerta\":{}}}",
            self.nodes,
            self.overlaps,
            self.cohesion_milli,
            distance,
            self.omitted,
            escape(self.focus.as_str()),
            escape(self.neighbor.as_str()),
            self.alert
        )
    }
}

/// Distancia de edición de raíces, acotada a 16 bytes.
///
/// El recorte es por bytes ya empaquetados en el punto, así que no parte un
/// carácter: [`MetricPoint::root`] sólo publica texto válido.
#[allow(clippy::needless_range_loop)]
pub fn root_edit_distance(left: &str, right: &str) -> u32 {
    let left_bytes = left.as_bytes();
    let right_bytes = right.as_bytes();
    let rows = left_bytes.len().min(16);
    let cols = right_bytes.len().min(16);
    let mut prev = [0u16; 17];
    let mut curr = [0u16; 17];
    for column in 0..=cols {
        if let Some(slot) = prev.get_mut(column) {
            *slot = u16::try_from(column).unwrap_or(0);
        }
    }
    for row in 1..=rows {
        if let Some(slot) = curr.get_mut(0) {
            *slot = u16::try_from(row).unwrap_or(0);
        }
        for column in 1..=cols {
            let left_byte = left_bytes.get(row.saturating_sub(1)).copied().unwrap_or(0);
            let right_byte = right_bytes
                .get(column.saturating_sub(1))
                .copied()
                .unwrap_or(0);
            let cost = u16::from(left_byte != right_byte);
            let deletion = prev.get(column).copied().unwrap_or(0).saturating_add(1);
            let insertion = curr
                .get(column.saturating_sub(1))
                .copied()
                .unwrap_or(0)
                .saturating_add(1);
            let substitution = prev
                .get(column.saturating_sub(1))
                .copied()
                .unwrap_or(0)
                .saturating_add(cost);
            if let Some(slot) = curr.get_mut(column) {
                *slot = deletion.min(insertion).min(substitution);
            }
        }
        prev = curr;
    }
    u32::from(prev.get(cols).copied().unwrap_or(0))
}

/// Distancia topológica: saltos en el documento, edición de la raíz y aridad.
///
/// El resultado queda en `0..=METRIC_CAP`. El mismo par, en cualquier orden de
/// llamada, devuelve el mismo entero.
pub fn topological_distance(left: &MetricPoint, right: &MetricPoint) -> u32 {
    let hops = u32::from(left.index.abs_diff(right.index));
    let edit = root_edit_distance(left.root(), right.root());
    let arity = u32::from(left.arity.abs_diff(right.arity));
    hops.saturating_add(edit)
        .saturating_add(arity)
        .min(METRIC_CAP)
}

/// Carta de nodos y su vista para el cockpit.
pub fn survey(nodes: &[crate::ffi_ingest::ShoreshNode]) -> TopoView {
    view_of(&AstChart::from_nodes(nodes))
}

/// Carta de raíces sueltas, en el orden recibido.
pub fn survey_roots(roots: &[&str]) -> TopoView {
    view_of(&AstChart::from_roots(roots))
}

fn view_of(chart: &AstChart) -> TopoView {
    let points = chart.points();
    let mut total = 0u32;
    let mut pairs = 0u32;
    let mut nearest = u32::from(u16::MAX);
    let mut focus = RootKey::empty();
    let mut neighbor = RootKey::empty();
    for (index, left) in points.iter().enumerate() {
        let Some(rest) = points.get(index.saturating_add(1)..) else {
            continue;
        };
        for right in rest {
            let distance = topological_distance(left, right);
            pairs = pairs.saturating_add(1);
            total = total.saturating_add(distance);
            if distance < nearest {
                nearest = distance;
                focus = RootKey::new(left.root()).unwrap_or_else(RootKey::empty);
                neighbor = RootKey::new(right.root()).unwrap_or_else(RootKey::empty);
            }
        }
    }
    let cohesion_milli = if pairs == 0 {
        1000u32
    } else {
        let mean = total.checked_div(pairs).unwrap_or(0);
        1000u32.saturating_sub(mean.saturating_mul(1000) / METRIC_CAP)
    };
    TopoView {
        nodes: chart.len(),
        overlaps: chart.overlaps(),
        cohesion_milli: u16::try_from(cohesion_milli).unwrap_or(1000),
        nearest: u16::try_from(nearest).unwrap_or(u16::MAX),
        omitted: chart.spilled(),
        focus,
        neighbor,
        alert: chart.overlaps() > 0,
    }
}

/// Distancia euclídea de los carriles en punto fijo. Cero si los vectores coinciden.
pub fn conceptual_euclidean(left: SymbolicEmbedding, right: SymbolicEmbedding) -> f32 {
    let mut acc: i64 = 0;
    for (left_lane, right_lane) in left.lanes.iter().zip(right.lanes.iter()) {
        let delta = i64::from(*left_lane) - i64::from(*right_lane);
        acc += delta * delta;
    }
    (acc as f32).sqrt()
}

/// Sección `nucleo` con la cognición de un marco.
///
/// Función libre, para que el runtime la llame sin arrastrar el tipo:
/// `section_cognition(&frame)`.
pub fn section_cognition(frame: &NeuralFrame) -> Result<Section, BridgeError> {
    frame.section()
}

/// Incrusta la cognición en un cuerpo de sección ya existente.
///
/// Si `base` es un objeto JSON, devuelve el mismo objeto con la clave
/// `neuronal` al final. Devuelve `None` si `base` no es un objeto. La función
/// no interpreta el JSON: sólo añade una clave al final, sin reescribir las
/// existentes.
pub fn embed(frame: &NeuralFrame, base: &str) -> Option<String> {
    let trimmed = base.trim();
    if !(trimmed.starts_with('{') && trimmed.ends_with('}')) {
        return None;
    }
    let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
    let mut out = String::with_capacity(trimmed.len() + 256);
    out.push('{');
    let empty = inner.trim().is_empty();
    if !empty {
        out.push_str(inner.trim_end_matches(','));
        out.push(',');
    }
    out.push('"');
    out.push_str(NEURAL_KEY);
    out.push_str("\":");
    out.push_str(&frame.json());
    out.push('}');
    Some(out)
}
/// Escapa un texto para que quepa en una cadena JSON.
///
/// El propósito de un contrato es `&'static str` y puede traer comillas o
/// controles; el panel debe poder leerlo sin romper el documento.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", control as u32));
            }
            plain => out.push(plain),
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────
// Pruebas
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::autopoiesis::{CycleVerdict, PurposeContract, PurposeViolation};
    use crate::ffi_ingest::{BaraType, ShoreshAst, ShoreshNode};
    use crate::flight_recorder::FlightRecorder;
    use crate::ide_bridge::{section_identity, Manifest, SectionKind};
    use crate::long_term_memory::MemoryDraft;

    fn report() -> InferenceReport {
        InferenceReport {
            nodes: 4,
            rules: 3,
            applied: 5,
            changed: 2,
            true_count: 2,
            false_count: 1,
            both_count: 0,
            neither_count: 1,
            derived: 1,
            layers_used: 2,
            truncated: false,
        }
    }

    fn frame() -> NeuralFrame {
        NeuralFrame::new(7, report())
    }

    fn memory() -> LongTermMemory {
        let mut memory = LongTermMemory::new();
        assert!(memory
            .insert(
                MemoryDraft::new("אמת", 0, BelnapValue::True)
                    .hazard(120)
                    .arity(2)
            )
            .is_ok());
        assert!(memory
            .insert(MemoryDraft::new("שקר", 1, BelnapValue::False))
            .is_ok());
        memory
    }
    fn cycle() -> CycleReport {
        let mut report = CycleReport::new("orden", 3, CycleVerdict::Committed { revision: 12 });
        report.proposal = Some(7);
        report.base_revision = 11;
        report.operations = 2;
        report.nodes = 4;
        report.audit_passed = 9;
        report.audit_total = 9;
        report.verdict = Some(BelnapValue::True);
        report
    }

    fn semantic_tree() -> ShoreshAst {
        ShoreshAst {
            nodes: vec![ShoreshNode {
                root: "שמר".to_string(),
                original: "shamar".to_string(),
                arity: 2,
                ret: BaraType::Truth,
                hazard: 0.2,
                valence: BelnapValue::True.to_state(),
                sanitized: false,
            }],
        }
    }

    #[test]
    fn el_censo_deriva_del_informe() {
        let census = BelnapCensus::from_report(&report());
        assert_eq!(census.get(BelnapValue::True), 2);
        assert_eq!(census.get(BelnapValue::False), 1);
        assert_eq!(census.get(BelnapValue::Both), 0);
        assert_eq!(census.get(BelnapValue::Neither), 1);
        assert_eq!(census.total(), 4);
        assert_eq!(census.counts(), [2, 1, 0, 1]);
        assert_eq!(census.dominant(), Some(BelnapValue::True));
        assert!(!census.is_empty());
    }

    #[test]
    fn el_censo_vacio_no_tiene_dominante() {
        let census = BelnapCensus::new();
        assert_eq!(census.total(), 0);
        assert!(census.is_empty());
        assert_eq!(census.dominant(), None);
    }

    #[test]
    fn el_dominante_rompe_empates_en_orden_canonico() {
        let census = BelnapCensus::from_census([1, 1, 1, 1]);
        assert_eq!(census.dominant(), Some(BelnapValue::True));
        let census = BelnapCensus::from_census([0, 2, 2, 0]);
        assert_eq!(census.dominant(), Some(BelnapValue::False));
    }

    #[test]
    fn el_marco_sin_memoria_serializa_nulo() {
        let frame = frame();
        assert!(frame.is_coherent());
        let body = frame.body();
        assert!(body.starts_with("{\"neuronal\":{"));
        assert!(body.ends_with("}}"));
        assert!(body.contains("\"esquema\":\"aether-omega/neural/1\""));
        assert!(body.contains("\"generacion\":7"));
        assert!(body.contains("\"memoria\":null"));
        assert!(body.contains("\"coherente\":true"));
        assert!(body.contains("\"contradictorio\":0"));
    }

    #[test]
    fn el_marco_con_memoria_copia_el_censo() {
        let memory = memory();
        let frame = NeuralFrame::capture(3, report(), &memory);
        assert!(frame.is_coherent());
        let view = match frame.memory {
            Some(view) => view,
            None => panic!("el marco debe llevar la vista de memoria"),
        };
        assert_eq!(view.entries, 2);
        assert_eq!(view.capacity, memory.capacity());
        assert_eq!(view.census, memory.census());
        assert_eq!(view.hazard_total, 120);
        assert_eq!(view.writes, 2);
        assert_eq!(view.digest, memory.digest());
        assert!(!view.is_empty());
        assert!(!view.is_full());
        let body = frame.body();
        assert!(body.contains("\"memoria\":{\"entradas\":2"));
        assert!(body.contains("\"riesgo\":120"));
        assert!(body.contains("\"coherente\":true"));
    }

    #[test]
    fn el_marco_incoherente_se_marca_sin_panico() {
        let mut frame = frame();
        frame.census = BelnapCensus::from_census([1, 0, 0, 0]);
        assert!(!frame.is_coherent());
        assert!(frame.body().contains("\"coherente\":false"));
        let view = MemoryView {
            entries: 4,
            capacity: 2,
            census: [4, 0, 0, 0],
            hazard_total: 0,
            writes: 0,
            digest: [0u8; 32],
        };
        assert!(!view.is_coherent());
        assert!(view.is_full());
    }

    #[test]
    fn dos_marcos_iguales_comparten_huella() {
        let first = frame();
        let second = NeuralFrame::new(7, report());
        assert_eq!(first, second);
        assert_eq!(first.body(), second.body());
        assert_eq!(first.digest(), second.digest());
        assert_eq!(first.fingerprint(), second.fingerprint());
        assert_eq!(first.fingerprint().len(), 64);
        let other = NeuralFrame::new(8, report());
        assert_ne!(first.digest(), other.digest());
    }

    #[test]
    fn la_seccion_es_nucleo_y_valida() {
        let frame = frame();
        let section = match frame.section() {
            Ok(section) => section,
            Err(error) => panic!("la sección debe validar: {}", error),
        };
        assert_eq!(section.kind(), SectionKind::Nucleo);
        assert_eq!(section.name(), "nucleo");
        assert!(section.body().starts_with('{'));
        assert!(section.body().ends_with('}'));
        assert!(section_cognition(&frame).is_ok());
    }

    #[test]
    fn incrustar_anade_la_clave_sin_reescribir_el_resto() {
        let frame = frame();
        let body = match embed(&frame, "{\"pila\":1,\"memoria\":2}") {
            Some(body) => body,
            None => panic!("un objeto debe aceptar la incrustación"),
        };
        assert!(body.starts_with("{\"pila\":1,\"memoria\":2,\"neuronal\":{"));
        assert!(body.ends_with('}'));
        assert!(body.contains("\"generacion\":7"));
        let empty = match embed(&frame, "{}") {
            Some(body) => body,
            None => panic!("un objeto vacío debe aceptar la incrustación"),
        };
        assert!(empty.starts_with("{\"neuronal\":{"));
        assert!(embed(&frame, "[1,2]").is_none());
        assert!(embed(&frame, "no-json").is_none());
        assert!(embed(&frame, "").is_none());
    }

    #[test]
    fn el_marco_serializa_el_ciclo() {
        let frame = frame().with_cycle(cycle());
        assert!(frame.is_coherent());
        let body = frame.body();
        assert!(body.contains("\"ciclo\":{\"proposito\":\"orden\""));
        assert!(body.contains("\"revision_base\":11"));
        assert!(body.contains("\"propuesta\":7"));
        assert!(body.contains("\"resultado\":\"fusionado\""));
        assert!(body.contains("\"conforme\":true"));
        assert!(body.contains("\"juicio\":0"));
        assert!(body.contains("\"violacion\":null"));
        assert!(body.contains("\"coherente\":true"));
    }

    #[test]
    fn un_ciclo_fusionado_sin_auditoria_rompe_la_coherencia() {
        let mut cycle = cycle();
        cycle.audit_total = 0;
        cycle.audit_passed = 0;
        let frame = frame().with_cycle(cycle);
        assert!(!frame.is_coherent());
        assert!(frame.body().contains("\"coherente\":false"));
    }

    #[test]
    fn el_rechazo_de_proposito_viaja_con_codigo() {
        let violation = PurposeViolation::HazardCeiling {
            index: 0,
            permille: 900,
            limit: 500,
        };
        let mut cycle = CycleReport::new(
            "orden \"estricto\"",
            4,
            CycleVerdict::ContractRejected(violation),
        );
        cycle.proposal = Some(9);
        cycle.violation = Some(violation);
        cycle.audit_passed = 9;
        cycle.audit_total = 9;
        let frame = frame().with_cycle(cycle);
        assert!(frame.is_coherent());
        let body = frame.body();
        assert!(body.contains("\"proposito\":\"orden \\\"estricto\\\"\""));
        assert!(body.contains("\"resultado\":\"proposito.rechazado\""));
        assert!(body.contains("\"violacion\":\"proposito.riesgo\""));
        assert!(body.contains("\"explicacion\":\"propósito rechazado:"));
    }

    #[test]
    fn dos_marcos_distintos_comparten_esquema_pero_no_huella() {
        let plain = frame();
        let with_cycle = frame().with_cycle(cycle());
        assert_ne!(plain, with_cycle);
        assert_ne!(plain.digest(), with_cycle.digest());
        assert!(plain.body().contains("\"ciclo\":null"));
        assert!(with_cycle.body().contains("\"ciclo\":{"));
    }

    #[test]
    fn el_marco_expone_la_semantica_neural_it() {
        let mut engine = NeuralIt::new();
        let contract = PurposeContract::new("cognicion");
        let recorder = FlightRecorder::new();
        assert!(engine
            .synchronize_with(&semantic_tree(), &contract, Some(&recorder))
            .is_ok());
        let frame = frame().with_semantic(&engine);
        assert!(frame.is_coherent());
        assert!(frame.body().contains("\"semantica\":{\"ranuras\":1"));
        assert!(frame.body().contains("\"coherente\":true"));
        let view = match frame.semantic {
            Some(view) => view,
            None => return,
        };
        assert_eq!(view.slots, 1);
        assert_eq!(view.nodes, 1);
        assert_eq!(view.census, [1, 0, 0, 0]);
        assert!(view.is_coherent());
    }

    #[test]
    fn una_vista_semantica_incoherente_marca_el_marco() {
        let view = SemanticView {
            slots: 2,
            capacity: 1,
            nodes: 2,
            census: [2, 0, 0, 0],
            contradictions: 0,
            unknown: 0,
            digest: [0; 32],
        };
        let frame = frame().with_semantic_view(view);
        assert!(!frame.is_coherent());
        assert!(frame.body().contains("\"coherente\":false"));
    }

    #[test]
    fn el_contrato_del_ide_no_cambia() {
        let manifest = Manifest::canon();
        assert_eq!(manifest.len(), 4);
        let names: [&str; 4] = ["identidad", "inmunidad", "pasarela", "nucleo"];
        for (index, kind) in SectionKind::ALL.iter().copied().enumerate() {
            assert_eq!(kind.index(), index);
            assert_eq!(kind.name(), names[index]);
            assert!(manifest.contains(kind));
            assert_eq!(SectionKind::from_name(kind.name()), Some(kind));
        }
        assert!(manifest.contains(NEURAL_SECTION));
        assert_eq!(manifest.fingerprint(), IDENTITY_FINGERPRINT);
        assert!(section_identity().is_ok());
    }
}
