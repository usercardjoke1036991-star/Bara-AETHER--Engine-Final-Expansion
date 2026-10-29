//! # Temporal State Navigation & Rollback — `temporal_rollback.rs`
//!
//! Navegación temporal del estado de ejecución con **rollback atómico**
//! (`Δ⁻¹`) a resolución de microsegundos.
//!
//! Cada mutación de estado se registra como un [`Delta`] *reversible*. Un
//! [`Marker`] captura un instante lógico; `rollback_to(marker)` invierte
//! todos los deltas posteriores en orden inverso, restaurando el estado
//! anterior de forma **atómica** (o todo, o nada).
//!
//! El runtime invoca este motor cuando intercepta una **paradoja
//! irresoluble** ([`detect_paradox`]): una contradicción absoluta `⊤∧⊥`
//! donde la verdad y la falsedad alcanzan simultáneamente su máximo. En vez
//! de colapsar (o explotar), el estado se rebobina a un punto consistente.

use crate::runtime::QuantumState;
use std::time::Instant;

/// Marca lógica: los deltas con `id >= Marker.0` son los reversibles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Marker(pub u64);

/// Delta reversible sobre la pila de estados.
#[derive(Debug, Clone)]
pub enum DeltaKind {
    /// Apilado de un estado (inverso: desapilar).
    Push(QuantumState),
    /// Desapilado que devolvió un estado (inverso: reapilar).
    Pop(QuantumState),
    /// Sustitución de la cumbre (inverso: restaurar `before`).
    Replace {
        /// Estado previo a la operación.
        before: QuantumState,
        /// Estado posterior a la operación.
        after: QuantumState,
    },
}

impl DeltaKind {
    /// Operador inverso `Δ⁻¹` asociado al delta.
    pub fn inverse_label(&self) -> &'static str {
        match self {
            DeltaKind::Push(_) => "Δ⁻¹ ⇒ pop",
            DeltaKind::Pop(_) => "Δ⁻¹ ⇒ push",
            DeltaKind::Replace { .. } => "Δ⁻¹ ⇒ restore",
        }
    }
}

/// Un paso temporal reversible.
#[derive(Debug, Clone)]
pub struct Delta {
    /// Identificador monótono.
    pub id: u64,
    /// Marca temporal en microsegundos desde el inicio del motor.
    ///
    /// **NO DETERMINISTA** (matiz de A7): reloj de pared, no estado lógico. El
    /// diario no es reproducible *bit a bit* por este campo; ningún otro valor
    /// (colapso, valencia, huella FNV‑1a, digest de malla) depende de él.
    pub at_micros: u128,
    /// Etiqueta descriptiva de la operación.
    pub label: String,
    /// Naturaleza del delta.
    pub kind: DeltaKind,
    /// `true` si ya fue revertido por un `Δ⁻¹`.
    pub reverted: bool,
}

impl Delta {
    /// Operador inverso del delta.
    pub fn inv_label(&self) -> &'static str {
        self.kind.inverse_label()
    }
}

/// Informe de una operación de rollback.
#[derive(Debug, Clone)]
pub struct RollbackReport {
    /// Número de deltas revertidos.
    pub reverted: usize,
    /// Duración del rollback en microsegundos.
    ///
    /// **NO DETERMINISTA** (matiz de A7): métrica de reloj de pared; no
    /// interviene en la atomicidad ni en la reversibilidad del `Δ⁻¹`.
    pub micros: u128,
    /// Paradoja que motivó el rollback, si la hubo.
    pub paradox: Option<String>,
}

/// Paradoja irresoluble detectada en un estado.
#[derive(Debug, Clone)]
pub struct Paradox {
    /// Descripción ontológica.
    pub description: String,
    /// Masa de verdad.
    pub truth: f64,
    /// Masa de falsedad.
    pub falsity: f64,
}

/// Detecta una contradicción absoluta `⊤∧⊥` (verdad y falsedad al máximo).
pub fn detect_paradox(state: &QuantumState) -> Option<Paradox> {
    let (truth, falsity) = state.belnap();
    if truth >= 1.0 && falsity >= 1.0 {
        Some(Paradox {
            description: "⊤∧⊥ absoluto: paradoja irresoluble".to_string(),
            truth,
            falsity,
        })
    } else {
        None
    }
}

/// Tope del ledger de resoluciones. Lo viejo se descarta; el reloj no entra.
pub const RESOLUTION_LIMIT: usize = 32;

/// Quién cerró la contradicción.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionOrigin {
    /// El juicio `שפט` (conjunción) sacó el estado de `⊤∧⊥`.
    Judge,
    /// El operador confirmó el patrón a mano.
    User,
}

/// Rastro determinista de una contradicción ya resuelta.
///
/// No lleva marca de reloj: dos ejecuciones con los mismos juicios producen
/// el mismo ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionTrace {
    /// Patrón corto (`B*F`) o raíz que cupo en el optimizador.
    pub pattern: String,
    /// Origen de la resolución.
    pub origin: ResolutionOrigin,
    /// `true` si la corrección fue un sello; `false` si fue una separación.
    pub seal: bool,
}

/// Motor de navegación temporal: pila de estados + diario de deltas.
#[derive(Debug, Clone)]
pub struct TemporalEngine {
    /// Origen del reloj de pared (`Instant::now()`) del que derivan las marcas
    /// **NO DETERMINISTAS** `Delta.at_micros` y `RollbackReport.micros`.
    epoch: Instant,
    stack: Vec<QuantumState>,
    deltas: Vec<Delta>,
    next_id: u64,
    /// Resoluciones de `⊤∧⊥`. Este diario no consulta `epoch`.
    resolutions: Vec<ResolutionTrace>,
}

impl Default for TemporalEngine {
    fn default() -> Self {
        TemporalEngine {
            epoch: Instant::now(),
            stack: Vec::new(),
            deltas: Vec::new(),
            next_id: 0,
            resolutions: Vec::new(),
        }
    }
}

impl TemporalEngine {
    /// Crea un motor temporal virgen.
    pub fn new() -> Self {
        Self::default()
    }

    /// Microsegundos transcurridos desde la creación del motor.
    pub fn now_micros(&self) -> u128 {
        self.epoch.elapsed().as_micros()
    }

    /// Pila de estados actual.
    pub fn stack(&self) -> &[QuantumState] {
        &self.stack
    }

    /// Diario completo de deltas (incluidos los revertidos).
    pub fn deltas(&self) -> &[Delta] {
        &self.deltas
    }

    /// Resoluciones de contradicción, de la más antigua a la más reciente.
    pub fn resolutions(&self) -> &[ResolutionTrace] {
        &self.resolutions
    }

    /// Cuántas resoluciones siguen en el ledger.
    pub fn resolution_len(&self) -> usize {
        self.resolutions.len()
    }

    /// Anota una resolución. Al pasar de [`RESOLUTION_LIMIT`] cae la más antigua.
    pub fn record_resolution(&mut self, trace: ResolutionTrace) {
        if self.resolutions.len() >= RESOLUTION_LIMIT {
            self.resolutions.remove(0);
        }
        self.resolutions.push(trace);
    }

    /// Marca lógica del instante actual.
    pub fn mark(&self) -> Marker {
        Marker(self.next_id)
    }

    /// Apila un estado (registra `Δ: Push`).
    pub fn push(&mut self, state: QuantumState) -> u64 {
        let label = format!("push {}", state.label());
        self.perform(DeltaKind::Push(state), label)
    }

    /// Desapila un estado (registra `Δ: Pop` si había algo).
    pub fn pop(&mut self) -> Option<QuantumState> {
        match self.stack.pop() {
            Some(value) => {
                let label = format!("pop {}", value.label());
                let id = self.record(DeltaKind::Pop(value.clone()), label);
                let _ = id;
                Some(value)
            }
            None => None,
        }
    }

    /// Sustituye la cumbre (registra `Δ: Replace`).
    pub fn replace(&mut self, after: QuantumState) -> Option<u64> {
        let before = self.stack.last().cloned()?;
        if let Some(top) = self.stack.last_mut() {
            *top = after.clone();
        }
        let label = format!("replace {} → {}", before.label(), after.label());
        Some(self.perform_no_apply(DeltaKind::Replace { before, after }, label))
    }

    /// Aplica y registra un delta.
    pub fn perform(&mut self, kind: DeltaKind, label: String) -> u64 {
        match &kind {
            DeltaKind::Push(state) => self.stack.push(state.clone()),
            DeltaKind::Pop(value) => {
                debug_assert_eq!(self.stack.last(), Some(value));
                self.stack.pop();
            }
            DeltaKind::Replace { after, .. } => {
                if let Some(top) = self.stack.last_mut() {
                    *top = after.clone();
                }
            }
        }
        self.record(kind, label)
    }

    /// Registra un delta sin aplicarlo (porque ya se aplicó in situ).
    fn perform_no_apply(&mut self, kind: DeltaKind, label: String) -> u64 {
        self.record(kind, label)
    }

    /// Añade un delta al diario y devuelve su identificador.
    fn record(&mut self, kind: DeltaKind, label: String) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.deltas.push(Delta {
            id,
            at_micros: self.now_micros(),
            label,
            kind,
            reverted: false,
        });
        id
    }

    /// Invierte un delta sobre la pila de estados.
    fn invert(&mut self, kind: &DeltaKind) {
        match kind {
            DeltaKind::Push(_) => {
                self.stack.pop();
            }
            DeltaKind::Pop(value) => self.stack.push(value.clone()),
            DeltaKind::Replace { before, .. } => {
                if let Some(top) = self.stack.last_mut() {
                    *top = before.clone();
                }
            }
        }
    }

    /// **Rollback atómico `Δ⁻¹`**: revierte todos los deltas vivos posteriores
    /// a `marker`, en orden inverso. Devuelve el informe con la duración.
    pub fn rollback_to(&mut self, marker: Marker) -> RollbackReport {
        let start = Instant::now();
        let targets: Vec<usize> = self
            .deltas
            .iter()
            .enumerate()
            .filter(|(_, d)| d.id >= marker.0 && !d.reverted)
            .map(|(i, _)| i)
            .collect();
        let reverted = targets.len();
        for &i in targets.iter().rev() {
            let kind = self.deltas[i].kind.clone();
            self.invert(&kind);
            self.deltas[i].reverted = true;
        }
        RollbackReport {
            reverted,
            micros: start.elapsed().as_micros(),
            paradox: None,
        }
    }

    /// Rollback motivado por una paradoja interceptada.
    pub fn rollback_paradox(&mut self, marker: Marker, paradox: &Paradox) -> RollbackReport {
        let mut report = self.rollback_to(marker);
        report.paradox = Some(paradox.description.clone());
        report
    }
}
