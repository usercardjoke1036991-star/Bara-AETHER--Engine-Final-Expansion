//! # Native Quantum Superposition Types — `quantum_native.rs`
//!
//! Tipos **nativos** de cuántica para el AST de Bara: qubits `Qubit<|ψ⟩>`,
//! vectores de amplitudes de probabilidad complejas y enlaces de
//! entrelazamiento (Φ±/Ψ±), todos evaluables dentro del runtime
//! paraconsistente.
//!
//! ## Principios de diseño
//! * **Determinismo absoluto** — no se usa `rand`. El colapso se resuelve con
//!   la **regla de Born** alimentada por un hash FNV‑1a del nombre del qubit:
//!   la misma ejecución produce siempre el mismo log.
//! * **Nunca falla** — un qubit inexistente, un entrelazamiento imposible o un
//!   vector degenerado se degradan a un valor tolerado, jamás a un pánico.
//! * **Puente paraconsistente** — [`Qubit::valence`] traduce el estado cuántico
//!   nativo a [`QuantumState`]: una superposición genuina es una
//!   `SUPERPOSITION`, mientras que un par **máximamente entrelazado** no
//!   admite factorización clásica (su traza parcial es máximamente mixta) y se
//!   representa como `PARACONSISTENT(⊤, ⊥)`: la contradicción se **tolera** en
//!   lugar de colapsar el programa.
//!
//! ## Convención de lectura
//! En la proyección lógica, el estado base `|0⟩` se interpreta como `⊤`
//! (verdad) y `|1⟩` como `⊥` (falsedad); el resto de la base, si la hay, se
//! agrega como masa indeterminada `∅`.

use crate::runtime::QuantumState;
use std::collections::BTreeMap;

/// Sal de la semilla de colapso (Knuth): evita que dos qubits gemelos
/// colapsen con la misma semilla.
const COLLAPSE_SALT: u64 = 0x9E37_79B9_7F4A_7C15;

/// Masa asignada a cada rama de un estado local máximamente mixto (`I/2`).
const MIXED_MASS: f64 = 0.5;

/// Tolerancia numérica del estado máximamente mixto: sitúa ambas masas un
/// ápice por encima del umbral de designación para que la contradicción
/// `⊤∧⊥` no se degrade a `∅` por redondeo de coma flotante.
const MIXED_TOLERANCE: f64 = 1e-9;

// ─────────────────────────────────────────────────────────────────────────
// Amplitud compleja
// ─────────────────────────────────────────────────────────────────────────

/// Amplitud de probabilidad compleja `α = a + b·i`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Amplitude {
    /// Parte real.
    pub re: f64,
    /// Parte imaginaria.
    pub im: f64,
}

impl Amplitude {
    /// Cero aditivo.
    pub const ZERO: Amplitude = Amplitude { re: 0.0, im: 0.0 };
    /// Uno multiplicativo.
    pub const ONE: Amplitude = Amplitude { re: 1.0, im: 0.0 };
    /// Unidad imaginaria `i`.
    pub const IMAGINARY: Amplitude = Amplitude { re: 0.0, im: 1.0 };

    /// Construye `a + b·i`.
    pub const fn new(re: f64, im: f64) -> Self {
        Amplitude { re, im }
    }

    /// Amplitud real pura.
    pub const fn real(re: f64) -> Self {
        Amplitude { re, im: 0.0 }
    }

    /// Amplitud desde forma polar `r·e^{iθ}`.
    pub fn from_polar(r: f64, theta: f64) -> Self {
        Amplitude {
            re: r * theta.cos(),
            im: r * theta.sin(),
        }
    }

    /// Suma de amplitudes (interferencia constructiva/destructiva).
    pub fn add(&self, other: &Amplitude) -> Amplitude {
        Amplitude::new(self.re + other.re, self.im + other.im)
    }

    /// Resta de amplitudes (interferencia destructiva).
    pub fn sub(&self, other: &Amplitude) -> Amplitude {
        Amplitude::new(self.re - other.re, self.im - other.im)
    }

    /// Producto de amplitudes.
    pub fn mul(&self, other: &Amplitude) -> Amplitude {
        Amplitude::new(
            self.re * other.re - self.im * other.im,
            self.re * other.im + self.im * other.re,
        )
    }

    /// Escalado real.
    pub fn scale(&self, k: f64) -> Amplitude {
        Amplitude::new(self.re * k, self.im * k)
    }

    /// Conjugado complejo `ᾱ`.
    pub fn conj(&self) -> Amplitude {
        Amplitude::new(self.re, -self.im)
    }

    /// Módulo al cuadrado `|α|²` (probabilidad de Born).
    pub fn norm_sqr(&self) -> f64 {
        self.re * self.re + self.im * self.im
    }

    /// Módulo `|α|`.
    pub fn modulus(&self) -> f64 {
        self.norm_sqr().sqrt()
    }

    /// Fase `arg(α)` en radianes.
    pub fn phase(&self) -> f64 {
        self.im.atan2(self.re)
    }

    /// ¿Es la amplitud nula?
    pub fn is_zero(&self) -> bool {
        self.norm_sqr() <= f64::EPSILON
    }

    /// Representación compacta `a+b·i`.
    pub fn label(&self) -> String {
        if self.im.abs() <= f64::EPSILON {
            format!("{:.3}", self.re)
        } else if self.re.abs() <= f64::EPSILON {
            format!("{:.3}i", self.im)
        } else {
            format!("{:.3}{:+.3}i", self.re, self.im)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Vector de amplitudes de probabilidad
// ─────────────────────────────────────────────────────────────────────────

/// Estado base etiquetado de la base computacional.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasisState {
    /// Índice dentro del vector de amplitudes.
    pub index: usize,
    /// Etiqueta legible (`|0⟩`, `|⊤⟩`, `|alef⟩`…).
    pub label: String,
}

impl BasisState {
    /// Construye un estado base etiquetado.
    pub fn new(index: usize, label: impl Into<String>) -> Self {
        BasisState {
            index,
            label: label.into(),
        }
    }

    /// Estado base con notación de Dirac `|0⟩`.
    pub fn dirac(index: usize) -> Self {
        BasisState::new(index, format!("|{}⟩", index))
    }
}

/// Vector de amplitudes de probabilidad `|ψ⟩ = Σ αᵢ |i⟩`.
#[derive(Debug, Clone, PartialEq)]
pub struct AmplitudeVector {
    /// Amplitudes complejas, en orden de base.
    pub amplitudes: Vec<Amplitude>,
}

impl AmplitudeVector {
    /// Construye el vector y lo **normaliza** (regla de Born).
    pub fn new(amplitudes: Vec<Amplitude>) -> Self {
        let raw = AmplitudeVector { amplitudes };
        raw.normalized()
    }

    /// Superposición uniforme `(1/√d)·Σ|i⟩`.
    pub fn uniform(dim: usize) -> Self {
        let dim = dim.max(1);
        let r = 1.0 / (dim as f64).sqrt();
        AmplitudeVector {
            amplitudes: vec![Amplitude::real(r); dim],
        }
    }

    /// Estado base puro `|i⟩` de dimensión `dim`.
    pub fn from_index(dim: usize, index: usize) -> Self {
        let dim = dim.max(1);
        let mut amplitudes = vec![Amplitude::ZERO; dim];
        amplitudes[index.min(dim - 1)] = Amplitude::ONE;
        AmplitudeVector { amplitudes }
    }

    /// Dimensión del espacio de Hilbert.
    pub fn dim(&self) -> usize {
        self.amplitudes.len()
    }

    /// Norma euclídea del vector.
    pub fn norm(&self) -> f64 {
        self.amplitudes.iter().map(|a| a.norm_sqr()).sum::<f64>().sqrt()
    }

    /// Devuelve una copia normalizada. Si el vector es degenerado se sustituye
    /// por la superposición uniforme (jamás se divide por cero).
    pub fn normalized(&self) -> Self {
        let norm = self.norm();
        if norm <= f64::EPSILON {
            return AmplitudeVector::uniform(self.dim());
        }
        AmplitudeVector {
            amplitudes: self.amplitudes.iter().map(|a| a.scale(1.0 / norm)).collect(),
        }
    }

    /// Distribución de probabilidad de Born `|αᵢ|²`.
    pub fn probabilities(&self) -> Vec<f64> {
        self.amplitudes.iter().map(|a| a.norm_sqr()).collect()
    }

    /// Amplitud en un índice (cero si está fuera de rango).
    pub fn amplitude_of(&self, index: usize) -> Amplitude {
        self.amplitudes.get(index).copied().unwrap_or(Amplitude::ZERO)
    }

    /// Entropía de Shannon de la distribución, en bits.
    pub fn entropy_bits(&self) -> f64 {
        let mut total = 0.0;
        for p in self.probabilities() {
            if p > f64::EPSILON {
                total -= p * p.log2();
            }
        }
        if total < 0.0 {
            0.0
        } else {
            total
        }
    }

    /// Probabilidad máxima de la distribución.
    pub fn top_probability(&self) -> f64 {
        self.probabilities().into_iter().fold(0.0_f64, f64::max)
    }

    /// Índice más probable.
    pub fn argmax(&self) -> usize {
        let mut best = 0;
        let mut best_p = -1.0;
        for (i, p) in self.probabilities().iter().enumerate() {
            if *p > best_p {
                best_p = *p;
                best = i;
            }
        }
        best
    }

    /// Índice que la regla de Born selecciona para una semilla determinista.
    ///
    /// La semilla sustituye al generador aleatorio: al ser un hash del nombre
    /// del qubit, el colapso es reproducible bit a bit.
    pub fn measurement_index(&self, seed: u64) -> usize {
        let probabilities = self.probabilities();
        if probabilities.is_empty() {
            return 0;
        }
        let uniform = ((seed % 1_000_000) as f64) / 1_000_000.0;
        let mut acc = 0.0;
        for (index, p) in probabilities.iter().enumerate() {
            acc += p;
            if uniform < acc {
                return index;
            }
        }
        probabilities.len() - 1
    }

    /// Interferencia coherente `|ψ⟩ + e^{iθ}|φ⟩`, normalizada.
    pub fn interfere(&self, other: &AmplitudeVector, theta: f64) -> AmplitudeVector {
        if self.dim() != other.dim() {
            return self.clone();
        }
        let phase = Amplitude::from_polar(1.0, theta);
        let combined = self
            .amplitudes
            .iter()
            .zip(other.amplitudes.iter())
            .map(|(a, b)| a.add(&b.mul(&phase)))
            .collect();
        AmplitudeVector::new(combined)
    }

    /// Producto tensorial `|ψ⟩ ⊗ |φ⟩` normalizado (origen del entrelazamiento).
    pub fn tensor(&self, other: &AmplitudeVector) -> AmplitudeVector {
        let mut out = Vec::with_capacity(self.dim() * other.dim());
        for a in &self.amplitudes {
            for b in &other.amplitudes {
                out.push(a.mul(b));
            }
        }
        AmplitudeVector::new(out)
    }

    /// Traza parcial sobre la mitad derecha de un sistema bipartito.
    ///
    /// Devuelve la distribución local `(|α|², |β|²)` del subsistema
    /// izquierdo; para un par máximamente entrelazado es `(0.5, 0.5)`, es
    /// decir, un estado local **máximamente mixto**.
    pub fn partial_trace_left(&self) -> (f64, f64) {
        let dim = self.dim();
        if dim < 4 {
            let p = self.probabilities();
            return (
                p.first().copied().unwrap_or(1.0),
                p.get(1).copied().unwrap_or(0.0),
            );
        }
        let half = dim / 2;
        let (mut left, mut right) = (0.0, 0.0);
        for index in 0..dim {
            let p = self.amplitudes[index].norm_sqr();
            if index < half {
                left += p;
            } else {
                right += p;
            }
        }
        (left, right)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Entrelazamiento
// ─────────────────────────────────────────────────────────────────────────

/// Convención de fase de un par de Bell (base maximamente entrelazada).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BellPhase {
    /// `|Φ⁺⟩ = (|00⟩ + |11⟩)/√2` — correlación perfecta positiva.
    PhiPlus,
    /// `|Φ⁻⟩ = (|00⟩ − |11⟩)/√2`.
    PhiMinus,
    /// `|Ψ⁺⟩ = (|01⟩ + |10⟩)/√2` — anticorrelación perfecta.
    PsiPlus,
    /// `|Ψ⁻⟩ = (|01⟩ − |10⟩)/√2` — el singlete.
    PsiMinus,
}

impl BellPhase {
    /// Las cuatro convenciones, en orden canónico.
    pub fn all() -> [BellPhase; 4] {
        [
            BellPhase::PhiPlus,
            BellPhase::PhiMinus,
            BellPhase::PsiPlus,
            BellPhase::PsiMinus,
        ]
    }

    /// Etiqueta de Dirac del par.
    pub fn label(&self) -> &'static str {
        match self {
            BellPhase::PhiPlus => "Φ⁺",
            BellPhase::PhiMinus => "Φ⁻",
            BellPhase::PsiPlus => "Ψ⁺",
            BellPhase::PsiMinus => "Ψ⁻",
        }
    }

    /// Significado ontológico de la correlación.
    pub fn meaning(&self) -> &'static str {
        match self {
            BellPhase::PhiPlus => "correlación total (misma dirección)",
            BellPhase::PhiMinus => "antifase sobre la correlación total",
            BellPhase::PsiPlus => "anticorrelación total (direcciones opuestas)",
            BellPhase::PsiMinus => "singlete: anticorrelación en todas las bases",
        }
    }

    /// Correlación `⟨Z⊗Z⟩`: `+1` para Φ, `−1` para Ψ.
    pub fn correlation(&self) -> f64 {
        match self {
            BellPhase::PhiPlus | BellPhase::PhiMinus => 1.0,
            BellPhase::PsiPlus | BellPhase::PsiMinus => -1.0,
        }
    }

    /// Vector conjunto de 4 amplitudes `α₀₀|00⟩ + α₀₁|01⟩ + α₁₀|10⟩ + α₁₁|11⟩`.
    pub fn joint(&self) -> AmplitudeVector {
        let h = 1.0 / 2.0_f64.sqrt();
        let amplitudes = match self {
            BellPhase::PhiPlus => vec![
                Amplitude::real(h),
                Amplitude::ZERO,
                Amplitude::ZERO,
                Amplitude::real(h),
            ],
            BellPhase::PhiMinus => vec![
                Amplitude::real(h),
                Amplitude::ZERO,
                Amplitude::ZERO,
                Amplitude::real(-h),
            ],
            BellPhase::PsiPlus => vec![
                Amplitude::ZERO,
                Amplitude::real(h),
                Amplitude::real(h),
                Amplitude::ZERO,
            ],
            BellPhase::PsiMinus => vec![
                Amplitude::ZERO,
                Amplitude::real(h),
                Amplitude::real(-h),
                Amplitude::ZERO,
            ],
        };
        AmplitudeVector { amplitudes }
    }

    /// Índice del socio correlacionado tras medir el qubit local.
    pub fn correlated_index(&self, local: usize) -> usize {
        if self.correlation() > 0.0 {
            local % 2
        } else {
            1 - (local % 2)
        }
    }
}

/// Enlace de entrelazamiento entre dos qubits nativos.
#[derive(Debug, Clone)]
pub struct EntanglementBinding {
    /// Nombre del primer qubit.
    pub left: String,
    /// Nombre del segundo qubit.
    pub right: String,
    /// Convención de fase del par.
    pub phase: BellPhase,
    /// Fuerza del enlace en `[0,1]` (`1.0` = par de Bell maximal).
    pub strength: f64,
    /// Época lógica en que se creó el enlace.
    pub epoch: u64,
}

impl EntanglementBinding {
    /// Etiqueta legible del enlace.
    pub fn label(&self) -> String {
        format!("{} ⧉ {} ({})", self.left, self.right, self.phase.label())
    }

    /// ¿Afecta este enlace a un qubit concreto?
    pub fn involves(&self, name: &str) -> bool {
        self.left == name || self.right == name
    }

    /// Devuelve el nombre del socio, si `name` participa en el enlace.
    pub fn partner(&self, name: &str) -> Option<&str> {
        if self.left == name {
            Some(self.right.as_str())
        } else if self.right == name {
            Some(self.left.as_str())
        } else {
            None
        }
    }

    /// Vector conjunto del par.
    pub fn joint(&self) -> AmplitudeVector {
        self.phase.joint()
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Qubit nativo
// ─────────────────────────────────────────────────────────────────────────

/// Qubit nativo del AST: `Qubit<|ψ⟩>`.
///
/// Agrupa el espacio de Hilbert declarado, el vector de amplitudes complejas
/// y los enlaces de entrelazamiento que lo atan a otros qubits del registro.
#[derive(Debug, Clone)]
pub struct Qubit {
    /// Nombre simbólico del qubit.
    pub name: String,
    /// Base declarada (`|0⟩`, `|1⟩`, …).
    pub basis: Vec<BasisState>,
    /// Vector de amplitudes del estado.
    pub amplitudes: AmplitudeVector,
    /// Nombres de los qubits a los que está entrelazado.
    pub entangled_with: Vec<String>,
    /// Índice medido, si ya colapsó.
    pub measured: Option<usize>,
    /// Número de mediciones aplicadas.
    pub measurements: u64,
}

impl Qubit {
    /// Crea un qubit a partir de un vector de amplitudes (se normaliza).
    pub fn new(name: impl Into<String>, amplitudes: AmplitudeVector) -> Self {
        let amplitudes = amplitudes.normalized();
        let basis = (0..amplitudes.dim()).map(BasisState::dirac).collect();
        Qubit {
            name: name.into(),
            basis,
            amplitudes,
            entangled_with: Vec::new(),
            measured: None,
            measurements: 0,
        }
    }

    /// Qubit puro `|0…0⟩` de dimensión `dim`.
    pub fn pure(name: impl Into<String>, dim: usize) -> Self {
        Qubit::new(name, AmplitudeVector::from_index(dim, 0))
    }

    /// Qubit equiprobable de dimensión `dim`.
    pub fn uniform(name: impl Into<String>, dim: usize) -> Self {
        Qubit::new(name, AmplitudeVector::uniform(dim))
    }

    /// Dimensión del espacio de Hilbert del qubit.
    pub fn dim(&self) -> usize {
        self.amplitudes.dim()
    }

    /// ¿Ya colapsó?
    pub fn is_measured(&self) -> bool {
        self.measured.is_some()
    }

    /// ¿Participa en algún enlace de entrelazamiento?
    pub fn is_entangled(&self) -> bool {
        !self.entangled_with.is_empty()
    }

    /// Distribución de probabilidad de Born del qubit.
    pub fn probabilities(&self) -> Vec<f64> {
        self.amplitudes.probabilities()
    }

    /// Entropía de Shannon del qubit, en bits.
    pub fn entropy_bits(&self) -> f64 {
        self.amplitudes.entropy_bits()
    }

    /// Probabilidad del estado más probable.
    pub fn top_probability(&self) -> f64 {
        self.amplitudes.top_probability()
    }

    /// Etiqueta del resultado medido, si lo hay.
    pub fn outcome_label(&self) -> Option<String> {
        self.measured.map(|i| {
            self.basis
                .get(i)
                .map(|b| b.label.clone())
                .unwrap_or_else(|| format!("|{}⟩", i))
        })
    }

    /// Puerta de fase `e^{iθ}` sobre el estado excitado `|1⟩`.
    pub fn phase_shift(&mut self, theta: f64) {
        if let Some(amplitude) = self.amplitudes.amplitudes.get_mut(1) {
            *amplitude = amplitude.mul(&Amplitude::from_polar(1.0, theta));
        }
    }

    /// Puerta de Hadamard sobre un qubit de dimensión 2.
    pub fn hadamard(&mut self) {
        if self.dim() != 2 {
            return;
        }
        let h = 1.0 / 2.0_f64.sqrt();
        let (a, b) = (
            self.amplitudes.amplitude_of(0),
            self.amplitudes.amplitude_of(1),
        );
        self.amplitudes = AmplitudeVector::new(vec![a.add(&b).scale(h), a.sub(&b).scale(h)]);
        self.measured = None;
    }

    /// **Puente paraconsistente**: traduce el estado nativo a [`QuantumState`].
    ///
    /// * Qubit ya medido ⇒ `Classical`.
    /// * Superposición genuina ⇒ `Superposition(|α⊤|², |α⊥|²)`.
    /// * Qubit **entrelazado** ⇒ su descripción local es la traza parcial del
    ///   par y resulta máximamente mixta (`I/2`), que ninguna puerta local
    ///   puede alterar (la conjugación unitaria deja `I/2` invariante). Es
    ///   decir, el qubit es simultáneamente `⊤` y `⊥`: se emite
    ///   `PARACONSISTENT` y el runtime **tolera** la contradicción en vez de
    ///   colapsar.
    pub fn valence(&self) -> QuantumState {
        if let Some(index) = self.measured {
            return QuantumState::classical(index == 0);
        }
        if self.is_entangled() {
            return QuantumState::paraconsistent(
                MIXED_MASS + MIXED_TOLERANCE,
                MIXED_MASS + MIXED_TOLERANCE,
            );
        }
        let probabilities = self.probabilities();
        let truth = probabilities.first().copied().unwrap_or(1.0);
        let falsity = probabilities.get(1).copied().unwrap_or(0.0);
        QuantumState::superposition(truth.sqrt(), falsity.sqrt())
    }

    /// Descripción compacta para el log ontológico.
    pub fn describe(&self) -> String {
        let probabilities: Vec<String> = self
            .probabilities()
            .iter()
            .map(|p| format!("{:.3}", p))
            .collect();
        format!(
            "Qubit<{}> dim={} p=[{}] S={:.3} bits{}",
            self.name,
            self.dim(),
            probabilities.join(", "),
            self.entropy_bits(),
            match &self.measured {
                Some(index) => format!(" ⇒ colapsado a |{}⟩", index),
                None => String::new(),
            }
        )
    }
}

/// Resultado de evaluar una operación cuántica nativa.
#[derive(Debug, Clone)]
pub struct QuantumEvaluation {
    /// Qubit evaluado.
    pub name: String,
    /// Valencia paraconsistente equivalente.
    pub valence: QuantumState,
    /// Índice colapsado, si hubo medición.
    pub measured: Option<usize>,
    /// Probabilidad del resultado (1.0 si sólo se construyó el estado).
    pub probability: f64,
    /// Entropía de la distribución, en bits.
    pub entropy_bits: f64,
    /// Socios que colapsaron de forma **no local** por entrelazamiento.
    pub nonlocal: Vec<String>,
}

impl QuantumEvaluation {
    /// Etiqueta legible de la evaluación.
    pub fn label(&self) -> String {
        format!(
            "«{}» p={:.3} S={:.3} bits{} ⇒ {}",
            self.name,
            self.probability,
            self.entropy_bits,
            match &self.measured {
                Some(index) => format!(" |{}⟩", index),
                None => String::new(),
            },
            self.valence.label()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Registro cuántico nativo
// ─────────────────────────────────────────────────────────────────────────

/// Registro de qubits nativos: el *banco cuántico* del runtime.
///
/// Mantiene los qubits vivos, los enlaces de entrelazamiento y el contador de
/// colapsos. Toda operación es **total y determinista**.
#[derive(Debug, Clone, Default)]
pub struct QuantumNative {
    qubits: BTreeMap<String, Qubit>,
    bindings: Vec<EntanglementBinding>,
    collapses: u64,
    seed: u64,
}

impl QuantumNative {
    /// Registro cuántico vacío.
    pub fn new() -> Self {
        Self::default()
    }

    /// Número de qubits vivos.
    pub fn len(&self) -> usize {
        self.qubits.len()
    }

    /// ¿No hay qubits registrados?
    pub fn is_empty(&self) -> bool {
        self.qubits.is_empty()
    }

    /// Número de colapsos ejecutados.
    pub fn collapses(&self) -> u64 {
        self.collapses
    }

    /// Enlaces de entrelazamiento vigentes.
    pub fn bindings(&self) -> &[EntanglementBinding] {
        &self.bindings
    }

    /// Nombres de los qubits, en orden determinista.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.qubits.keys().map(|k| k.as_str())
    }

    /// Recupera un qubit por nombre.
    pub fn get(&self, name: &str) -> Option<&Qubit> {
        self.qubits.get(name)
    }

    /// Socios entrelazados de un qubit.
    pub fn partners_of(&self, name: &str) -> Vec<String> {
        self.bindings
            .iter()
            .filter(|b| b.involves(name))
            .filter_map(|b| b.partner(name).map(|p| p.to_string()))
            .collect()
    }

    /// Materializa un qubit desde un vector de amplitudes.
    pub fn materialize(&mut self, name: &str, amplitudes: AmplitudeVector) -> QuantumEvaluation {
        self.qubits
            .insert(name.to_string(), Qubit::new(name, amplitudes));
        self.evaluate(name)
            .unwrap_or_else(|| QuantumEvaluation {
                name: name.to_string(),
                valence: QuantumState::classical(false),
                measured: None,
                probability: 0.0,
                entropy_bits: 0.0,
                nonlocal: Vec::new(),
            })
    }

    /// Materializa un qubit en superposición `α|⊤⟩ + β|⊥⟩`.
    pub fn superpose(&mut self, name: &str, alpha: Amplitude, beta: Amplitude) -> QuantumEvaluation {
        self.materialize(name, AmplitudeVector::new(vec![alpha, beta]))
    }

    /// Materializa un qubit equiprobable de dimensión `dim`.
    pub fn uniform(&mut self, name: &str, dim: usize) -> QuantumEvaluation {
        self.materialize(name, AmplitudeVector::uniform(dim))
    }

    /// Evalúa un qubit sin tocarlo.
    pub fn evaluate(&self, name: &str) -> Option<QuantumEvaluation> {
        let qubit = self.qubits.get(name)?;
        Some(QuantumEvaluation {
            name: name.to_string(),
            valence: qubit.valence(),
            measured: qubit.measured,
            probability: qubit.top_probability(),
            entropy_bits: qubit.entropy_bits(),
            nonlocal: self.partners_of(name),
        })
    }

    /// Aplica una puerta de Hadamard a un qubit de dimensión 2.
    pub fn hadamard(&mut self, name: &str) -> Option<QuantumEvaluation> {
        self.qubits.get_mut(name)?.hadamard();
        self.evaluate(name)
    }

    /// Aplica una puerta de fase `e^{iθ}` al estado excitado `|1⟩`.
    pub fn phase_shift(&mut self, name: &str, theta: f64) -> Option<QuantumEvaluation> {
        self.qubits.get_mut(name)?.phase_shift(theta);
        self.evaluate(name)
    }

    /// Entrelaza dos qubits con una convención de fase de Bell.
    ///
    /// Devuelve `None` si alguno de los qubits no existe o si son el mismo.
    /// Si el enlace ya existía, la operación es **idempotente** (entropía cero)
    /// y se limita a reevaluar el par.
    pub fn entangle(
        &mut self,
        left: &str,
        right: &str,
        phase: BellPhase,
    ) -> Option<QuantumEvaluation> {
        if left == right || !self.qubits.contains_key(left) || !self.qubits.contains_key(right) {
            return None;
        }

        let already = self
            .bindings
            .iter()
            .any(|b| b.involves(left) && b.involves(right) && b.phase == phase);
        if !already {
            self.seed += 1;
            self.bindings.push(EntanglementBinding {
                left: left.to_string(),
                right: right.to_string(),
                phase,
                strength: 1.0,
                epoch: self.seed,
            });
            // La descripción local de cada mitad de un par de Bell es la traza
            // parcial del conjunto: máximamente mixta (equiprobable y sin
            // coherencia). Se materializa como superposición uniforme de dim 2.
            let half = AmplitudeVector::uniform(2);
            for name in [left, right] {
                if let Some(qubit) = self.qubits.get_mut(name) {
                    qubit.amplitudes = half.clone();
                    qubit.measured = None;
                    qubit.entangled_with.clear();
                }
            }
            for (name, partner) in [(left, right), (right, left)] {
                if let Some(qubit) = self.qubits.get_mut(name) {
                    if !qubit.entangled_with.iter().any(|n| n == partner) {
                        qubit.entangled_with.push(partner.to_string());
                    }
                }
            }
        }

        let joint = phase.joint();
        let (local_truth, local_falsity) = joint.partial_trace_left();
        let mixed = local_truth.max(local_falsity);
        let valence = self
            .qubits
            .get(left)
            .map(|q| q.valence())
            .unwrap_or_else(|| QuantumState::paraconsistent(mixed, mixed));
        Some(QuantumEvaluation {
            name: left.to_string(),
            valence,
            measured: None,
            probability: joint.top_probability(),
            entropy_bits: joint.entropy_bits(),
            nonlocal: self.partners_of(left),
        })
    }

    /// Colapsa un qubit aplicando la regla de Born y propaga el resultado de
    /// forma **no local** a sus socios entrelazados.
    ///
    /// Si el qubit ya estaba medido, la función es idempotente. Si no existe,
    /// devuelve `None` (el runtime lo tolera).
    pub fn collapse(&mut self, name: &str) -> Option<QuantumEvaluation> {
        let (entropy, dim, index, probability) = {
            let qubit = self.qubits.get(name)?;
            if let Some(index) = qubit.measured {
                return Some(QuantumEvaluation {
                    name: name.to_string(),
                    valence: qubit.valence(),
                    measured: Some(index),
                    probability: 1.0,
                    entropy_bits: qubit.entropy_bits(),
                    nonlocal: self.partners_of(name),
                });
            }
            let seed = fnv1a(name.as_bytes()) ^ self.collapses.wrapping_mul(COLLAPSE_SALT);
            let index = qubit.amplitudes.measurement_index(seed);
            let probability = qubit.probabilities().get(index).copied().unwrap_or(1.0);
            (qubit.entropy_bits(), qubit.dim(), index, probability)
        };

        self.collapses += 1;
        if let Some(qubit) = self.qubits.get_mut(name) {
            qubit.amplitudes = AmplitudeVector::from_index(dim, index);
            qubit.measured = Some(index);
            qubit.measurements += 1;
        }

        // Colapso no local: la correlación del par queda determinada.
        let mut nonlocal = Vec::new();
        let partners: Vec<(String, BellPhase)> = self
            .bindings
            .iter()
            .filter(|b| b.involves(name))
            .filter_map(|b| b.partner(name).map(|p| (p.to_string(), b.phase)))
            .collect();
        for (partner, phase) in partners {
            let partner_index = phase.correlated_index(index);
            if let Some(qubit) = self.qubits.get_mut(&partner) {
                let partner_dim = qubit.dim().max(1);
                qubit.amplitudes =
                    AmplitudeVector::from_index(partner_dim, partner_index % partner_dim);
                qubit.measured = Some(partner_index % partner_dim);
                qubit.measurements += 1;
                nonlocal.push(format!("{} ⇒ |{}⟩", partner, partner_index));
            }
        }

        let valence = self
            .qubits
            .get(name)
            .map(|q| q.valence())
            .unwrap_or(QuantumState::classical(true));
        Some(QuantumEvaluation {
            name: name.to_string(),
            valence,
            measured: Some(index),
            probability,
            entropy_bits: entropy,
            nonlocal,
        })
    }

    /// Valencia global del registro: conjunción paraconsistente de todos los
    /// qubits vivos (el "estado del sistema" tal como lo ve el runtime).
    pub fn global_valence(&self) -> QuantumState {
        let mut accumulator: Option<QuantumState> = None;
        for qubit in self.qubits.values() {
            let valence = qubit.valence();
            accumulator = Some(match accumulator {
                Some(previous) => previous.conjunction(&valence),
                None => valence,
            });
        }
        accumulator.unwrap_or_else(|| QuantumState::classical(true))
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
