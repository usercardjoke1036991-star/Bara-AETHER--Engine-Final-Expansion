//! # Autopoiesis activa — Bara / AETHER‑Ω (FASE 4)
//!
//! Convierte la autopoiesis *pasiva* del mutador de *sandbox*
//! ([`crate::autopoietic::AutopoieticMutator`]) en un **ciclo gobernado por
//! propósito**: abrir célula → aplicar mutaciones → proponer → **re-auditar** →
//! verificar el contrato de propósito → fusionar.
//!
//! El mutador ya audita por dentro, pero este módulo no se fía de esa
//! auditoría: vuelve a ejecutar [`audit_ast`] sobre el candidato de la
//! propuesta, de modo que una mutación sólo llega al núcleo si **dos**
//! evaluaciones independientes del árbol coinciden. Después aplica el contrato
//! de propósito —cota de nodos, techo de riesgo, aridad, sello y tipos— que es
//! lo que distingue «un parche válido» de «un parche válido *para esto*».
//!
//! ## Invariantes
//! 1. **Cero `unsafe`** (`#![forbid(unsafe_code)]`).
//! 2. **Totalidad** — ni una entrada provoca un pánico: las mutaciones se
//!    atrapan en la célula y los rechazos vuelven como valores tipados.
//! 3. **Nada se fusiona sin auditoría** — si la re-auditoría falla o el
//!    contrato se incumple, la célula se libera y el núcleo recibido sigue
//!    intacto.
//! 4. **Determinismo** — los contratos son datos constantes, el informe sólo
//!    depende del estado y su huella es SHA‑256; no hay reloj ni azar.
//! 5. **Acotado** — como máximo [`MAX_PURPOSES`] contratos vivos.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

use std::fmt;

use crate::ast_dna::short_hex;
use crate::autopoietic::{
    audit_ast, AutopoieticMutator, BelnapValue, Evidence, KernelCore, Mutation, MutatorError,
};
use crate::crypto_native::Sha256;
use crate::ffi_ingest::{BaraType, ShoreshAst};

/// Contratos de propósito que admite un motor.
pub const MAX_PURPOSES: usize = 8;

/// Dominio de hash de los informes de ciclo.
pub const AUTOPOIESIS_DOMAIN: &[u8] = b"bara:aether-omega:autopoiesis-activa:v1";

/// Techo por defecto de nodos de un contrato.
pub const DEFAULT_MAX_NODES: usize = 512;

/// Aridad máxima por defecto de un contrato.
pub const DEFAULT_MAX_ARITY: usize = 8;

/// Riesgo máximo por defecto, en milésimas.
pub const FULL_HAZARD: u16 = 1_000;

// ─────────────────────────────────────────────────────────────────────────
// Cuantización del riesgo
// ─────────────────────────────────────────────────────────────────────────

/// Riesgo continuo `[0, 1]` → milésimas enteras.
///
/// Es total: un valor no finito se trata como riesgo máximo (`1_000`) y
/// cualquier valor fuera de rango se acota. La cuantización usa `round`, así
/// que `0.125` → `125` y la comparación con el techo del contrato es exacta y
/// reproducible.
pub fn hazard_permille(hazard: f64) -> u16 {
    if !hazard.is_finite() {
        return FULL_HAZARD;
    }
    let clamped = hazard.clamp(0.0, 1.0);
    let scaled = (clamped * 1_000.0).round();
    if scaled <= 0.0 {
        0
    } else if scaled >= f64::from(FULL_HAZARD) {
        FULL_HAZARD
    } else {
        scaled as u16
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Contrato de propósito
// ─────────────────────────────────────────────────────────────────────────

/// Motivo por el que un contrato de propósito rechaza un parche.
///
/// Guarda índices, no cadenas: el informe es `Copy`, determinista y no reserva
/// memoria al construirse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurposeViolation {
    /// El parche no aporta nodos.
    Empty,
    /// El parche supera el techo de nodos del contrato.
    TooManyNodes {
        /// Nodos del parche.
        nodes: usize,
        /// Techo admitido.
        limit: usize,
    },
    /// Un nodo supera el techo de riesgo.
    HazardCeiling {
        /// Índice del nodo infractor.
        index: usize,
        /// Riesgo cuantizado del nodo.
        permille: u16,
        /// Techo admitido.
        limit: u16,
    },
    /// Un nodo excede la aridad admitida.
    Arity {
        /// Índice del nodo infractor.
        index: usize,
        /// Aridad del nodo.
        arity: usize,
        /// Techo admitido.
        limit: usize,
    },
    /// El contrato exige sello y el nodo no lo lleva.
    Unsanitized {
        /// Índice del nodo infractor.
        index: usize,
    },
    /// El contrato exige tipo declarado y el nodo no lo trae.
    Untyped {
        /// Índice del nodo infractor.
        index: usize,
    },
}

impl PurposeViolation {
    /// Identificador estable de la regla incumplida.
    pub const fn code(self) -> &'static str {
        match self {
            PurposeViolation::Empty => "proposito.vacio",
            PurposeViolation::TooManyNodes { .. } => "proposito.nodos",
            PurposeViolation::HazardCeiling { .. } => "proposito.riesgo",
            PurposeViolation::Arity { .. } => "proposito.aridad",
            PurposeViolation::Unsanitized { .. } => "proposito.sello",
            PurposeViolation::Untyped { .. } => "proposito.tipo",
        }
    }
}

impl fmt::Display for PurposeViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            PurposeViolation::Empty => f.write_str("el parche no aporta nodos"),
            PurposeViolation::TooManyNodes { nodes, limit } => write!(
                f,
                "el parche trae {nodes} nodos y el propósito admite {limit}"
            ),
            PurposeViolation::HazardCeiling {
                index,
                permille,
                limit,
            } => write!(
                f,
                "el nodo {index} tiene riesgo {permille}‰ y el propósito admite {limit}‰"
            ),
            PurposeViolation::Arity {
                index,
                arity,
                limit,
            } => write!(
                f,
                "el nodo {index} tiene aridad {arity} y el propósito admite {limit}"
            ),
            PurposeViolation::Unsanitized { index } => {
                write!(f, "el nodo {index} no está sellado y el propósito lo exige")
            }
            PurposeViolation::Untyped { index } => {
                write!(f, "el nodo {index} no declara tipo y el propósito lo exige")
            }
        }
    }
}

impl std::error::Error for PurposeViolation {}

/// Contrato que debe cumplir todo parche para un propósito concreto.
///
/// Es un valor `Copy` de campos públicos: un propósito se declara una vez y se
/// puede comparar, copiar y auditar sin reservar memoria.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurposeContract {
    /// Nombre estable del propósito.
    pub name: &'static str,
    /// Nodos máximos del parche.
    pub max_nodes: usize,
    /// Riesgo máximo por nodo, en milésimas.
    pub max_hazard_permille: u16,
    /// Aridad máxima por nodo.
    pub max_arity: usize,
    /// ¿Exige que todos los nodos estén sellados?
    pub require_sanitized: bool,
    /// ¿Exige que todos los nodos declaren tipo?
    pub require_typed: bool,
}

impl PurposeContract {
    /// Contrato con los topes por defecto.
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            max_nodes: DEFAULT_MAX_NODES,
            max_hazard_permille: FULL_HAZARD,
            max_arity: DEFAULT_MAX_ARITY,
            require_sanitized: false,
            require_typed: true,
        }
    }

    /// Fija el techo de nodos.
    pub const fn nodes(mut self, max_nodes: usize) -> Self {
        self.max_nodes = max_nodes;
        self
    }

    /// Fija el techo de riesgo en milésimas.
    pub const fn hazard(mut self, max_hazard_permille: u16) -> Self {
        self.max_hazard_permille = if max_hazard_permille > FULL_HAZARD {
            FULL_HAZARD
        } else {
            max_hazard_permille
        };
        self
    }

    /// Fija la aridad máxima.
    pub const fn arity(mut self, max_arity: usize) -> Self {
        self.max_arity = max_arity;
        self
    }

    /// Exige (o no) el sello de todos los nodos.
    pub const fn sealed(mut self, require_sanitized: bool) -> Self {
        self.require_sanitized = require_sanitized;
        self
    }

    /// Exige (o no) el tipo declarado de todos los nodos.
    pub const fn typed(mut self, require_typed: bool) -> Self {
        self.require_typed = require_typed;
        self
    }

    /// Evalúa el parche contra el contrato.
    ///
    /// Devuelve la **primera** violación en orden canónico (nodos, luego
    /// riesgo, aridad, sello y tipo), de modo que dos ejecuciones coinciden y el
    /// IDE puede señalar un nodo concreto.
    pub fn evaluate(&self, ast: &ShoreshAst) -> Result<(), PurposeViolation> {
        if ast.nodes.is_empty() {
            return Err(PurposeViolation::Empty);
        }
        if ast.nodes.len() > self.max_nodes {
            return Err(PurposeViolation::TooManyNodes {
                nodes: ast.nodes.len(),
                limit: self.max_nodes,
            });
        }
        for (index, node) in ast.nodes.iter().enumerate() {
            let permille = hazard_permille(node.hazard);
            if permille > self.max_hazard_permille {
                return Err(PurposeViolation::HazardCeiling {
                    index,
                    permille,
                    limit: self.max_hazard_permille,
                });
            }
            if node.arity > self.max_arity {
                return Err(PurposeViolation::Arity {
                    index,
                    arity: node.arity,
                    limit: self.max_arity,
                });
            }
            if self.require_sanitized && !node.sanitized {
                return Err(PurposeViolation::Unsanitized { index });
            }
            if self.require_typed && node.ret == BaraType::Unknown {
                return Err(PurposeViolation::Untyped { index });
            }
        }
        Ok(())
    }

    /// Acta de una línea.
    pub fn label(&self) -> String {
        format!(
            "propósito «{}» · ≤{} nodos · ≤{}‰ riesgo · aridad ≤{} · sello {} · tipo {}",
            self.name,
            self.max_nodes,
            self.max_hazard_permille,
            self.max_arity,
            if self.require_sanitized { "sí" } else { "no" },
            if self.require_typed { "sí" } else { "no" }
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Registro de propósitos
// ─────────────────────────────────────────────────────────────────────────

/// Fallo al registrar un contrato.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractError {
    /// El registro está lleno.
    Full {
        /// Techo de contratos.
        limit: usize,
    },
    /// Ya existe un contrato con ese nombre.
    Duplicate {
        /// Nombre repetido.
        name: &'static str,
    },
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContractError::Full { limit } => {
                write!(f, "el registro admite {limit} propósitos y ya está lleno")
            }
            ContractError::Duplicate { name } => {
                write!(f, "el propósito «{name}» ya está registrado")
            }
        }
    }
}

impl std::error::Error for ContractError {}

/// Registro acotado de contratos de propósito.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContractBook {
    slots: [Option<PurposeContract>; MAX_PURPOSES],
    len: usize,
}

impl ContractBook {
    /// Registro vacío.
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_PURPOSES],
            len: 0,
        }
    }

    /// Registro con un contrato.
    pub fn with(contract: PurposeContract) -> Self {
        let mut book = Self::new();
        let _ = book.register(contract);
        book
    }

    /// Alta de un contrato.
    pub fn register(&mut self, contract: PurposeContract) -> Result<(), ContractError> {
        if self.get(contract.name).is_some() {
            return Err(ContractError::Duplicate {
                name: contract.name,
            });
        }
        match self.slots.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => {
                *slot = Some(contract);
                self.len = self.len.saturating_add(1);
                Ok(())
            }
            None => Err(ContractError::Full {
                limit: MAX_PURPOSES,
            }),
        }
    }

    /// Contrato por nombre.
    pub fn get(&self, name: &str) -> Option<&PurposeContract> {
        self.slots
            .iter()
            .flatten()
            .find(|contract| contract.name == name)
    }

    /// Contratos registrados.
    pub fn iter(&self) -> impl Iterator<Item = &PurposeContract> {
        self.slots.iter().flatten()
    }

    /// Contratos vivos.
    pub fn len(&self) -> usize {
        self.len
    }

    /// ¿No hay contratos?
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// ¿Registro lleno?
    pub fn is_full(&self) -> bool {
        self.len >= MAX_PURPOSES
    }
}

impl Default for ContractBook {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Resultado de un ciclo
// ─────────────────────────────────────────────────────────────────────────

/// Desenlace de un ciclo autopoiético.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleVerdict {
    /// El parche se fusionó y el núcleo avanzó de revisión.
    Committed {
        /// Revisión resultante.
        revision: u64,
    },
    /// La re-auditoría estática encontró violaciones.
    AuditRejected {
        /// Reglas incumplidas.
        failed: usize,
    },
    /// El parche es válido pero no sirve a este propósito.
    ContractRejected(PurposeViolation),
    /// No se propuso ninguna mutación.
    EmptyPlan,
    /// Alguna mutación quedó atrapada en la célula.
    Trapped {
        /// Mutaciones atrapadas.
        faults: usize,
    },
}

impl CycleVerdict {
    /// ¿Avanzó el núcleo?
    pub const fn is_committed(self) -> bool {
        matches!(self, CycleVerdict::Committed { .. })
    }

    /// Identificador estable para el IDE y las huellas.
    pub const fn code(self) -> &'static str {
        match self {
            CycleVerdict::Committed { .. } => "fusionado",
            CycleVerdict::AuditRejected { .. } => "auditoria.rechazada",
            CycleVerdict::ContractRejected(_) => "proposito.rechazado",
            CycleVerdict::EmptyPlan => "plan.vacio",
            CycleVerdict::Trapped { .. } => "celula.atrapada",
        }
    }

    /// Descripción legible.
    pub fn label(self) -> String {
        match self {
            CycleVerdict::Committed { revision } => {
                format!("fusionado en la revisión {revision}")
            }
            CycleVerdict::AuditRejected { failed } => {
                format!("auditoría rechazada: {failed} reglas incumplidas")
            }
            CycleVerdict::ContractRejected(violation) => {
                format!("propósito rechazado: {violation}")
            }
            CycleVerdict::EmptyPlan => "plan vacío: no hay mutaciones".to_string(),
            CycleVerdict::Trapped { faults } => {
                format!("célula atrapada: {faults} mutaciones fallidas")
            }
        }
    }
}

/// Informe determinista de un ciclo.
///
/// No guarda el AST: guarda contadores, la valencia del juicio y la violación
/// concreta, que es lo que el IDE necesita para pintar el ciclo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CycleReport {
    /// Propósito aplicado.
    pub purpose: &'static str,
    /// Célula usada.
    pub cell: u64,
    /// Propuesta evaluada, si llegó a existir.
    pub proposal: Option<u64>,
    /// Revisión del núcleo de partida.
    pub base_revision: u64,
    /// Operaciones aplicadas en la célula.
    pub operations: usize,
    /// Nodos del candidato.
    pub nodes: usize,
    /// Reglas de auditoría superadas.
    pub audit_passed: usize,
    /// Reglas de auditoría totales.
    pub audit_total: usize,
    /// Unión de la matriz tetravalente.
    pub verdict: Option<BelnapValue>,
    /// Violación de propósito, si la hubo.
    pub violation: Option<PurposeViolation>,
    /// Desenlace.
    pub result: CycleVerdict,
}

impl CycleReport {
    /// Informe vacío con su desenlace.
    pub const fn new(purpose: &'static str, cell: u64, result: CycleVerdict) -> Self {
        Self {
            purpose,
            cell,
            proposal: None,
            base_revision: 0,
            operations: 0,
            nodes: 0,
            audit_passed: 0,
            audit_total: 0,
            verdict: None,
            violation: None,
            result,
        }
    }

    /// ¿Se fusionó?
    pub const fn is_committed(&self) -> bool {
        self.result.is_committed()
    }

    /// ¿La auditoría fue completa?
    pub fn audit_conforms(&self) -> bool {
        self.audit_total > 0 && self.audit_passed == self.audit_total
    }

    /// Huella SHA‑256 del informe.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(AUTOPOIESIS_DOMAIN);
        hasher.update(self.purpose.as_bytes());
        hasher.update(&self.cell.to_be_bytes());
        hasher.update(&self.proposal.unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(&self.base_revision.to_be_bytes());
        hasher.update(&(self.operations as u64).to_be_bytes());
        hasher.update(&(self.nodes as u64).to_be_bytes());
        hasher.update(&(self.audit_passed as u64).to_be_bytes());
        hasher.update(&(self.audit_total as u64).to_be_bytes());
        let value = self.verdict.map_or(0xFFu8, |value| value.index() as u8);
        hasher.update(&[value]);
        let violation = self.violation.map_or("ninguna", |rule| rule.code());
        hasher.update(violation.as_bytes());
        hasher.update(self.result.code().as_bytes());
        match self.result {
            CycleVerdict::Committed { revision } => hasher.update(&revision.to_be_bytes()),
            CycleVerdict::Trapped { faults } => hasher.update(&(faults as u64).to_be_bytes()),
            CycleVerdict::AuditRejected { failed } => hasher.update(&(failed as u64).to_be_bytes()),
            CycleVerdict::ContractRejected(_) | CycleVerdict::EmptyPlan => {}
        }
        hasher.finish()
    }

    /// Huella hexadecimal para el IDE.
    pub fn fingerprint(&self) -> String {
        short_hex(&self.digest())
    }

    /// Acta de una línea.
    pub fn label(&self) -> String {
        match self.proposal {
            Some(id) => format!(
                "ciclo «{}» · célula {} · propuesta #{} · {} nodos · {} · {}",
                self.purpose,
                self.cell,
                id,
                self.nodes,
                self.result.label(),
                self.fingerprint()
            ),
            None => format!(
                "ciclo «{}» · célula {} · {} · {}",
                self.purpose,
                self.cell,
                self.result.label(),
                self.fingerprint()
            ),
        }
    }
}

/// Salida de un ciclo gobernado.
///
/// El núcleo viaja **por valor**, sin `Box`: el motor es de capacidad fija y no
/// asigna memoria. La diferencia de tamaño entre variantes es el precio de no
/// poner el núcleo en el montón, así que el lint se silencia aquí, no en todo
/// el módulo.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum CycleOutcome {
    /// El núcleo avanzó.
    Committed {
        /// Núcleo nuevo, ya verificado.
        kernel: KernelCore,
        /// Informe del ciclo.
        report: CycleReport,
    },
    /// Nada se fusionó; el núcleo de entrada sigue vigente.
    Refused {
        /// Informe del ciclo.
        report: CycleReport,
    },
}

impl CycleOutcome {
    /// Informe del ciclo.
    pub const fn report(&self) -> &CycleReport {
        match self {
            CycleOutcome::Committed { report, .. } => report,
            CycleOutcome::Refused { report } => report,
        }
    }

    /// ¿Avanzó el núcleo?
    pub const fn is_committed(&self) -> bool {
        matches!(self, CycleOutcome::Committed { .. })
    }

    /// Descompone el resultado en núcleo (si lo hay) e informe.
    pub fn into_parts(self) -> (Option<KernelCore>, CycleReport) {
        match self {
            CycleOutcome::Committed { kernel, report } => (Some(kernel), report),
            CycleOutcome::Refused { report } => (None, report),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Errores
// ─────────────────────────────────────────────────────────────────────────

/// Fallo del ciclo.
#[derive(Debug)]
pub enum AutopoiesisError {
    /// El mutador rechazó una operación de contenedor.
    Mutator(MutatorError),
    /// Fallo al registrar un propósito.
    Contract(ContractError),
    /// No hay contrato registrado con ese nombre.
    UnknownPurpose {
        /// Nombre pedido.
        purpose: String,
    },
    /// La propuesta desapareció del mutador (estado imposible).
    MissingProposal {
        /// Identificador pedido.
        id: u64,
    },
}

impl fmt::Display for AutopoiesisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AutopoiesisError::Mutator(error) => write!(f, "mutador: {error}"),
            AutopoiesisError::Contract(error) => write!(f, "propósito: {error}"),
            AutopoiesisError::UnknownPurpose { purpose } => {
                write!(f, "propósito desconocido: «{purpose}»")
            }
            AutopoiesisError::MissingProposal { id } => {
                write!(f, "la propuesta #{id} no existe")
            }
        }
    }
}

impl std::error::Error for AutopoiesisError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AutopoiesisError::Mutator(error) => Some(error),
            AutopoiesisError::Contract(error) => Some(error),
            AutopoiesisError::UnknownPurpose { .. } | AutopoiesisError::MissingProposal { .. } => {
                None
            }
        }
    }
}

impl From<MutatorError> for AutopoiesisError {
    fn from(error: MutatorError) -> Self {
        AutopoiesisError::Mutator(error)
    }
}

impl From<ContractError> for AutopoiesisError {
    fn from(error: ContractError) -> Self {
        AutopoiesisError::Contract(error)
    }
}

/// Contadores acumulados del motor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EngineStats {
    /// Ciclos intentados.
    pub cycles: u64,
    /// Ciclos fusionados.
    pub commits: u64,
    /// Ciclos rechazados (auditoría, propósito, plan vacío o trampa).
    pub refusals: u64,
    /// Ciclos con al menos una mutación atrapada.
    pub traps: u64,
}

impl EngineStats {
    /// Tasa de fusión en puntos básicos (0–10 000).
    pub fn commit_rate(self) -> u16 {
        if self.cycles == 0 {
            return 0;
        }
        let scaled = (u128::from(self.commits) * 10_000) / u128::from(self.cycles);
        u16::try_from(scaled).unwrap_or(10_000)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Motor
// ─────────────────────────────────────────────────────────────────────────

/// Motor autopoiético gobernado por contratos de propósito.
///
/// Envuelve un [`AutopoieticMutator`] y no deja que una propuesta llegue al
/// núcleo sin pasar por dos auditorías y un contrato. La célula se libera en
/// **todos** los caminos de rechazo, así que un ciclo fallido no consume
/// contenedores ni deja propuestas vivas.
#[derive(Debug)]
pub struct AutopoieticEngine {
    mutator: AutopoieticMutator,
    contracts: ContractBook,
    stats: EngineStats,
}

impl AutopoieticEngine {
    /// Motor con un propósito inicial.
    pub fn new(seed: &[u8], contract: PurposeContract) -> Self {
        Self {
            mutator: AutopoieticMutator::new(seed),
            contracts: ContractBook::with(contract),
            stats: EngineStats::default(),
        }
    }

    /// Alta de un propósito adicional.
    pub fn register(&mut self, contract: PurposeContract) -> Result<(), AutopoiesisError> {
        self.contracts.register(contract)?;
        Ok(())
    }

    /// Mutador subyacente (sólo lectura).
    pub const fn mutator(&self) -> &AutopoieticMutator {
        &self.mutator
    }

    /// Registro de propósitos.
    pub const fn contracts(&self) -> &ContractBook {
        &self.contracts
    }

    /// Contrato registrado con ese nombre.
    pub fn purpose(&self, name: &str) -> Option<&PurposeContract> {
        self.contracts.get(name)
    }

    /// Contadores acumulados.
    pub const fn stats(&self) -> EngineStats {
        self.stats
    }
}

/// Datos copiados de la propuesta antes de soltar el préstamo del mutador.
struct ProposalSnapshot {
    base_revision: u64,
    operations: usize,
    nodes: usize,
    audit_passed: usize,
    audit_total: usize,
    audit_ok: bool,
    union: BelnapValue,
    violation: Option<PurposeViolation>,
}

impl AutopoieticEngine {
    /// Ejecuta un ciclo completo.
    ///
    /// Los rechazos *esperables* (auditoría, propósito, plan vacío, trampa) no
    /// son errores: vuelven como [`CycleOutcome::Refused`] con su informe. Un
    /// [`AutopoiesisError`] señala un fallo de contenedor o de registro, que el
    /// llamante no puede resolver dentro del ciclo.
    pub fn cycle(
        &mut self,
        kernel: &KernelCore,
        purpose: &str,
        mutations: &[Mutation],
    ) -> Result<CycleOutcome, AutopoiesisError> {
        let contract = match self.contracts.get(purpose) {
            Some(contract) => *contract,
            None => {
                return Err(AutopoiesisError::UnknownPurpose {
                    purpose: purpose.to_string(),
                })
            }
        };
        self.stats.cycles = self.stats.cycles.saturating_add(1);

        let cell = self.mutator.open_cell(kernel.read());
        let mut faults = 0usize;
        for mutation in mutations {
            match self.mutator.apply(cell, mutation) {
                Ok(outcome) => {
                    if outcome.is_trapped() {
                        faults = faults.saturating_add(1);
                    }
                }
                Err(error) => {
                    self.mutator.release(cell);
                    return Err(AutopoiesisError::Mutator(error));
                }
            }
        }

        if faults > 0 {
            self.stats.traps = self.stats.traps.saturating_add(1);
            self.stats.refusals = self.stats.refusals.saturating_add(1);
            self.mutator.release(cell);
            let mut report =
                CycleReport::new(contract.name, cell, CycleVerdict::Trapped { faults });
            report.base_revision = kernel.revision();
            return Ok(CycleOutcome::Refused { report });
        }

        if mutations.is_empty() {
            self.stats.refusals = self.stats.refusals.saturating_add(1);
            self.mutator.release(cell);
            let mut report = CycleReport::new(contract.name, cell, CycleVerdict::EmptyPlan);
            report.base_revision = kernel.revision();
            return Ok(CycleOutcome::Refused { report });
        }

        let evidence = Evidence::green(contract.name, 1);
        let proposal_id = match self.mutator.propose(kernel.read(), cell, &evidence) {
            Ok(id) => id,
            Err(error) => {
                self.mutator.release(cell);
                return Err(AutopoiesisError::Mutator(error));
            }
        };

        let snapshot = match self.mutator.proposal(proposal_id) {
            Some(proposal) => {
                let independent = audit_ast(&proposal.candidate);
                let (audit_passed, audit_total) = independent.score();
                let audit_ok = independent.passed();
                let violation = if audit_ok {
                    contract.evaluate(&proposal.candidate).err()
                } else {
                    None
                };
                Some(ProposalSnapshot {
                    base_revision: proposal.base_revision,
                    operations: proposal.operations,
                    nodes: proposal.candidate.nodes.len(),
                    audit_passed,
                    audit_total,
                    audit_ok,
                    union: proposal.verdict.union,
                    violation,
                })
            }
            None => None,
        };

        let Some(snapshot) = snapshot else {
            self.stats.refusals = self.stats.refusals.saturating_add(1);
            self.mutator.release(cell);
            return Err(AutopoiesisError::MissingProposal { id: proposal_id });
        };

        let result = if snapshot.audit_ok {
            match snapshot.violation {
                Some(rule) => CycleVerdict::ContractRejected(rule),
                None => CycleVerdict::Committed {
                    revision: kernel.revision().saturating_add(1),
                },
            }
        } else {
            CycleVerdict::AuditRejected {
                failed: snapshot.audit_total.saturating_sub(snapshot.audit_passed),
            }
        };

        let mut report = CycleReport::new(contract.name, cell, result);
        report.proposal = Some(proposal_id);
        report.base_revision = snapshot.base_revision;
        report.operations = snapshot.operations;
        report.nodes = snapshot.nodes;
        report.audit_passed = snapshot.audit_passed;
        report.audit_total = snapshot.audit_total;
        report.verdict = Some(snapshot.union);
        report.violation = snapshot.violation;

        if !result.is_committed() {
            self.stats.refusals = self.stats.refusals.saturating_add(1);
            self.mutator.release(cell);
            return Ok(CycleOutcome::Refused { report });
        }

        match self.mutator.commit(kernel, proposal_id) {
            Ok(next) => {
                self.stats.commits = self.stats.commits.saturating_add(1);
                report.result = CycleVerdict::Committed {
                    revision: next.revision(),
                };
                Ok(CycleOutcome::Committed {
                    kernel: next,
                    report,
                })
            }
            Err(error) => {
                self.stats.refusals = self.stats.refusals.saturating_add(1);
                self.mutator.release(cell);
                Err(AutopoiesisError::Mutator(error))
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Arnés de prueba
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi_ingest::{BaraType, ShoreshAst, ShoreshNode};
    use crate::runtime::QuantumState;

    /// Semilla determinista de las pruebas.
    const SEED: &[u8] = b"bara:pruebas:autopoiesis-activa:v1";

    /// Propósito inicial de las pruebas.
    const PURPOSE: &str = "estructural";

    /// Nodo *Shoresh* con valencia explícita.
    fn node(root: &str, arity: usize, hazard: f64, truth: f64, falsity: f64) -> ShoreshNode {
        ShoreshNode {
            root: root.to_string(),
            original: format!("legacy_{root}"),
            arity,
            ret: BaraType::Number,
            hazard,
            valence: QuantumState::paraconsistent(truth, falsity),
            sanitized: false,
        }
    }

    /// Nodo conforme: riesgo bajo y valencia `⊤`.
    fn sound(root: &str) -> ShoreshNode {
        node(root, 2, 0.10, 0.90, 0.10)
    }

    /// Núcleo génesis de dos nodos conformes.
    fn genesis() -> KernelCore {
        KernelCore::genesis(
            "pruebas.autopoiesis",
            ShoreshAst {
                nodes: vec![sound("אמת"), sound("דעת")],
            },
            SEED,
        )
    }

    /// Mutación `Add` conforme.
    fn add(root: &str) -> Mutation {
        Mutation::Add {
            root: root.to_string(),
            original: format!("legacy_{root}"),
            arity: 2,
            ret: BaraType::Number,
            hazard: 0.20,
            truth: 0.80,
            falsity: 0.20,
        }
    }

    /// Contrato por defecto del propósito de pruebas.
    fn contract() -> PurposeContract {
        PurposeContract::new(PURPOSE)
    }

    /// Motor con el contrato por defecto.
    fn engine() -> AutopoieticEngine {
        AutopoieticEngine::new(SEED, contract())
    }

    #[test]
    fn un_ciclo_conforme_fusiona_y_avanza_la_revision() {
        let kernel = genesis();
        let mut engine = engine();
        let outcome = engine.cycle(&kernel, PURPOSE, &[add("עדר")]);
        assert!(outcome.is_ok(), "un parche conforme debe ciclar");
        let Ok(outcome) = outcome else { return };
        assert!(outcome.is_committed());
        assert!(outcome.report().audit_conforms());
        assert_eq!(outcome.report().audit_passed, 9);
        assert_eq!(outcome.report().audit_total, 9);
        assert_eq!(outcome.report().nodes, 3);
        assert_eq!(outcome.report().operations, 1);
        assert_eq!(outcome.report().base_revision, 0);
        assert!(outcome.report().verdict.is_some());
        assert!(outcome.report().violation.is_none());
        assert_eq!(outcome.report().fingerprint().len(), 64);
        assert!(outcome.report().label().contains("fusionado"));
        assert_eq!(
            outcome.report().result,
            CycleVerdict::Committed { revision: 1 }
        );

        let (next, report) = outcome.into_parts();
        let Some(next) = next else { return };
        assert_eq!(next.revision(), 1);
        assert!(next.verify());
        assert_eq!(next.nodes().len(), 3);
        assert_eq!(report.cell, 1, "la primera célula empieza en 1");
        assert_eq!(report.proposal, Some(1));
        assert_eq!(engine.stats().cycles, 1);
        assert_eq!(engine.stats().commits, 1);
        assert_eq!(engine.stats().refusals, 0);
        assert_eq!(engine.stats().commit_rate(), 10_000);
    }

    #[test]
    fn la_reauditoria_detiene_un_tipo_indeterminado() {
        let kernel = genesis();
        let mut engine = engine();
        let outcome = engine.cycle(
            &kernel,
            PURPOSE,
            &[Mutation::Retarget {
                index: 0,
                ret: BaraType::Unknown,
            }],
        );
        let Ok(outcome) = outcome else { return };
        assert!(!outcome.is_committed());
        let report = *outcome.report();
        assert!(matches!(report.result, CycleVerdict::AuditRejected { failed } if failed > 0));
        assert!(!report.audit_conforms());
        assert!(report.violation.is_none());
        assert_eq!(kernel.revision(), 0);
        assert_eq!(engine.stats().commits, 0);
        assert_eq!(engine.stats().refusals, 1);
        assert_eq!(engine.mutator().counters().fusions, 0);
    }

    #[test]
    fn el_contrato_de_riesgo_detiene_antes_de_fusionar() {
        let kernel = genesis();
        let mut engine = AutopoieticEngine::new(SEED, contract().hazard(150));
        let outcome = engine.cycle(&kernel, PURPOSE, &[add("עדר")]);
        let Ok(outcome) = outcome else { return };
        assert!(!outcome.is_committed());
        let report = *outcome.report();
        assert_eq!(
            report.result,
            CycleVerdict::ContractRejected(PurposeViolation::HazardCeiling {
                index: 2,
                permille: 200,
                limit: 150,
            })
        );
        assert_eq!(
            report.violation.map(PurposeViolation::code),
            Some("proposito.riesgo")
        );
        assert!(report.audit_conforms(), "la auditoría estática sí pasa");
        assert_eq!(kernel.revision(), 0);
        assert_eq!(engine.mutator().counters().fusions, 0);
    }

    #[test]
    fn un_plan_vacio_no_abre_propuesta() {
        let kernel = genesis();
        let mut engine = engine();
        let outcome = engine.cycle(&kernel, PURPOSE, &[]);
        let Ok(outcome) = outcome else { return };
        assert!(!outcome.is_committed());
        let report = *outcome.report();
        assert_eq!(report.result, CycleVerdict::EmptyPlan);
        assert!(report.proposal.is_none());
        assert_eq!(report.audit_total, 0);
        assert!(!report.audit_conforms());
        assert_eq!(engine.stats().refusals, 1);
        assert_eq!(engine.stats().commit_rate(), 0);
    }

    #[test]
    fn una_mutacion_atrapada_no_toca_el_nucleo() {
        let kernel = genesis();
        let mut engine = engine();
        let outcome = engine.cycle(
            &kernel,
            PURPOSE,
            &[Mutation::Retarget {
                index: 999,
                ret: BaraType::Number,
            }],
        );
        let Ok(outcome) = outcome else { return };
        assert!(!outcome.is_committed());
        assert_eq!(outcome.report().result, CycleVerdict::Trapped { faults: 1 });
        assert!(outcome.report().proposal.is_none());
        assert_eq!(engine.stats().traps, 1);
        assert_eq!(engine.stats().refusals, 1);
        assert_eq!(engine.mutator().counters().fusions, 0);
        assert_eq!(kernel.revision(), 0);
    }

    #[test]
    fn un_proposito_desconocido_es_un_error_tipado() {
        let kernel = genesis();
        let mut engine = engine();
        let outcome = engine.cycle(&kernel, "inexistente", &[add("עדר")]);
        assert!(matches!(
            outcome,
            Err(AutopoiesisError::UnknownPurpose { .. })
        ));
        if let Err(error) = outcome {
            assert!(error.to_string().contains("inexistente"));
            assert!(std::error::Error::source(&error).is_none());
        }
        assert_eq!(engine.stats().cycles, 0);
    }

    #[test]
    fn dos_motores_coinciden_bit_a_bit() {
        let kernel = genesis();
        let mut first = engine();
        let mut second = engine();
        let plan = [add("עדר"), add("חכמ")];
        let left = first.cycle(&kernel, PURPOSE, &plan);
        let right = second.cycle(&kernel, PURPOSE, &plan);
        let (Ok(left), Ok(right)) = (left, right) else {
            return;
        };
        assert_eq!(left.report(), right.report());
        assert_eq!(left.report().digest(), right.report().digest());
        assert_eq!(left.report().nodes, 4);

        let (Some(next), _) = left.into_parts() else {
            return;
        };
        assert_eq!(next.revision(), 1);
        let again = first.cycle(&next, PURPOSE, &[add("בטח")]);
        let Ok(again) = again else { return };
        assert!(again.is_committed());
        assert_eq!(
            again.report().result,
            CycleVerdict::Committed { revision: 2 }
        );
        assert_eq!(again.report().base_revision, 1);
        assert_eq!(again.report().cell, 2);
        assert_eq!(first.stats().cycles, 2);
        assert_eq!(first.stats().commits, 2);
        assert_eq!(first.stats().commit_rate(), 10_000);
    }

    #[test]
    fn el_registro_de_propositos_es_acotado() {
        const NAMES: [&str; MAX_PURPOSES] = ["a", "b", "c", "d", "e", "f", "g", "h"];
        let mut book = ContractBook::new();
        assert!(book.is_empty());
        assert_eq!(book.len(), 0);
        for name in NAMES {
            assert!(book.register(PurposeContract::new(name)).is_ok());
        }
        assert_eq!(book.len(), MAX_PURPOSES);
        assert!(book.is_full());
        assert_eq!(book.iter().count(), MAX_PURPOSES);
        assert!(book.get("h").is_some());
        assert!(book.get("z").is_none());
        assert_eq!(
            book.register(PurposeContract::new("extra")),
            Err(ContractError::Full {
                limit: MAX_PURPOSES
            })
        );
        assert_eq!(
            book.register(PurposeContract::new("a")),
            Err(ContractError::Duplicate { name: "a" })
        );
        assert_eq!(book.len(), MAX_PURPOSES, "un rechazo no consume plaza");

        let single = ContractBook::with(PurposeContract::new("único"));
        assert_eq!(single.len(), 1);
        assert_eq!(ContractBook::default().len(), 0);
    }

    #[test]
    fn la_cuantizacion_del_riesgo_es_total() {
        assert_eq!(hazard_permille(0.0), 0);
        assert_eq!(hazard_permille(0.125), 125);
        assert_eq!(hazard_permille(0.2005), 201);
        assert_eq!(hazard_permille(1.0), FULL_HAZARD);
        assert_eq!(hazard_permille(-3.0), 0);
        assert_eq!(hazard_permille(9.0), FULL_HAZARD);
        assert_eq!(hazard_permille(f64::NAN), FULL_HAZARD);
        assert_eq!(hazard_permille(f64::INFINITY), FULL_HAZARD);
        assert_eq!(hazard_permille(f64::NEG_INFINITY), FULL_HAZARD);
    }

    #[test]
    fn el_contrato_evalua_en_orden_canonico() {
        let ast = ShoreshAst {
            nodes: vec![sound("אמת")],
        };
        let base = PurposeContract::new("prueba");
        assert!(base.evaluate(&ast).is_ok());
        assert_eq!(
            base.evaluate(&ShoreshAst::default()),
            Err(PurposeViolation::Empty)
        );
        assert_eq!(
            base.nodes(0).evaluate(&ast),
            Err(PurposeViolation::TooManyNodes { nodes: 1, limit: 0 })
        );
        assert_eq!(
            base.arity(1).evaluate(&ast),
            Err(PurposeViolation::Arity {
                index: 0,
                arity: 2,
                limit: 1,
            })
        );
        assert_eq!(
            base.sealed(true).evaluate(&ast),
            Err(PurposeViolation::Unsanitized { index: 0 })
        );

        let mut untyped = sound("אמת");
        untyped.ret = BaraType::Unknown;
        assert_eq!(
            base.evaluate(&ShoreshAst {
                nodes: vec![untyped]
            }),
            Err(PurposeViolation::Untyped { index: 0 })
        );
        assert_eq!(base.typed(false).evaluate(&ast), Ok(()));

        let risky = ShoreshAst {
            nodes: vec![node("אמת", 2, 0.75, 0.9, 0.1)],
        };
        assert_eq!(
            base.hazard(500).evaluate(&risky),
            Err(PurposeViolation::HazardCeiling {
                index: 0,
                permille: 750,
                limit: 500,
            })
        );
        assert!(base.label().contains("prueba"));
        assert_eq!(
            PurposeViolation::Empty.to_string(),
            "el parche no aporta nodos"
        );
    }
}
