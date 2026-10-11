//! # Bara (בָּרָא) — Núcleo del motor AETHER‑Ω
//!
//! Biblioteca del *bootstrap kernel* del lenguaje **Bara**. Es exactamente el
//! mismo núcleo que ejecuta el binario `bara`, pero expuesto como *crate* para
//! que la **suite de integración** (`tests/`) y cualquier consumidor externo
//! puedan enlazarlo sin duplicar código ni tipos.
//!
//! ## Mapa de módulos
//! * [`lexer`] — análisis léxico triconsonántico (*shoresh*), total e infalible.
//! * [`runtime`] — evaluador paraconsistente de Belnap, autopoiesis, memoria
//!   holográfica de entropía cero y log ontológico.
//! * [`memory_region`] — inferencia de regiones por rangos de vida y vistas
//!   *zero-copy* CPU/GPU.
//! * [`zk_proof`] — pipeline ZK‑SNARK didáctico sobre `𝔽ₚ` (`P = 2⁶¹ − 1`).
//! * [`ffi_ingest`] — ingesta omnívora de C/Python hacia el AST *Shoresh*.
//! * [`temporal_rollback`] — navegación temporal y rollback atómico `Δ⁻¹`.
//! * [`quantum_native`] — qubits `Qubit<|ψ⟩>`, amplitudes complejas y pares de
//!   Bell.
//! * [`mesh_sync`] — malla global holográfica (bus en proceso e hilos `std`).
//! * [`metal_ir`] — *layout* abstracto de registros, ISA de 32 bits y bypass del
//!   driver.
//! * [`repl`] — oráculo REPL: lengua natural → programa *Shoresh*.
//!
//! ## Invariantes globales de la biblioteca
//! 1. **Sólo `std`** — cero dependencias externas (`Cargo.toml` sin
//!    `[dependencies]`).
//! 2. **Totalidad** — ninguna entrada provoca un pánico: lo incomprensible se
//!    degrada a un valor *tolerado*.
//! 3. **Determinismo** — no hay aleatoriedad real; todo colapso o huella deriva
//!    de hashes FNV‑1a estables.
//! 4. **Sin `unsafe`** — el *kernel* entero es Rust seguro.

#![forbid(unsafe_code)]

pub mod ffi_ingest;
pub mod lexer;
pub mod memory_region;
pub mod mesh_sync;
pub mod metal_ir;
pub mod quantum_native;
pub mod repl;
pub mod runtime;
pub mod temporal_rollback;
pub mod zk_proof;

// ─────────────────────────────────────────────────────────────────────────
// Reexportaciones de conveniencia
// ─────────────────────────────────────────────────────────────────────────

pub use memory_region::{Device, RegionId, RegionKind};
pub use quantum_native::{Amplitude, BellPhase};
pub use repl::{MetaCommand, Oracle, OracleReport};
pub use runtime::{BaraRuntime, ExecutionEvent, Observation, QuantumState};
