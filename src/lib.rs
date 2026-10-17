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
//! * [`fractal_geometry`] — proporción áurea (`φ`) y retícula de Fibonacci para
//!   el reparto espacial de la memoria holográfica y de la tabla de regiones.
//! * [`temporal_rollback`] — navegación temporal y rollback atómico `Δ⁻¹`.
//! * [`quantum_native`] — qubits `Qubit<|ψ⟩>`, amplitudes complejas y pares de
//!   Bell.
//! * [`mesh_sync`] — malla global holográfica (bus en proceso e hilos `std`).
//! * [`metal_ir`] — *layout* abstracto de registros, ISA de 32 bits y bypass del
//!   driver.
//! * [`repl`] — oráculo REPL: lengua natural → programa *Shoresh*.
//! * [`bsc_bridge`] — puente híbrido con BNB Smart Chain (EVM): RLP, keccak‑256,
//!   secp256k1/EIP‑155 (Chain ID 56), ABI/BEP‑20 y cliente JSON‑RPC propio; cada
//!   respuesta se aísla como burbuja de datos antes de tocar el árbol *Shoresh*.
//! * [`topology`] — enrutamiento estático sin tablas: capas
//!   `Sovereign → Periphery → Cell → Observer` con aristas ZST y descenso
//!   unidireccional garantizado por tipos; contracción *Tzimtzum* de la
//!   información en registros de 16 B y filas de una línea de caché L1.
//! * [`autopoietic`] — autopoiesis soberana: núcleo inmutable (`KernelCore`),
//!   células *sandbox* de AST, IPC firmado (`SynapseLink`), auditoría estática
//!   *Shoresh*, compuerta paraconsistente de Belnap y fusión atómica con diff
//!   para el IDE.
//!
//! ## Invariantes globales de la biblioteca
//! 1. **Sólo `std`** — cero dependencias externas (`Cargo.toml` sin
//!    `[dependencies]`).
//! 2. **Totalidad** — ninguna entrada provoca un pánico: lo incomprensible se
//!    degrada a un valor *tolerado*.
//! 3. **Determinismo** — no hay aleatoriedad real; todo colapso o huella deriva
//!    de hashes FNV‑1a estables. Los campos de métricas de reloj de pared
//!    (`micros`, `Delta.at_micros`) están marcados como **NO DETERMINISTAS**:
//!    quedan fuera de comparaciones, huellas y firmas.
//! 4. **Sin `unsafe`** — el *kernel* entero es Rust seguro.

#![forbid(unsafe_code)]

pub mod ast_dna;
pub mod autopoietic;
pub mod bsc_bridge;
pub mod cognitive;
pub mod crypto_native;
pub mod emission;
pub mod ffi_ingest;
pub mod fractal_geometry;
pub mod ide_bridge;
pub mod immune;
pub mod immunity_gateway;
pub mod lexer;
pub mod memory_region;
pub mod mesh_sync;
pub mod metal_ir;
pub mod net_camouflage;
pub mod quantum_native;
pub mod repl;
pub mod runtime;
pub mod temporal_rollback;
pub mod topology;
pub mod visual_builder;
pub mod zk_proof;

// ─────────────────────────────────────────────────────────────────────────
// Reexportaciones de conveniencia
// ─────────────────────────────────────────────────────────────────────────

pub use bsc_bridge::{
    Address, BridgeError, LegacySignature, LegacyTx, SignedTransaction, SigningKey, BSC_CHAIN_ID,
    U256,
};
// La autopoiesis estructural se reexporta sin renombrar su tipo principal: el
// sintetizador de axiomas semánticos del runtime se llama igual
// (`runtime::AutopoieticMutator`), así que el mutador de *sandbox* se expone con
// un alias explícito y se accede completo como `bara::autopoietic::…`.
pub use autopoietic::{
    ast_fingerprint, audit_ast, AutopoieticMutator as SandboxMutator, BelnapMatrix, BelnapValue,
    BelnapVerdict, Capability, CellState, DiffLine, Evidence, Frame, FrameKind, KernelCore,
    KernelError, KernelRead, Mutation, MutationDiff, MutationRecord, MutatorCounts, MutatorError,
    Proposal, SandboxCell, SignedFrame, StaticAudit, SynapseGateway, SynapseLink,
};
pub use fractal_geometry::{fib_ceil, fibonacci, golden_angle, golden_slots, FractalLayout};
pub use memory_region::{Device, RegionId, RegionKind};
pub use quantum_native::{Amplitude, BellPhase};
pub use repl::{manifest_lines, MetaCommand, Oracle, OracleReport};
pub use runtime::{BaraRuntime, ExecutionEvent, Observation, QuantumState};
