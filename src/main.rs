#![forbid(unsafe_code)]
#![allow(dead_code)]
//! # Bara (בָּרָא) — Programa Génesis
//!
//! Punto de entrada del *bootstrap kernel* del lenguaje supremo trascendental
//! **Bara**. Este binario ejecuta el "programa génesis": analiza un programa
//! escrito con raíces triconsonánticas hebreas, lo evalúa sobre el runtime
//! paraconsistente/autopoiético y emite un **log ontológico**.
//!
//! Fases:
//! 1. Análisis léxico triconsonántico.
//! 2. Ejecución ontológica (log del génesis).
//! 3. Autopsia del núcleo (autopoiesis).
//! 4. Memoria holográfica de entropía cero.
//! 5. Tensión paraconsistente (demostración de no-explosión).
//! 6. Inferencia de regiones de memoria (zero-copy CPU/GPU).
//! 7. Verificación ZK-SNARK del AST (etapa de compilación).
//! 8. Ingesta FFI omnívora (legado C/Python → Shoresh AST).
//! 9. Navegación temporal y rollback `Δ⁻¹`.

//! 10. Tipos cuánticos nativos (`Qubit<|ψ⟩>`) y entrelazamiento.
//! 11. Malla global de memoria holográfica (bus e hilos `std`).
//! 12. Metal-IR: mapeo de registros y bypass del driver.
//! 13. Oráculo REPL interactivo con monitor `Δ⁻¹`.
//!
//! # Uso
//! * `bara` — ejecuta el génesis completo (fases 1‑13) y, si la entrada es un
//!   terminal real, entra en el oráculo en vivo.
//! * `bara --oracle` — fuerza el bucle interactivo aunque la entrada esté
//!   redirigida (útil para guiones e integración continua).

// El núcleo vive ahora en la biblioteca `bara` (véase `src/lib.rs`): este
// binario es un consumidor delgado que orquesta las trece fases del génesis y
// comparte tipos exactos con la suite de integración de `tests/`.
use bara::lexer::{Lexer, Token, TokenKind};
use bara::memory_region::{Access, Device, RegionAnalyzer, RegionKind};
use bara::mesh_sync::PeerId;
use bara::metal_ir::MetalProgram;
use bara::quantum_native::{Amplitude, BellPhase};
use bara::repl::Oracle;
use bara::runtime::{BaraRuntime, ExecutionEvent, QuantumState};
use bara::temporal_rollback::TemporalEngine;
use bara::zk_proof::Fp;

/// Programa génesis: una secuencia de raíces triconsonánticas.
const GENESIS_SOURCE: &str = r#"
# ── Programa Génesis de Bara ─────────────────────────────
ברא          # manifestación ex nihilo
חכם          # superposición adaptativa
עבד          # colapso observacional
ברא          # nueva manifestación
ברא          # segunda manifestación
!!           # fusión paraconsistente (contradicción controlada)
עבד          # observación de la contradicción
שמר          # sellar contra la explosión lógica
נצח          # raíz desconocida ⇒ autopoiesis
עבד          # colapso del axioma sintetizado
אמר          # emitir el estado resultante
שפט          # juicio por conjunción
אמר          # emitir el veredicto
"#;

fn main() {
    banner();

    // `--oracle` fuerza el bucle interactivo aunque la entrada esté redirigida
    // (útil para probar el REPL en un guion o en integración continua).
    let force_oracle = std::env::args().any(|arg| arg == "--oracle" || arg == "-o");

    // FASE 1 — análisis léxico.
    let tokens = Lexer::new(GENESIS_SOURCE).tokenize();
    lex_phase(&tokens);

    // FASE 2 — ejecución sobre el runtime.
    let mut runtime = BaraRuntime::new();
    let events: &[ExecutionEvent] = runtime.execute(&tokens);
    exec_phase(events);

    // FASE 3 — autopsia del núcleo.
    core_phase(&runtime);

    // FASE 4 — memoria holográfica.
    hologram_phase(&mut runtime);

    // FASE 5 — tensión paraconsistente.
    paradox_phase();

    // FASE 6 — inferencia de regiones de memoria.
    let log_base = runtime.log().len();
    region_phase(&runtime);

    // FASE 7 — verificación ZK-SNARK del AST.
    zk_phase(&mut runtime);

    // FASE 8 — ingesta FFI omnívora.
    ffi_phase(&mut runtime);

    // FASE 9 — navegación temporal y rollback Δ⁻¹.
    temporal_phase(&mut runtime);

    // FASE 10 — tipos cuánticos nativos.
    quantum_native_phase(&mut runtime);

    // FASE 11 — malla global de memoria holográfica.
    mesh_phase(&mut runtime);

    // FASE 12 — Metal-IR y bypass del driver.
    metal_phase(&mut runtime, &tokens);

    // FASE 13 — oráculo REPL.
    oracle_phase(&mut runtime, force_oracle);

    // LOG EXTENDIDO — eventos emitidos por los módulos de la Fase 2.
    extended_log_phase(&runtime, log_base);

    println!("\n✦ Génesis completado. El lenguaje respira: בָּרָא.");
}

/// Imprime el estandarte de apertura.
fn banner() {
    println!("══════════════════════════════════════════════════════════════");
    println!("  BARA  ·  בָּרָא  ·  El Lenguaje Supremo Trascendental");
    println!(
        "  bootstrap kernel / core engine  —  versión {}",
        env!("CARGO_PKG_VERSION")
    );
    println!("══════════════════════════════════════════════════════════════");
}

/// FASE 1 — volcado del análisis léxico triconsonántico.
fn lex_phase(tokens: &[Token]) {
    println!("\n── FASE 1 · ANÁLISIS LÉXICO TRICONSONÁNTICO ───────────────────");
    let mut count: usize = 0;
    for token in tokens {
        if matches!(token.kind, TokenKind::Newline | TokenKind::Eof) {
            continue;
        }
        count += 1;
        println!("   L{:<3} C{:<3} {}", token.line, token.column, token.kind);
    }
    println!("   → {} tokens significativos extraídos.", count);
}

/// FASE 2 — log ontológico de la ejecución del génesis.
fn exec_phase(events: &[ExecutionEvent]) {
    println!("\n── FASE 2 · EJECUCIÓN ONTOLÓGICA (LOG DEL GÉNESIS) ────────────");
    for (idx, event) in events.iter().enumerate() {
        println!("   [{:02}] {}", idx + 1, event.describe());
    }
}

/// FASE 3 — autopsia del núcleo autopoiético.
fn core_phase(runtime: &BaraRuntime) {
    println!("\n── FASE 3 · AUTOPSIA DEL NÚCLEO AUTOPOIÉTICO ──────────────────");
    println!(
        "   generaciones autopoiéticas : {}",
        runtime.mutator.generation()
    );
    println!(
        "   axiomas sintetizados       : {}",
        runtime.mutator.axioms().count()
    );
    for axiom in runtime.mutator.axioms() {
        println!(
            "      ✦ {}  (valencia: {})",
            axiom.rule,
            axiom.valence.label()
        );
    }
    println!("   profundidad de la pila     : {}", runtime.stack.len());
    println!(
        "   estado en la cumbre        : {}",
        runtime
            .stack
            .last()
            .map(|s| s.label())
            .unwrap_or_else(|| "<pila vacía>".to_string())
    );
}

/// FASE 4 — memoria holográfica de entropía cero.
fn hologram_phase(runtime: &mut BaraRuntime) {
    println!("\n── FASE 4 · MEMORIA HOLOGRÁFICA DE ENTROPÍA CERO ──────────────");
    let key_a = runtime
        .memory
        .store("celda-alef", QuantumState::classical(true));
    let key_b = runtime
        .memory
        .store("celda-bet", QuantumState::superposition(0.8, 0.2));
    // Escritura idempotente: no añade entropía ni escrituras.
    let _ = runtime
        .memory
        .store("celda-alef", QuantumState::classical(false));

    println!("   nodos retenidos : {}", runtime.memory.len());
    println!("   escrituras      : {}", runtime.memory.writes());
    println!(
        "   entropía        : {:.6}  (cero por construcción)",
        runtime.memory.entropy()
    );
    if let Some(node) = runtime.memory.recall("celda-alef") {
        println!(
            "   recall celda-alef ⇒ key=0x{:016X} afinidad={:.4} estado={}",
            node.key,
            node.affinity,
            node.state.label()
        );
    }
    println!(
        "   afinidad topológica alef↔bet : {:.4}",
        runtime.memory.topological_affinity_to(key_a, key_b)
    );
    // Reparto espacial armónico: pasos de Fibonacci y orden áureo `i·φ`.
    let lattice = runtime.memory.layout();
    println!("   φ-rejilla        : {}", lattice.label());
    println!(
        "   cota de relleno  : {:.2}%  (cubo potencia de dos: {:.2}%)",
        lattice.bound * 100.0,
        lattice.baseline_bound * 100.0
    );
}

/// FASE 5 — la contradicción como valor, no como fallo.
fn paradox_phase() {
    println!("\n── FASE 5 · TENSIÓN PARACONSISTENTE (NO-EXPLOSIÓN) ────────────");
    let paradox = QuantumState::paraconsistent(0.9, 0.9);
    let stable = QuantumState::classical(true);
    let fused = paradox.conjunction(&stable);

    println!("   estado contradictorio : {}", paradox.label());
    println!(
        "   observación           : {} ({})",
        paradox.observe().glyph(),
        paradox.observe().name()
    );
    println!("   ¿contradicción?       : {}", paradox.is_contradiction());
    println!("   conjunción con ⊤       : {}", fused.label());
    println!("   → el runtime NO colapsa; la contradicción es un valor lógico.");
}

/// FASE 6 — inferencia de regiones de memoria y vistas *zero-copy* CPU/GPU.
fn region_phase(runtime: &BaraRuntime) {
    println!("\n── FASE 6 · INFERENCIA DE REGIONES DE MEMORIA ─────────────────");

    // Regiones vivas introducidas por el runtime durante el génesis.
    println!("   regiones vivas del runtime : {}", runtime.regions.len());
    println!(
        "   bytes direccionados        : {} B",
        runtime.regions.total_bytes()
    );
    for region in runtime.regions.regions() {
        println!(
            "   {} {:<14} [{}] {:>5} B · depth={}",
            region.kind.glyph(),
            region.name,
            region.kind.label(),
            region.bytes,
            region.depth
        );
    }
    // Retícula áurea de las regiones vivas (mismo reparto que la memoria).
    println!(
        "   φ-rejilla de regiones : {}",
        runtime.regions.fractal_layout().label()
    );

    // Inferencia pura sobre un conjunto de accesos con rangos de vida.
    let accesses = vec![
        Access {
            label: "α".to_string(),
            bytes: 64,
            kind: RegionKind::Stack,
            birth: 0,
            death: 3,
        },
        Access {
            label: "β".to_string(),
            bytes: 32,
            kind: RegionKind::Stack,
            birth: 1,
            death: 2,
        },
        Access {
            label: "γ".to_string(),
            bytes: 128,
            kind: RegionKind::Shared,
            birth: 4,
            death: 9,
        },
        Access {
            label: "δ".to_string(),
            bytes: 256,
            kind: RegionKind::Heap,
            birth: 5,
            death: 7,
        },
    ];
    let plan = RegionAnalyzer::infer(&accesses);
    println!("   ── inferencia por rangos de vida ──");
    for region in plan.table.regions() {
        println!(
            "   {} {:<9} [{}] {:>5} B",
            region.kind.glyph(),
            region.name,
            region.kind.label(),
            region.bytes
        );
    }
    for (label, id) in &plan.assignment {
        let name = plan
            .table
            .get(*id)
            .map(|r| r.name.clone())
            .unwrap_or_default();
        println!("   ↳ {} → {}", label, name);
    }

    // Vistas de copia cero compartidas entre CPU y GPU.
    if let Some(first) = plan.table.regions().first() {
        let id = first.id;
        for device in [Device::Cpu, Device::Gpu] {
            if let Some(handle) = plan.table.share("vista-arlef", id, 0, 16, device) {
                println!(
                    "   ⇄ zero-copy «{}» región#{} offset={} len={} ⇒ {} (sin copia)",
                    handle.label,
                    handle.region.0,
                    handle.offset,
                    handle.len,
                    handle.device.label()
                );
            }
        }
    }
    println!("   → memoria determinista: sin GC, sin borrow checker, liberación estática.");
}

/// FASE 7 — certificación ZK-SNARK de los invariantes del AST.
fn zk_phase(runtime: &mut BaraRuntime) {
    println!("\n── FASE 7 · VERIFICACIÓN ZK-SNARK DEL AST ─────────────────────");
    let certificate = runtime.certify();

    println!(
        "   declaración pública  : «{}»",
        certificate.statement.label
    );
    println!(
        "   invariantes (n)      : {}",
        certificate.statement.n_constraints
    );
    println!(
        "   entradas públicas    : {}",
        certificate.statement.public_inputs.len()
    );
    println!(
        "   desafío Fiat–Shamir  : 0x{:016X}",
        certificate.result.challenge.0
    );
    println!("   compromisos emitidos :");
    for (name, commitment) in &certificate.proof.commitments {
        println!("      ↳ {} = 0x{:016X}", name, commitment);
    }
    for (name, passed) in &certificate.result.checks {
        println!(
            "   {} {:<40} {}",
            if *passed { "✓" } else { "✗" },
            name,
            if *passed { "OK" } else { "FALLO" }
        );
    }
    println!(
        "   veredicto            : {}",
        if certificate.result.verified {
            "AST CERTIFICADO ✓"
        } else {
            "RECHAZADO ✗"
        }
    );

    // Manipulación del testigo ⇒ la verificación debe fallar.
    let mut tampered = certificate.proof.clone();
    tampered.evals.c = Fp::new(tampered.evals.c.0 ^ 1);
    let rejected = bara::zk_proof::verify(&certificate.statement, &tampered);
    println!(
        "   prueba manipulada    : verificado={} (esperado=false)",
        rejected.verified
    );
}

/// FASE 8 — ingesta FFI omnívora de código legado hacia el AST *Shoresh*.
fn ffi_phase(runtime: &mut BaraRuntime) {
    println!("\n── FASE 8 · INGESTA FFI OMNÍVORA (LEGADO → SHORESH AST) ────────");
    let c_source = r#"
int shamar_domain(int fd, char* buffer);
void* bara_alloc(unsigned long n);
double chakam_score(int x, double y);
int nachash_orphan(int unused);
"#;
    let python_source = r#"
def bara_manifest(name, weight):
def shamar_guard(handle, flags):
def nachash_eval(expr):
"#;

    let c_nodes = runtime.ingest_c(c_source);
    let python_nodes = runtime.ingest_python(python_source);
    println!("   declaraciones C ingeridas   : {}", c_nodes.len());
    println!("   funciones Python ingeridas  : {}", python_nodes.len());
    println!("   ── mapeo a raíces triconsonánticas ──");
    for node in c_nodes.iter().chain(python_nodes.iter()) {
        println!(
            "   ⇄ {:<20} ⇒ raíz {} · aridad={} · ret={} · riesgo={:.2} · saneado={}",
            node.original,
            node.root,
            node.arity,
            node.ret.label(),
            node.hazard,
            node.sanitized
        );
    }
    let total = c_nodes.len() + python_nodes.len();
    let sanitized = c_nodes
        .iter()
        .chain(python_nodes.iter())
        .filter(|n| n.sanitized)
        .count();
    println!(
        "   → {} nodos ingeridos, {} saneados bajo reglas paraconsistentes.",
        total, sanitized
    );
}

/// FASE 9 — navegación temporal y rollback atómico `Δ⁻¹`.
fn temporal_phase(runtime: &mut BaraRuntime) {
    println!("\n── FASE 9 · NAVEGACIÓN TEMPORAL Y ROLLBACK Δ⁻¹ ────────────────");

    // Rollback atómico de demostración sobre un motor temporal independiente.
    let mut engine = TemporalEngine::new();
    let marker = engine.mark();
    engine.push(QuantumState::classical(true));
    engine.push(QuantumState::paraconsistent(1.0, 1.0));
    let paradox = engine
        .stack()
        .last()
        .and_then(bara::temporal_rollback::detect_paradox);
    let report = match &paradox {
        Some(paradox) => engine.rollback_paradox(marker, paradox),
        None => engine.rollback_to(marker),
    };
    println!(
        "   demostración Δ⁻¹     : {} deltas revertidos en {} µs",
        report.reverted, report.micros
    );
    println!(
        "   pila tras rollback   : {} estado(s)",
        engine.stack().len()
    );
    println!(
        "   paradoja interceptada: {}",
        report.paradox.as_deref().unwrap_or("<ninguna>")
    );

    // Diario temporal del runtime (incluye el rollback disparado por `!!`).
    println!("   ── diario temporal del runtime ──");
    if runtime.timeline.deltas().is_empty() {
        println!("      (sin deltas registrados)");
    }
    for delta in runtime.timeline.deltas() {
        println!(
            "   ⧗ #{:<2} t={:>6} µs · {:<28} {:<16} {}",
            delta.id,
            delta.at_micros,
            delta.label,
            delta.inv_label(),
            if delta.reverted {
                "[Δ⁻¹ revertido]"
            } else {
                "[vivo]"
            }
        );
    }
    println!("   → el runtime rebobina a un punto consistente en vez de colapsar.");
}

/// Log extendido: eventos emitidos por los módulos de las fases 2 y 3.
fn extended_log_phase(runtime: &BaraRuntime, base: usize) {
    println!(
        "\n── LOG EXTENDIDO · AETHER-Ω (REGIONES · ZK · FFI · Δ⁻¹ · ψ · MALLA · METAL · ORÁCULO) ─"
    );
    let mut count = 0;
    for (idx, event) in runtime.log().iter().enumerate().skip(base) {
        count += 1;
        println!("   [{:02}] {}", idx + 1, event.describe());
    }
    if count == 0 {
        println!("   (sin eventos nuevos)");
    }
}

/// FASE 10 — tipos cuánticos nativos y entrelazamiento.
fn quantum_native_phase(runtime: &mut BaraRuntime) {
    println!("\n── FASE 10 · TIPOS CUÁNTICOS NATIVOS (Qubit<|ψ⟩>) ─────────────");

    // Superposición con fase compleja: (√3/2)|⊤⟩ + (i/2)|⊥⟩.
    let alef = runtime.superpose_native(
        "qubit-alef",
        Amplitude::real(3.0_f64.sqrt() / 2.0),
        Amplitude::from_polar(0.5, std::f64::consts::FRAC_PI_2),
    );
    let bet = runtime.superpose_native("qubit-bet", Amplitude::real(0.6), Amplitude::real(0.8));
    println!("   qubit-alef           : {}", alef.label());
    println!("   qubit-bet            : {}", bet.label());
    for name in ["qubit-alef", "qubit-bet"] {
        if let Some(qubit) = runtime.qubits.get(name) {
            println!("      ⌬ {}", qubit.describe());
        }
    }

    // Entrelazamiento máximo Φ⁺: la traza parcial es máximamente mixta.
    if let Some(pair) = runtime.entangle_native("qubit-alef", "qubit-bet", BellPhase::PhiPlus) {
        println!(
            "   entrelazado «Φ⁺»      : {} ⇒ observación {} ({})",
            pair.label(),
            pair.observe().glyph(),
            pair.observe().name()
        );
        println!(
            "      ¿contradicción tolerada? {} · ¿el runtime colapsó? no",
            pair.is_contradiction()
        );
    }
    println!("   ── las cuatro convenciones de Bell ──");
    for phase in BellPhase::all() {
        let joint = phase.joint();
        let (left, right) = joint.partial_trace_left();
        let probabilities: Vec<String> = joint
            .probabilities()
            .iter()
            .map(|p| format!("{:.2}", p))
            .collect();
        println!(
            "      ⧉ {} {:<38} p=[{}] traza=({:.2},{:.2}) ⟨Z⊗Z⟩={:+.0}",
            phase.label(),
            phase.meaning(),
            probabilities.join(" "),
            left,
            right,
            phase.correlation()
        );
    }

    // Puertas unitarias sobre un qubit local.
    if let Some(rotated) = runtime.qubits.hadamard("qubit-alef") {
        println!("   puerta H sobre alef   : {}", rotated.label());
    }
    if let Some(fased) = runtime
        .qubits
        .phase_shift("qubit-bet", std::f64::consts::FRAC_PI_2)
    {
        println!("   fase e^{{iπ/2}} sobre bet: {}", fased.label());
    }
    println!(
        "   → una puerta local no altera la traza parcial del par: la valencia del qubit entrelazado sigue siendo ⊤∧⊥."
    );

    // Qubit de dimensión 4: entropía máxima de 2 bits.
    let uniform = runtime.qubits.uniform("qubit-gimel", 4);
    println!(
        "   qubit-gimel (dim=4)   : {} · entropía máxima log₂4=2 bits",
        uniform.label()
    );

    // Colapso con propagación no local del par entrelazado.
    if let Some(collapsed) = runtime.collapse_native("qubit-alef") {
        println!("   colapso de alef       : {}", collapsed.label());
    }
    if let Some(partner) = runtime.qubits.get("qubit-bet") {
        println!(
            "   socio bet (no local)  : {} · entrelazado con {:?}",
            partner.outcome_label().unwrap_or_else(|| "∅".to_string()),
            partner.entangled_with
        );
    }
    println!(
        "   valencia global       : {}",
        runtime.qubits.global_valence().label()
    );
    println!(
        "   → {} qubit(s) · {} enlace(s) · {} colapso(s) · evaluados dentro del runtime paraconsistente.",
        runtime.qubits.len(),
        runtime.qubits.bindings().len(),
        runtime.qubits.collapses()
    );
}

/// FASE 11 — malla global de memoria holográfica.
fn mesh_phase(runtime: &mut BaraRuntime) {
    println!("\n── FASE 11 · MALLA GLOBAL DE MEMORIA HOLOGRÁFICA ──────────────");

    let seeded = runtime.mesh_sync(4, 2, false);
    println!("   siembra + gossip      : {}", seeded.label());

    // Divergencia controlada sobre una clave ya sincronizada.
    let target = runtime
        .mesh
        .nodes()
        .first()
        .and_then(|node| node.entries().next().map(|e| (e.name.clone(), e.region)));
    if let Some((name, region)) = target {
        let injected =
            runtime
                .mesh
                .diverge(PeerId(1), &name, region, QuantumState::classical(false));
        println!(
            "   divergencia inyectada : «{}» escrita=false en peer-01 = {} · deriva={:.4} · convergido={}",
            name,
            injected,
            runtime.mesh.drift(),
            runtime.mesh.converged()
        );
    }

    let fused = runtime.mesh_sync(4, 2, false);
    println!("   fusión paraconsistente: {}", fused.label());
    println!(
        "   estado de la malla    : convergido={} · deriva={:.4} · hológrafo global=0x{:016X}",
        runtime.mesh.converged(),
        runtime.mesh.drift(),
        runtime.mesh.hologram()
    );

    let threaded = runtime.mesh_sync(4, 3, true);
    println!("   hilos std (mpsc)      : {}", threaded.label());

    println!("   ── nodos de la malla ──");
    for node in runtime.mesh.nodes() {
        println!(
            "      ⬡ {} · entradas={} · hológrafo=0x{:016X} · reloj={} · aplicadas={} · obsoletas={}",
            node.name,
            node.len(),
            node.hologram(),
            node.clock().label(),
            node.applied(),
            node.rejected()
        );
    }

    // Ida y vuelta del formato *wire* (transporte listo para red, sin sockets).
    if let Some(node) = runtime.mesh.nodes().first() {
        let frame = node.snapshot();
        let wire = frame.to_wire();
        let decoded = bara::mesh_sync::MeshFrame::from_wire(&wire);
        println!(
            "   formato wire          : {} B · {} entrada(s) · decodificación íntegra={}",
            wire.len(),
            frame.len(),
            decoded
                .as_ref()
                .map(|f| f.digest == frame.digest)
                .unwrap_or(false)
        );
        let mut corrupted = wire.clone();
        if let Some(last) = corrupted.last_mut() {
            *last ^= 0xFF;
        }
        println!(
            "   wire corrompido       : aceptado={} (esperado=false, huella inválida)",
            bara::mesh_sync::MeshFrame::from_wire(&corrupted).is_some()
        );
    }
    println!(
        "   → el estado del todo vive en cada parte: cero sockets, cero entropía por reenvío."
    );
}

/// Imprime las primeras instrucciones de un programa Metal-IR.
fn print_metal_program(program: &MetalProgram, limit: usize) {
    println!(
        "   «{}» · vía {} · {} op(s) · carriles={} · firma: {}",
        program.label,
        program.device.label(),
        program.len(),
        program.lanes(),
        program.signature()
    );
    for (index, op) in program.ops.iter().take(limit).enumerate() {
        let physical = op
            .dst
            .and_then(|virt| program.physical_of(virt))
            .map(|reg| reg.label())
            .unwrap_or_else(|| "—".to_string());
        println!("      {:02} {} ⇒ {}", index, op.describe(), physical);
    }
    if program.len() > limit {
        println!("      … {} instrucción(es) más", program.len() - limit);
    }
    println!(
        "      descriptor=0x{:016X} · {} palabra(s) de 32 bits",
        program.descriptor(),
        program.words().len()
    );
}

/// FASE 12 — Metal-IR y bypass del driver.
fn metal_phase(runtime: &mut BaraRuntime, tokens: &[Token]) {
    println!("\n── FASE 12 · METAL-IR · BYPASS DEL DRIVER ─────────────────────");
    let banks: Vec<String> = bara::metal_ir::LAYOUT
        .iter()
        .map(|bank| bank.label())
        .collect();
    println!("   layout abstracto      : {}", banks.join(" │ "));
    println!(
        "   capacidad             : {} registros · {} B de banco",
        bara::metal_ir::capacity(),
        bara::metal_ir::layout_bytes()
    );

    let cpu = runtime.lower_metal("genesis.metal", Device::Cpu, tokens);
    print_metal_program(&cpu, 8);
    let gpu = runtime.lower_metal("genesis.vector.metal", Device::Gpu, tokens);
    print_metal_program(&gpu, 4);

    println!("   ── asignación de registros (linear scan) ──");
    for (class, used) in cpu.allocation.bank_usage() {
        println!(
            "      {} {:<4} {}/{} registros",
            class.glyph(),
            class.label(),
            used,
            class.slots()
        );
    }
    println!(
        "   presión de registros  : {:.3} · {} derrame(s) · {} B en ranuras estáticas",
        cpu.allocation.pressure(),
        cpu.allocation.spilled(),
        cpu.allocation.spill_bytes()
    );
    println!("   despacho CPU          : {}", cpu.dispatch().label());
    println!("   despacho GPU          : {}", gpu.dispatch().label());
    println!("   ruta de bypass (CPU)  : {}", cpu.bypass.label());
    println!("   → el AST llega al silicio sin pedir permiso al driver del sistema operativo.");
}

/// FASE 13 — oráculo REPL interactivo.
fn oracle_phase(runtime: &mut BaraRuntime, force_oracle: bool) {
    println!("\n── FASE 13 · ORÁCULO REPL INTERACTIVO ─────────────────────────");
    println!("   guion de arranque (modo determinista):");
    let script = [
        "crea un mundo con luz y ordena el caos",
        "guarda el fuego con שמר",
        "entrelaza alef con bet",
        "!!",
        "colapsa el estado y muestra el veredicto",
        ":cuántica",
        ":malla",
        ":metal",
        ":tiempo",
        ":deshacer",
        "juzga la creación holográfica",
        ":memoria",
        ":zk",
        ":salir",
    ];
    let report = {
        let mut oracle = Oracle::new(&mut *runtime);
        oracle.run_script(&script)
    };
    println!("   ── informe de la sesión ──");
    println!("   {}", report.label());

    if bara::repl::interactive_available() || force_oracle {
        println!("   ── terminal interactivo detectado: entrando en el oráculo en vivo ──");
        let live = {
            let mut oracle = Oracle::new(&mut *runtime);
            oracle.run()
        };
        println!("   sesión en vivo: {}", live.label());
    } else {
        println!(
            "   (entrada no interactiva: ejecuta `bara` en un terminal real para conversar en vivo)"
        );
    }
}
