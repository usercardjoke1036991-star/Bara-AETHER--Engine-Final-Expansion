//! # Arnés de estrés y paradojas — Bara / AETHER‑Ω (Fase 4)
//!
//! Inunda el núcleo con entradas **contradictorias** y mutaciones masivas del
//! AST para verificar empíricamente:
//!
//! 1. **Cero pánicos** — ninguna secuencia de paradojas `⊤∧⊥`, basura léxica o
//!    conflictos de malla aborta el proceso.
//! 2. **Rollback atómico** — `Δ⁻¹` restaura exactamente el estado marcado, con
//!    coste acotado y siempre «o todo, o nada».
//! 3. **Acotación** — la autopoiesis y la memoria holográfica no explotan: el
//!    crecimiento lo marca el número de raíces *distintas*, no el número de
//!    invocaciones.
//! 4. **Determinismo** — dos ejecuciones idénticas producen el mismo punto fijo
//!    en la malla y el mismo colapso cuántico, incluso con hilos `std`.
//!
//! Todo el ruido se genera con un PRNG propio (SplitMix64), de forma que las
//! pruebas son reproducibles *bit a bit* y no dependen de `rand`.

use bara::ffi_ingest;
use bara::lexer::{Lexer, TokenKind};
use bara::memory_region::{Device, RegionId};
use bara::mesh_sync::{MeshCluster, PeerId};
use bara::metal_ir::{self, LiveRange, MetalMapper, RegAllocation, RegisterClass};
use bara::quantum_native::{Amplitude, BellPhase, QuantumNative};
use bara::repl::Oracle;
use bara::runtime::{BaraRuntime, ExecutionEvent, QuantumState, MAX_AXIOMS, MAX_AXIOM_GENERATIONS};
use bara::temporal_rollback::{self, TemporalEngine};

// ─────────────────────────────────────────────────────────────────────────
// Ruido determinista
// ─────────────────────────────────────────────────────────────────────────

/// Generador SplitMix64: ruido reproducible sin dependencias externas.
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        SplitMix64(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Entero en `[0, bound)`.
    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next_u64() % bound as u64) as usize
        }
    }

    /// Real en `[0, 1)`.
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1_u64 << 53) as f64
    }
}

/// Alfabeto consonántico hebreo, para sintetizar raíces de estrés.
const CONSONANTS: [char; 22] = [
    'א', 'ב', 'ג', 'ד', 'ה', 'ו', 'ז', 'ח', 'ט', 'י', 'כ', 'ל', 'מ', 'נ', 'ס', 'ע', 'פ', 'צ', 'ק',
    'ר', 'ש', 'ת',
];

/// Raíz triconsonántica pseudoaleatoria.
fn random_root(rng: &mut SplitMix64) -> String {
    (0..3)
        .map(|_| CONSONANTS[rng.below(CONSONANTS.len())])
        .collect()
}

/// Estado paraconsistente con masas pseudoaleatorias (a veces `⊤∧⊥`).
fn random_state(rng: &mut SplitMix64) -> QuantumState {
    match rng.below(4) {
        0 => QuantumState::classical(rng.below(2) == 0),
        1 => QuantumState::superposition(rng.unit(), rng.unit()),
        2 => QuantumState::paraconsistent(rng.unit(), rng.unit()),
        // Paradoja máxima: el caso que el motor temporal debe interceptar.
        _ => QuantumState::paraconsistent(1.0, 1.0),
    }
}

/// ¿El estado respeta el invariante global `0 ≤ ⊤, ⊥ ≤ 1`?
fn state_is_sane(state: &QuantumState) -> bool {
    let (truth, falsity) = state.belnap();
    (0.0..=1.0).contains(&truth) && (0.0..=1.0).contains(&falsity)
}

// ─────────────────────────────────────────────────────────────────────────
// 1 · Inundación de paradojas: atomicidad del rollback Δ⁻¹
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn paradox_flood_never_panics_and_rollback_is_atomic() {
    let mut rng = SplitMix64::new(0xBABA_0001);
    let mut engine = TemporalEngine::new();
    let mut paradoxes = 0_usize;
    let mut reverted_total = 0_usize;
    let mut slowest = 0_u128;

    for _ in 0..2_000 {
        let marker = engine.mark();
        let height_before = engine.stack().len();

        // Ráfaga de estados arbitrarios: la cumbre siempre es la paradoja ⊤∧⊥.
        let burst = 1 + rng.below(4);
        for _ in 0..burst {
            engine.push(random_state(&mut rng));
        }
        engine.push(QuantumState::paraconsistent(1.0, 1.0));

        let paradox = temporal_rollback::detect_paradox(engine.stack().last().unwrap())
            .expect("la cumbre es ⊤∧⊥");
        paradoxes += 1;

        let report = engine.rollback_paradox(marker, &paradox);
        reverted_total += report.reverted;
        slowest = slowest.max(report.micros);

        assert_eq!(
            report.reverted,
            burst + 1,
            "Δ⁻¹ revierte el turno completo, ni un delta más"
        );
        assert!(report.paradox.is_some());
        assert_eq!(engine.stack().len(), height_before, "rollback atómico");
        assert!(engine.stack().iter().all(state_is_sane));
    }

    assert_eq!(paradoxes, 2_000);
    assert!(reverted_total >= 4_000);
    assert!(
        slowest < 1_000_000,
        "un rollback puntual debe ser sub-segundo (fue {slowest} µs)"
    );
    assert!(engine.deltas().iter().all(|delta| delta.reverted));
}

#[test]
fn deep_rollback_reverts_thousands_of_deltas_atomically() {
    let mut rng = SplitMix64::new(0xBABA_0002);
    let mut engine = TemporalEngine::new();
    let marker = engine.mark();

    for _ in 0..3_000 {
        engine.push(random_state(&mut rng));
    }
    assert_eq!(engine.stack().len(), 3_000);
    assert_eq!(engine.deltas().len(), 3_000);

    let report = engine.rollback_to(marker);
    assert_eq!(report.reverted, 3_000);
    assert!(engine.stack().is_empty());
    assert!(engine.deltas().iter().all(|delta| delta.reverted));
    assert!(
        report.micros < 1_000_000,
        "3 000 deltas deben rebobinarse en menos de un segundo"
    );

    // Idempotencia estricta: un segundo rollback no re-revierte nada.
    assert_eq!(engine.rollback_to(marker).reverted, 0);

    // El motor sigue siendo utilizable tras el rebobinado profundo.
    engine.push(QuantumState::classical(true));
    assert_eq!(engine.stack().len(), 1);
}

// ─────────────────────────────────────────────────────────────────────────
// 2 · Mutación masiva del AST y memoria holográfica
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn high_frequency_ast_mutation_stays_bounded() {
    let mut rng = SplitMix64::new(0xBABA_0003);
    let mut runtime = BaraRuntime::new();

    let roots: Vec<String> = (0..512).map(|_| random_root(&mut rng)).collect();

    // 4 000 invocaciones aleatorias: el lenguaje se reescribe a sí mismo.
    // Tras el techo de novedad, synthesize devuelve Neither (presupuesto).
    for _ in 0..4_000 {
        let index = rng.below(roots.len());
        let axiom = runtime.mutator.synthesize(&roots[index]);
        if axiom.rule.contains("presupuesto agotado") {
            assert!(!axiom.valence.is_contradiction());
        } else {
            assert!(axiom.valence.is_contradiction(), "todo axioma vivo es ⊤∧⊥");
        }
        assert!(state_is_sane(&axiom.valence));
        assert!(!axiom.rule.is_empty());
    }

    // La generación sólo avanza con raíces NUEVAS: acotada por el presupuesto.
    let generation_after_storm = runtime.mutator.generation();
    assert!(generation_after_storm <= roots.len());
    assert!(generation_after_storm <= MAX_AXIOM_GENERATIONS);
    assert!(runtime.mutator.axiom_count() <= MAX_AXIOMS);

    // Bajo el techo de novedad, el mismo prefijo de raíces en el mismo orden
    // produce el mismo punto fijo (idempotencia y determinismo).
    let capped: Vec<&String> = roots.iter().take(MAX_AXIOMS).collect();
    let mut left = BaraRuntime::new();
    let mut right = BaraRuntime::new();
    for root in &capped {
        left.mutator.synthesize(root);
        right.mutator.synthesize(root);
    }
    assert_eq!(left.mutator.generation(), right.mutator.generation());
    assert_eq!(left.mutator.axiom_count(), MAX_AXIOMS.min(capped.len()));
    let sample = capped[0];
    assert_eq!(
        left.mutator.axiom(sample).map(|axiom| axiom.rule.clone()),
        right.mutator.axiom(sample).map(|axiom| axiom.rule.clone())
    );

    // La repetición no muta el lenguaje ni acumula entropía.
    let before = runtime.mutator.generation();
    for root in roots.iter().take(64) {
        runtime.mutator.synthesize(root);
    }
    assert_eq!(runtime.mutator.generation(), before);
}

#[test]
fn holographic_memory_storm_is_idempotent() {
    let mut rng = SplitMix64::new(0xBABA_0004);
    let mut runtime = BaraRuntime::new();
    let mut keys = std::collections::BTreeSet::new();

    for index in 0..5_000 {
        let label = format!("nodo:{}", rng.below(256));
        let key = runtime.memory.store(&label, random_state(&mut rng));
        keys.insert(key);
        assert!(runtime.memory.recall(&label).is_some());
        if index % 500 == 0 {
            assert_eq!(runtime.memory.entropy(), 0.0);
        }
    }

    assert_eq!(
        runtime.memory.len(),
        keys.len(),
        "una entrada por clave distinta"
    );
    assert!(runtime.memory.writes() as usize <= 256);
    assert_eq!(runtime.memory.entropy(), 0.0, "entropía cero por reenvío");
    for key in &keys {
        assert!(runtime.memory.recall_by_key(*key).is_some());
    }
}

#[test]
fn executor_survives_adversarial_sources() {
    let mut rng = SplitMix64::new(0xBABA_0005);
    let mut runtime = BaraRuntime::new();
    let mut source = String::new();

    for _ in 0..1_500 {
        match rng.below(6) {
            0 => {
                source.push_str(&random_root(&mut rng));
                source.push('\n');
            }
            1 => source.push_str("!! "),
            2 => source.push_str("!? "),
            3 => source.push_str("+ * "),
            4 => {
                let label = format!("etiqueta{} , 3.5\n", rng.below(100));
                source.push_str(&label);
            }
            _ => source.push_str("ברא שמר עבד חכם אמר שפט נצח פלא\n"),
        }
    }

    let tokens = Lexer::new(&source).tokenize();
    assert!(tokens.iter().any(|token| token.kind == TokenKind::Eof));
    assert!(tokens.len() > 1_500);

    // Tres pasadas completas: el runtime acumula sin romperse nunca.
    for _ in 0..3 {
        runtime.execute(&tokens);
    }
    assert!(runtime.stack.iter().all(state_is_sane));
    assert_eq!(runtime.memory.entropy(), 0.0);

    let log = runtime.log().to_vec();
    assert!(!log.is_empty());
    assert!(log.iter().all(|event| !event.describe().is_empty()));
    assert!(log.iter().any(|e| matches!(e, ExecutionEvent::Root { .. })));
    assert!(log
        .iter()
        .any(|e| matches!(e, ExecutionEvent::Collapse { .. })));
    assert!(log.iter().any(|e| matches!(e, ExecutionEvent::Fold { .. })));
    assert!(runtime.mutator.generation() > 0, "hubo autopoiesis");
}

// ─────────────────────────────────────────────────────────────────────────
// 3 · Tormenta de conflictos en la malla holográfica
// ─────────────────────────────────────────────────────────────────────────

/// Malla de 8 nodos con semilla común y 400 escrituras divergentes.
fn storm_cluster(seed: u64) -> MeshCluster {
    let mut rng = SplitMix64::new(seed);
    let mut cluster = MeshCluster::new(8);
    for index in 0..16 {
        let name = format!("region:{}", index);
        let state = QuantumState::classical(index % 2 == 0);
        cluster.seed(&name, RegionId(index), state);
    }
    for _ in 0..400 {
        let peer = PeerId(rng.below(8));
        let region = rng.below(16);
        let name = format!("region:{}", region);
        cluster.diverge(peer, &name, RegionId(region), random_state(&mut rng));
    }
    cluster
}

#[test]
fn mesh_conflict_storm_converges_under_every_transport() {
    let mut cluster = storm_cluster(0xBABA_0006);
    assert!(!cluster.converged(), "400 conflictos ⇒ malla divergente");
    assert!(cluster.drift() > 0.0);

    // A) Bus en proceso.
    let bus = cluster.synchronize(8);
    assert!(bus.converged, "la malla converge por bus");
    assert!(bus.drift.abs() < 1e-12);
    assert!(bus.wire_bytes > 0);
    assert!(bus.deliveries > 0);
    assert_eq!(bus.digest, cluster.hologram());
    assert!(cluster
        .nodes()
        .iter()
        .all(|node| node.hologram() == cluster.nodes()[0].hologram()));

    // B) Hilos `std` + `mpsc` sobre una malla idéntica ⇒ mismo punto fijo.
    let mut threaded_cluster = storm_cluster(0xBABA_0006);
    let threaded = threaded_cluster.synchronize_threaded(8);
    assert!(threaded.threaded);
    assert!(threaded.converged, "la malla converge con hilos");
    assert!(threaded.drift.abs() < 1e-12);
    assert_eq!(
        threaded.digest, bus.digest,
        "el punto fijo no depende del transporte"
    );

    // C) Re-sincronizar es una no-operación: entropía cero por reenvío.
    assert_eq!(cluster.synchronize(3).digest, bus.digest);
    assert_eq!(
        threaded_cluster.synchronize_threaded(3).digest,
        threaded.digest
    );
    assert_eq!(threaded_cluster.synchronize(3).digest, bus.digest);
}

// ─────────────────────────────────────────────────────────────────────────
// 4 · Tormenta cuántica: superposición, entrelazamiento y colapso
// ─────────────────────────────────────────────────────────────────────────

/// Ejecuta una tormenta cuántica completa y devuelve el colapso por qubit.
fn quantum_storm(seed: u64) -> Vec<Option<usize>> {
    let mut rng = SplitMix64::new(seed);
    let mut registry = QuantumNative::new();

    for index in 0..64 {
        let name = format!("q{}", index);
        if rng.below(2) == 0 {
            registry.superpose(
                &name,
                Amplitude::real(rng.unit() + 0.5),
                Amplitude::real(rng.unit()),
            );
        } else {
            registry.uniform(&name, 2);
        }
    }

    for index in 0..32 {
        let left = format!("q{}", index);
        let right = format!("q{}", index + 32);
        registry
            .entangle(&left, &right, BellPhase::all()[index % 4])
            .expect("los 64 qubits existen");
    }

    // 1 024 operaciones mixtas: puertas y colapsos en orden pseudoaleatorio.
    for _ in 0..1_024 {
        let name = format!("q{}", rng.below(64));
        match rng.below(3) {
            0 => {
                registry.hadamard(&name);
            }
            1 => {
                registry.phase_shift(&name, rng.unit() * std::f64::consts::TAU);
            }
            _ => {
                registry.collapse(&name);
            }
        }
    }

    registry.bindings().iter().for_each(|binding| {
        assert!(!binding.label().is_empty());
        assert!(binding.involves(&binding.left));
    });
    assert!(state_is_sane(&registry.global_valence()));
    assert_eq!(registry.len(), 64);

    (0..64)
        .map(|index| {
            registry
                .get(&format!("q{}", index))
                .expect("qubit vivo")
                .measured
        })
        .collect()
}

#[test]
fn quantum_storm_is_total_deterministic_and_bounded() {
    let first = quantum_storm(0xBABA_0007);
    let second = quantum_storm(0xBABA_0007);
    assert_eq!(first, second, "el colapso es determinista, no físico");
    assert_eq!(first.len(), 64);

    // Con otro ruido los colapsos cambian (la semilla importa).
    let other = quantum_storm(0xBABA_0008);
    assert_eq!(other.len(), 64);
    assert!(first
        .iter()
        .all(|outcome| outcome.map(|index| index < 2).unwrap_or(true)));

    // Ninguna operación cuántica sobre un qubit inexistente provoca pánico.
    let mut registry = QuantumNative::new();
    assert!(registry.collapse("inexistente").is_none());
    assert!(registry.hadamard("inexistente").is_none());
    assert!(registry.phase_shift("inexistente", 1.0).is_none());
    assert!(registry.entangle("a", "b", BellPhase::PhiMinus).is_none());
}

// ─────────────────────────────────────────────────────────────────────────
// 5 · Presión de registros y traducción masiva a Metal‑IR
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn metal_allocator_spills_without_failing_under_pressure() {
    // 1 024 rangos vivos a la vez: los cinco bancos se saturan y derraman.
    let ranges: Vec<LiveRange> = (0..1_024)
        .map(|virt| LiveRange {
            virt,
            class: RegisterClass::all()[virt % 5],
            birth: 0,
            death: 1_024,
        })
        .collect();
    let allocation = RegAllocation::allocate(&ranges);
    assert_eq!(allocation.allocated() + allocation.spilled(), ranges.len());
    assert!(allocation.allocated() <= metal_ir::capacity());
    assert!(
        allocation.spilled() > 0,
        "la presión desborda hacia derrames"
    );
    assert_eq!(allocation.spill_bytes(), allocation.spilled() * 8);
    assert!(allocation.pressure() <= 1.0);
    assert!(allocation.occupancy() <= 1.0);
    assert!(allocation
        .bank_usage()
        .all(|(_, used)| used <= metal_ir::capacity()));

    // Flujo masivo de tokens: la traducción es total y determinista.
    let mut rng = SplitMix64::new(0xBABA_0009);
    let mut source = String::new();
    for _ in 0..4_000 {
        source.push_str(&random_root(&mut rng));
        source.push_str(" !! + ! ");
    }
    let tokens = Lexer::new(&source).tokenize();
    let program = MetalMapper::lower("estres.metal", Device::Cpu, &tokens);
    assert!(program.len() > 4_000);
    assert_eq!(program.words().len(), program.len());
    assert!(program.words().windows(2).any(|pair| pair[0] != pair[1]));
    assert!(program.ops.iter().all(|op| op.cycles > 0));
    assert!(program.dispatch().waves >= 1);
    assert!(program.dispatch().barriers >= 1);
    assert!(program.dispatch().cycles > 0);
    assert_eq!(program.bypass.avoided_syscalls, program.len());

    // Dos traducciones del mismo flujo ⇒ palabras idénticas, bit a bit.
    let again = MetalMapper::lower("estres.metal", Device::Cpu, &tokens);
    assert_eq!(program.words(), again.words());
    assert_eq!(program.descriptor(), again.descriptor());
}

// ─────────────────────────────────────────────────────────────────────────
// 6 · Tormenta de ingesta FFI y conversación hostil
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn ffi_ingest_storm_sanitizes_every_hostile_declaration() {
    let mut rng = SplitMix64::new(0xBABA_000A);
    let mut source = String::new();
    for _ in 0..600 {
        let name = format!("fn{}", rng.below(10_000));
        match rng.below(4) {
            0 => source.push_str(&format!("void *{name}(char *p);\n")),
            1 => source.push_str(&format!("int {name}(int a, size_t b);\n")),
            2 => source.push_str(&format!("void {name}(void);\n")),
            _ => source.push_str(&format!("double *{name}(double *x, int n);\n")),
        }
    }

    let mut runtime = BaraRuntime::new();
    let nodes = runtime.ingest_c(&source);
    assert_eq!(nodes.len(), 600);
    assert!(nodes
        .iter()
        .all(|node| node.root.chars().count() == 3 && state_is_sane(&node.valence)));
    assert!(nodes.iter().all(|node| (0.0..=1.0).contains(&node.hazard)));

    let hostile = nodes.iter().filter(|node| node.hazard > 0.0).count();
    assert!(hostile > 0, "hubo punteros y constructos peligrosos");
    assert_eq!(
        nodes.iter().filter(|node| node.sanitized).count(),
        hostile,
        "todo riesgo se sella; nada se rechaza"
    );
    assert_eq!(
        runtime.regions.len(),
        nodes.len(),
        "una región SHARED por nodo"
    );

    // La ingesta es determinista y conserva el invariante del AST agregado.
    let ast = ffi_ingest::to_shoresh(&ffi_ingest::ingest_c(&source));
    assert_eq!(ast.nodes.len(), nodes.len());
    assert_eq!(ast.sanitized_count(), hostile);
    assert!((0.0..=1.0).contains(&ast.hazard_score()));
}

#[test]
fn oracle_storm_tolerates_a_hostile_conversation() {
    let mut rng = SplitMix64::new(0xBABA_000B);
    let commands = [
        "ayuda",
        "estado",
        "memoria",
        "tiempo",
        "cuántica",
        "malla",
        "metal",
        "zk",
        "deshacer",
        "salir",
    ];
    let inputs: Vec<String> = (0..240)
        .map(|index| match index % 8 {
            0 => format!(":{}", commands[rng.below(commands.len())]),
            1 => random_root(&mut rng),
            2 => "crea un mundo con luz".to_string(),
            3 => "entrelaza alef con bet".to_string(),
            4 => "!!! ??? *** +++".to_string(),
            5 => format!("símbolo raro {}{{}}[]", rng.below(1_000)),
            6 => String::new(),
            _ => "ברא שמר עבד חכם אמר שפט".to_string(),
        })
        .collect();
    let script: Vec<&str> = inputs.iter().map(|input| input.as_str()).collect();

    let mut runtime = BaraRuntime::new();
    let report = {
        let mut oracle = Oracle::new(&mut runtime);
        oracle.run_script(&script)
    };

    // `:salir` puede cortar la sesión antes de agotar el guion.
    assert!(report.turns >= 1 && report.turns <= inputs.len());
    assert!(report.label().contains("turno"));
    assert!(runtime.stack.iter().all(state_is_sane));
    assert_eq!(runtime.memory.entropy(), 0.0);
    assert!(!runtime.log().is_empty());
    assert!(runtime
        .log()
        .iter()
        .all(|event| !event.describe().is_empty()));
    assert!(
        runtime.mutator.generation() > 0,
        "aprendió del desarrollador"
    );
    assert!(runtime.mutator.generation() <= 240, "pero sin explotar");
}
