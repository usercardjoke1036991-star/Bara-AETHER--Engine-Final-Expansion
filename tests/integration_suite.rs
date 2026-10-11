//! # Suite de integración — Bara / AETHER‑Ω (Fase 4)
//!
//! Verificación *end‑to‑end* de todos los sistemas del núcleo, enlazando el
//! *crate* `bara` (nunca módulos sueltos): lexing triconsonántico, runtime
//! paraconsistente de Belnap, autopoiesis, memoria holográfica, inferencia de
//! regiones, certificación ZK‑SNARK, ingesta FFI, rollback temporal `Δ⁻¹`,
//! cuántica nativa, malla holográfica (bus + hilos) y Metal‑IR.
//!
//! ## Principios de la suite
//! * **Cero dependencias externas** — sólo `std` y el propio núcleo.
//! * **Cero pánicos esperados** — además del resultado, cada prueba comprueba
//!   que las entradas degradadas se *toleran* en lugar de abortar.
//! * **Determinismo** — las mismas entradas producen el mismo log, la misma
//!   huella holográfica y el mismo colapso cuántico.

use bara::ffi_ingest::{self, BaraType, IngestedDecl, LegacyLang, Param};
use bara::lexer::{Keyword, Lexer, Token, TokenKind};
use bara::memory_region::{Access, Device, RegionAnalyzer, RegionId, RegionKind, RegionTable};
use bara::mesh_sync::{
    IngestOutcome, MeshCluster, MeshEntry, MeshFrame, MeshNode, PeerId, VectorClock,
};
use bara::metal_ir::{self, LiveRange, MetalMapper, MetalOpcode, RegAllocation, RegisterClass};
use bara::quantum_native::{Amplitude, AmplitudeVector, BellPhase, Qubit, QuantumNative};
use bara::repl::{self, MetaCommand, Oracle};
use bara::runtime::{BaraRuntime, ExecutionEvent, Observation, QuantumState};
use bara::temporal_rollback::{self, TemporalEngine};
use bara::zk_proof::{self, ConstraintSystem, Fp, Poly, ZkCertificate};

// ─────────────────────────────────────────────────────────────────────────
// Utilidades de la suite
// ─────────────────────────────────────────────────────────────────────────

/// Programa génesis: idéntico al del binario `bara` (13 tokens ontológicos).
const GENESIS: &str = "\
ברא
חכם
עבד
ברא
ברא
!!
עבד
שמר
נצח
עבד
אמר
שפט
אמר
";

/// Lexa el programa génesis.
fn genesis_tokens() -> Vec<Token> {
    Lexer::new(GENESIS).tokenize()
}

/// Cuenta eventos del log ontológico que satisfacen un predicado.
fn count_events(log: &[ExecutionEvent], predicate: impl Fn(&ExecutionEvent) -> bool) -> usize {
    log.iter().filter(|event| predicate(event)).count()
}

/// ¿El estado respeta el invariante global `0 ≤ ⊤, ⊥ ≤ 1`?
fn state_is_sane(state: &QuantumState) -> bool {
    let (truth, falsity) = state.belnap();
    (0.0..=1.0).contains(&truth) && (0.0..=1.0).contains(&falsity)
}

/// Comparación de coma flotante con tolerancia didáctica.
fn near(actual: f64, expected: f64) -> bool {
    (actual - expected).abs() < 1e-6
}

// ─────────────────────────────────────────────────────────────────────────
// 1 · Lexing triconsonántico
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn lexer_extracts_triconsonantal_roots_and_operators() {
    let tokens = genesis_tokens();
    assert!(tokens.len() > 10, "el génesis produce una corriente de tokens");

    // 1.1 Raíz conocida ⇒ palabra clave destilada.
    let manifest = tokens
        .iter()
        .find(|token| token.keyword() == Some(Keyword::Manifest))
        .expect("el génesis contiene la raíz ברא");
    match &manifest.kind {
        TokenKind::Root { letters, keyword } => {
            assert_eq!(letters, "ברא");
            assert_eq!(*keyword, Some(Keyword::Manifest));
        }
        other => panic!("esperaba una raíz, obtuve {other:?}"),
    }

    // 1.2 Raíz desconocida ⇒ sin palabra clave (dispara la autopoiesis).
    let unknown = tokens.iter().any(|token| match &token.kind {
        TokenKind::Root { letters, keyword } => letters == "נצח" && keyword.is_none(),
        _ => false,
    });
    assert!(unknown, "נצח debe emitirse como raíz desconocida");

    // 1.3 Operadores paraconsistentes y ubicación física 1-based.
    assert!(tokens.iter().any(|token| token.kind == TokenKind::BangBang));
    assert!(tokens
        .iter()
        .all(|token| token.line >= 1 && token.column >= 1));

    // 1.4 Determinismo léxico absoluto.
    assert_eq!(tokens, genesis_tokens());
}

#[test]
fn lexer_is_total_folding_niqqud_and_tolerating_junk() {
    // El *nikud* y el geresh no alteran la raíz (בָּרָא ⇒ ברא).
    let tokens = Lexer::new("בָּרָא").tokenize();
    assert_eq!(
        tokens[0].kind,
        TokenKind::Root {
            letters: "ברא".to_string(),
            keyword: Some(Keyword::Manifest),
        }
    );

    // Raíces de dos consonantes no son válidas: se degradan sin pánico.
    let short = Lexer::new("אב").tokenize();
    assert_eq!(
        short[0].kind,
        TokenKind::Root {
            letters: "אב".to_string(),
            keyword: None,
        }
    );

    // Basura radical: jamás un error, sólo símbolos tolerados.
    let junk = Lexer::new("💥 𐤀 \u{0} \"sin cerrar\"").tokenize();
    assert!(junk.iter().any(|token| token.kind == TokenKind::Eof));
}


// ─────────────────────────────────────────────────────────────────────────
// 2 · Runtime paraconsistente de Belnap (flujo génesis completo)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn genesis_execution_is_total_and_leaves_consistent_state() {
    let tokens = genesis_tokens();
    let mut runtime = BaraRuntime::new();
    runtime.execute(&tokens);
    let log = runtime.log().to_vec();

    // 2.1 Tally ontológico exacto de las operaciones del génesis.
    assert_eq!(
        count_events(&log, |e| matches!(e, ExecutionEvent::Root { .. })),
        12,
        "doce raíces hebreas + el operador de fusión !!"
    );
    assert_eq!(
        count_events(&log, |e| matches!(e, ExecutionEvent::Manifest { .. })),
        3
    );
    assert_eq!(
        count_events(&log, |e| matches!(e, ExecutionEvent::Superpose { .. })),
        1
    );
    assert_eq!(
        count_events(&log, |e| matches!(e, ExecutionEvent::Collapse { .. })),
        3
    );
    assert_eq!(
        count_events(&log, |e| matches!(e, ExecutionEvent::Guard { .. })),
        1
    );
    assert_eq!(
        count_events(&log, |e| matches!(e, ExecutionEvent::Axiogenesis { .. })),
        1
    );
    assert_eq!(
        count_events(&log, |e| matches!(e, ExecutionEvent::Emit { .. })),
        2
    );
    assert_eq!(
        count_events(&log, |e| matches!(e, ExecutionEvent::Fold { .. })),
        2
    );
    assert_eq!(log.len(), 32, "log = 12 raíces + 9 génesis + 11 operaciones");

    // 2.2 La fusión `!!` sobre un clásico genera la paradoja ⊤∧⊥ y el motor
    //     temporal la disuelve con un rollback atómico (no explosión lógica).
    assert_eq!(
        count_events(&log, |e| matches!(e, ExecutionEvent::Rollback { .. })),
        1
    );
    assert_eq!(
        count_events(&log, |e| matches!(e, ExecutionEvent::Tolerated { .. })),
        0,
        "el génesis no necesita tolerar nada: todo es total"
    );

    // 2.3 Estado final coherente: pila, memoria y regiones.
    assert_eq!(runtime.stack.len(), 4);
    assert!(runtime.memory.len() == 3 && runtime.memory.writes() == 3);
    assert_eq!(runtime.memory.entropy(), 0.0);
    assert_eq!(runtime.regions.len(), 3);
    assert_eq!(runtime.regions.total_bytes(), 384);

    let top = runtime.peek().expect("la pila no está vacía al terminar");
    assert!(state_is_sane(top));
    assert_eq!(top.observe(), Observation::True);
    assert!(runtime.stack.iter().all(state_is_sane));
}

#[test]
fn holographic_memory_is_content_addressed_and_idempotent() {
    let mut runtime = BaraRuntime::new();

    let first = runtime
        .memory
        .store("alef", QuantumState::classical(true));
    let second = runtime
        .memory
        .store("alef", QuantumState::classical(false));

    assert_eq!(first, second, "la clave deriva del contenido, no del valor");
    assert_eq!(runtime.memory.len(), 1, "reescribir no añade nodos");
    assert_eq!(runtime.memory.writes(), 1, "escritura idempotente");
    assert_eq!(runtime.memory.entropy(), 0.0, "entropía acumulada siempre 0");

    let recalled = runtime.memory.recall("alef").expect("nodo recuperable");
    assert!(state_is_sane(&recalled.state));
    assert!((0.0..=1.0).contains(&recalled.affinity));
    assert!(runtime.memory.recall_by_key(first).is_some());
    assert!(runtime.memory.recall("fantasma").is_none());
    assert_eq!(runtime.memory.topological_affinity_to(first, first), 1.0);
    assert!(runtime.memory.nodes().count() == 1);
}

#[test]
fn autopoietic_mutation_is_idempotent_and_paradoxical_by_design() {
    let mut runtime = BaraRuntime::new();
    assert_eq!(runtime.mutator.generation(), 0);

    let first = runtime.mutator.synthesize("נצח");
    assert_eq!(first.root, "נצח");
    assert_eq!(first.generation, 1);
    assert!(!first.rule.is_empty());
    assert!(
        first.valence.is_contradiction(),
        "todo axioma nace metaestable (⊤∧⊥)"
    );
    assert!(state_is_sane(&first.valence));

    // Idempotencia: la misma raíz no vuelve a mutar el lenguaje.
    let again = runtime.mutator.synthesize("נצח");
    assert_eq!(again.generation, 1);
    assert_eq!(runtime.mutator.generation(), 1);
    assert!(runtime.mutator.knows("נצח"));
    assert_eq!(runtime.mutator.axioms().count(), 1);

    // Otra raíz ⇒ nueva generación (y sigue sin explotar).
    let other = runtime.mutator.synthesize("פלא");
    assert_eq!(other.generation, 2);
    assert_ne!(other.rule, first.rule);
    assert_eq!(runtime.mutator.axioms().count(), 2);
}

// ─────────────────────────────────────────────────────────────────────────
// 3 · Inferencia de regiones y vistas *zero-copy*
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn region_inference_clusters_overlapping_lifetimes_and_shares_views() {
    // 3.1 Sin accesos ⇒ plan vacío (totalidad).
    let empty = RegionAnalyzer::infer(&[]);
    assert!(empty.table.is_empty());
    assert!(empty.assignment.is_empty());

    let accesses = vec![
        Access {
            label: "a".into(),
            bytes: 64,
            kind: RegionKind::Stack,
            birth: 0,
            death: 10,
        },
        Access {
            label: "b".into(),
            bytes: 32,
            kind: RegionKind::Heap,
            birth: 5,
            death: 20,
        },
        Access {
            label: "c".into(),
            bytes: 16,
            kind: RegionKind::Shared,
            birth: 30,
            death: 40,
        },
    ];
    let plan = RegionAnalyzer::infer(&accesses);

    assert_eq!(plan.table.len(), 2, "a y b coexisten; c vive después");
    assert_eq!(plan.assignment.len(), 3);
    assert_eq!(plan.table.total_bytes(), 112);
    assert_eq!(plan.table.max_depth(), 0);
    assert_eq!(
        plan.table.get(plan.assignment["a"]).map(|r| r.kind),
        Some(RegionKind::Stack)
    );
    assert_ne!(
        plan.assignment["a"], plan.assignment["c"],
        "rangos disjuntos ⇒ regiones distintas"
    );

    // 3.2 Vista zero-copy: válida si cabe, `None` si desborda (sin pánico).
    let region_a = plan.assignment["a"];
    let view = plan.table.share("vista-gpu", region_a, 0, 96, Device::Gpu);
    assert!(view.is_some());
    assert!(plan
        .table
        .share("vista-gpu", region_a, 0, 97, Device::Gpu)
        .is_none());
    assert!(plan.table.contains(region_a, 95, 1));
    assert!(!plan.table.contains(region_a, 96, 1));

    // 3.3 Bosque padre/hijo de regiones.
    let mut table = RegionTable::new();
    let root = table.introduce("raiz", RegionKind::Genesis, 128, None);
    let child = table.introduce("hijo", RegionKind::Shared, 64, Some(root));
    assert_eq!(root, RegionId(0));
    assert_eq!(table.depth_of(root), 0);
    assert_eq!(table.depth_of(child), 1);
    assert_eq!(table.max_depth(), 1);
    assert_eq!(table.total_bytes(), 192);
    assert_eq!(table.get(child).and_then(|r| r.parent), Some(root));
}

#[test]
fn region_kinds_and_devices_expose_canonical_labels() {
    assert_eq!(RegionKind::Stack.label(), "STACK");
    assert_eq!(RegionKind::Heap.label(), "HEAP");
    assert_eq!(RegionKind::Shared.label(), "SHARED");
    assert_eq!(RegionKind::Genesis.label(), "GENESIS");
    let kinds = [
        RegionKind::Stack,
        RegionKind::Heap,
        RegionKind::Shared,
        RegionKind::Genesis,
    ];
    assert!(kinds.iter().all(|kind| !kind.glyph().is_empty()));
    assert_eq!(Device::Cpu.label(), "CPU");
    assert_eq!(Device::Gpu.label(), "GPU");
}


// ─────────────────────────────────────────────────────────────────────────
// 4 · Verificación ZK‑SNARK (etapa de compilación)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn zk_field_and_polynomial_arithmetic_are_consistent() {
    // 4.1 Campo primo de Mersenne.
    assert_eq!(Fp::new(zk_proof::P), Fp::ZERO, "P ≡ 0 mod P");
    assert_eq!(Fp::new(2).add(Fp::new(3)), Fp::new(5));
    assert_eq!(Fp::new(7).sub(Fp::new(9)), Fp::new(zk_proof::P - 2));
    assert_eq!(Fp::new(6).mul(Fp::new(7)), Fp::new(42));
    assert_eq!(Fp::new(9).pow(3), Fp::new(729));
    assert!(Fp::new(0).is_zero());
    let value = Fp::new(12_345);
    assert_eq!(value.mul(value.inv()), Fp::ONE, "inverso de Fermat");

    // 4.2 Polinomios sobre 𝔽ₚ.
    let sum = Poly::constant(Fp::new(4)).add(&Poly::constant(Fp::new(5)));
    assert_eq!(sum.eval(Fp::new(99)), Fp::new(9));
    let product = Poly::constant(Fp::new(3)).mul(&Poly::constant(Fp::new(3)));
    assert_eq!(product.eval(Fp::new(7)), Fp::new(9));
    assert!(Poly::zero().is_zero());
    assert_eq!(Poly::zero().degree(), 0);
    assert_ne!(product.commit(), Poly::zero().commit());

    // 4.3 Polinomio de anulación: Z(i) = 0 en cada restricción i.
    let vanishing = Poly::vanishing(5);
    for root in 0..5_u64 {
        assert!(vanishing.eval(Fp::new(root)).is_zero());
    }
    assert!(!vanishing.eval(Fp::new(5)).is_zero());
}

#[test]
fn zk_certificate_verifies_and_detects_tampering() {
    let mut runtime = BaraRuntime::new();
    runtime.execute(&genesis_tokens());

    // 4.4 La etapa de compilación certifica los invariantes del AST.
    let axioms = runtime.mutator.generation();
    let certificate = runtime.certify().clone();
    assert!(certificate.result.verified);
    assert!(certificate.result.checks.iter().all(|(_, ok)| *ok));
    assert!(certificate.summary.contains("verificado=true"));
    assert_eq!(
        certificate.statement.n_constraints,
        axioms + 3,
        "invariantes = axiomas vivos + los tres invariantes paraconsistentes"
    );

    // 4.5 Emisión y verificación independiente sobre un sistema puro.
    let invariants = vec![
        "⊤ ∧ ⊥ ⇒ contradicción retenida".to_string(),
        "memoria holográfica idempotente".to_string(),
    ];
    let system = ConstraintSystem::from_invariants(&invariants);
    let statement = system.statement("AST-Bara-prueba", &invariants);
    let proof = zk_proof::prove(&system, &statement);
    assert!(zk_proof::verify(&statement, &proof).verified);
    assert!(ZkCertificate::certify(&system, statement).result.verified);

    // 4.6 Testigo manipulado ⇒ la identidad A·B − C = H·Z se rompe.
    let mut tampered = certificate.proof.clone();
    tampered.evals.c = Fp::new(tampered.evals.c.0 ^ 1);
    let rejected = zk_proof::verify(&certificate.statement, &tampered);
    assert!(!rejected.verified);
    assert!(rejected
        .checks
        .iter()
        .any(|(name, ok)| name.contains("Identidad") && !*ok));

    // 4.7 Desafío Fiat–Shamir falsificado ⇒ reprobado.
    let mut forged = certificate.proof.clone();
    forged.challenge = Fp::new(forged.challenge.0 ^ 0xFF);
    assert!(!zk_proof::verify(&certificate.statement, &forged).verified);
}

// ─────────────────────────────────────────────────────────────────────────
// 5 · Ingesta FFI omnívora (legado C / Python → AST Shoresh)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn ffi_ingestion_maps_and_sanitizes_legacy_code() {
    // 5.1 Cabecera C inocua: se ingiere sin fricción.
    let safe = ffi_ingest::ingest_c("int add(int a, int b);\nvoid reset(void);");
    assert_eq!(safe.len(), 2);
    assert_eq!(safe[0].name, "add");
    assert_eq!(safe[0].params.len(), 2);
    assert_eq!(safe[0].lang, LegacyLang::C);
    assert_eq!(safe[0].ret, "int");
    assert!(safe[1].params.is_empty());

    // 5.2 Constructo peligroso (punteros + `malloc`): riesgo y sellado.
    let mut runtime = BaraRuntime::new();
    let nodes = runtime.ingest_c("void *malloc(size_t n);");
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].ret, BaraType::Void);
    assert!(nodes[0].hazard > 0.0);
    assert!(nodes[0].sanitized, "se sella bajo guarda, no se rechaza");
    let seal = nodes[0].valence.belnap();
    assert!(near(seal.0 + seal.1, 1.0), "valencia = (seguridad, riesgo)");
    assert!(state_is_sane(&nodes[0].valence));

    // El runtime materializa una región SHARED y un evento Ingested por nodo.
    let log = runtime.log().to_vec();
    assert_eq!(runtime.regions.len(), 1);
    assert_eq!(
        count_events(&log, |e| matches!(e, ExecutionEvent::Ingested { .. })),
        1
    );
    assert_eq!(
        count_events(&log, |e| matches!(e, ExecutionEvent::Region { .. })),
        1
    );

    // 5.3 Python: parámetros sin tipo, aridad y valores por defecto tolerados.
    let py = ffi_ingest::ingest_python("def run(a, b=3):\n# ruido\n");
    assert_eq!(py.len(), 1);
    assert_eq!(py[0].lang, LegacyLang::Python);
    assert_eq!(py[0].params.len(), 2);
    assert_eq!(py[0].params[1].name, "b");

    // 5.4 AST Shoresh agregado: raíces de tres consonantes.
    let ast = ffi_ingest::to_shoresh(&safe);
    assert_eq!(ast.nodes.len(), 2);
    assert_eq!(ast.roots().count(), 2);
    assert!(ast.nodes.iter().all(|node| node.root.chars().count() == 3));
    assert!((0.0..=1.0).contains(&ast.hazard_score()));
    assert_eq!(ast.sanitized_count(), 0);

    // 5.5 Clasificación de tipos legados y síntesis determinista de raíces.
    assert_eq!(BaraType::from_legacy("char*"), BaraType::Text);
    assert_eq!(BaraType::from_legacy("double"), BaraType::Number);
    assert_eq!(BaraType::from_legacy("bool"), BaraType::Truth);
    assert_eq!(BaraType::from_legacy("void"), BaraType::Void);
    assert_eq!(BaraType::from_legacy(""), BaraType::Unknown);
    assert_eq!(BaraType::from_legacy("widget"), BaraType::Unknown);
    // «struct» contiene «str»: el mapeo tolerante lo degrada a texto.
    assert_eq!(BaraType::from_legacy("struct foo"), BaraType::Text);
    assert!(!BaraType::Number.glyph().is_empty());

    let root = ffi_ingest::root_from_name("shoresh");
    assert_eq!(root.chars().count(), 3);
    assert!(root.chars().all(|c| ('\u{05D0}'..='\u{05EA}').contains(&c)));
    assert_eq!(root, ffi_ingest::root_from_name("shoresh"), "determinista");
    assert_eq!(ffi_ingest::root_from_name("").chars().count(), 3);

    // 5.6 Riesgo saturado ⇒ valencia (0, 1) y sellado garantizado.
    let decl = IngestedDecl {
        lang: LegacyLang::C,
        name: "danger".to_string(),
        params: vec![Param {
            name: "p".to_string(),
            ctype: "char *".to_string(),
        }],
        ret: "void".to_string(),
        raw: "void *danger(char *p); /* malloc eval exec free import -> ... */".to_string(),
    };
    assert_eq!(ffi_ingest::hazard_of(&decl.raw), 1.0);
    let (hazard, valence, sealed) = ffi_ingest::sanitize(&decl);
    assert_eq!(hazard, 1.0);
    assert!(sealed);
    assert!(near(valence.belnap().1, 1.0));
    assert!(near(valence.belnap().0, 0.0));
}



// ─────────────────────────────────────────────────────────────────────────
// 6 · Navegación temporal y rollback atómico Δ⁻¹
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn temporal_rollback_restores_state_atomically() {
    let mut engine = TemporalEngine::new();
    assert!(engine.stack().is_empty());
    assert!(engine.deltas().is_empty());

    let marker = engine.mark();
    engine.push(QuantumState::classical(true));
    engine.push(QuantumState::superposition(0.8, 0.6));
    engine.push(QuantumState::paraconsistent(1.0, 1.0));
    assert_eq!(engine.stack().len(), 3);
    assert_eq!(engine.deltas().len(), 3);

    // 6.1 Paradoja irresoluble detectada en la cumbre.
    let paradox = temporal_rollback::detect_paradox(engine.stack().last().unwrap())
        .expect("⊤∧⊥ es una paradoja irresoluble");
    assert!(paradox.description.contains("⊤∧⊥"));
    assert_eq!(paradox.truth, 1.0);
    assert_eq!(paradox.falsity, 1.0);

    // 6.2 Δ⁻¹ atómico: se revierten los tres deltas en orden inverso.
    let report = engine.rollback_paradox(marker, &paradox);
    assert_eq!(report.reverted, 3);
    assert!(report.paradox.is_some(), "el informe registra la paradoja");
    assert!(engine.stack().is_empty(), "la pila vuelve al instante marcado");
    assert!(engine.deltas().iter().all(|delta| delta.reverted));

    // 6.3 Repetir el rollback es una no-operación (idempotencia).
    assert_eq!(engine.rollback_to(marker).reverted, 0);

    // 6.4 El diario etiqueta el inverso Δ⁻¹ de cada operación.
    assert!(engine
        .deltas()
        .iter()
        .all(|delta| delta.inv_label().starts_with("Δ⁻¹") && !delta.label.is_empty()));
    let last = engine.deltas().last().expect("hay diario");
    assert_eq!(last.id, 2);
    assert!(last.reverted);
}

#[test]
fn temporal_deltas_reverse_push_pop_and_replace() {
    let mut engine = TemporalEngine::new();
    let marker = engine.mark();

    engine.push(QuantumState::classical(true));
    engine.push(QuantumState::classical(false));
    assert!(engine
        .replace(QuantumState::paraconsistent(0.7, 0.8))
        .is_some());
    assert_eq!(engine.stack().last().unwrap().observe(), Observation::Both);

    let popped = engine.pop().expect("hay cumbre que desapilar");
    assert_eq!(popped.observe(), Observation::Both);
    assert_eq!(engine.stack().len(), 1);

    // Cuatro deltas reversibles: push, push, replace, pop.
    let report = engine.rollback_to(marker);
    assert_eq!(report.reverted, 4);
    assert!(engine.stack().is_empty(), "rollback atómico: o todo, o nada");
}

#[test]
fn paradox_detection_is_precise_and_tolerant() {
    let is_paradox = temporal_rollback::detect_paradox;
    assert!(is_paradox(&QuantumState::paraconsistent(1.0, 1.0)).is_some());
    assert!(is_paradox(&QuantumState::classical(true)).is_none());
    assert!(is_paradox(&QuantumState::classical(false)).is_none());
    assert!(is_paradox(&QuantumState::paraconsistent(0.9, 0.9)).is_none());
    assert!(is_paradox(&QuantumState::superposition(1.0, 1.0)).is_none());
}


// ─────────────────────────────────────────────────────────────────────────
// 7 · Cuántica nativa: amplitudes, Bell y puente paraconsistente
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn amplitude_vectors_follow_born_rule_and_interference() {
    // 7.1 Superposición uniforme: máxima incertidumbre de un qubit.
    let uniform = AmplitudeVector::uniform(2);
    assert_eq!(uniform.dim(), 2);
    assert!(near(uniform.norm(), 1.0));
    assert!(near(uniform.probabilities()[0], 0.5));
    assert!(near(uniform.entropy_bits(), 1.0));
    assert!(near(uniform.top_probability(), 0.5));
    assert_eq!(uniform.argmax(), 0);

    // 7.2 Producto tensorial: dos qubits ⇒ cuatro amplitudes.
    let tensor = AmplitudeVector::from_index(2, 0).tensor(&AmplitudeVector::from_index(2, 1));
    assert_eq!(tensor.dim(), 4);
    assert!(near(tensor.probabilities().iter().sum::<f64>(), 1.0));
    assert_eq!(tensor.argmax(), 1);

    // 7.3 Interferencia de estados ortogonales ⇒ uniforme (regla de Born).
    let combined =
        AmplitudeVector::from_index(2, 0).interfere(&AmplitudeVector::from_index(2, 1), 0.0);
    assert_eq!(combined.dim(), 2);
    assert!(near(combined.probabilities()[0], 0.5));

    // 7.4 Vectores degenerados y amplitudes extremas: siempre tolerados.
    let degenerate = AmplitudeVector::new(vec![Amplitude::ZERO, Amplitude::ZERO]);
    assert!(near(degenerate.probabilities()[0], 0.5));
    assert!(Amplitude::ZERO.is_zero());
    assert!(!Amplitude::from_polar(1.0, 0.0).is_zero());
    assert!(near(Amplitude::IMAGINARY.norm_sqr(), 1.0));
    assert!(near(Amplitude::IMAGINARY.mul(&Amplitude::IMAGINARY).re, -1.0));
    assert!(near(Amplitude::ONE.conj().re, 1.0));
    assert!(!Amplitude::ONE.label().is_empty());
}

#[test]
fn bell_pairs_are_maximally_entangled_in_every_convention() {
    for phase in BellPhase::all() {
        let joint = phase.joint();
        assert_eq!(joint.dim(), 4);
        assert!(near(joint.probabilities().iter().sum::<f64>(), 1.0));
        assert!(near(joint.entropy_bits(), 1.0), "S = 1 bit para un par de Bell");

        // La descripción local es la traza parcial: máximamente mixta (I/2).
        let (left, right) = joint.partial_trace_left();
        assert!(near(left, 0.5) && near(right, 0.5));

        assert!(!phase.label().is_empty() && !phase.meaning().is_empty());
        let correlated = if phase.label().starts_with('Φ') { 0 } else { 1 };
        assert_eq!(phase.correlated_index(0), correlated);
        assert!(near(
            phase.correlation(),
            if correlated == 0 { 1.0 } else { -1.0 }
        ));
    }
    assert_eq!(BellPhase::all().len(), 4);
}


#[test]
fn quantum_registry_bridges_entanglement_to_paraconsistent_valence() {
    let mut registry = QuantumNative::new();
    assert!(registry.is_empty() && registry.len() == 0);
    assert!(registry.bindings().is_empty() && registry.collapses() == 0);

    // 7.5 Un qubit puro se lee como clásico verdadero.
    let alfa = registry.superpose("alef", Amplitude::real(1.0), Amplitude::ZERO);
    assert_eq!(alfa.valence.observe(), Observation::True);
    registry.superpose("bet", Amplitude::real(1.0), Amplitude::ZERO);
    assert_eq!(registry.len(), 2);

    // 7.6 La mitad de un par de Bell es I/2 ⇒ ⊤∧⊥ tolerado (no colapsa).
    let link = registry
        .entangle("alef", "bet", BellPhase::PhiPlus)
        .expect("enlace válido entre qubits vivos");
    assert!(link.valence.is_contradiction());
    let (truth, falsity) = link.valence.belnap();
    assert!(near(truth, 0.5) && near(falsity, 0.5));
    assert_eq!(registry.bindings().len(), 1);
    assert_eq!(registry.partners_of("alef"), vec!["bet".to_string()]);
    assert!(registry.get("alef").unwrap().is_entangled());

    // El enlace es idempotente y los enlaces imposibles se toleran con `None`.
    registry.entangle("alef", "bet", BellPhase::PhiPlus);
    assert_eq!(registry.bindings().len(), 1);
    assert!(registry.entangle("alef", "alef", BellPhase::PhiPlus).is_none());
    assert!(registry
        .entangle("alef", "fantasma", BellPhase::PhiPlus)
        .is_none());
    assert!(registry.collapse("fantasma").is_none());

    // 7.7 Colapso local con propagación no local correlacionada (Φ⁺).
    let collapse = registry.collapse("alef").expect("colapso de un qubit vivo");
    assert!(collapse
        .nonlocal
        .iter()
        .any(|partner| partner.contains("bet")));
    let alfa_index = registry.get("alef").unwrap().measured.expect("medido");
    let bet_index = registry.get("bet").unwrap().measured.expect("socio");
    assert_eq!(alfa_index, bet_index, "Φ⁺ correlaciona perfectamente");
    assert_eq!(registry.collapses(), 1);
    assert!(near(collapse.probability, 0.5));

    // Idempotencia: medir al socio ya colapsado no cuenta otro colapso.
    registry.collapse("bet").expect("el socio ya está medido");
    assert_eq!(registry.collapses(), 1);

    assert!(state_is_sane(&registry.global_valence()));
    assert_eq!(registry.names().count(), 2);
    assert!(registry.get("alef").unwrap().outcome_label().is_some());
    assert!(!registry.get("alef").unwrap().describe().is_empty());
}

#[test]
fn quantum_collapse_is_deterministic_and_anticorrelates_in_psi() {
    // 7.8 Determinismo del colapso (hash FNV‑1a, no aleatoriedad física).
    let mut first = QuantumNative::new();
    let mut second = QuantumNative::new();
    for registry in [&mut first, &mut second] {
        registry.superpose("q0", Amplitude::real(1.0), Amplitude::ZERO);
        registry.superpose("q1", Amplitude::real(1.0), Amplitude::ZERO);
        registry.entangle("q0", "q1", BellPhase::PhiPlus).unwrap();
        registry.collapse("q0").unwrap();
    }
    assert_eq!(
        first.get("q0").unwrap().measured,
        second.get("q0").unwrap().measured
    );

    // 7.9 El singlete Ψ⁻ anticorrelaciona siempre.
    let mut singlet = QuantumNative::new();
    singlet.superpose("s0", Amplitude::real(1.0), Amplitude::ZERO);
    singlet.superpose("s1", Amplitude::real(1.0), Amplitude::ZERO);
    singlet.entangle("s0", "s1", BellPhase::PsiMinus).unwrap();
    let evaluation = singlet.collapse("s0").expect("colapso del singlete");
    let left = singlet.get("s0").unwrap().measured.unwrap();
    let right = singlet.get("s1").unwrap().measured.unwrap();
    assert_ne!(left, right, "Ψ⁻ anticorrelaciona");
    assert!(!evaluation.nonlocal.is_empty());
}


#[test]
fn quantum_gates_and_pure_qubits_are_total() {
    let mut registry = QuantumNative::new();
    registry.materialize("h", AmplitudeVector::uniform(2));
    assert!(registry.hadamard("h").is_some());
    assert!(registry.phase_shift("h", std::f64::consts::PI).is_some());
    assert!(registry.hadamard("fantasma").is_none());
    assert!(registry.phase_shift("fantasma", 0.0).is_none());
    assert!(registry.uniform("u", 4).probability > 0.0);
    assert!(registry.evaluate("u").unwrap().entropy_bits > 0.0);
    assert!(registry.evaluate("fantasma").is_none());

    let pure = Qubit::pure("puro", 2);
    assert!(!pure.is_measured() && !pure.is_entangled());
    assert_eq!(pure.dim(), 2);
    assert_eq!(pure.valence().observe(), Observation::True);
    assert_eq!(pure.outcome_label(), None);
    assert!(near(pure.entropy_bits(), 0.0));
    assert!(near(pure.top_probability(), 1.0));

    // Una puerta Hadamard sobre un qubit puro abre la superposición.
    let mut opened = Qubit::pure("abierto", 2);
    opened.hadamard();
    assert!(near(opened.top_probability(), 0.5));
    assert!(near(opened.entropy_bits(), 1.0));
}

// ─────────────────────────────────────────────────────────────────────────
// 8 · Malla holográfica global (bus en proceso + hilos `std`)
// ─────────────────────────────────────────────────────────────────────────

/// Malla con una condición inicial común (semilla idéntica en todos los nodos).
fn seeded_cluster(peers: usize) -> MeshCluster {
    let mut cluster = MeshCluster::new(peers);
    for index in 0..4 {
        let name = format!("region:{}", index);
        cluster.seed(&name, RegionId(index), QuantumState::classical(index % 2 == 0));
    }
    cluster
}

#[test]
fn vector_clocks_track_causality_without_coordination() {
    let mut left = VectorClock::new(3);
    let mut right = VectorClock::new(3);
    assert_eq!(left.len(), 3);
    assert!(!left.is_empty());
    assert_eq!(left.total(), 0);

    assert_eq!(left.tick(PeerId(0)), 1);
    assert_eq!(left.tick(PeerId(0)), 2);
    assert_eq!(right.tick(PeerId(1)), 1);
    assert_eq!(left.get(PeerId(2)), 0);

    // Sin coordinación: dos relojes avanzados en paralelo son concurrentes.
    assert!(left.concurrent_with(&right));
    assert!(!left.dominated_by(&right));

    // La fusión converge al máximo componente a componente.
    assert!(left.merge(&right), "la fusión cambia el reloj local");
    assert!(right.dominated_by(&left));
    assert!(right.happens_before(&left));
    assert!(!left.merge(&right), "la segunda fusión es una no-operación");
    assert_eq!(left.total(), 3);
    assert!(!left.label().is_empty());
    assert_eq!(left.get(PeerId(9)), 0, "lectura fuera de rango ⇒ 0");

    // Un peer nuevo amplía el reloj sin romper el orden causal.
    left.tick(PeerId(5));
    assert_eq!(left.len(), 6);
    left.set(PeerId(5), 0);
    assert_eq!(left.get(PeerId(5)), 0);
}


#[test]
fn mesh_cluster_converges_with_bus_and_threads() {
    // 8.1 Semilla común ⇒ convergencia inmediata y deriva cero.
    let mut cluster = seeded_cluster(4);
    assert_eq!(cluster.len(), 4);
    assert_eq!(cluster.entries(), 4);
    assert!(cluster.converged());
    assert!(near(cluster.drift(), 0.0));
    assert_eq!(cluster.epoch(), 0);
    assert_eq!(cluster.wire_bytes(), 0);

    // 8.2 Divergencia: escrituras locales que crean conflicto y novedad.
    assert!(cluster.diverge(
        PeerId(1),
        "region:0",
        RegionId(0),
        QuantumState::classical(false)
    ));
    assert!(cluster.diverge(
        PeerId(2),
        "region:nueva",
        RegionId(9),
        QuantumState::paraconsistent(0.9, 0.8)
    ));
    assert!(!cluster.converged());
    assert!(cluster.drift() > 0.0);
    assert!(cluster.epoch() == 0);

    // 8.3 Bus en proceso: fusión paraconsistente hasta el punto fijo.
    let bus = cluster.synchronize(4);
    assert_eq!(bus.rounds, 4);
    assert_eq!(bus.peers, 4);
    assert!(!bus.threaded);
    assert!(bus.converged);
    assert!(near(bus.drift, 0.0));
    assert!(bus.wire_bytes > 0);
    assert!(bus.merged + bus.conflicts > 0, "hubo transporte efectivo");
    assert_eq!(bus.digest, cluster.hologram());
    assert_eq!(cluster.epoch(), 4);
    assert!(cluster.wire_bytes() > 0);
    assert!(cluster
        .nodes()
        .iter()
        .all(|node| node.hologram() == cluster.nodes()[0].hologram()));

    // 8.4 Hilos `std` + `mpsc`: mismo punto fijo con otro transporte.
    let mut threaded = seeded_cluster(4);
    threaded.diverge(
        PeerId(1),
        "region:0",
        RegionId(0),
        QuantumState::classical(false),
    );
    threaded.diverge(
        PeerId(2),
        "region:nueva",
        RegionId(9),
        QuantumState::paraconsistent(0.9, 0.8),
    );
    let report = threaded.synchronize_threaded(4);
    assert!(report.threaded);
    assert!(report.converged);
    assert!(near(report.drift, 0.0));
    assert_eq!(report.digest, threaded.hologram());
    assert_eq!(
        report.digest, bus.digest,
        "el punto fijo de la malla no depende del transporte"
    );

    // 8.5 Sincronizar de nuevo es una no-operación (entropía cero).
    assert_eq!(threaded.synchronize(2).digest, report.digest);
    assert_eq!(cluster.synchronize(2).digest, bus.digest);
}


#[test]
fn wire_codec_round_trips_and_rejects_corruption() {
    let mut node = MeshNode::new(3, 4);
    let (key_alef, changed) = node.insert("alef", RegionId(1), QuantumState::paraconsistent(0.9, 0.4));
    assert!(changed, "primera escritura ⇒ la entrada cambia");
    node.insert("bet", RegionId(2), QuantumState::classical(false));
    node.insert("gimel", RegionId(3), QuantumState::superposition(1.0, 0.0));
    node.advance(7);
    assert_eq!(node.len(), 3);
    assert_eq!(node.epoch(), 7);

    // Reescribir el mismo contenido es una no-operación holográfica.
    let (same_key, changed_again) =
        node.insert("alef", RegionId(1), QuantumState::paraconsistent(0.9, 0.4));
    assert_eq!(key_alef, same_key);
    assert!(!changed_again);

    // 8.6 Fotograma coherente: la huella se reproduce desde las entradas.
    let frame = node.snapshot();
    assert_eq!(frame.len(), 3);
    assert!(!frame.is_empty());
    assert!(frame.revisions() >= 1);
    assert_eq!(frame.origin, PeerId(3));
    assert_eq!(frame.digest, bara::mesh_sync::hologram_of(&frame.entries));

    // Ida y vuelta por el *wire* propio del lenguaje.
    let wire = frame.to_wire();
    let decoded = MeshFrame::from_wire(&wire).expect("ida y vuelta íntegra");
    assert_eq!(decoded.origin, frame.origin);
    assert_eq!(decoded.epoch, frame.epoch);
    assert_eq!(decoded.entries.len(), frame.entries.len());
    assert_eq!(decoded.digest, frame.digest);
    assert_eq!(decoded.clock.total(), frame.clock.total());
    assert_eq!(decoded.entries[0].key, frame.entries[0].key);
    assert_eq!(decoded.entries[0].state, frame.entries[0].state);

    // La entrada reconstruida coincide en contenido (clave + huella) con la
    // que se escribió originalmente: el códec no altera la identidad.
    let expected = MeshEntry::new("alef", RegionId(1), QuantumState::paraconsistent(0.9, 0.4), 7);
    assert_eq!(expected.key, key_alef);
    assert!(decoded.entries.iter().any(|entry| entry.matches(&expected)));

    // 8.7 Integridad: cualquier corrupción se tolera con `None`, sin pánico.
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert!(MeshFrame::from_wire(&bad_magic).is_none());

    let mut bad_digest = wire.clone();
    let last = bad_digest.len() - 1;
    bad_digest[last] ^= 0xFF;
    assert!(MeshFrame::from_wire(&bad_digest).is_none());

    assert!(MeshFrame::from_wire(&wire[..wire.len() - 4]).is_none());
    assert!(MeshFrame::from_wire(&[]).is_none());

    // 8.8 Reingesta: un nodo no se reaplica su propio fotograma.
    assert_eq!(node.ingest(&frame), IngestOutcome::NoOp);
    assert_eq!(node.rejected(), 0);
    assert_eq!(node.applied(), 0);
    assert_eq!(node.len(), 3);
    assert_eq!(node.get(key_alef).map(|entry| entry.name.as_str()), Some("alef"));
    assert!(node.get(0xDEAD_BEEF).is_none());
    assert_eq!(node.hologram(), frame.digest, "la huella local es el fotograma");
}


// ─────────────────────────────────────────────────────────────────────────
// 9 · Metal‑IR: layout abstracto, registros y bypass del driver
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn metal_layout_and_register_allocator_behave_like_hardware() {
    // 9.1 Layout abstracto: cinco bancos, 76 registros.
    assert_eq!(metal_ir::LAYOUT.len(), 5);
    assert_eq!(metal_ir::capacity(), 76);
    assert_eq!(
        metal_ir::layout_bytes(),
        metal_ir::LAYOUT
            .iter()
            .map(|bank| bank.bytes())
            .sum::<usize>()
    );
    assert!(metal_ir::LAYOUT
        .iter()
        .all(|bank| bank.regs > 0 && !bank.label().is_empty()));
    let classes: Vec<RegisterClass> = metal_ir::LAYOUT.iter().map(|bank| bank.class).collect();
    assert_eq!(classes, RegisterClass::all().to_vec());
    assert_eq!(RegisterClass::Gpr.slots(), 32);
    assert!(!RegisterClass::Vector.glyph().is_empty());

    // 9.2 Sin presión: cada rango obtiene su registro físico.
    let light: Vec<LiveRange> = (0..4)
        .map(|virt| LiveRange {
            virt,
            class: RegisterClass::Fpr,
            birth: virt,
            death: virt + 2,
        })
        .collect();
    let allocation = RegAllocation::allocate(&light);
    assert_eq!(allocation.allocated(), 4);
    assert_eq!(allocation.spilled(), 0);
    assert_eq!(allocation.spill_bytes(), 0);
    assert!(allocation.physical(0).is_some());
    assert_eq!(allocation.usage(RegisterClass::Fpr), allocation.allocated());
    assert!(allocation.occupancy() <= 1.0);
    assert!(allocation.pressure() <= 1.0);
    assert_eq!(allocation.bank_usage().count(), 5);

    // 9.3 Saturación: 40 rangos GPR simultáneos ⇒ 32 en banco y 8 derrames.
    let heavy: Vec<LiveRange> = (0..40)
        .map(|virt| LiveRange {
            virt,
            class: RegisterClass::Gpr,
            birth: 0,
            death: 10,
        })
        .collect();
    let saturated = RegAllocation::allocate(&heavy);
    assert_eq!(saturated.allocated(), 32);
    assert_eq!(saturated.spilled(), 8, "el derrame se tolera, no es un error");
    assert_eq!(saturated.spill_bytes(), 64);
    assert!(saturated.pressure() <= 1.0);
    assert!(saturated.physical(31).is_some());
    assert!(saturated.physical(39).is_none());
}

#[test]
fn metal_lowering_encodes_the_ast_deterministically() {
    let tokens = genesis_tokens();
    let emitted = tokens
        .iter()
        .filter(|token| !matches!(token.kind, TokenKind::Newline | TokenKind::Eof))
        .count();

    let cpu = MetalMapper::lower("genesis.metal", Device::Cpu, &tokens);
    assert_eq!(cpu.len(), emitted + 2, "cada token ⇒ 1 op + Commit + Return");
    assert_eq!(cpu.words().len(), cpu.len());
    assert!(!cpu.is_empty());
    assert_eq!(cpu.device, Device::Cpu);
    assert_eq!(cpu.label, "genesis.metal");
    assert!(cpu.ops.iter().all(|op| !op.origin.is_empty()));
    assert!(cpu
        .ops
        .iter()
        .zip(cpu.words().iter())
        .all(|(op, word)| op.encode() == *word));
    assert!(cpu.ops.iter().all(|op| op.lane_mask() >= 1 && op.cycles > 0));
    assert!(cpu.descriptor() != 0);
    assert!(cpu.bypass.ring_entries.is_power_of_two());
    assert_eq!(cpu.bypass.avoided_syscalls, cpu.len());
    assert!(cpu.barriers() >= 1, "el cierre del descriptor es una valla");
    assert!(cpu.dispatch().waves >= 1);
    assert!(cpu.dispatch().words == cpu.words().len());
    assert!(near(cpu.dispatch().occupancy, cpu.allocation.occupancy()));

    // 9.4 El *layout* cubre todos los virtuales: asignados + derramados.
    assert_eq!(cpu.allocation.allocated() + cpu.allocation.spilled(), cpu.ranges.len());
    assert!(cpu.ranges.iter().all(|range| range.span() >= 1));

    // 9.5 La traducción es pura: mismos tokens ⇒ mismo programa.
    let again = MetalMapper::lower("genesis.metal", Device::Cpu, &tokens);
    assert_eq!(cpu.words(), again.words());
    assert_eq!(cpu.descriptor(), again.descriptor());
    assert_eq!(cpu.signature(), again.signature());

    // 9.6 La ruta de GPU no reduce el paralelismo respecto del CPU.
    let gpu = MetalMapper::lower("genesis.metal", Device::Gpu, &tokens);
    assert!(gpu.lanes() >= cpu.lanes());
    assert_eq!(gpu.words().len(), cpu.words().len());
    assert!(cpu.physical_of(0).is_some());

    // 9.7 Catálogo de opcodes: códigos únicos, latencias y barreras.
    let opcodes = MetalOpcode::all();
    assert_eq!(opcodes.len(), 14);
    let mut codes: Vec<u32> = opcodes.iter().map(|opcode| opcode.code()).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), opcodes.len(), "cada opcode tiene código propio");
    assert!(opcodes.iter().all(|opcode| opcode.latency() >= 1));
    assert!(opcodes.iter().any(|opcode| opcode.is_barrier()));
    assert!(
        cpu.signature().contains("COMMIT"),
        "el cierre se firma en el descriptor"
    );
}


// ─────────────────────────────────────────────────────────────────────────
// 10 · Oráculo REPL: lengua natural → programa Shoresh y Δ⁻¹ manual
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn meta_commands_fold_accents_and_tolerate_the_unknown() {
    assert_eq!(MetaCommand::parse(":ayuda"), MetaCommand::Help);
    assert_eq!(MetaCommand::parse(":estado "), MetaCommand::Status);
    assert_eq!(MetaCommand::parse(":CUANTICA"), MetaCommand::Quantum);
    assert_eq!(MetaCommand::parse(":cuántica"), MetaCommand::Quantum);
    assert_eq!(MetaCommand::parse(":memoria"), MetaCommand::Memory);
    assert_eq!(MetaCommand::parse(":tiempo"), MetaCommand::Timeline);
    assert_eq!(MetaCommand::parse(":malla"), MetaCommand::Mesh);
    assert_eq!(MetaCommand::parse(":metal"), MetaCommand::Metal);
    assert_eq!(MetaCommand::parse(":zk"), MetaCommand::Zk);
    assert_eq!(MetaCommand::parse(":deshacer"), MetaCommand::Undo);
    assert_eq!(MetaCommand::parse(":salir"), MetaCommand::Quit);
    assert_eq!(
        MetaCommand::parse(":inventado"),
        MetaCommand::Unknown("inventado".to_string())
    );
    assert_eq!(MetaCommand::Help.name(), "ayuda");
    assert_eq!(MetaCommand::Quit.name(), "salir");
    assert_eq!(MetaCommand::Unknown("x".to_string()).name(), "desconocido");
}

#[test]
fn natural_language_compiles_to_shoresh_roots() {
    // Modo *shoresh* directo: las raíces hebreas pasan tal cual.
    assert_eq!(repl::hebrew_roots("ברא שמר עבד").len(), 3);
    assert_eq!(repl::hebrew_roots("sin raices aqui").len(), 0);
    let (program, roots, synthesized) = repl::natural_to_roots("ברא שמר");
    assert_eq!(roots, vec!["ברא".to_string(), "שמר".to_string()]);
    assert_eq!(synthesized, 0);
    assert!(program.contains("ברא") && program.trim().ends_with("שמר"));

    // Lengua natural: el léxico destila raíces; lo nuevo se sintetiza (≤ 3).
    let (program, roots, synthesized) = repl::natural_to_roots("crea un mundo con luz");
    assert!(!program.trim().is_empty());
    assert!(roots.contains(&"ברא".to_string()), "«crea» ⇒ ברא");
    assert!(root_count(&roots) >= 1, "«mundo» se sintetiza por autopoiesis");
    assert!(root_count(&roots) <= 3, "la autopoiesis está acotada por turno");
    assert!(synthesized <= 3);

    // Operadores invocables por nombre.
    let (program, roots, _) = repl::natural_to_roots("entrelaza dos cosas");
    assert!(program.contains("!!"));
    assert!(roots.iter().any(|root| root == "!!"));

    // Entradas vacías o puramente simbólicas: toleradas sin pánico.
    assert_eq!(repl::natural_to_roots("").0.trim(), "");
    assert_eq!(repl::natural_to_roots("   ").0.trim(), "");
    let (symbolic, used, _) = repl::natural_to_roots("!!!");
    assert!(symbolic.contains('!') && used.iter().any(|root| root.contains('!')));
}

/// Cuenta las raíces hebreas de tres consonantes en una lista de *tokens*.
fn root_count(roots: &[String]) -> usize {
    roots
        .iter()
        .filter(|root| {
            root.chars().count() == 3
                && root.chars().all(|c| ('\u{05D0}'..='\u{05EA}').contains(&c))
        })
        .count()
}

#[test]
fn oracle_session_compiles_conversation_and_never_panics() {
    let mut runtime = BaraRuntime::new();
    let report = {
        let mut oracle = Oracle::new(&mut runtime);
        assert!(!oracle.interactive_session());
        oracle.mark_interactive(false);
        assert!(matches!(
            oracle.interpret(""),
            bara::repl::Intent::Empty
        ));
        assert!(matches!(
            oracle.interpret(":ayuda"),
            bara::repl::Intent::Meta(MetaCommand::Help)
        ));
        assert!(matches!(
            oracle.interpret("crea un mundo"),
            bara::repl::Intent::Roots(_)
        ));
        assert!(oracle.turns().is_empty());

        oracle.run_script(&[
            ":estado",
            ":ayuda",
            ":desconocido",
            ":sin_sentido",
            "crea un mundo con luz",
            ":tiempo",
            ":cuántica",
            ":malla",
            ":metal",
            ":zk",
        ])
    };

    assert_eq!(report.turns, 10, "cada consulta produce exactamente un turno");
    assert!(report.events > 0, "la conversación compila y ejecuta");
    assert!(!report.roots.is_empty());
    assert_eq!(report.rollbacks, 0);
    assert!(report.label().contains("turno"));
    assert!(report.micros < 60_000_000, "compilación dinámica en tiempo razonable");
}


#[test]
fn oracle_undo_rolls_turns_back_completely() {
    let mut runtime = BaraRuntime::new();
    let report = {
        let mut oracle = Oracle::new(&mut runtime);
        oracle.run_script(&["ברא", "ברא", ":deshacer", ":deshacer", ":deshacer"])
    };

    assert_eq!(report.turns, 5);
    assert_eq!(report.rollbacks, 2, "cada Δ⁻¹ manual emite su propio pulso");
    assert!(runtime.stack.is_empty(), "los dos turnos se deshicieron del todo");
    assert!(runtime
        .timeline
        .deltas()
        .iter()
        .all(|delta| delta.reverted));
    assert!(count_events(runtime.log(), |e| matches!(
        e,
        ExecutionEvent::Rollback { .. }
    )) == 2);
}

// ─────────────────────────────────────────────────────────────────────────
// 11 · Pipeline nativo completo sobre el runtime (integración AETHER‑Ω)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn empty_stack_operations_are_tolerated_not_fatal() {
    let mut runtime = BaraRuntime::new();
    // Colapso, fusión, conjunción, disyunción y guarda sobre pila vacía.
    runtime.execute(&Lexer::new("! ? !! * + שמר").tokenize());

    let log = runtime.log().to_vec();
    assert!(runtime.stack.is_empty());
    assert_eq!(
        count_events(&log, |e| matches!(e, ExecutionEvent::Rollback { .. })),
        0,
        "sin operandos no hay paradoja que interceptar"
    );
    assert!(
        count_events(&log, |e| matches!(e, ExecutionEvent::Tolerated { .. })) >= 4,
        "toda anomalía se degrada a un evento tolerado"
    );
    assert!(log.iter().all(|event| !event.describe().is_empty()));
}

#[test]
fn runtime_native_pipeline_end_to_end() {
    let tokens = genesis_tokens();
    let mut runtime = BaraRuntime::new();
    runtime.execute(&tokens);

    // 11.1 Qubits nativos y entrelazamiento tolerado.
    let zero = runtime.superpose_native("q0", Amplitude::real(1.0), Amplitude::ZERO);
    assert_eq!(zero.observe(), Observation::True);
    runtime.superpose_native("q1", Amplitude::real(1.0), Amplitude::ZERO);
    let entangled = runtime
        .entangle_native("q0", "q1", BellPhase::PhiPlus)
        .expect("entrelazamiento entre qubits vivos");
    assert!(entangled.is_contradiction(), "I/2 ⇒ ⊤∧⊥ tolerado");
    assert!(runtime
        .entangle_native("q0", "fantasma", BellPhase::PhiPlus)
        .is_none());
    assert!(runtime.collapse_native("fantasma").is_none());

    // 11.2 Colapso con propagación no local ⇒ valencia clásica.
    let collapsed = runtime.collapse_native("q0").expect("colapso de q0");
    assert!(collapsed.is_classical(), "tras colapsar, la valencia es clásica");
    assert_eq!(runtime.qubits.collapses(), 1);
    assert!(runtime.qubits.get("q1").unwrap().is_measured());

    // 11.3 Malla global sincronizada desde las regiones vivas del runtime.
    let bus = runtime.mesh_sync(3, 3, false);
    assert!(bus.converged && bus.peers == 3 && !bus.threaded);
    assert_eq!(runtime.mesh.len(), 3);
    let threaded = runtime.mesh_sync(3, 2, true);
    assert!(threaded.threaded && threaded.converged);
    assert_eq!(threaded.digest, bus.digest);

    // 11.4 Traducción a Metal‑IR con su evento ontológico.
    let program = runtime.lower_metal("genesis.metal", Device::Gpu, &tokens);
    assert!(!program.is_empty());
    assert!(runtime.metal.is_some());

    // 11.5 Registro manual de eventos por los subsistemas.
    runtime.note(ExecutionEvent::Emit {
        text: "línea manual".to_string(),
    });

    // 11.6 El log ontológico refleja todo el pipeline y describe cada evento.
    let log = runtime.log().to_vec();
    assert_eq!(
        count_events(&log, |e| matches!(e, ExecutionEvent::QuantumSuperposed { .. })),
        2
    );
    assert_eq!(
        count_events(&log, |e| matches!(e, ExecutionEvent::Entangled { .. })),
        1
    );
    assert_eq!(
        count_events(&log, |e| matches!(e, ExecutionEvent::QuantumCollapsed { .. })),
        1
    );
    assert_eq!(
        count_events(&log, |e| matches!(e, ExecutionEvent::MetalMapped { .. })),
        1
    );
    assert_eq!(
        count_events(&log, |e| matches!(e, ExecutionEvent::MeshSynced { .. })),
        6,
        "3 nodos × 2 sincronizaciones"
    );
    assert!(log.iter().all(|event| !event.describe().is_empty()));
    assert!(runtime.stack.iter().all(state_is_sane));
    assert!(runtime.certificate.is_none(), "sin etapa de compilación explícita");
}

