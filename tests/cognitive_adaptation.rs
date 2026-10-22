//! Embeddings simbólicos, atención autopoiética y corrección formal.
//!
//! Las tres piezas tienen que repetir el mismo bit ante la misma entrada:
//! el vector sale de `𝔽ₚ`, el peso sale del orden de evaluación y la
//! anticipación sale de contar resoluciones, nunca de un reloj.

#![forbid(unsafe_code)]

use bara::ast_dna::{embed_node, embed_root};
use bara::autopoietic::{AutopoieticMutator, BelnapValue};
use bara::ffi_ingest::{BaraType, ShoreshNode};
use bara::inference::{InferenceEngine, ResolutionTactic, RuleKind};
use bara::lexer::Lexer;
use bara::neural_bridge::{conceptual_cosine, conceptual_euclidean, conceptual_milli};
use bara::runtime::BaraRuntime;
use bara::temporal_rollback::ResolutionOrigin;

fn nodo(root: &str) -> ShoreshNode {
    ShoreshNode {
        root: root.to_string(),
        original: root.to_string(),
        arity: 1,
        ret: BaraType::Truth,
        hazard: 0.0,
        valence: BelnapValue::True.to_state(),
        sanitized: false,
    }
}

#[test]
fn el_embedding_repite_el_mismo_vector_y_mide_cero_consigo() {
    let origen = embed_root("ברא");
    let otra = embed_root("ברא");
    let distinta = embed_root("שמר");
    assert_eq!(origen, otra);
    assert_ne!(origen, distinta);
    assert_eq!(embed_node(&nodo("שמר")), embed_node(&nodo("שמר")));
    assert_eq!(conceptual_milli(origen, otra), 1000);
    assert_eq!(conceptual_milli(origen, distinta), conceptual_milli(distinta, origen));
    assert_eq!(conceptual_cosine(origen, origen), 1.0);
    assert_eq!(conceptual_euclidean(origen, origen), 0.0);
    assert_eq!(conceptual_milli(origen, distinta), conceptual_milli(origen, distinta));
}

#[test]
fn la_atencion_prioriza_la_raiz_mas_evaluada_sin_reloj() {
    let source = "צור\nצור\nאבג\n";
    let mut first = BaraRuntime::new();
    let mut second = BaraRuntime::new();
    first.execute(&Lexer::new(source).tokenize());
    second.execute(&Lexer::new(source).tokenize());
    assert_eq!(first.mutator.attention_of("צור"), 7);
    assert_eq!(first.mutator.attention_of("אבג"), 4);
    assert_eq!(first.mutator.priority_root(), Some("צור"));
    assert_eq!(first.mutator.attention_total(), second.mutator.attention_total());
    assert_eq!(first.mutator.priority_root(), second.mutator.priority_root());
    assert_eq!(first.mutator.generation(), 2);
}

#[test]
fn el_juicio_repetido_anticipa_y_el_usuario_no_toca_el_nucleo() {
    let mut runtime = BaraRuntime::new();
    let source = "צור\n0\nשפט\nאבג\n0\nשפט\n";
    runtime.execute(&Lexer::new(source).tokenize());
    assert_eq!(runtime.timeline.resolution_len(), 2);
    assert!(runtime
        .timeline
        .resolutions()
        .iter()
        .all(|trace| trace.origin == ResolutionOrigin::Judge && !trace.seal));
    assert_eq!(
        runtime.correction.anticipate("B*F"),
        Some(ResolutionTactic::Split)
    );

    let generation = runtime.mutator.generation();
    runtime.accept_resolution("אבג", true);
    runtime.accept_resolution("אבג", true);
    assert_eq!(runtime.mutator.generation(), generation);
    assert_eq!(
        runtime.correction.anticipate("אבג"),
        Some(ResolutionTactic::Seal)
    );
    assert_eq!(runtime.timeline.resolutions().last().map(|trace| trace.origin), Some(ResolutionOrigin::User));
}

#[test]
fn la_historia_cambia_el_consejo_sin_cambiar_el_valor() {
    let mut engine = InferenceEngine::new();
    let left = match engine.assert(0, "א", BelnapValue::True) {
        Ok(id) => id,
        Err(error) => panic!("verdad: {error}"),
    };
    let right = match engine.assert(0, "ב", BelnapValue::False) {
        Ok(id) => id,
        Err(error) => panic!("falsedad: {error}"),
    };
    let joined = match engine.assert(1, "ג", BelnapValue::Neither) {
        Ok(id) => id,
        Err(error) => panic!("unión: {error}"),
    };
    assert!(engine
        .add_rule(left, joined, RuleKind::Fusion, BelnapValue::True, Some(right))
        .is_ok());
    let before = engine.evaluate();
    assert!(engine
        .resolutions()
        .iter()
        .flatten()
        .any(|item| item.root.as_str() == "ג" && item.tactic == ResolutionTactic::Split));
    engine.absorb("ג", true);
    engine.absorb("ג", true);
    let after = engine.evaluate();
    assert_eq!(before.both_count, after.both_count);
    assert!(engine
        .resolutions()
        .iter()
        .flatten()
        .any(|item| item.root.as_str() == "ג" && item.tactic == ResolutionTactic::Seal));
}

#[test]
fn anotar_atencion_en_el_sandbox_no_escribe_el_nucleo() {
    let mut sandbox = AutopoieticMutator::new(b"bara:pruebas:atencion");
    let before = sandbox.counters();
    sandbox.note_attention(0x11, 4);
    assert_eq!(
        sandbox.journal_tail(),
        Some("atencion fp=0000000000000011 peso=4")
    );
    assert_eq!(sandbox.counters(), before);
}
