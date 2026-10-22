//! Neurotopología estructural: la carta del AST, la distancia y el `Both`
//! que nace de un solape. Misma entrada, misma carta, mismo consejo.

#![forbid(unsafe_code)]

use bara::autopoietic::BelnapValue;
use bara::ffi_ingest::{BaraType, ShoreshNode};
use bara::inference::{InferenceEngine, ResolutionTactic, RuleKind};
use bara::neural_bridge::{root_edit_distance, survey, topological_distance};
use bara::runtime::QuantumState;
use bara::topology::AstChart;

fn nodo(root: &str, arity: usize) -> ShoreshNode {
    ShoreshNode {
        root: root.to_string(),
        original: root.to_string(),
        arity,
        ret: BaraType::Truth,
        hazard: 0.0,
        valence: QuantumState::classical(true),
        sanitized: false,
    }
}

#[test]
fn la_carta_es_determinista_y_el_solape_acerca_la_raiz_repetida() {
    let nodes = [nodo("ברא", 1), nodo("שמר", 1), nodo("ברא", 1)];
    let first = survey(&nodes);
    let second = survey(&nodes);
    assert_eq!(first, second);
    assert_eq!(first.nodes, 3);
    assert!(first.overlaps >= 1);
    assert!(first.alert);
    assert_eq!(first.nearest, 2);
    assert_eq!(first.focus.as_str(), "ברא");
    assert_eq!(first.neighbor.as_str(), "ברא");
    assert_eq!(root_edit_distance("ברא", "ברא"), 0);
    assert!(root_edit_distance("ברא", "שמר") > 0);
}

#[test]
fn raices_distintas_no_comparten_residuo() {
    let chart = AstChart::from_nodes(&[nodo("ברא", 0), nodo("שמר", 2)]);
    let points = chart.points();
    let left = points.first().expect("origen");
    let right = points.get(1).expect("destino");
    let distance = topological_distance(left, right);
    assert_eq!(chart.overlaps(), 0);
    assert!(distance > 1);
    assert_eq!(distance, topological_distance(left, right));
    let again = AstChart::from_roots(&["ברא", "שמר"]);
    assert_eq!(again.overlaps(), 0);
    assert_eq!(again.len(), 2);
}

#[test]
fn el_solape_eleva_both_y_el_vecindario_separa_sin_colapsar() {
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
    assert!(engine.raise_overlap("ג"));
    assert_eq!(engine.overlap_marks(), 1);
    assert_eq!(
        engine.node(joined).map(|node| node.value),
        Some(BelnapValue::Both)
    );
    assert_eq!(
        engine.neighborhood_tactic("ג"),
        Some(ResolutionTactic::Split)
    );
    let advice = engine.resolutions();
    assert!(advice.iter().flatten().any(|item| {
        item.root.as_str() == "ג" && item.tactic == ResolutionTactic::Split
    }));
    let after = engine.report(before.applied, before.changed);
    assert!(after.both_count >= before.both_count);
    assert!(engine.node_count() > 0);
}
