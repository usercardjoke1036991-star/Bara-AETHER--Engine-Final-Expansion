//! # Puente cognitivo `end-to‑end` — Bara / AETHER‑Ω
//!
//! Verifica desde fuera del crate que la memoria a largo plazo, la inferencia y
//! el ciclo autopoiético se publican juntos en la sección canónica `nucleo`,
//! sin abrir secciones nuevas ni romper el manifiesto del IDE.
//!
//! ## Invariantes
//! * **Determinismo**: dos memorias con las mismas entradas tienen la misma
//!   huella; dos marcos iguales, el mismo digest.
//! * **Sin duplicados**: `insert` rechaza un segundo hecho sobre `(raíz, capa)`
//!   en lugar de sobrescribirlo en silencio.
//! * **Coherencia honesta**: el censo suma los nodos del informe, el de memoria
//!   sus entradas y un ciclo fusionado sólo es coherente si está auditado.
//! * **Frontera**: incrustar cognición en algo que no sea un objeto JSON
//!   devuelve `None`; nunca se reescribe el documento base.
//!
//! Cero `unsafe`, cero `unwrap`: las pruebas deciden con `assert!`/`matches!`.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

use bara::autopoiesis::{CycleReport, CycleVerdict};
use bara::autopoietic::BelnapValue;
use bara::inference::InferenceReport;
use bara::long_term_memory::{LongTermMemory, MemoryDraft};
use bara::neural_bridge::{
    embed, section_cognition, NeuralFrame, NEURAL_KEY, NEURAL_SCHEMA, NEURAL_SECTION,
};

fn report() -> InferenceReport {
    InferenceReport {
        nodes: 4,
        rules: 3,
        applied: 5,
        changed: 2,
        true_count: 2,
        false_count: 1,
        both_count: 0,
        neither_count: 1,
        derived: 1,
        layers_used: 2,
        truncated: false,
    }
}

fn memory() -> LongTermMemory {
    let mut memory = LongTermMemory::new();
    assert!(memory
        .insert(
            MemoryDraft::new("אמת", 0, BelnapValue::True)
                .hazard(120)
                .arity(2)
                .sanitized(true)
        )
        .is_ok());
    assert!(memory
        .insert(MemoryDraft::new("שקר", 1, BelnapValue::False))
        .is_ok());
    memory
}

fn cycle() -> CycleReport {
    let mut report = CycleReport::new("orden", 3, CycleVerdict::Committed { revision: 12 });
    report.proposal = Some(7);
    report.base_revision = 11;
    report.operations = 2;
    report.nodes = 4;
    report.audit_passed = 9;
    report.audit_total = 9;
    report.verdict = Some(BelnapValue::True);
    report
}

fn frame() -> NeuralFrame {
    NeuralFrame::new(7, report())
        .with_memory(&memory())
        .with_cycle(cycle())
}

#[test]
fn la_memoria_es_determinista_y_rechaza_duplicados() {
    let first = memory();
    let second = memory();
    assert_eq!(first.len(), 2);
    assert_eq!(first.census(), [1, 1, 0, 0]);
    assert_eq!(first.census().iter().sum::<usize>(), first.len());
    assert_eq!(first.hazard_total(), 120);
    assert_eq!(first.digest(), second.digest());
    assert!(first.capacity() >= 2);

    let mut duplicated = first.clone();
    let again = duplicated.insert(MemoryDraft::new("אמת", 0, BelnapValue::Both));
    assert!(again.is_err());
    assert_eq!(duplicated.len(), first.len());
    assert_eq!(duplicated.digest(), first.digest());
}

#[test]
fn el_marco_lleva_inferencia_memoria_y_ciclo() {
    let frame = frame();
    assert!(frame.is_coherent());
    assert_eq!(frame.census.total(), frame.report.nodes as u64);
    let body = frame.body();
    assert!(body.contains("\"esquema\":\"aether-omega/neural/1\""));
    assert!(body.contains("\"memoria\":{\"entradas\":2"));
    assert!(body.contains("\"ciclo\":{\"proposito\":\"orden\""));
    assert!(body.contains("\"resultado\":\"fusionado\""));
    assert!(body.contains("\"coherente\":true"));
    assert_eq!(body.matches('{').count(), body.matches('}').count());
    assert_eq!(frame.digest(), frame.clone().digest());
    assert_eq!(frame.fingerprint(), frame.clone().fingerprint());
}

#[test]
fn la_cognicion_viaja_dentro_de_nucleo() {
    let frame = frame();
    let section = match section_cognition(&frame) {
        Ok(section) => section,
        Err(error) => panic!("la sección canónica debe aceptar la cognición: {error}"),
    };
    assert_eq!(section.kind(), NEURAL_SECTION);
    assert_eq!(section.kind().name(), "nucleo");
    assert!(section.body().contains(NEURAL_KEY));
    assert!(section.body().contains(NEURAL_SCHEMA));

    let base = "{\"pila\":1,\"memoria\":2}";
    let merged = match embed(&frame, base) {
        Some(merged) => merged,
        None => panic!("un objeto JSON debe aceptar la incrustación"),
    };
    assert!(merged.starts_with("{\"pila\":1,\"memoria\":2,\"neuronal\":{"));
    assert!(merged.ends_with('}'));
    assert_eq!(merged.matches('{').count(), merged.matches('}').count());
}

#[test]
fn incrustar_rechaza_bases_que_no_son_objetos() {
    let frame = frame();
    for hostile in ["", "no-json", "[1,2]", "\"texto\"", "{"] {
        assert!(embed(&frame, hostile).is_none(), "aceptó: {hostile}");
    }
    let empty = match embed(&frame, "  {}  ") {
        Some(merged) => merged,
        None => panic!("un objeto vacío debe aceptar la incrustación"),
    };
    assert!(empty.starts_with("{\"neuronal\":{"));
    assert!(empty.ends_with('}'));
}
