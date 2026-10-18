//! # Transmutador universal: pruebas de integración
//!
//! Verifican el contrato público de [`bara::transmuter`]: totalidad (ninguna
//! entrada produce un pánico), pureza (todo AST entregado pasa la auditoría
//! Shoresh), determinismo (mismo fragmento, mismo árbol) y cuarentena explícita
//! de lo hostil o ilegible. Sin `unsafe`, `unwrap` ni `expect`.

#![forbid(unsafe_code)]

use bara::ffi_ingest::BaraType;
use bara::transmuter::{
    detect_language, transmute, transmute_bytes, Concept, SourceLanguage, Transmutation,
    MAX_FRAGMENT_BYTES, MAX_STATEMENTS,
};

/// Huella estructural de un AST: todo lo que la auditoría examina y algo más.
///
/// Se comparan bits de `f64` (`to_bits`) para que el determinismo sea exacto y
/// no dependa del redondeo de `==`.
type NodePrint = (String, String, usize, BaraType, u64, u64, u64, bool);

fn fingerprint(out: &Transmutation) -> Vec<NodePrint> {
    out.ast
        .nodes
        .iter()
        .map(|node| {
            (
                node.root.clone(),
                node.original.clone(),
                node.arity,
                node.ret,
                node.hazard.to_bits(),
                node.valence.truth_mass().to_bits(),
                node.valence.falsity_mass().to_bits(),
                node.sanitized,
            )
        })
        .collect()
}

/// ¿La raíz es triconsonántica? (Tres consonantes hebreas, ni una más.)
fn triconsonantal(root: &str) -> bool {
    let mut chars = root.chars();
    let (first, second, third, rest) = (chars.next(), chars.next(), chars.next(), chars.next());
    rest.is_none()
        && [first, second, third]
            .iter()
            .all(|slot| matches!(slot, Some(ch) if ('\u{05d0}'..='\u{05ea}').contains(ch)))
}

#[test]
fn el_ejemplo_del_modulo_es_admisible() {
    let out = transmute("def f(x):\n    return x + 1\n");
    assert!(
        out.is_admissible(),
        "el ejemplo del módulo debe ser admisible"
    );
    assert_eq!(out.report.language, SourceLanguage::Python);
    assert_eq!(out.report.statements, 2);
    assert_eq!(out.report.accepted, 2);
    // Designados = ⊤ + (⊤∧⊥); ninguno se pierde ni se cuenta dos veces.
    assert_eq!(
        out.report.both + out.report.true_count,
        out.report.accepted,
        "la partición de Belnap debe ser exacta"
    );
    assert_eq!(out.report.rejected, 0);
    assert_eq!(out.report.quarantined, 0);
    assert_eq!(out.report.audit_total_rules, 9);
    assert_eq!(out.report.audit_passed_rules, 9);
    assert!(out.report.audit_passed);
}

#[test]
fn todos_los_lenguajes_producen_un_ast_admisible() {
    let samples = [
        ("const x = 1;\nconsole.log(x);", SourceLanguage::JavaScript),
        ("def f(x):\n    return x + 1\n", SourceLanguage::Python),
        ("fn main() { println!(\"hola\"); }", SourceLanguage::Rust),
        ("package main\nfunc main() { x := 1 }", SourceLanguage::Go),
        ("public class App { int x = 1; }", SourceLanguage::Java),
        (
            "using System;\nConsole.WriteLine(\"hola\");",
            SourceLanguage::CSharp,
        ),
        (
            "#include <stdio.h>\nint main() { printf(\"hola\"); }",
            SourceLanguage::C,
        ),
        (
            "SELECT nombre FROM usuarios WHERE id = 1;",
            SourceLanguage::Sql,
        ),
        ("#!/bin/sh\necho hola\n", SourceLanguage::Shell),
    ];

    for (fragment, expected) in samples {
        assert_eq!(
            detect_language(fragment),
            expected,
            "detección fallida para «{fragment}»"
        );
        let out = transmute(fragment);
        assert!(out.is_admissible(), "AST no admisible para «{fragment}»");
        assert!(
            !out.ast.nodes.is_empty(),
            "un fragmento con control de flujo no puede quedar vacío"
        );
        assert_eq!(
            out.report.audit_passed_rules, out.report.audit_total_rules,
            "auditoría incompleta para «{fragment}»"
        );
        assert!(
            out.report.statements >= 1,
            "el segmentador perdió todas las sentencias de «{fragment}»"
        );
    }
}

#[test]
fn las_raices_son_unicas_y_triconsonanticas() {
    let out =
        transmute("let a = 1;\nif a == 1 { print(a); }\nfor i in 0..3 { a += i; }\nreturn a;\n");
    assert!(out.is_admissible());

    let mut seen: Vec<&str> = Vec::new();
    for node in &out.ast.nodes {
        assert!(
            triconsonantal(&node.root),
            "raíz no triconsonántica: «{}»",
            node.root
        );
        assert!(
            !seen.contains(&node.root.as_str()),
            "raíz repetida: «{}» (la auditoría exige una por concepto)",
            node.root
        );
        seen.push(&node.root);
        assert!(node.original.starts_with("extern:"), "sin trazabilidad");
        assert!(node.original.len() > "extern:".len());
    }
    assert!(!seen.is_empty());
}

#[test]
fn el_mismo_fragmento_produce_el_mismo_ast() {
    let sample = "const x = 1;\nif (x == 1) { console.log(\"ok\"); }\nreturn x;\n";
    let first = transmute(sample);
    let second = transmute(sample);
    assert_eq!(fingerprint(&first), fingerprint(&second));
    assert_eq!(first.report, second.report, "el informe debe ser idéntico");
}

#[test]
fn el_fragmento_vacio_no_inventa_axiomas() {
    for empty in ["", "   ", "\n\t\n", "// sólo un comentario\n"] {
        let out = transmute(empty);
        assert!(out.ast.nodes.is_empty(), "«{empty}» produjo nodos");
        assert!(!out.is_admissible(), "«{empty}» no puede ser admisible");
        assert!(!out.report.audit_passed);
        assert_eq!(
            out.report.audit_passed_rules, 8,
            "sólo debe fallar «plan.no-vacio»"
        );
        assert_eq!(out.report.statements, 0);
    }
}

#[test]
fn lo_hostil_va_a_cuarentena_sellada() {
    // 300 ‰ (borrado recursivo) + 250 ‰ (destrucción de tabla) = 550 ‰.
    let out = transmute("rm -rf / && drop table usuarios");
    assert_eq!(out.report.accepted, 0, "lo hostil no puede entrar");
    assert_eq!(out.report.rejected, 1);
    assert_eq!(out.report.false_count, 1);
    assert_eq!(out.report.quarantined, 1);
    assert_eq!(out.ast.nodes.len(), 1);
    let node = &out.ast.nodes[0];
    assert_eq!(node.root, Concept::Quarantine.root());
    assert!(node.sanitized, "el nodo de cuarentena debe ir sellado");
    assert!(node.hazard >= 0.5);
    assert!(node.valence.falsity_mass() >= 0.5);
    assert!(node.valence.truth_mass() <= 0.5);
    assert!(out.is_admissible(), "la cuarentena es un parche admisible");
    assert_eq!(out.report.audit_passed_rules, 9);
}

#[test]
fn lo_ilegible_se_degrada_a_cuarentena() {
    // Cadena sin cerrar: el segmentador no adivina, se rinde y confina.
    let out = transmute("x = \"sin cerrar");
    assert_eq!(out.report.accepted, 0);
    assert_eq!(out.report.quarantined, 1);
    assert_eq!(out.ast.nodes.len(), 1);
    assert_eq!(out.ast.nodes[0].root, Concept::Quarantine.root());
    assert!(out.ast.nodes[0].sanitized);
    assert!(out.is_admissible());

    // Delimitadores desbalanceados, mismo destino.
    let out = transmute("if (x {");
    assert_eq!(out.report.accepted, 0);
    assert_eq!(out.ast.nodes[0].root, Concept::Quarantine.root());
    assert_eq!(out.report.statements, 0);
}

#[test]
fn la_cuarentena_agrupa_todo_lo_no_designado() {
    // Dos expresiones sueltas: ambas `∅`, pero un solo nodo de cuarentena.
    let out = transmute("x + y\nfoo bar\n");
    assert_eq!(out.report.neither, 2);
    assert_eq!(out.report.accepted, 0);
    assert_eq!(out.report.rejected, 2);
    assert_eq!(out.report.quarantined, 1, "la cuarentena no crece sin cota");
    assert_eq!(out.ast.nodes.len(), 1);
    assert_eq!(out.ast.nodes[0].root, Concept::Quarantine.root());
    assert!(
        out.ast.nodes[0].original.contains("(+1)"),
        "la traza debe declarar las sentencias agrupadas: {}",
        out.ast.nodes[0].original
    );
}

#[test]
fn el_limite_de_sentencias_deja_una_cerca() {
    let long = "x = 1;\n".repeat(MAX_STATEMENTS + 32);
    let out = transmute(&long);
    assert!(out.report.truncated);
    assert_eq!(out.report.statements, MAX_STATEMENTS);
    assert_eq!(out.report.accepted, MAX_STATEMENTS);
    assert_eq!(out.ast.nodes.len(), 2, "asignación + cerca");
    assert_eq!(out.ast.nodes[1].root, Concept::Fence.root());
    assert!(
        !out.ast.nodes[1].sanitized,
        "la cerca no es peligrosa: sólo marca el borde"
    );
    assert!(out.is_admissible());
}

#[test]
fn el_limite_de_bytes_se_respeta_en_la_frontera_de_caracter() {
    // Mitad del límite en «ñ» (2 bytes cada una) más holgura: corta sin romper.
    let long = "ñ".repeat(MAX_FRAGMENT_BYTES / 2 + 64);
    let out = transmute(&long);
    assert!(out.report.truncated);
    assert_eq!(
        out.ast.nodes.last().map(|node| node.root.as_str()),
        Some(Concept::Fence.root())
    );
    assert!(out.is_admissible());
}

#[test]
fn los_bytes_invalidos_se_sustituyen_sin_panico() {
    let raw = [0xff_u8, 0xfe, b'x', b' ', b'=', b' ', b'1'];
    let out = transmute_bytes(&raw);
    assert!(out.report.lossy, "los bytes inválidos deben declararse");
    assert!(out.is_admissible());
    assert_eq!(out.report.language, SourceLanguage::Unknown);
    assert_eq!(out.report.accepted, 1);

    // Bytes válidos: no se marca pérdida.
    let out = transmute_bytes(b"x = 1;");
    assert!(!out.report.lossy);
    assert!(!out.report.truncated);

    // Entrada gigante: se acota y se declara.
    let big = vec![b'a'; MAX_FRAGMENT_BYTES + 16];
    let out = transmute_bytes(&big);
    assert!(out.report.truncated);
    assert_eq!(
        out.ast.nodes.last().map(|node| node.root.as_str()),
        Some(Concept::Fence.root())
    );
}

#[test]
fn el_ast_entregado_siempre_es_auditable() {
    let samples = [
        "let a = 1;\nif a == 1 { print(a); }\n",
        "rm -rf / && drop table usuarios",
        "x + y",
        "",
        "open(f); read(f); close(f);",
    ];
    for sample in samples {
        let out = transmute(sample);
        assert_eq!(out.report.audit_total_rules, 9, "«{sample}»");
        if out.ast.nodes.is_empty() {
            // Sin nodos sólo puede fallar «plan.no-vacio»; el resto es vacuo.
            assert_eq!(
                out.report.audit_passed_rules, 8,
                "«{sample}»: un AST vacío no puede fallar más reglas"
            );
            assert!(!out.report.audit_passed);
        } else {
            assert_eq!(
                out.report.audit_passed_rules, 9,
                "«{sample}» produjo un AST que la auditoría rechaza"
            );
            assert!(out.report.audit_passed);
        }
        assert_eq!(out.is_admissible(), !out.ast.nodes.is_empty());
    }
}
