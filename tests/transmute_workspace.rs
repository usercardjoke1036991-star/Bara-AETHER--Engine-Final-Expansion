//! El lote de un directorio no hereda el tope de 256 sentencias.

#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;

use bara::transmute_engine::transmute_workspace_dir;
use bara::transmuter::MAX_FRAGMENT_BYTES;

fn scratch(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("bara-lote-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("directorio");
    path
}

#[test]
fn un_directorio_heterogeneo_produce_una_carta_determinista() {
    let root = scratch("mixto");
    fs::write(root.join("lib.rs"), "fn visible() { return 1; }\n").expect("rs");
    fs::write(root.join("app.ts"), "function main() { return 1; }\n").expect("ts");
    fs::write(root.join("app.py"), "def main():\n    return 1\n").expect("py");
    fs::write(
        root.join("Token.sol"),
        "pragma solidity ^0.8.0;\ncontract Token { function transfer() public {} }\n",
    )
    .expect("sol");
    fs::write(root.join("main.cpp"), "int main() { return 0; }\n").expect("cpp");
    fs::write(root.join("main.go"), "package main\nfunc main() {}\n").expect("go");
    fs::write(root.join("app.js"), "function ping() { return 1; }\n").expect("js");
    fs::create_dir_all(root.join("target")).expect("target");
    fs::write(root.join("target/oculto.rs"), "fn oculto() {}\n").expect("oculto");

    let first = transmute_workspace_dir(&root).expect("lote");
    let second = transmute_workspace_dir(&root).expect("repeticion");
    assert_eq!(first.files, 7);
    assert_eq!(second.files, first.files);
    assert_eq!(second.statements, first.statements);
    assert!(first.statements > 0);
    assert!(!first.nodes.is_empty());
    assert_eq!(first.topology.nodes, second.topology.nodes);
    assert_eq!(first.topology.cohesion_milli, second.topology.cohesion_milli);
    assert!(first.languages.windows(2).all(|pair| pair[0] <= pair[1]));
    assert!(first.languages.contains(&"sol"));
    assert!(first.languages.contains(&"rs"));

    fs::remove_dir_all(&root).expect("limpiar");
}

#[test]
fn un_archivo_mayor_que_una_ventana_se_lee_entero() {
    let root = scratch("ancho");
    let line = "fn paso() { return 1; }\n";
    let repeats = (MAX_FRAGMENT_BYTES / line.len()) + 64;
    fs::write(root.join("largo.rs"), line.repeat(repeats)).expect("largo");

    let project = transmute_workspace_dir(&root).expect("lote");
    assert!(project.chunks > 1);
    assert!(project.statements > 256);

    fs::remove_dir_all(&root).expect("limpiar");
}
