//! Ingesta de un directorio de proyecto en cartas *Shoresh*.
//!
//! El fragmento suelto sigue acotado por [`transmute`](crate::transmuter::transmute).
//! Este módulo recorre un árbol ya canonizado y parte cada archivo en ventanas
//! de [`MAX_FRAGMENT_BYTES`]. Cada ventana entra primero por la gramática nativa
//! (`syntax`). Si no hay declaraciones ni llamadas, queda el clasificador.

#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use crate::ffi_ingest::ShoreshNode;
use crate::neural_bridge::{survey, TopoView};
use crate::syntax;
use crate::transmuter::{transmute_stream, SourceLanguage, MAX_FRAGMENT_BYTES};

/// Extensiones que el lote reconoce. El orden es el de desempate, no el de lectura.
pub const PROJECT_EXTENSIONS: [&str; 13] = [
    "c", "cc", "cpp", "go", "h", "hpp", "js", "jsx", "py", "rs", "sol", "ts", "tsx",
];

/// Profundidad máxima del recorrido.
const MAX_DEPTH: usize = 24;

/// Archivos que se abren en una pasada. El resto se cuenta y no se lee.
const MAX_FILES: usize = 4_000;

/// Nodos que se conservan para la carta. El resto se cuenta en `omitted_nodes`.
const NODE_KEEP: usize = 4_096;

/// Directorios que no se recorren.
const EXCLUDED_DIRS: [&str; 3] = ["target", "node_modules", ".git"];

/// Resultado determinista de un directorio.
#[derive(Debug, Clone)]
pub struct ProjectTransmutation {
    /// Archivos de código abiertos.
    pub files: usize,
    /// Archivos que quedaron fuera de [`MAX_FILES`].
    pub omitted_files: usize,
    /// Ventanas de [`MAX_FRAGMENT_BYTES`] clasificadas.
    pub chunks: usize,
    /// Sentencias clasificadas en todas las ventanas.
    pub statements: usize,
    /// Nodos *Shoresh* conservados, en orden de archivo.
    pub nodes: Vec<ShoreshNode>,
    /// Nodos que no cupieron en [`NODE_KEEP`].
    pub omitted_nodes: usize,
    /// Carta métrica de los nodos conservados.
    pub topology: TopoView,
    /// Etiquetas de lenguaje presentes, ordenadas.
    pub languages: Vec<&'static str>,
}

/// Recorre `root` y transmuta cada archivo admitido.
///
/// Los enlaces simbólicos no se siguen. Un directorio que, ya canonizado,
/// queda fuera de la raíz se ignora. El orden de lectura es el de la ruta
/// relativa, no el del sistema de archivos.
pub fn transmute_workspace_dir(root: &Path) -> Result<ProjectTransmutation, String> {
    let root = fs::canonicalize(root).map_err(|err| {
        format!(
            "no se pudo canonizar «{}»: {err}",
            root.display()
        )
    })?;
    let meta = fs::symlink_metadata(&root)
        .map_err(|err| format!("no se pudo inspeccionar «{}»: {err}", root.display()))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err("la raíz del lote no es un directorio".to_string());
    }

    let mut files = Vec::new();
    let mut omitted_files = 0usize;
    collect(&root, &root, 0, &mut files, &mut omitted_files)?;
    files.sort();

    let mut nodes = Vec::new();
    let mut omitted_nodes = 0usize;
    let mut chunks = 0usize;
    let mut statements = 0usize;
    let mut languages: Vec<&'static str> = Vec::new();

    for path in &files {
        let language = language_of(path);
        let tag = language.tag();
        if !languages.contains(&tag) {
            languages.push(tag);
        }
        let (piece_chunks, piece_statements, piece_nodes) = stream_file(path, language)?;
        chunks = chunks.saturating_add(piece_chunks);
        statements = statements.saturating_add(piece_statements);
        for node in piece_nodes {
            if nodes.len() < NODE_KEEP {
                nodes.push(node);
            } else {
                omitted_nodes = omitted_nodes.saturating_add(1);
            }
        }
    }
    languages.sort_unstable();

    let topology = survey(&nodes);
    Ok(ProjectTransmutation {
        files: files.len(),
        omitted_files,
        chunks,
        statements,
        nodes,
        omitted_nodes,
        topology,
        languages,
    })
}

/// Lenguaje del lote a partir de la extensión, sin mirar el contenido.
pub fn language_of_extension(ext: &str) -> SourceLanguage {
    match ext.to_ascii_lowercase().as_str() {
        "rs" => SourceLanguage::Rust,
        "ts" | "js" | "tsx" | "jsx" => SourceLanguage::JavaScript,
        "py" => SourceLanguage::Python,
        "sol" => SourceLanguage::Solidity,
        "c" | "h" | "cc" | "cpp" | "hpp" => SourceLanguage::C,
        "go" => SourceLanguage::Go,
        _ => SourceLanguage::Unknown,
    }
}

fn language_of(path: &Path) -> SourceLanguage {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(language_of_extension)
        .unwrap_or(SourceLanguage::Unknown)
}

fn collect(
    root: &Path,
    dir: &Path,
    depth: usize,
    files: &mut Vec<PathBuf>,
    omitted_files: &mut usize,
) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Ok(());
    }
    let entries = fs::read_dir(dir).map_err(|err| {
        format!("no se pudo enumerar «{}»: {err}", dir.display())
    })?;
    for entry in entries {
        let entry = entry.map_err(|err| format!("entrada ilegible: {err}"))?;
        let path = entry.path();
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(_) => continue,
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if meta.is_dir() {
            if EXCLUDED_DIRS.contains(&name.as_ref()) {
                continue;
            }
            let canon = match fs::canonicalize(&path) {
                Ok(canon) => canon,
                Err(_) => continue,
            };
            if !canon.starts_with(root) {
                continue;
            }
            collect(root, &canon, depth.saturating_add(1), files, omitted_files)?;
        } else if meta.is_file() && is_project_file(&path) {
            if files.len() >= MAX_FILES {
                *omitted_files = omitted_files.saturating_add(1);
            } else {
                files.push(path);
            }
        }
    }
    Ok(())
}

fn is_project_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| {
            PROJECT_EXTENSIONS
                .iter()
                .any(|candidate| ext.eq_ignore_ascii_case(candidate))
        })
        .unwrap_or(false)
}

fn stream_file(
    path: &Path,
    language: SourceLanguage,
) -> Result<(usize, usize, Vec<ShoreshNode>), String> {
    let file = File::open(path)
        .map_err(|err| format!("no se pudo abrir «{}»: {err}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let mut window = String::new();
    let mut chunks = 0usize;
    let mut statements = 0usize;
    let mut nodes = Vec::new();

    loop {
        line.clear();
        let read = reader
            .read_line(&mut line)
            .map_err(|err| format!("no se pudo leer «{}»: {err}", path.display()))?;
        if read == 0 {
            break;
        }
        if line.len() > MAX_FRAGMENT_BYTES {
            if !window.is_empty() {
                absorb_window(&window, language, &mut chunks, &mut statements, &mut nodes);
                window.clear();
            }
            let mut start = 0usize;
            while start < line.len() {
                let mut end = (start + MAX_FRAGMENT_BYTES).min(line.len());
                while end > start && !line.is_char_boundary(end) {
                    end -= 1;
                }
                if end == start {
                    end = (start + 1).min(line.len());
                }
                let piece = line.get(start..end).unwrap_or("");
                absorb_window(piece, language, &mut chunks, &mut statements, &mut nodes);
                start = end;
            }
            continue;
        }
        if !window.is_empty() && window.len().saturating_add(line.len()) > MAX_FRAGMENT_BYTES {
            absorb_window(&window, language, &mut chunks, &mut statements, &mut nodes);
            window.clear();
        }
        window.push_str(&line);
    }
    if !window.is_empty() {
        absorb_window(&window, language, &mut chunks, &mut statements, &mut nodes);
    }
    Ok((chunks, statements, nodes))
}

fn absorb_window(
    window: &str,
    language: SourceLanguage,
    chunks: &mut usize,
    statements: &mut usize,
    nodes: &mut Vec<ShoreshNode>,
) {
    if window.trim().is_empty() {
        return;
    }
    let parsed = syntax::parse(language, window);
    if parsed.statement_count() > 0 {
        *chunks = chunks.saturating_add(1);
        *statements = statements.saturating_add(parsed.statement_count());
        nodes.extend(parsed.into_nodes(language));
        return;
    }
    let transmutation = transmute_stream(window, language);
    *chunks = chunks.saturating_add(1);
    *statements = statements.saturating_add(transmutation.report.statements);
    nodes.extend(transmutation.ast.nodes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn las_extensiones_del_ide_entran_en_el_lote() {
        for ext in ["jsx", "tsx", "c", "h", "cc", "hpp"] {
            assert!(
                PROJECT_EXTENSIONS.contains(&ext),
                "{ext} tiene que entrar en el lote"
            );
            assert_ne!(language_of_extension(ext), SourceLanguage::Unknown);
        }
        assert_eq!(language_of_extension("tsx"), SourceLanguage::JavaScript);
        assert_eq!(language_of_extension("hpp"), SourceLanguage::C);
        assert_eq!(language_of_extension("bara"), SourceLanguage::Unknown);
    }
}
