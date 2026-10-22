//! Auditoría en reposo de un archivo ya parseado.
//!
//! Busca una declaración repetida con el mismo texto y propone dejar una sola
//! copia. La propuesta sólo sale si el archivo resultante sigue equilibrado y
//! el nombre queda una vez: el valor de Belnap es `∅`. No hay hilos ni reloj.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use crate::syntax::{self, SourceSymbol};
use crate::transmuter::SourceLanguage;

/// Mutación que el cockpit puede ofrecer. El texto ya pasó el veto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdleProposal {
    /// Nombre de la declaración redundante.
    pub name: String,
    /// Fuente con la segunda copia idéntica retirada.
    pub revised: String,
}

/// Primera optimización limpia del archivo, si existe.
pub fn propose(language: SourceLanguage, source: &str) -> Option<IdleProposal> {
    let tree = syntax::parse(language, source);
    if !tree.balanced {
        return None;
    }
    let decls: Vec<SourceSymbol> = tree
        .symbols()
        .into_iter()
        .filter(|symbol| symbol.kind != "call" && !symbol.name.is_empty())
        .collect();
    let mut lines: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    for symbol in &decls {
        lines.entry(symbol.name.clone()).or_default().push(symbol.line);
    }
    let (name, copies) = lines.iter().find(|(_, rows)| rows.len() >= 2)?;
    let first = *copies.first()?;
    let second = *copies.get(1)?;
    if second <= first {
        return None;
    }
    let end = decls
        .iter()
        .map(|symbol| symbol.line)
        .filter(|line| *line > second)
        .min();
    let original = span(source, first, Some(second));
    let duplicate = span(source, second, end);
    if original.trim() != duplicate.trim() || duplicate.trim().is_empty() {
        return None;
    }
    let revised = without(source, second, end);
    let again = syntax::parse(language, &revised);
    if !again.balanced {
        return None;
    }
    let left = again
        .symbols()
        .into_iter()
        .filter(|symbol| symbol.kind != "call" && symbol.name == *name)
        .count();
    if left != 1 {
        return None;
    }
    Some(IdleProposal {
        name: name.clone(),
        revised,
    })
}

fn span(source: &str, from: u32, until: Option<u32>) -> String {
    let mut out = String::new();
    for (index, line) in source.lines().enumerate() {
        let number = u32::try_from(index).unwrap_or(u32::MAX).saturating_add(1);
        if number >= from && until.is_none_or(|end| number < end) {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn without(source: &str, from: u32, until: Option<u32>) -> String {
    let mut out = String::new();
    for (index, line) in source.lines().enumerate() {
        let number = u32::try_from(index).unwrap_or(u32::MAX).saturating_add(1);
        if number >= from && until.is_none_or(|end| number < end) {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_copia_identica_se_retira_y_el_cuerpo_distinto_no() {
        let clean = propose(
            SourceLanguage::Rust,
            "fn alpha() {}\nfn alpha() {}\n",
        )
        .expect("copia");
        assert_eq!(clean.name, "alpha");
        assert_eq!(clean.revised.matches("fn alpha()").count(), 1);
        assert!(propose(
            SourceLanguage::Rust,
            "fn alpha() {}\nfn alpha() { return 1; }\n",
        )
        .is_none());
        assert!(propose(SourceLanguage::Rust, "fn alpha() {\n").is_none());
    }
}
