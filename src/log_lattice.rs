//! Lectura del bilátice sobre una línea de registro.
//!
//! Si la línea ya trae un glifo (`⊤`, `⊥`, `⊤∧⊥`, `∅`), ese glifo es el valor.
//! Si no, sólo se admite un diagnóstico con forma de token (`error:` , `error[`,
//! `error TS`, `warning:`). Un identificador como `error_handler` no es un fallo.

#![forbid(unsafe_code)]

use crate::autopoietic::BelnapValue;

/// Valor de Belnap de una línea. Total: no entra en pánico.
pub fn observe_log_line(line: &str) -> BelnapValue {
    if let Some(value) = read_glyph(line) {
        return value;
    }
    let (truth, falsity) = diagnostic_masses(line);
    BelnapValue::from_masses(truth, falsity)
}

/// Clave estable para el panel (`true`, `false`, `both`, `neither`).
pub const fn status_key(value: BelnapValue) -> &'static str {
    match value {
        BelnapValue::True => "true",
        BelnapValue::False => "false",
        BelnapValue::Both => "both",
        BelnapValue::Neither => "neither",
    }
}

/// El glifo compuesto va primero: `⊤` también aparece dentro de `⊤∧⊥`.
fn read_glyph(line: &str) -> Option<BelnapValue> {
    if line.contains("⊤∧⊥") {
        return Some(BelnapValue::Both);
    }
    let truth = line.contains('⊤');
    let falsity = line.contains('⊥');
    match (truth, falsity) {
        (true, true) => Some(BelnapValue::Both),
        (true, false) => Some(BelnapValue::True),
        (false, true) => Some(BelnapValue::False),
        (false, false) if line.contains('∅') => Some(BelnapValue::Neither),
        (false, false) => None,
    }
}

fn diagnostic_masses(line: &str) -> (f64, f64) {
    let trimmed = line.trim_start();
    if diagnostic_token(trimmed, "error", &[":", "[", " TS"]) {
        return (0.0, 1.0);
    }
    if diagnostic_token(trimmed, "warning", &[":"]) {
        return (1.0, 1.0);
    }
    if trimmed.starts_with("test result: ok") || trimmed.starts_with("Finished") {
        return (1.0, 0.0);
    }
    if trimmed.starts_with("test result: FAILED") || trimmed.starts_with("panicked at") {
        return (0.0, 1.0);
    }
    (0.0, 0.0)
}

/// `word` sólo cuenta en frontera de identificador y con una cola de diagnóstico.
fn diagnostic_token(line: &str, word: &str, tails: &[&str]) -> bool {
    let mut offset = 0usize;
    while let Some(found) = line[offset..].find(word) {
        let at = offset.saturating_add(found);
        let after = at.saturating_add(word.len());
        if after > line.len() || !line.is_char_boundary(at) || !line.is_char_boundary(after) {
            break;
        }
        if boundary_before(line, at) && tails.iter().any(|tail| line[after..].starts_with(tail)) {
            return true;
        }
        offset = after;
        if offset >= line.len() || !line.is_char_boundary(offset) {
            break;
        }
    }
    false
}

fn boundary_before(line: &str, index: usize) -> bool {
    if index == 0 {
        return true;
    }
    match line[..index].chars().next_back() {
        Some(ch) => !ch.is_ascii_alphanumeric() && ch != '_',
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn el_glifo_manda_y_el_identificador_no_es_un_fallo() {
        assert_eq!(
            observe_log_line("error[E0308]: mismatched types"),
            BelnapValue::False
        );
        assert_eq!(observe_log_line("warning: unused variable"), BelnapValue::Both);
        assert_eq!(
            observe_log_line("test result: ok. 1 passed"),
            BelnapValue::True
        );
        assert_eq!(observe_log_line("   Compiling bara"), BelnapValue::Neither);
        assert_eq!(observe_log_line("src/error_handler.rs"), BelnapValue::Neither);
        assert_eq!(observe_log_line("⊤∧⊥ en el nodo"), BelnapValue::Both);
        assert_eq!(
            observe_log_line("src/App.tsx(3,1): error TS2322: tipo"),
            BelnapValue::False
        );
        assert_eq!(status_key(BelnapValue::Neither), "neither");
        assert_eq!(BelnapValue::False.glyph(), "⊥");
    }
}
