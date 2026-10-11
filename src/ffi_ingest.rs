//! # Omnivorous FFI Ingestion — `ffi_ingest.rs`
//!
//! Ingesta inversa de código legado hacia el AST de Bara (*Shoresh*).
//!
//! El ingestor es **omnívoro**: traga estructuras de C y Python sin protestar,
//! las mapea a raíces triconsonánticas hebreas y las **sanea** bajo las
//! reglas paraconsistentes del runtime. Un constructo peligroso (punteros,
//! `malloc`, `eval`, `exec`…) no provoca un error: se convierte en una
//! valencia paraconsistente `(seguridad, riesgo)` y se sella bajo la guarda
//! `שמר` cuando procede.
//!
//! Flujo: `ingest_c` / `ingest_python` → `IngestedDecl` → `to_shoresh` →
//! [`ShoreshAst`] (nodos con raíz, aridad, tipo, riesgo y valencia).

use crate::runtime::QuantumState;

/// Lenguaje legado de origen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyLang {
    /// C / cabecera de C.
    C,
    /// Python.
    Python,
}

impl LegacyLang {
    /// Nombre legible del lenguaje.
    pub fn label(&self) -> &'static str {
        match self {
            LegacyLang::C => "C",
            LegacyLang::Python => "PY",
        }
    }
}

/// Parámetro formal de una declaración legada.
#[derive(Debug, Clone)]
pub struct Param {
    /// Nombre del parámetro.
    pub name: String,
    /// Tipo declarado (vacío en Python).
    pub ctype: String,
}

/// Declaración legada ya parseada.
#[derive(Debug, Clone)]
pub struct IngestedDecl {
    /// Lenguaje de origen.
    pub lang: LegacyLang,
    /// Nombre de la función.
    pub name: String,
    /// Parámetros formales.
    pub params: Vec<Param>,
    /// Tipo de retorno declarado.
    pub ret: String,
    /// Texto original de la declaración.
    pub raw: String,
}

/// Tipo del sistema Bara, derivado del tipo legado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaraType {
    /// Número (`מספר`).
    Number,
    /// Texto (`מלים`).
    Text,
    /// Vacío (`אין`).
    Void,
    /// Valor de verdad (`אמת`).
    Truth,
    /// Desconocido (se tolera).
    Unknown,
}

impl BaraType {
    /// Nombre canónico en hebreo.
    pub fn label(&self) -> &'static str {
        match self {
            BaraType::Number => "מספר",
            BaraType::Text => "מלים",
            BaraType::Void => "אין",
            BaraType::Truth => "אמת",
            BaraType::Unknown => "נעלם",
        }
    }

    /// Glifo ASCII.
    pub fn glyph(&self) -> &'static str {
        match self {
            BaraType::Number => "#",
            BaraType::Text => "§",
            BaraType::Void => "∅",
            BaraType::Truth => "⊤⊥",
            BaraType::Unknown => "?",
        }
    }

    /// Mapea un tipo legado (C/Python) al tipo Bara correspondiente.
    pub fn from_legacy(ctype: &str) -> BaraType {
        let t = ctype.trim().to_ascii_lowercase();
        if t.contains("char") || t.contains("str") || t.contains("text") {
            BaraType::Text
        } else if t.contains("float")
            || t.contains("double")
            || t.contains("int")
            || t.contains("long")
            || t.contains("short")
            || t.contains("size")
        {
            BaraType::Number
        } else if t.contains("bool") {
            BaraType::Truth
        } else if t.contains("void") || t.is_empty() {
            if t.is_empty() {
                BaraType::Unknown
            } else {
                BaraType::Void
            }
        } else {
            BaraType::Unknown
        }
    }
}

/// Nodo del AST *Shoresh* (raíz triconsonántica) resultante de la ingesta.
#[derive(Debug, Clone)]
pub struct ShoreshNode {
    /// Raíz triconsonántica hebrea generada.
    pub root: String,
    /// Nombre original de la función legada.
    pub original: String,
    /// Aridad (número de parámetros).
    pub arity: usize,
    /// Tipo de retorno traducido.
    pub ret: BaraType,
    /// Riesgo detectado en `[0, 1]`.
    pub hazard: f64,
    /// Valencia paraconsistente `(seguridad, riesgo)`.
    pub valence: QuantumState,
    /// `true` si fue saneado (sellado bajo guarda).
    pub sanitized: bool,
}

/// AST *Shoresh* completo.
#[derive(Debug, Clone, Default)]
pub struct ShoreshAst {
    /// Nodos del AST.
    pub nodes: Vec<ShoreshNode>,
}

impl ShoreshAst {
    /// Riesgo medio de todos los nodos.
    pub fn hazard_score(&self) -> f64 {
        if self.nodes.is_empty() {
            return 0.0;
        }
        self.nodes.iter().map(|n| n.hazard).sum::<f64>() / self.nodes.len() as f64
    }

    /// Número de nodos saneados.
    pub fn sanitized_count(&self) -> usize {
        self.nodes.iter().filter(|n| n.sanitized).count()
    }

    /// Iterador sobre las raíces del AST.
    pub fn roots(&self) -> impl Iterator<Item = &str> {
        self.nodes.iter().map(|n| n.root.as_str())
    }
}

/// Alfabeto consonántico hebreo (22 letras) para sintetizar raíces.
const CONSONANTS: [char; 22] = [
    'א', 'ב', 'ג', 'ד', 'ה', 'ו', 'ז', 'ח', 'ט', 'י', 'כ', 'ל', 'מ', 'נ', 'ס', 'ע', 'פ', 'צ', 'ק',
    'ר', 'ש', 'ת',
];

/// Tokens considerados peligrosos al ingerir, con su peso de riesgo.
const HAZARDS: [(&str, f64); 8] = [
    ("malloc", 0.40),
    ("free", 0.30),
    ("eval", 0.60),
    ("exec", 0.60),
    ("->", 0.20),
    ("import", 0.15),
    ("*", 0.25),
    ("...", 0.35),
];

/// Genera una raíz triconsonántica determinista a partir de un nombre.
pub fn root_from_name(name: &str) -> String {
    let mut out = String::new();
    for ch in name.chars().filter(|c| c.is_alphanumeric()) {
        if out.chars().count() >= 3 {
            break;
        }
        let idx = (ch as u32) % CONSONANTS.len() as u32;
        out.push(CONSONANTS[idx as usize]);
    }
    while out.chars().count() < 3 {
        out.push('א');
    }
    out
}

/// Calcula el riesgo acumulado de un texto (saturado a `1.0`).
pub fn hazard_of(text: &str) -> f64 {
    let lower = text.to_ascii_lowercase();
    let mut score = 0.0_f64;
    for (needle, weight) in HAZARDS {
        if lower.contains(needle) {
            score += weight;
        }
    }
    if score > 1.0 {
        1.0
    } else {
        score
    }
}

/// Sanitiza una declaración bajo las reglas paraconsistentes.
///
/// Devuelve `(riesgo, valencia, sellado)`. La valencia es
/// `(seguridad, riesgo)` con `seguridad = 1 − riesgo`; si hay riesgo, el
/// constructo legado se sella (`sealed = true`) en vez de rechazarse.
pub fn sanitize(decl: &IngestedDecl) -> (f64, QuantumState, bool) {
    let mut haystack = String::new();
    haystack.push_str(&decl.raw);
    haystack.push(' ');
    haystack.push_str(&decl.ret);
    for param in &decl.params {
        haystack.push(' ');
        haystack.push_str(&param.ctype);
    }
    let hazard = hazard_of(&haystack);
    let safety = 1.0 - hazard;
    let valence = QuantumState::paraconsistent(safety, hazard);
    let sealed = hazard > 0.0;
    (hazard, valence, sealed)
}

/// Convierte una lista de declaraciones legadas al AST *Shoresh* saneado.
pub fn to_shoresh(decls: &[IngestedDecl]) -> ShoreshAst {
    let mut ast = ShoreshAst::default();
    for decl in decls {
        let (hazard, valence, sanitized) = sanitize(decl);
        ast.nodes.push(ShoreshNode {
            root: root_from_name(&decl.name),
            original: decl.name.clone(),
            arity: decl.params.len(),
            ret: BaraType::from_legacy(&decl.ret),
            hazard,
            valence,
            sanitized,
        });
    }
    ast
}

// ─────────────────────────────────────────────────────────────────────────
// Parsers tolerantes (nunca fallan: lo que no casa se ignora)
// ─────────────────────────────────────────────────────────────────────────

/// Elimina comentarios `//`, `#` y `/*` de una línea.
fn strip_comment(line: &str) -> &str {
    let mut cut = line.len();
    for marker in ["//", "#", "/*"] {
        if let Some(pos) = line.find(marker) {
            cut = cut.min(pos);
        }
    }
    &line[..cut]
}

/// Parsea la lista de parámetros de una firma C.
fn parse_c_params(args: &str) -> Vec<Param> {
    let trimmed = args.trim();
    if trimmed.is_empty() || trimmed == "void" {
        return Vec::new();
    }
    trimmed
        .split(',')
        .filter(|p| !p.trim().is_empty())
        .map(|param| {
            let mut words: Vec<&str> = param.split_whitespace().collect();
            if words.is_empty() {
                return Param {
                    name: String::new(),
                    ctype: String::new(),
                };
            }
            let name = words
                .pop()
                .unwrap_or("")
                .trim_start_matches('*')
                .to_string();
            Param {
                name,
                ctype: words.join(" "),
            }
        })
        .collect()
}

/// **Ingiere** declaraciones de una cabecera C (`int foo(int a, char* b);`).
pub fn ingest_c(source: &str) -> Vec<IngestedDecl> {
    let mut decls = Vec::new();
    for raw_line in source.lines() {
        let line = strip_comment(raw_line).trim();
        if line.is_empty() || !line.contains('(') || !line.ends_with(';') {
            continue;
        }
        let body = line.trim_end_matches(';').trim();
        let (open, close) = match (body.find('('), body.rfind(')')) {
            (Some(open), Some(close)) if close > open => (open, close),
            _ => continue,
        };
        let header = body[..open].trim();
        let args = &body[open + 1..close];

        let mut parts: Vec<&str> = header.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let name = parts.pop().unwrap_or("").trim_start_matches('*').to_string();
        if name.is_empty() {
            continue;
        }
        let ret = parts.join(" ");
        decls.push(IngestedDecl {
            lang: LegacyLang::C,
            name,
            params: parse_c_params(args),
            ret,
            raw: raw_line.trim().to_string(),
        });
    }
    decls
}

/// **Ingiere** funciones de un módulo Python (`def foo(a, b):`).
pub fn ingest_python(source: &str) -> Vec<IngestedDecl> {
    let mut decls = Vec::new();
    for raw_line in source.lines() {
        let line = strip_comment(raw_line).trim();
        let rest = match line.strip_prefix("def ") {
            Some(rest) => rest,
            None => continue,
        };
        let (open, close) = match (rest.find('('), rest.rfind(')')) {
            (Some(open), Some(close)) if close > open => (open, close),
            _ => continue,
        };
        let name = rest[..open].trim().to_string();
        if name.is_empty() {
            continue;
        }
        let params: Vec<Param> = rest[open + 1..close]
            .split(',')
            .map(|a| a.trim())
            .filter(|a| !a.is_empty())
            .map(|a| Param {
                name: a.split('=').next().unwrap_or(a).trim().to_string(),
                ctype: String::new(),
            })
            .collect();
        decls.push(IngestedDecl {
            lang: LegacyLang::Python,
            name,
            params,
            ret: String::new(),
            raw: raw_line.trim().to_string(),
        });
    }
    decls
}
