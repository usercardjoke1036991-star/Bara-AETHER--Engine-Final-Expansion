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

use crate::runtime::{Observation, QuantumState};

/// Lenguaje legado de origen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyLang {
    /// C / cabecera de C.
    C,
    /// Python.
    Python,
    /// JSON: documentos de datos que cruzan la frontera FFI.
    Json,
    /// TypeScript: contratos y SDK tipados del AETHER‑Ω.
    TypeScript,
}

impl LegacyLang {
    /// Nombre legible del lenguaje.
    pub fn label(&self) -> &'static str {
        match self {
            LegacyLang::C => "C",
            LegacyLang::Python => "PY",
            LegacyLang::Json => "JSN",
            LegacyLang::TypeScript => "TS",
        }
    }

    /// Dialectos canónicos, en el orden de sondeo de [`ingest_auto`].
    ///
    /// El orden es **determinista** y va del dialecto más estricto al más
    /// laxo: C (exige `;`), Python (exige `def`), TypeScript (exige firma
    /// tipada o `=>`) y JSON (exige `"clave": valor`).
    pub fn dialects() -> [LegacyLang; 4] {
        [
            LegacyLang::C,
            LegacyLang::Python,
            LegacyLang::TypeScript,
            LegacyLang::Json,
        ]
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
    /// Secuencia (`רשימה`): listas y vectores JSON/TypeScript.
    List,
    /// Registro (`רשומה`): objetos JSON y `interface` de TypeScript.
    Record,
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
            BaraType::List => "רשימה",
            BaraType::Record => "רשומה",
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
            BaraType::List => "[]",
            BaraType::Record => "{}",
            BaraType::Unknown => "?",
        }
    }

    /// Mapea un tipo legado (C/Python/JSON/TypeScript) al tipo Bara.
    ///
    /// El mapeo es **tolerante** y por subcadena, de modo que nunca falla: un
    /// tipo irreconocible se degrada a [`BaraType::Unknown`]. El orden de las
    /// comprobaciones es normativo (lo fija la suite de integración):
    /// forma de arreglo → texto → número → verdad → vacío → secuencia →
    /// registro → desconocido. La forma `T[]` se comprueba primero porque en
    /// TypeScript describe una secuencia aunque `T` sea un escalar.
    pub fn from_legacy(ctype: &str) -> BaraType {
        let t = ctype.trim().to_ascii_lowercase();
        if t.ends_with("[]") {
            BaraType::List
        } else if t.contains("char") || t.contains("str") || t.contains("text") {
            BaraType::Text
        } else if t.contains("float")
            || t.contains("double")
            || t.contains("int")
            || t.contains("long")
            || t.contains("short")
            || t.contains("size")
            || t.contains("number")
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
        } else if t.contains("list")
            || t.contains("array")
            || t.contains("vec")
            || t.contains("seq")
        {
            BaraType::List
        } else if t.contains("dict")
            || t.contains("object")
            || t.contains("map")
            || t.contains("record")
        {
            BaraType::Record
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

    /// Riesgo máximo de todos los nodos (cota superior del AST).
    pub fn hazard_ceiling(&self) -> f64 {
        self.nodes.iter().map(|n| n.hazard).fold(0.0_f64, f64::max)
    }

    /// Número de nodos saneados.
    pub fn sanitized_count(&self) -> usize {
        self.nodes.iter().filter(|n| n.sanitized).count()
    }

    /// Iterador sobre las raíces del AST.
    pub fn roots(&self) -> impl Iterator<Item = &str> {
        self.nodes.iter().map(|n| n.root.as_str())
    }

    /// Absorbe otro AST conservando el orden de llegada (fusión FFI).
    ///
    /// Es la operación que usa [`ingest_auto`] al unir varios dialectos en una
    /// sola traducción: los nodos del AST receptor van primero y los del
    /// absorbido después, de modo que el resultado es reproducible.
    pub fn merge(&mut self, other: ShoreshAst) {
        self.nodes.extend(other.nodes);
    }

    /// Sella todos los nodos cuyo riesgo supere `threshold`.
    ///
    /// Devuelve cuántos nodos quedaron sellados por esta llamada. Un umbral
    /// fuera de `[0, 1]` no es un error: `≤ 0` sella todo y `> 1` no sella
    /// nada, porque el riesgo vive siempre en `[0, 1]`.
    pub fn seal_over(&mut self, threshold: f64) -> usize {
        let mut sealed = 0;
        for node in &mut self.nodes {
            if node.hazard > threshold && !node.sanitized {
                node.sanitized = true;
                sealed += 1;
            }
        }
        sealed
    }

    /// Recuento de los cuatro valores de Belnap presentes en el AST.
    ///
    /// La valencia de cada nodo es `(seguridad, riesgo)`; al proyectarla con
    /// [`QuantumState::observe`] se obtiene una de las cuatro etiquetas
    /// paraconsistentes, lo que permite auditar de un vistazo si el legado
    /// ingerido es contradictorio (`⊤∧⊥`) o simplemente incompleto.
    pub fn census(&self) -> BelnapCensus {
        let mut census = BelnapCensus::default();
        for node in &self.nodes {
            match node.valence.observe() {
                Observation::True => census.truth += 1,
                Observation::False => census.falsehood += 1,
                Observation::Both => census.both += 1,
                Observation::Neither => census.neither += 1,
            }
        }
        census
    }

    /// Emite el AST como **programa *Shoresh* ejecutable**.
    ///
    /// Cada nodo se convierte en un turno del oráculo (su raíz) y, si quedó
    /// sellado, en un turno de guarda `שמר`; el guion cierra con ejecución
    /// (`עבד`), emisión (`אמר`) y una fotografía del estado. El texto resultante
    /// es determinista y se conversa tal cual con
    /// [`Oracle::run_manifest`](crate::repl::Oracle::run_manifest), de modo que
    /// el código legado acaba materializándose como axiomas vivos de Bara.
    ///
    /// La emisión es proporcional al tamaño del AST (una o dos líneas por
    /// nodo): el llamante decide si destila una cabecera corta o una tormenta
    /// de seiscientas declaraciones.
    pub fn to_shoresh_source(&self) -> String {
        let census = self.census();
        let mut out = String::new();
        out.push_str("# AST *Shoresh* destilado por `ffi_ingest` (ingesta omnívora).\n");
        out.push_str(&format!(
            "# nodo(s)={} · riesgo medio={:.3} · cota={:.3} · sellados={} · {}\n",
            self.nodes.len(),
            self.hazard_score(),
            self.hazard_ceiling(),
            self.sanitized_count(),
            census.label()
        ));
        for node in &self.nodes {
            out.push_str(&node.root);
            out.push('\n');
            if node.sanitized {
                out.push_str("שמר\n");
            }
        }
        out.push_str("עבד\nאמר\n:estado\n:salir\n");
        out
    }
}

/// Recuento de los cuatro valores de la lógica de Belnap en un AST.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BelnapCensus {
    /// Nodos designados como verdaderos (`⊤`).
    pub truth: usize,
    /// Nodos designados como falsos (`⊥`).
    pub falsehood: usize,
    /// Nodos contradictorios (`⊤∧⊥`): verdad y falsedad a la vez.
    pub both: usize,
    /// Nodos sin designación (`∅`): ni verdad ni falsedad.
    pub neither: usize,
}

impl BelnapCensus {
    /// Total de nodos censados.
    pub fn total(&self) -> usize {
        self.truth + self.falsehood + self.both + self.neither
    }

    /// ¿Hay alguna contradicción viva en el AST?
    pub fn contradictions(&self) -> usize {
        self.both
    }

    /// Etiqueta compacta `⊤=a ⊥=b ⊤∧⊥=c ∅=d`.
    pub fn label(&self) -> String {
        format!(
            "⊤={} ⊥={} ⊤∧⊥={} ∅={}",
            self.truth, self.falsehood, self.both, self.neither
        )
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
        let name = parts
            .pop()
            .unwrap_or("")
            .trim_start_matches('*')
            .to_string();
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

/// Máximo de miembros o elementos que se expanden de una estructura anidada.
///
/// La cota es deliberada: un objeto JSON con mil claves no debe inflar el AST
/// con mil nodos. Se ingieren los primeros y el resto se resume en el propio
/// nodo contenedor (que conserva `aridad = MAX_STRUCT_MEMBERS` como techo).
pub const MAX_STRUCT_MEMBERS: usize = 4;

/// Salta espacios en blanco desde `from`.
fn skip_ws(chars: &[char], from: usize) -> usize {
    let mut i = from;
    while i < chars.len() && chars[i].is_whitespace() {
        i += 1;
    }
    i
}

/// Lee una cadena JSON; `at` debe apuntar a la comilla de apertura.
///
/// Devuelve el contenido (sin comillas, con los escapes despojados de su
/// barra) y la posición posterior a la comilla de cierre. Una cadena sin
/// cerrar se tolera: consume hasta el final del texto.
fn json_string(chars: &[char], at: usize) -> (String, usize) {
    let mut out = String::new();
    let mut i = at + 1;
    while i < chars.len() {
        match chars[i] {
            '\\' => {
                if let Some(escaped) = chars.get(i + 1) {
                    out.push(*escaped);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            '"' => return (out, i + 1),
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    (out, i)
}

/// Final de un literal escalar: se detiene en `,`, `}`, `]` o espacio.
fn scalar_end(chars: &[char], from: usize) -> usize {
    let mut i = from;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() || c == ',' || c == '}' || c == ']' {
            break;
        }
        i += 1;
    }
    if i == from {
        (from + 1).min(chars.len())
    } else {
        i
    }
}

/// Posición posterior al cierre del contenedor abierto en `at`.
///
/// Respeta cadenas y escapes, así que llaves o corchetes dentro de un texto no
/// descuadran la cuenta. Un contenedor sin cerrar se tolera: devuelve el final
/// del documento.
fn balanced_end(chars: &[char], at: usize) -> usize {
    let mut depth = 0isize;
    let mut in_string = false;
    let mut i = at;
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            if c == '\\' {
                i += 2;
                continue;
            }
            if c == '"' {
                in_string = false;
            }
        } else {
            match c {
                '"' => in_string = true,
                '{' | '[' => depth += 1,
                '}' | ']' => {
                    depth -= 1;
                    if depth <= 0 {
                        return i + 1;
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    chars.len()
}

/// Lee el valor JSON que empieza en `at` (tras espacios).
///
/// Devuelve `(tipo legado, miembros, posición posterior al valor)`. El tipo
/// legado se elige de modo que [`BaraType::from_legacy`] recupere la forma
/// correcta: `char*` para textos, `int`/`double` para números, `bool` para
/// booleanos, `void` para `null`, `object` para objetos y `array` para
/// secuencias.
fn json_value(chars: &[char], at: usize) -> (&'static str, Vec<Param>, usize) {
    let start = skip_ws(chars, at);
    match chars.get(start) {
        None => ("", Vec::new(), chars.len()),
        Some(&head) => match head {
            '"' => {
                let (_, end) = json_string(chars, start);
                ("char*", Vec::new(), end)
            }
            '{' => {
                let (params, end) = json_members(chars, start);
                ("object", params, end)
            }
            '[' => {
                let (params, end) = json_elements(chars, start);
                ("array", params, end)
            }
            't' | 'f' => ("bool", Vec::new(), scalar_end(chars, start)),
            'n' => ("void", Vec::new(), scalar_end(chars, start)),
            c if c.is_ascii_digit() || c == '-' || c == '+' || c == '.' => {
                let end = scalar_end(chars, start);
                let literal: String = chars[start..end].iter().collect();
                if literal.contains('.') || literal.contains('e') || literal.contains('E') {
                    ("double", Vec::new(), end)
                } else {
                    ("int", Vec::new(), end)
                }
            }
            _ => ("", Vec::new(), (start + 1).min(chars.len())),
        },
    }
}

/// Lee los miembros del objeto JSON abierto en `at` (hasta la cota).
fn json_members(chars: &[char], at: usize) -> (Vec<Param>, usize) {
    let mut params = Vec::new();
    let mut i = at + 1;
    while i < chars.len() && params.len() < MAX_STRUCT_MEMBERS {
        i = skip_ws(chars, i);
        match chars.get(i) {
            None | Some(&'}') => break,
            Some(&'"') => {
                let (key, after) = json_string(chars, i);
                let colon = skip_ws(chars, after);
                if chars.get(colon) == Some(&':') {
                    let (kind, _, end) = json_value(chars, colon + 1);
                    params.push(Param {
                        name: key,
                        ctype: kind.to_string(),
                    });
                    i = end.max(colon + 1);
                } else {
                    i = after;
                }
            }
            Some(_) => i += 1,
        }
    }
    (params, balanced_end(chars, at))
}

/// Lee los elementos del arreglo JSON abierto en `at` (hasta la cota).
///
/// Los separadores (`,`), el espacio y los saltos de línea se **saltan**: no
/// son elementos, sólo puntuación del documento. Un elemento sin forma
/// reconocible tampoco descuadra la cuenta, porque avanza una posición.
fn json_elements(chars: &[char], at: usize) -> (Vec<Param>, usize) {
    let mut params = Vec::new();
    let mut i = at + 1;
    while i < chars.len() && params.len() < MAX_STRUCT_MEMBERS {
        i = skip_ws(chars, i);
        match chars.get(i) {
            None | Some(&']') => break,
            Some(&',') => i += 1,
            Some(_) => {
                let (kind, _, end) = json_value(chars, i);
                let name = format!("e{}", params.len());
                params.push(Param {
                    name,
                    ctype: kind.to_string(),
                });
                i = end.max(i + 1);
            }
        }
    }
    (params, balanced_end(chars, at))
}

/// **Ingiere** un documento JSON: cada clave de primer nivel es un nodo.
///
/// La forma del valor decide el tipo Bara (`object` → registro, `array` →
/// secuencia, `"..."` → texto, número → número, `true`/`false` → verdad,
/// `null` → vacío) y los miembros anidados se expanden como parámetros hasta
/// [`MAX_STRUCT_MEMBERS`]. Un arreglo raíz se ingiere como un único nodo
/// `items`. La aridad resume la **forma** del valor, no su tamaño real.
pub fn ingest_json(source: &str) -> Vec<IngestedDecl> {
    let chars: Vec<char> = source.chars().collect();
    let mut decls = Vec::new();
    let head = skip_ws(&chars, 0);
    if chars.get(head) == Some(&'[') {
        let (params, _) = json_elements(&chars, head);
        decls.push(IngestedDecl {
            lang: LegacyLang::Json,
            name: "items".to_string(),
            params,
            ret: "array".to_string(),
            raw: source.trim().to_string(),
        });
        return decls;
    }

    let mut depth = 0isize;
    let mut index = 0usize;
    while index < chars.len() {
        match chars[index] {
            '"' => {
                let member_start = index;
                let (token, next) = json_string(&chars, index);
                let colon = skip_ws(&chars, next);
                if depth == 1 && chars.get(colon) == Some(&':') {
                    let (kind, params, value_end) = json_value(&chars, colon + 1);
                    let stop = value_end.max(colon + 1);
                    decls.push(IngestedDecl {
                        lang: LegacyLang::Json,
                        name: token,
                        params,
                        ret: kind.to_string(),
                        raw: chars[member_start..stop].iter().collect(),
                    });
                    index = stop;
                } else {
                    index = next;
                }
            }
            '{' | '[' => {
                depth += 1;
                index += 1;
            }
            '}' | ']' => {
                depth -= 1;
                index += 1;
            }
            _ => index += 1,
        }
    }
    decls
}

// ─────────────────────────────────────────────────────────────────────────
// TypeScript (el dialecto tipado de la frontera web)
// ─────────────────────────────────────────────────────────────────────────

/// Quita los modificadores de una declaración TypeScript.
///
/// Se aplica en bucle porque se encadenan (`export default async function`), y
/// cada vuelta acorta la entrada, así que la terminación está garantizada.
fn ts_strip_modifiers(line: &str) -> &str {
    let mut rest = line.trim_start();
    loop {
        let mut changed = false;
        for modifier in [
            "export",
            "default",
            "declare",
            "async",
            "abstract",
            "public",
            "private",
            "protected",
        ] {
            if let Some(next) = rest.strip_prefix(modifier) {
                if next.is_empty() || next.starts_with(char::is_whitespace) {
                    rest = next.trim_start();
                    changed = true;
                }
            }
        }
        if !changed {
            return rest;
        }
    }
}

/// Parsea los parámetros de una firma TypeScript (`a: number, b?: string`).
///
/// El modificador de reposo (`...rest`) se despoja y el valor por omisión se
/// descarta: el AST guarda la **forma** de la firma, no su semántica.
fn parse_ts_params(args: &str) -> Vec<Param> {
    let trimmed = args.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    trimmed
        .split(',')
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .map(|part| {
            let cleaned = part.trim_start_matches("...").trim();
            match cleaned.split_once(':') {
                Some((name, ctype)) => Param {
                    name: name.trim().trim_end_matches('?').to_string(),
                    ctype: ctype.split('=').next().unwrap_or("").trim().to_string(),
                },
                None => Param {
                    name: cleaned.split('=').next().unwrap_or("").trim().to_string(),
                    ctype: String::new(),
                },
            }
        })
        .collect()
}

/// Parsea los miembros de una interfaz escrita en una sola línea.
fn parse_ts_members(body: &str) -> Vec<Param> {
    body.split([';', ','])
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .take(MAX_STRUCT_MEMBERS)
        .filter_map(|part| {
            let (name, ctype) = part.split_once(':')?;
            Some(Param {
                name: name.trim().trim_end_matches('?').to_string(),
                ctype: ctype.trim().to_string(),
            })
        })
        .collect()
}

/// Extrae el nombre declarado en la cabecera previa a los paréntesis.
fn ts_declared_name(head: &str) -> Option<String> {
    let before_assign = head.split('=').next().unwrap_or("");
    let word = before_assign.split_whitespace().last().unwrap_or("");
    let name = word.trim_end_matches(':').trim_end_matches('?');
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Reconoce una declaración `interface` (una sola línea, con miembros).
fn ts_interface_decl(line: &str, raw_line: &str) -> Option<IngestedDecl> {
    let rest = line.strip_prefix("interface ")?;
    let name = rest
        .split(|c: char| c.is_whitespace() || c == '{' || c == '<')
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    if name.is_empty() {
        return None;
    }
    let params = match (rest.find('{'), rest.rfind('}')) {
        (Some(open), Some(close)) if close > open => parse_ts_members(&rest[open + 1..close]),
        _ => Vec::new(),
    };
    Some(IngestedDecl {
        lang: LegacyLang::TypeScript,
        name,
        params,
        ret: "object".to_string(),
        raw: raw_line.trim().to_string(),
    })
}

/// Reconoce una declaración `function nombre(...): Tipo {`.
fn ts_function_decl(line: &str, raw_line: &str) -> Option<IngestedDecl> {
    let rest = line.strip_prefix("function ")?;
    let open = rest.find('(')?;
    let close = rest.rfind(')')?;
    if close < open {
        return None;
    }
    let name = rest[..open].trim().trim_end_matches('?').to_string();
    if name.is_empty() {
        return None;
    }
    let params = parse_ts_params(&rest[open + 1..close]);
    let after = rest[close + 1..].trim();
    let ret = after
        .strip_prefix(':')
        .unwrap_or("")
        .split('{')
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    Some(IngestedDecl {
        lang: LegacyLang::TypeScript,
        name,
        params,
        ret,
        raw: raw_line.trim().to_string(),
    })
}

/// Reconoce una flecha tipada (`const suma = (a: number): number => a + b`).
fn ts_arrow_decl(line: &str, raw_line: &str) -> Option<IngestedDecl> {
    let arrow = line.find("=>")?;
    let before = &line[..arrow];
    let open = before.rfind('(')?;
    let close = before.rfind(')')?;
    if close < open {
        return None;
    }
    let name = ts_declared_name(&before[..open])?;
    let params = parse_ts_params(&before[open + 1..close]);
    let ret = before[close + 1..]
        .trim()
        .strip_prefix(':')
        .unwrap_or("")
        .trim()
        .to_string();
    Some(IngestedDecl {
        lang: LegacyLang::TypeScript,
        name,
        params,
        ret,
        raw: raw_line.trim().to_string(),
    })
}

/// **Ingiere** funciones e interfaces de un módulo TypeScript.
///
/// Cubre las tres formas canónicas del SDK: `function` con firma tipada,
/// `const ... = (...) => ...` e `interface` de una línea. Como en los demás
/// dialectos, una línea que no case simplemente se ignora.
pub fn ingest_typescript(source: &str) -> Vec<IngestedDecl> {
    let mut decls = Vec::new();
    for raw_line in source.lines() {
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        let stripped = ts_strip_modifiers(line);
        let parsed = ts_interface_decl(stripped, raw_line)
            .or_else(|| ts_function_decl(stripped, raw_line))
            .or_else(|| ts_arrow_decl(stripped, raw_line));
        if let Some(decl) = parsed {
            decls.push(decl);
        }
    }
    decls
}

// ─────────────────────────────────────────────────────────────────────────
// Ingesta omnívora: sondeo de dialecto y traducción de una sola llamada
// ─────────────────────────────────────────────────────────────────────────

/// Sondea el dialecto de un texto legado.
///
/// La detección es **por evidencia positiva** y en orden de fiabilidad
/// decreciente: la forma del documento (JSON), la directiva del preprocesador
/// (C), la palabra clave `def` sin llaves (Python) y la firma tipada o la
/// flecha (TypeScript). Si nada resulta concluyente se devuelve `None` y
/// [`ingest_auto`] prueba cada dialecto en orden canónico.
pub fn detect_lang(source: &str) -> Option<LegacyLang> {
    let trimmed = source.trim_start();
    if trimmed.is_empty() {
        return None;
    }
    let lowered = source.to_ascii_lowercase();
    if (trimmed.starts_with('{') || trimmed.starts_with('[')) && source.contains('"') {
        return Some(LegacyLang::Json);
    }
    if lowered.contains("#include") || lowered.contains("#define") {
        return Some(LegacyLang::C);
    }
    if lowered.contains("def ") {
        return Some(LegacyLang::Python);
    }
    if lowered.contains("=>")
        || lowered.contains("function ")
        || lowered.contains("interface ")
        || lowered.contains(": number")
        || lowered.contains(": string")
        || lowered.contains(": boolean")
        || lowered.contains(": void")
    {
        return Some(LegacyLang::TypeScript);
    }
    if lowered.contains(';') && lowered.contains('(') {
        return Some(LegacyLang::C);
    }
    None
}

/// **Ingiere** un texto legado declarando su dialecto explícitamente.
pub fn ingest(source: &str, lang: LegacyLang) -> Vec<IngestedDecl> {
    match lang {
        LegacyLang::C => ingest_c(source),
        LegacyLang::Python => ingest_python(source),
        LegacyLang::Json => ingest_json(source),
        LegacyLang::TypeScript => ingest_typescript(source),
    }
}

/// **Ingesta omnívora**: sondea el dialecto y devuelve las declaraciones.
///
/// Primero se fía del sondeo de [`detect_lang`]; si el dialecto sondeado no
/// produce ninguna declaración (un texto ambiguo o una muestra truncada),
/// recorre los dialectos canónicos de [`LegacyLang::dialects`] y devuelve el
/// primer resultado no vacío. Un texto sin nada ingerible devuelve `Vec::new()`
/// en lugar de fallar: la frontera FFI degrada, nunca aborta.
pub fn ingest_auto(source: &str) -> Vec<IngestedDecl> {
    if let Some(lang) = detect_lang(source) {
        let decls = ingest(source, lang);
        if !decls.is_empty() {
            return decls;
        }
    }
    for lang in LegacyLang::dialects() {
        let decls = ingest(source, lang);
        if !decls.is_empty() {
            return decls;
        }
    }
    Vec::new()
}

/// Traduce un texto legado (dialecto sondeado) directamente a AST *Shoresh*.
pub fn ingest_auto_to_shoresh(source: &str) -> ShoreshAst {
    to_shoresh(&ingest_auto(source))
}
