//! Gramática nativa de los lenguajes que el lote transmuta.
//!
//! No usa Tree-sitter ni ninguna dependencia: el kernel sigue en `std`, con
//! `forbid(unsafe_code)` en este módulo. El análisis es un descenso recursivo
//! sobre un léxico real (cadenas, comentarios, anidamiento), no una búsqueda
//! de palabras sueltas. De cada archivo salen declaraciones, tipos, llamadas
//! y la relación padre/hijo, en un orden fijo.

#![forbid(unsafe_code)]

use crate::autopoietic::{BelnapValue, MAX_ARITY, SEAL_THRESHOLD};
use crate::ffi_ingest::{BaraType, ShoreshNode};
use crate::runtime::QuantumState;
use crate::transmuter::{Concept, SourceLanguage};

const MAX_DEPTH: u32 = 24;
const MAX_NODES: usize = 1_024;
const MAX_NAME: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SynKind {
    Function,
    Type,
    Call,
}

#[derive(Debug, Clone)]
struct SynNode {
    kind: SynKind,
    name: String,
    ty: String,
    params: Vec<(String, String)>,
    argc: usize,
    depth: u32,
    parent: String,
    /// Línea 1-based del nombre en la fuente.
    line: u32,
    children: Vec<SynNode>,
}

/// Árbol sintáctico de un fragmento. Vacío si no hubo declaraciones ni llamadas.
#[derive(Debug, Clone)]
pub struct SyntaxTree {
    items: Vec<SynNode>,
    /// `false` cuando los delimitadores no cuadran. El árbol parcial se conserva.
    pub balanced: bool,
}

impl SyntaxTree {
    /// Declaraciones, tipos y llamadas, contando los hijos.
    pub fn statement_count(&self) -> usize {
        self.items.iter().map(SynNode::size).sum()
    }

    /// Proyección *Shoresh* en preorden. El padre queda escrito en `original`.
    pub fn into_nodes(self, language: SourceLanguage) -> Vec<ShoreshNode> {
        let mut out = Vec::new();
        for item in &self.items {
            item.emit(language, &mut out);
        }
        out
    }

    /// Nombres declarados o llamados, en preorden. No incluye nodos sin nombre.
    pub fn symbols(&self) -> Vec<SourceSymbol> {
        let mut out = Vec::new();
        for item in &self.items {
            item.collect_symbols(&mut out);
        }
        out
    }
}

/// Nombre que el autocompletado puede ofrecer sin volver a parsear la etiqueta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSymbol {
    /// Identificador tal como aparece en la fuente.
    pub name: String,
    /// `fn`, `type` o `call`.
    pub kind: &'static str,
    /// Declaración que lo contiene. Vacío en la raíz del fragmento.
    pub parent: String,
    /// Parámetros, campos o argumentos, ya acotados por el parser.
    pub arity: usize,
    /// Profundidad de anidamiento.
    pub depth: u32,
    /// Línea 1-based del nombre.
    pub line: u32,
}

impl SynNode {
    fn size(&self) -> usize {
        1usize.saturating_add(self.children.iter().map(SynNode::size).sum())
    }

    fn emit(&self, language: SourceLanguage, out: &mut Vec<ShoreshNode>) {
        if out.len() >= MAX_NODES {
            return;
        }
        out.push(self.to_shoresh(language));
        for child in &self.children {
            child.emit(language, out);
        }
    }

    fn collect_symbols(&self, out: &mut Vec<SourceSymbol>) {
        if out.len() >= MAX_NODES {
            return;
        }
        if !self.name.is_empty() {
            let kind = match self.kind {
                SynKind::Function => "fn",
                SynKind::Type => "type",
                SynKind::Call => "call",
            };
            let arity = match self.kind {
                SynKind::Call => self.argc,
                SynKind::Function | SynKind::Type => self.params.len(),
            };
            out.push(SourceSymbol {
                name: self.name.clone(),
                kind,
                parent: self.parent.clone(),
                arity,
                depth: self.depth,
                line: self.line,
            });
        }
        for child in &self.children {
            child.collect_symbols(out);
        }
    }

    fn to_shoresh(&self, language: SourceLanguage) -> ShoreshNode {
        let concept = match self.kind {
            SynKind::Call => Concept::Import,
            SynKind::Function | SynKind::Type => Concept::Define,
        };
        let falsity = concept.falsity();
        let truth = (1.0 - falsity).clamp(0.0, 1.0);
        let hazard = concept.hazard().clamp(0.0, 1.0);
        let arity = match self.kind {
            SynKind::Call => self.argc,
            SynKind::Function | SynKind::Type => self.params.len(),
        };
        let ret = match self.kind {
            SynKind::Function => bara_type(&self.ty),
            SynKind::Call => concept.ret(),
            SynKind::Type => {
                if self.params.is_empty() {
                    concept.ret()
                } else {
                    BaraType::Record
                }
            }
        };
        ShoreshNode {
            root: concept.root().to_string(),
            original: self.label(language),
            arity: arity.min(MAX_ARITY),
            ret,
            hazard,
            valence: QuantumState::paraconsistent(truth, falsity),
            sanitized: hazard > SEAL_THRESHOLD,
        }
    }

    fn label(&self, language: SourceLanguage) -> String {
        let kind = match self.kind {
            SynKind::Function => "fn",
            SynKind::Type => "type",
            SynKind::Call => "call",
        };
        let parent = if self.parent.is_empty() {
            "-"
        } else {
            self.parent.as_str()
        };
        let extra = match self.kind {
            SynKind::Function => format!(
                "ret={}:params={}",
                clip(&self.ty, MAX_NAME),
                pairs(&self.params)
            ),
            SynKind::Type => format!("fields={}", pairs(&self.params)),
            SynKind::Call => format!("argc={}", self.argc),
        };
        clip(
            &format!(
                "syntax:{}:{kind}:parent={parent}:name={}:d={}:{}",
                language.tag(),
                clip(&self.name, MAX_NAME),
                self.depth,
                extra
            ),
            240,
        )
    }
}

/// Parsea `source` con la gramática de `language`.
///
/// Es total: un texto vacío o ilegible devuelve un árbol vacío. No entra en
/// pánico y no consulta el reloj.
pub fn parse(language: SourceLanguage, source: &str) -> SyntaxTree {
    let (tokens, lex_balanced) = lex(source, language);
    let mut parser = Parser {
        source,
        language,
        tokens,
        index: 0,
        balanced: lex_balanced,
        named_line: 1,
    };
    let items = parser.parse_seq(0, "", false, Stop::End);
    SyntaxTree {
        items,
        balanced: parser.balanced,
    }
}

/// Motivo por el que el léxico *Shoresh* no verifica un parche.
///
/// `None` significa que el lexer no encontró raíces desconocidas ni signos
/// ajenos al alfabeto que reconoce el kernel. Una raíz autopoiética o un
/// símbolo fuera del operadorium dejan el parche como «propuesta no verificada».
pub fn shoresh_unverified_reason(patch: &str) -> Option<String> {
    use crate::lexer::{Lexer, TokenKind};

    let tokens = Lexer::new(patch).tokenize();
    let mut unknown_roots: Vec<String> = Vec::new();
    let mut odd_symbols: Vec<char> = Vec::new();
    let mut saw_root = false;

    for token in tokens {
        match token.kind {
            TokenKind::Root { letters, keyword } => {
                saw_root = true;
                if keyword.is_none() {
                    unknown_roots.push(letters);
                }
            }
            // Signos que el lexer conserva sin juicio: no forman parte de la
            // sintaxis *Shoresh* reconocida (operadores tipados arriba).
            TokenKind::Punct(symbol) if !odd_symbols.contains(&symbol) => {
                odd_symbols.push(symbol);
            }
            _ => {}
        }
    }

    if !unknown_roots.is_empty() {
        return Some(format!(
            "propuesta no verificada: raíces desconocidas ({})",
            unknown_roots.join(", ")
        ));
    }
    // Sólo cuando el bloque habla Shoresh (hay raíces) los signos sueltos
    // cuentan: un parche Rust/ASCII puro no se marca por `{` o `(`.
    if saw_root && !odd_symbols.is_empty() {
        let list: String = odd_symbols
            .iter()
            .map(|ch| ch.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        return Some(format!(
            "propuesta no verificada: símbolos no reconocidos por el lexer ({list})"
        ));
    }
    None
}

/// Juicio del bloque que el modo autónomo quiere escribir.
///
/// - `⊥` — bloque vacío: no hay hecho que escribir.
/// - `⊤∧⊥` — desequilibrio o un nombre que ya existe.
/// - `∅` — falta información o el léxico no verifica el texto (raíces o
///   símbolos desconocidos): **nunca** debe aplicarse en automático.
/// - `⊤` — parche equilibrado, sin choque de nombres y léxico verificado.
///
/// Las llamadas no cuentan como declaración.
pub fn judge_patch(language: SourceLanguage, host: &str, patch: &str) -> BelnapValue {
    if patch.trim().is_empty() {
        return BelnapValue::False;
    }
    if shoresh_unverified_reason(patch).is_some() {
        return BelnapValue::Neither;
    }
    let incoming = parse(language, patch);
    if !incoming.balanced {
        return BelnapValue::Both;
    }
    let host_names = declarations(&parse(language, host));
    let mut seen: Vec<String> = Vec::new();
    for name in declarations(&incoming) {
        if seen.iter().any(|previous| previous == &name)
            || host_names.iter().any(|previous| previous == &name)
        {
            return BelnapValue::Both;
        }
        seen.push(name);
    }
    BelnapValue::True
}

fn declarations(tree: &SyntaxTree) -> Vec<String> {
    tree.symbols()
        .into_iter()
        .filter(|symbol| symbol.kind != "call" && !symbol.name.is_empty())
        .map(|symbol| symbol.name)
        .collect()
}

fn bara_type(raw: &str) -> BaraType {
    let t = raw.trim().trim_start_matches(['&', '*']).trim();
    let lower = t.to_ascii_lowercase();
    if lower.is_empty() {
        return BaraType::Unknown;
    }
    if matches!(
        lower.as_str(),
        "i8" | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "usize"
            | "isize"
            | "f32"
            | "f64"
            | "int"
            | "uint"
            | "byte"
            | "rune"
            | "number"
    ) || lower.starts_with("int")
        || lower.starts_with("uint")
        || lower.starts_with("float")
    {
        return BaraType::Number;
    }
    if matches!(lower.as_str(), "bool" | "boolean") {
        return BaraType::Truth;
    }
    if matches!(
        lower.as_str(),
        "str" | "string" | "&str" | "address" | "bytes" | "char"
    ) || lower.contains("string")
    {
        return BaraType::Text;
    }
    if matches!(lower.as_str(), "()" | "void" | "nil" | "none" | "unit") {
        return BaraType::Void;
    }
    BaraType::from_legacy(t)
}

fn pairs(items: &[(String, String)]) -> String {
    if items.is_empty() {
        return "-".to_string();
    }
    let mut out = String::new();
    for (index, (name, ty)) in items.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&clip(name, 32));
        if !ty.is_empty() {
            out.push(':');
            out.push_str(&clip(ty, 48));
        }
    }
    clip(&out, 120)
}

fn clip(text: &str, max: usize) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        if out.chars().count() >= max {
            break;
        }
        if ch.is_control() {
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Ident,
    Punct,
    Newline,
    Indent,
    Dedent,
}

struct Token {
    kind: Kind,
    lo: usize,
    hi: usize,
}

struct Parser<'a> {
    source: &'a str,
    language: SourceLanguage,
    tokens: Vec<Token>,
    index: usize,
    balanced: bool,
    /// Línea del último nombre tomado.
    named_line: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stop {
    Brace,
    Dedent,
    End,
}

#[derive(Clone, Copy)]
enum ParamStyle {
    Colon,
    NameType,
    TypeName,
}

impl<'a> Parser<'a> {
    fn parse_seq(&mut self, depth: u32, parent: &str, in_type: bool, stop: Stop) -> Vec<SynNode> {
        let mut items = Vec::new();
        let mut spins = 0usize;
        let budget = self.tokens.len().saturating_mul(4).saturating_add(8);
        while !self.eof() && spins < budget && items.len() < MAX_NODES {
            spins += 1;
            if stop == Stop::Brace && self.punct("}") {
                break;
            }
            if stop == Stop::Dedent && self.at(Kind::Dedent) {
                break;
            }
            if self.at(Kind::Newline) || self.at(Kind::Indent) {
                self.bump();
                continue;
            }
            let before = self.index;
            if depth > MAX_DEPTH {
                self.balanced = false;
                self.bump();
                continue;
            }
            if let Some(node) = self.try_decl(depth, parent, in_type) {
                items.push(node);
            } else if in_type {
                if let Some(field) = self.try_field() {
                    items.push(SynNode {
                        kind: SynKind::Type,
                        name: String::new(),
                        ty: String::new(),
                        params: vec![field],
                        argc: 0,
                        depth,
                        parent: parent.to_string(),
                        line: self.cursor_line(),
                        children: Vec::new(),
                    });
                } else if let Some(node) = self.try_call(depth, parent) {
                    items.push(node);
                } else {
                    self.bump();
                }
            } else if let Some(node) = self.try_call(depth, parent) {
                items.push(node);
            } else {
                self.bump();
            }
            if self.index == before {
                self.bump();
            }
        }
        if spins >= budget {
            self.balanced = false;
        }
        items
    }

    fn try_decl(&mut self, depth: u32, parent: &str, _in_type: bool) -> Option<SynNode> {
        if self.language == SourceLanguage::C {
            if let Some(node) = self.try_c_function(depth, parent) {
                return Some(node);
            }
        }
        if self.language == SourceLanguage::Go && self.word_is("func") {
            return Some(self.parse_go_func(depth, parent));
        }
        let word = self.word()?;
        let function = matches!(
            (self.language, word.as_str()),
            (SourceLanguage::Rust, "fn")
                | (SourceLanguage::JavaScript, "function")
                | (SourceLanguage::Python, "def")
                | (SourceLanguage::Solidity, "function")
        );
        let ty = matches!(
            (self.language, word.as_str()),
            (
                SourceLanguage::Rust,
                "struct" | "enum" | "trait" | "union" | "type" | "impl"
            ) | (SourceLanguage::JavaScript, "class" | "interface" | "type")
                | (SourceLanguage::Python, "class")
                | (
                    SourceLanguage::Solidity,
                    "contract" | "struct" | "enum" | "interface" | "library" | "event"
                )
                | (SourceLanguage::Go, "type")
                | (SourceLanguage::C, "class" | "struct" | "enum" | "namespace")
        );
        if function {
            self.bump();
            return Some(self.parse_function(depth, parent));
        }
        if ty {
            self.bump();
            return Some(self.parse_type(depth, parent));
        }
        None
    }

    fn parse_function(&mut self, depth: u32, parent: &str) -> SynNode {
        if self.punct("*") {
            self.bump();
        }
        let name = self.take_name();
        self.skip_angles();
        let params = self.read_params();
        self.skip_modifiers();
        let ty = self.read_return();
        self.skip_where();
        let children = self.take_body(depth, &name, false);
        SynNode {
            kind: SynKind::Function,
            name,
            ty,
            params,
            argc: 0,
            depth,
            parent: parent.to_string(),
            line: self.named_line,
            children,
        }
    }

    fn parse_go_func(&mut self, depth: u32, parent: &str) -> SynNode {
        self.bump();
        if self.punct("(") {
            let _ = self.read_paren();
        }
        let name = self.take_name();
        let params = self.read_params();
        let ty = self.read_return();
        let children = self.take_body(depth, &name, false);
        SynNode {
            kind: SynKind::Function,
            name,
            ty,
            params,
            argc: 0,
            depth,
            parent: parent.to_string(),
            line: self.named_line,
            children,
        }
    }

    fn parse_type(&mut self, depth: u32, parent: &str) -> SynNode {
        let name = self.take_name();
        self.skip_angles();
        self.skip_heritage();
        if self.punct("(") {
            let _ = self.read_paren();
        }
        let mut node = SynNode {
            kind: SynKind::Type,
            name: name.clone(),
            ty: String::new(),
            params: Vec::new(),
            argc: 0,
            depth,
            parent: parent.to_string(),
            line: self.named_line,
            children: Vec::new(),
        };
        self.skip_newlines();
        if self.punct("{") {
            self.bump();
            let inner = self.parse_seq(depth.saturating_add(1), &name, true, Stop::Brace);
            if self.punct("}") {
                self.bump();
            } else {
                self.balanced = false;
            }
            let mut fields = Vec::new();
            let mut children = Vec::new();
            for item in inner {
                if item.kind == SynKind::Type && item.name.is_empty() {
                    fields.extend(item.params);
                } else {
                    children.push(item);
                }
            }
            node.params = fields;
            node.children = children;
        } else if self.language == SourceLanguage::Python && self.punct(":") {
            self.bump();
            node.children = self.take_python_body(depth, &name, true);
        }
        node
    }

    fn try_c_function(&mut self, depth: u32, parent: &str) -> Option<SynNode> {
        let mark = self.index;
        let mut idents: Vec<String> = Vec::new();
        loop {
            if self.punct("*") || self.punct("&") {
                self.bump();
                continue;
            }
            let Some(word) = self.word() else {
                break;
            };
            if is_control(&word) {
                self.index = mark;
                return None;
            }
            idents.push(word);
            self.bump();
            if self.punct("(") {
                self.named_line = self.cursor_line();
                break;
            }
            if !self.kind_is(Kind::Ident) && !self.punct("*") && !self.punct("&") {
                break;
            }
        }
        if idents.len() < 2 || !self.punct("(") {
            self.index = mark;
            return None;
        }
        let name = idents.last().cloned().unwrap_or_else(|| "_".to_string());
        let ty = idents[..idents.len().saturating_sub(1)].join(" ");
        let params = self.read_params();
        self.skip_modifiers();
        if name == "_" {
            self.index = mark;
            return None;
        }
        let children = self.take_body(depth, &name, false);
        Some(SynNode {
            kind: SynKind::Function,
            name,
            ty,
            params,
            argc: 0,
            depth,
            parent: parent.to_string(),
            line: self.named_line,
            children,
        })
    }

    fn try_call(&mut self, depth: u32, parent: &str) -> Option<SynNode> {
        let mark = self.index;
        self.named_line = self.cursor_line();
        let name = self.read_path()?;
        let head = name.split(['.', ':']).next().unwrap_or(name.as_str());
        if is_control(head) || is_decl_word(head) {
            self.index = mark;
            return None;
        }
        if !self.punct("(") && !(self.punct("!") && self.lookahead_punct(1, "(")) {
            self.index = mark;
            return None;
        }
        if self.punct("!") {
            self.bump();
        }
        let inner = self.read_paren();
        let argc = count_args(&inner);
        Some(SynNode {
            kind: SynKind::Call,
            name,
            ty: String::new(),
            params: Vec::new(),
            argc,
            depth,
            parent: parent.to_string(),
            line: self.named_line,
            children: Vec::new(),
        })
    }

    fn try_field(&mut self) -> Option<(String, String)> {
        let mark = self.index;
        let name = self.word()?;
        if is_control(&name) || is_decl_word(&name) {
            return None;
        }
        self.bump();
        if self.punct(":") {
            self.bump();
            let ty = self.read_type_until(&["}", ",", ";"]);
            if self.punct(",") || self.punct(";") {
                self.bump();
            }
            return Some((clip(&name, 32), clip(&ty, 48)));
        }
        if matches!(self.language, SourceLanguage::Go | SourceLanguage::C)
            && self.kind_is(Kind::Ident)
        {
            let ty = self.read_type_until(&[",", ";", "}"]);
            if self.punct(",") || self.punct(";") {
                self.bump();
            }
            return Some((clip(&name, 32), clip(&ty, 48)));
        }
        self.index = mark;
        None
    }

    fn take_body(&mut self, depth: u32, name: &str, in_type: bool) -> Vec<SynNode> {
        self.skip_modifiers();
        self.skip_newlines();
        if self.punct("{") {
            self.bump();
            let children = self.parse_seq(depth.saturating_add(1), name, in_type, Stop::Brace);
            if self.punct("}") {
                self.bump();
            } else {
                self.balanced = false;
            }
            return children;
        }
        if self.language == SourceLanguage::Python && self.punct(":") {
            self.bump();
            return self.take_python_body(depth, name, in_type);
        }
        if self.punct(";") {
            self.bump();
        }
        Vec::new()
    }

    fn take_python_body(&mut self, depth: u32, name: &str, in_type: bool) -> Vec<SynNode> {
        self.skip_newlines();
        if !self.at(Kind::Indent) {
            return Vec::new();
        }
        self.bump();
        let children = self.parse_seq(depth.saturating_add(1), name, in_type, Stop::Dedent);
        if self.at(Kind::Dedent) {
            self.bump();
        } else {
            self.balanced = false;
        }
        children
    }

    fn read_params(&mut self) -> Vec<(String, String)> {
        if !self.punct("(") {
            return Vec::new();
        }
        let inner = self.read_paren();
        let style = match self.language {
            SourceLanguage::Go => ParamStyle::NameType,
            SourceLanguage::C | SourceLanguage::Solidity => ParamStyle::TypeName,
            _ => ParamStyle::Colon,
        };
        split_top(&inner)
            .into_iter()
            .filter_map(|piece| param_of(&piece, style))
            .take(MAX_ARITY)
            .collect()
    }

    fn read_return(&mut self) -> String {
        if self.punct("->") {
            self.bump();
            return clip(&self.read_type_until(&["{", ";", ":"]), MAX_NAME);
        }
        if self.language == SourceLanguage::JavaScript && self.punct(":") {
            self.bump();
            return clip(&self.read_type_until(&["{", ";", "=>"]), MAX_NAME);
        }
        if self.word_is("returns") {
            self.bump();
            if self.punct("(") {
                return clip(&self.read_paren(), MAX_NAME);
            }
        }
        if self.language == SourceLanguage::Go && (self.kind_is(Kind::Ident) || self.punct("(")) {
            if self.punct("(") {
                return clip(&self.read_paren(), MAX_NAME);
            }
            return clip(&self.read_type_until(&["{"]), MAX_NAME);
        }
        String::new()
    }

    fn read_paren(&mut self) -> String {
        if !self.punct("(") {
            return String::new();
        }
        let start = self
            .tokens
            .get(self.index)
            .map(|token| token.hi)
            .unwrap_or(0);
        self.bump();
        let mut depth = 1i32;
        let mut end = start;
        while let Some(token) = self.tokens.get(self.index) {
            let text = self.owned(self.index);
            if text == "(" {
                depth += 1;
            }
            if text == ")" {
                depth -= 1;
                if depth == 0 {
                    end = token.lo;
                    self.bump();
                    break;
                }
            }
            end = token.hi;
            self.bump();
        }
        if depth != 0 {
            self.balanced = false;
        }
        self.source.get(start..end).unwrap_or("").trim().to_string()
    }

    fn read_type_until(&mut self, stops: &[&str]) -> String {
        let mut lo = None;
        let mut hi = None;
        let mut angle = 0i32;
        let mut paren = 0i32;
        let mut bracket = 0i32;
        while self.index < self.tokens.len() {
            let kind = self.tokens[self.index].kind;
            let text = self.owned(self.index);
            let nested = angle > 0 || paren > 0 || bracket > 0;
            if !nested
                && (stops.contains(&text.as_str())
                    || kind == Kind::Newline
                    || kind == Kind::Dedent
                    || text == "where"
                    || text == "returns")
            {
                break;
            }
            match text.as_str() {
                "<" => angle += 1,
                ">" if angle > 0 => angle -= 1,
                "(" => paren += 1,
                ")" if paren == 0 => break,
                ")" => paren -= 1,
                "[" => bracket += 1,
                "]" if bracket == 0 => break,
                "]" => bracket -= 1,
                _ => {}
            }
            let (start, end) = {
                let token = &self.tokens[self.index];
                (token.lo, token.hi)
            };
            if lo.is_none() {
                lo = Some(start);
            }
            hi = Some(end);
            self.bump();
        }
        match (lo, hi) {
            (Some(start), Some(end)) => {
                self.source.get(start..end).unwrap_or("").trim().to_string()
            }
            _ => String::new(),
        }
    }

    fn read_path(&mut self) -> Option<String> {
        let mut name = self.word()?;
        if is_control(&name) || is_decl_word(&name) {
            return None;
        }
        self.bump();
        while self.punct(".") || self.punct("::") {
            let sep = if self.punct(".") { "." } else { "::" };
            self.bump();
            let Some(next) = self.word() else {
                break;
            };
            self.bump();
            name.push_str(sep);
            name.push_str(&next);
        }
        Some(clip(&name, MAX_NAME))
    }

    fn take_name(&mut self) -> String {
        self.skip_newlines();
        self.named_line = self.cursor_line();
        match self.word() {
            Some(name)
                if !matches!(
                    name.as_str(),
                    "struct" | "enum" | "interface" | "for" | "is"
                ) =>
            {
                self.bump();
                clip(&name, MAX_NAME)
            }
            _ => "_".to_string(),
        }
    }

    fn skip_angles(&mut self) {
        if !self.punct("<") {
            return;
        }
        self.bump();
        let mut depth = 1i32;
        let mut guard = 0usize;
        while !self.eof() && depth > 0 && guard < 2_000 {
            guard += 1;
            if self.punct("<") {
                depth += 1;
            } else if self.punct(">") {
                depth -= 1;
            }
            self.bump();
        }
        if depth != 0 {
            self.balanced = false;
        }
    }

    fn skip_heritage(&mut self) {
        let mut guard = 0usize;
        while !self.eof() && guard < 32 {
            guard += 1;
            if self.punct("{") || self.punct("(") || self.punct(":") || self.punct(";") {
                break;
            }
            if self.punct("<") {
                self.skip_angles();
                continue;
            }
            self.bump();
        }
    }

    fn skip_where(&mut self) {
        if !self.word_is("where") {
            return;
        }
        let mut guard = 0usize;
        while !self.eof() && guard < 80 {
            guard += 1;
            if self.punct("{") || self.punct(";") {
                break;
            }
            self.bump();
        }
    }

    fn skip_modifiers(&mut self) {
        if !matches!(self.language, SourceLanguage::Solidity | SourceLanguage::C) {
            return;
        }
        let mut guard = 0usize;
        while self.kind_is(Kind::Ident) && guard < 16 {
            let word = self.owned(self.index);
            if !is_modifier(&word) {
                break;
            }
            self.bump();
            guard += 1;
        }
    }

    fn skip_newlines(&mut self) {
        while self.at(Kind::Newline) {
            self.bump();
        }
    }

    fn lookahead_punct(&self, offset: usize, op: &str) -> bool {
        let Some(token) = self.tokens.get(self.index.saturating_add(offset)) else {
            return false;
        };
        token.kind == Kind::Punct && self.piece(token) == op
    }

    fn punct(&self, op: &str) -> bool {
        self.lookahead_punct(0, op)
    }

    fn word(&self) -> Option<String> {
        if !self.kind_is(Kind::Ident) {
            return None;
        }
        let text = self.owned(self.index);
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    }

    fn word_is(&self, expected: &str) -> bool {
        self.word().as_deref() == Some(expected)
    }

    fn at(&self, kind: Kind) -> bool {
        self.tokens
            .get(self.index)
            .is_some_and(|token| token.kind == kind)
    }

    fn kind_is(&self, kind: Kind) -> bool {
        self.at(kind)
    }

    fn eof(&self) -> bool {
        self.index >= self.tokens.len()
    }

    fn bump(&mut self) {
        if self.index < self.tokens.len() {
            self.index += 1;
        }
    }

    fn owned(&self, index: usize) -> String {
        self.tokens
            .get(index)
            .map(|token| self.piece(token).to_string())
            .unwrap_or_default()
    }

    fn piece(&self, token: &Token) -> &str {
        self.source.get(token.lo..token.hi).unwrap_or("")
    }

    fn cursor_line(&self) -> u32 {
        let offset = self
            .tokens
            .get(self.index)
            .map(|token| token.lo)
            .unwrap_or(0);
        let end = offset.min(self.source.len());
        let Some(prefix) = self.source.get(..end) else {
            return 1;
        };
        let breaks = prefix.bytes().filter(|byte| *byte == b'\n').count();
        u32::try_from(breaks).unwrap_or(u32::MAX).saturating_add(1)
    }
}

fn is_control(word: &str) -> bool {
    matches!(
        word,
        "if" | "for"
            | "while"
            | "switch"
            | "catch"
            | "sizeof"
            | "return"
            | "match"
            | "elif"
            | "else"
            | "new"
            | "delete"
            | "typeof"
            | "await"
            | "yield"
            | "case"
            | "do"
            | "pragma"
            | "import"
            | "package"
            | "use"
            | "let"
            | "var"
            | "const"
    )
}

fn is_decl_word(word: &str) -> bool {
    matches!(
        word,
        "fn" | "func"
            | "function"
            | "def"
            | "class"
            | "struct"
            | "enum"
            | "trait"
            | "impl"
            | "contract"
            | "interface"
            | "library"
            | "event"
            | "namespace"
            | "type"
            | "union"
    )
}

fn is_modifier(word: &str) -> bool {
    matches!(
        word,
        "public"
            | "private"
            | "internal"
            | "external"
            | "view"
            | "pure"
            | "payable"
            | "override"
            | "virtual"
            | "const"
            | "static"
            | "inline"
            | "explicit"
            | "mutable"
            | "noexcept"
            | "extern"
            | "unsigned"
            | "signed"
    )
}

fn param_of(piece: &str, style: ParamStyle) -> Option<(String, String)> {
    let piece = piece.trim();
    if piece.is_empty() {
        return None;
    }
    let (name, ty) = match style {
        ParamStyle::Colon => colon_param(piece),
        ParamStyle::NameType => {
            let name = first_ident(piece);
            if name.is_empty() {
                ("_".to_string(), clip(piece, 48))
            } else {
                let rest = piece[name.len()..].trim();
                (name, clip(rest, 48))
            }
        }
        ParamStyle::TypeName => type_name_param(piece),
    };
    if name == "_" && ty.is_empty() {
        None
    } else {
        Some((clip(&name, 32), ty))
    }
}

fn colon_param(piece: &str) -> (String, String) {
    if let Some(index) = top_colon(piece) {
        (
            bind_name(&piece[..index]),
            clip(piece[index + 1..].trim(), 48),
        )
    } else {
        (bind_name(piece), String::new())
    }
}

fn type_name_param(piece: &str) -> (String, String) {
    let ids = idents(piece);
    if ids.len() < 2 {
        return ("_".to_string(), clip(piece, 48));
    }
    let name = ids.last().cloned().unwrap_or_else(|| "_".to_string());
    let ty = piece
        .trim_end()
        .trim_end_matches(name.as_str())
        .trim()
        .trim_end_matches(['*', '&'])
        .trim();
    (name, clip(ty, 48))
}

fn bind_name(piece: &str) -> String {
    let filtered: Vec<String> = idents(piece)
        .into_iter()
        .filter(|word| !matches!(word.as_str(), "mut" | "pub" | "ref" | "const"))
        .collect();
    filtered.last().cloned().unwrap_or_else(|| "_".to_string())
}

fn first_ident(piece: &str) -> String {
    idents(piece.trim_start_matches(['*', '&', ' ']))
        .into_iter()
        .next()
        .unwrap_or_default()
}

fn idents(piece: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for ch in piece.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '$' {
            current.push(ch);
        } else if !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn top_colon(piece: &str) -> Option<usize> {
    let mut angle = 0i32;
    let mut paren = 0i32;
    let bytes = piece.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        let ch = bytes[index] as char;
        match ch {
            '<' => angle += 1,
            '>' if angle > 0 => angle -= 1,
            '(' => paren += 1,
            ')' if paren > 0 => paren -= 1,
            ':' if angle == 0 && paren == 0 && bytes.get(index + 1) != Some(&b':') => {
                return Some(index);
            }
            _ => {}
        }
        index += 1;
    }
    None
}

fn split_top(inner: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;
    let mut angle = 0i32;
    let mut chars = inner.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '(' | '[' | '{' => {
                depth += 1;
                current.push(ch);
            }
            ')' | ']' | '}' => {
                depth -= 1;
                current.push(ch);
            }
            '<' => {
                angle += 1;
                current.push(ch);
            }
            '>' if angle > 0 => {
                angle -= 1;
                current.push(ch);
            }
            '"' | '\'' => {
                current.push(ch);
                while let Some(inner_ch) = chars.next() {
                    current.push(inner_ch);
                    if inner_ch == '\\' {
                        if let Some(escaped) = chars.next() {
                            current.push(escaped);
                        }
                        continue;
                    }
                    if inner_ch == ch {
                        break;
                    }
                }
            }
            ',' if depth == 0 && angle == 0 => {
                if !current.trim().is_empty() {
                    out.push(current.trim().to_string());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        out.push(current.trim().to_string());
    }
    out
}

fn count_args(inner: &str) -> usize {
    if inner.trim().is_empty() {
        0
    } else {
        split_top(inner).len()
    }
}

fn lex(source: &str, language: SourceLanguage) -> (Vec<Token>, bool) {
    let mut tokens = Vec::new();
    let mut chars = source.char_indices().peekable();
    let python = language == SourceLanguage::Python;
    let mut indents = vec![0usize];
    let mut balanced = true;
    let mut at_line = true;
    let mut guard = 0usize;
    let budget = source.len().saturating_mul(2).saturating_add(8);
    while chars.peek().is_some() && guard < budget {
        guard += 1;
        if at_line && python {
            if !apply_indent(&mut chars, &mut indents, &mut tokens) {
                balanced = false;
            }
            at_line = false;
            continue;
        }
        let Some((index, ch)) = chars.peek().copied() else {
            break;
        };
        if ch == ' ' || ch == '\t' || ch == '\r' {
            chars.next();
            continue;
        }
        if ch == '\n' {
            chars.next();
            if python {
                tokens.push(Token {
                    kind: Kind::Newline,
                    lo: index,
                    hi: index + 1,
                });
            }
            at_line = true;
            continue;
        }
        at_line = false;
        if ch == '/' && slash(&mut chars, &mut tokens, index) {
            continue;
        }
        if ch == '#' {
            hash_token(&mut chars, language, &mut tokens, index);
            continue;
        }
        if ch == '"' || ch == '\'' {
            if !string_token(&mut chars, language, &mut tokens, index, ch) {
                balanced = false;
            }
            continue;
        }
        if ch == 'r' && raw_string(&mut chars, &mut tokens, index) {
            continue;
        }
        if ch.is_ascii_digit() {
            number_token(&mut chars, &mut tokens, index);
            continue;
        }
        if ch.is_ascii_alphabetic() || ch == '_' || ch == '$' {
            ident_token(&mut chars, &mut tokens, index);
            continue;
        }
        punct_token(&mut chars, &mut tokens, index, ch);
    }
    if guard >= budget {
        balanced = false;
    }
    while indents.len() > 1 {
        indents.pop();
        tokens.push(Token {
            kind: Kind::Dedent,
            lo: source.len(),
            hi: source.len(),
        });
    }
    (tokens, balanced)
}

fn apply_indent(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    indents: &mut Vec<usize>,
    tokens: &mut Vec<Token>,
) -> bool {
    loop {
        let mut spaces = 0usize;
        while let Some((_, ch)) = chars.peek().copied() {
            if ch == ' ' || ch == '\t' {
                spaces += 1;
                chars.next();
            } else {
                break;
            }
        }
        let Some((index, ch)) = chars.peek().copied() else {
            return true;
        };
        if ch == '\n' || ch == '\r' {
            chars.next();
            continue;
        }
        if ch == '#' {
            while chars.peek().is_some_and(|(_, next)| *next != '\n') {
                chars.next();
            }
            continue;
        }
        let _ = index;
        return push_indent(spaces, indents, tokens);
    }
}

fn push_indent(spaces: usize, indents: &mut Vec<usize>, tokens: &mut Vec<Token>) -> bool {
    let current = indents.last().copied().unwrap_or(0);
    if spaces > current {
        indents.push(spaces);
        tokens.push(Token {
            kind: Kind::Indent,
            lo: 0,
            hi: 0,
        });
        return true;
    }
    let mut balanced = true;
    while indents.last().copied().unwrap_or(0) > spaces {
        indents.pop();
        tokens.push(Token {
            kind: Kind::Dedent,
            lo: 0,
            hi: 0,
        });
    }
    if indents.last().copied().unwrap_or(0) != spaces {
        balanced = false;
    }
    balanced
}

fn slash(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    tokens: &mut Vec<Token>,
    index: usize,
) -> bool {
    chars.next();
    let Some((_, next)) = chars.peek().copied() else {
        tokens.push(Token {
            kind: Kind::Punct,
            lo: index,
            hi: index + 1,
        });
        return true;
    };
    if next == '/' {
        chars.next();
        while chars.peek().is_some_and(|(_, ch)| *ch != '\n') {
            chars.next();
        }
        return true;
    }
    if next == '*' {
        chars.next();
        while let Some((_, ch)) = chars.next() {
            if ch == '*' && chars.peek().is_some_and(|(_, next)| *next == '/') {
                chars.next();
                break;
            }
        }
        return true;
    }
    tokens.push(Token {
        kind: Kind::Punct,
        lo: index,
        hi: index + 1,
    });
    true
}

fn hash_token(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    language: SourceLanguage,
    tokens: &mut Vec<Token>,
    index: usize,
) {
    chars.next();
    if language == SourceLanguage::Rust && chars.peek().is_some_and(|(_, ch)| *ch == '[') {
        chars.next();
        let mut depth = 1i32;
        for (_, ch) in chars.by_ref() {
            if ch == '[' {
                depth += 1;
            } else if ch == ']' {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
        }
        return;
    }
    let _ = (tokens, index);
    while chars.peek().is_some_and(|(_, ch)| *ch != '\n') {
        chars.next();
    }
}

fn string_token(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    language: SourceLanguage,
    tokens: &mut Vec<Token>,
    index: usize,
    quote: char,
) -> bool {
    chars.next();
    if quote == '\'' && language == SourceLanguage::Rust {
        let mut look = chars.clone();
        let Some((_, first)) = look.next() else {
            return false;
        };
        let second = look.next().map(|(_, ch)| ch);
        if first != '\\' && second != Some('\'') && (first.is_ascii_alphabetic() || first == '_') {
            while let Some((_, ch)) = chars.peek().copied() {
                if ch.is_ascii_alphanumeric() || ch == '_' {
                    chars.next();
                } else {
                    break;
                }
            }
            return true;
        }
    }
    let mut closed = false;
    while let Some((_, ch)) = chars.next() {
        if ch == '\\' {
            chars.next();
            continue;
        }
        if ch == quote {
            closed = true;
            break;
        }
        if ch == '\n' && quote == '\'' {
            break;
        }
    }
    let _ = tokens;
    let _ = index;
    closed
}

fn raw_string(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    _tokens: &mut Vec<Token>,
    _index: usize,
) -> bool {
    let mut look = chars.clone();
    look.next();
    let Some((_, next)) = look.next() else {
        return false;
    };
    if next != '"' && next != '#' {
        return false;
    }
    chars.next();
    let mut hashes = 0usize;
    while chars.peek().is_some_and(|(_, ch)| *ch == '#') {
        hashes += 1;
        chars.next();
    }
    if chars.peek().is_some_and(|(_, ch)| *ch == '"') {
        chars.next();
    }
    let mut seen = 0usize;
    while let Some((_, ch)) = chars.next() {
        if ch == '"' {
            seen = 0;
            continue;
        }
        if ch == '#' && seen == 0 {
            seen = 1;
            let mut count = 1usize;
            while count < hashes && chars.peek().is_some_and(|(_, next)| *next == '#') {
                chars.next();
                count += 1;
            }
            if count == hashes {
                return true;
            }
        }
    }
    false
}

fn number_token(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    tokens: &mut Vec<Token>,
    index: usize,
) {
    let mut end = index;
    while let Some((pos, ch)) = chars.peek().copied() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' {
            end = pos + ch.len_utf8();
            chars.next();
        } else {
            break;
        }
    }
    tokens.push(Token {
        kind: Kind::Punct,
        lo: index,
        hi: end,
    });
}

fn ident_token(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    tokens: &mut Vec<Token>,
    index: usize,
) {
    let mut end = index;
    while let Some((pos, ch)) = chars.peek().copied() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '$' {
            end = pos + ch.len_utf8();
            chars.next();
        } else {
            break;
        }
    }
    tokens.push(Token {
        kind: Kind::Ident,
        lo: index,
        hi: end,
    });
}

fn punct_token(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    tokens: &mut Vec<Token>,
    index: usize,
    ch: char,
) {
    chars.next();
    let next = chars.peek().map(|(_, next)| *next);
    let pair = match (ch, next) {
        ('-', Some('>')) => Some(2usize),
        ('=', Some('>')) => Some(2),
        (':', Some(':')) => Some(2),
        (':', Some('=')) => Some(2),
        ('=', Some('=')) => Some(2),
        ('!', Some('=')) => Some(2),
        ('<', Some('=')) => Some(2),
        ('>', Some('=')) => Some(2),
        _ => None,
    };
    let width = if pair.is_some() {
        chars.next();
        ch.len_utf8() + next.map(|item| item.len_utf8()).unwrap_or(0)
    } else {
        ch.len_utf8()
    };
    tokens.push(Token {
        kind: Kind::Punct,
        lo: index,
        hi: index + width,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find<'a>(nodes: &'a [ShoreshNode], needle: &str) -> &'a ShoreshNode {
        nodes
            .iter()
            .find(|node| node.original.contains(needle))
            .unwrap_or_else(|| panic!("falta {needle}"))
    }

    #[test]
    fn rust_extrae_tipo_parametro_retorno_y_llamada_anidada() {
        let source =
            "struct Point { x: i32, y: i32 }\nfn length(p: &Point) -> i32 {\n    helper(p)\n}\n";
        let tree = parse(SourceLanguage::Rust, source);
        let nodes = tree.into_nodes(SourceLanguage::Rust);
        let point = find(&nodes, "name=Point:");
        assert_eq!(point.root, "בנה");
        assert_eq!(point.ret, BaraType::Record);
        assert!(point.original.contains("x:i32"));
        assert!(point.original.contains("y:i32"));
        let length = find(&nodes, "name=length:");
        assert_eq!(length.ret, BaraType::Number);
        assert_eq!(length.arity, 1);
        assert!(length.original.contains("ret=i32"));
        assert!(length.original.contains("p:&Point"));
        let call = find(&nodes, "name=helper:");
        assert_eq!(call.root, "קרא");
        assert_eq!(call.arity, 1);
        assert!(call.original.contains("parent=length"));
        assert!(call.original.contains("d=1"));
    }

    #[test]
    fn los_otros_lenguajes_conservan_el_nombre_y_el_padre() {
        let py = parse(
            SourceLanguage::Python,
            "class Caja:\n    def abrir(self):\n        return 1\n",
        );
        let nodes = py.into_nodes(SourceLanguage::Python);
        assert!(find(&nodes, "name=abrir:").original.contains("parent=Caja"));

        let sol = parse(
            SourceLanguage::Solidity,
            "contract Token { function transfer(address to) public returns (bool) { send(to) } }\n",
        );
        let nodes = sol.into_nodes(SourceLanguage::Solidity);
        let transfer = find(&nodes, "name=transfer:");
        assert!(transfer.original.contains("parent=Token"));
        assert_eq!(transfer.ret, BaraType::Truth);
        assert!(find(&nodes, "name=send:")
            .original
            .contains("parent=transfer"));

        let go = parse(
            SourceLanguage::Go,
            "package main\nfunc main() int { ping() }\n",
        );
        let nodes = go.into_nodes(SourceLanguage::Go);
        assert_eq!(find(&nodes, "name=main:").ret, BaraType::Number);
        assert!(find(&nodes, "name=ping:").original.contains("parent=main"));

        let cpp = parse(SourceLanguage::C, "int main() { return 0; }\n");
        let nodes = cpp.into_nodes(SourceLanguage::C);
        assert_eq!(find(&nodes, "name=main:").ret, BaraType::Number);

        let ts = parse(
            SourceLanguage::JavaScript,
            "function ping(n: number): number { return n; }\n",
        );
        let nodes = ts.into_nodes(SourceLanguage::JavaScript);
        let ping = find(&nodes, "name=ping:");
        assert_eq!(ping.ret, BaraType::Number);
        assert!(ping.original.contains("n:number"));
    }

    #[test]
    fn el_script_android_nombra_el_target() {
        let script = include_str!("../scripts/check-android.ps1");
        assert!(script.contains("aarch64-linux-android"));
        assert!(script.contains("cargo check -p bara"));
    }

    #[test]
    fn el_parche_limpio_es_verdadero_y_el_choque_es_both() {
        assert_eq!(
            judge_patch(SourceLanguage::Rust, "", "fn beta() {}\n"),
            BelnapValue::True
        );
        assert_eq!(
            judge_patch(SourceLanguage::Rust, "fn alpha() {}\n", "fn alpha() {}\n"),
            BelnapValue::Both
        );
        assert_eq!(
            judge_patch(SourceLanguage::Rust, "", "fn gamma() {\n"),
            BelnapValue::Both
        );
        assert_eq!(
            judge_patch(SourceLanguage::Rust, "fn alpha() {}\n", "   \n"),
            BelnapValue::False
        );
        assert_eq!(
            judge_patch(
                SourceLanguage::Rust,
                "fn alpha() {}\nfn beta() {}\n",
                "fn beta() {}\n"
            ),
            BelnapValue::Both
        );
    }

    #[test]
    fn una_raiz_desconocida_deja_el_parche_en_vacio() {
        assert_eq!(
            judge_patch(SourceLanguage::Unknown, "", "זזז\n"),
            BelnapValue::Neither
        );
        let reason = shoresh_unverified_reason("זזז\n");
        assert!(
            reason
                .as_deref()
                .is_some_and(|text| text.contains("propuesta no verificada"))
        );
        assert!(shoresh_unverified_reason("ברא\n").is_none());
    }
}
