//! # Bara Lexer — Analizador de Raíces Triconsonánticas
//!
//! El lexer de Bara no tokeniza palabras clave en inglés, sino **raíces
//! triconsonánticas hebreas** (שֹׁרֶשׁ, *shoresh*). Cada raíz de tres
//! consonantes concentra un campo semántico completo que actúa como
//! instrucción primitiva del lenguaje.
//!
//! Reglas de tokenización:
//! * Se descartan los signos diacríticos (*nikud*, cantilación) y se
//!   conservan únicamente las consonantes del bloque hebreo `U+05D0..=U+05EA`.
//! * Una secuencia de exactamente tres consonantes forma una raíz válida.
//! * Las raíces desconocidas **no** producen error: se emiten como
//!   [`TokenKind::Root`] sin [`Keyword`] asociada, y el runtime se encarga
//!   de sintetizar su axioma (autopoiesis).
//!
//! El lexer es **totalmente infalible**: jamás rechaza su entrada. Aquello
//! que no comprende lo degrada a un símbolo genérico en lugar de abortar.

use std::fmt;

/// Palabras clave semánticas destiladas de raíces triconsonánticas conocidas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keyword {
    /// ברא — manifestación / creación.
    Manifest,
    /// שמר — guarda / aislamiento de día-cero.
    Guard,
    /// חכם — heurística adaptativa / sabiduría.
    Synthesize,
    /// עבד — ejecución.
    Execute,
    /// אמר — emisión / enunciación.
    Emit,
    /// שפט — evaluación / juicio lógico.
    Judge,
}

impl Keyword {
    /// Destila la palabra clave asociada a una raíz, si existe.
    pub fn from_root(root: &str) -> Option<Keyword> {
        match root {
            "ברא" => Some(Keyword::Manifest),
            "שמר" => Some(Keyword::Guard),
            "חכם" => Some(Keyword::Synthesize),
            "עבד" => Some(Keyword::Execute),
            "אמר" => Some(Keyword::Emit),
            "שפט" => Some(Keyword::Judge),
            _ => None,
        }
    }

    /// El glifo hebreo canónico de la raíz.
    pub fn glyph(&self) -> &'static str {
        match self {
            Keyword::Manifest => "ברא",
            Keyword::Guard => "שמר",
            Keyword::Synthesize => "חכם",
            Keyword::Execute => "עבד",
            Keyword::Emit => "אמר",
            Keyword::Judge => "שפט",
        }
    }

    /// Descripción ontológica de la instrucción.
    pub fn meaning(&self) -> &'static str {
        match self {
            Keyword::Manifest => "manifestar (creación ex nihilo)",
            Keyword::Guard => "guardar (aislamiento de día-cero)",
            Keyword::Synthesize => "sintetizar (heurística adaptativa)",
            Keyword::Execute => "ejecutar (colapso operacional)",
            Keyword::Emit => "emitir (enunciar el estado)",
            Keyword::Judge => "juzgar (evaluación lógica)",
        }
    }
}

/// Tipos de token producidos por el lexer.
#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    /// Raíz triconsonántica, con su palabra clave si es conocida.
    Root {
        /// Consonantes puras que componen la raíz.
        letters: String,
        /// Semántica reconocida, o `None` si la raíz es desconocida.
        keyword: Option<Keyword>,
    },
    /// Identificador ASCII (p. ej. etiqueta de memoria).
    Identifier(String),
    /// Literal numérico.
    Number(f64),
    /// Literal de cadena.
    Str(String),
    /// `:`
    Colon,
    /// `;`
    Semicolon,
    /// `,`
    Comma,
    /// `->`
    Arrow,
    /// `+` disyunción paraconsistente.
    Plus,
    /// `*` conjunción paraconsistente.
    Star,
    /// `!` colapso forzado / observación.
    Bang,
    /// `!!` fusión paraconsistente (contradicción controlada).
    BangBang,
    /// `?` interrogación / observación heurística.
    Question,
    /// Cualquier otro símbolo, preservado sin juicio.
    Punct(char),
    /// Fin de línea.
    Newline,
    /// Fin de entrada.
    Eof,
}

/// Un token con su ubicación física en la fuente.
#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    /// Clase léxica.
    pub kind: TokenKind,
    /// Línea (1-based).
    pub line: usize,
    /// Columna (1-based).
    pub column: usize,
}

impl Token {
    /// Devuelve la palabra clave de la raíz, si la hay.
    pub fn keyword(&self) -> Option<Keyword> {
        match &self.kind {
            TokenKind::Root { keyword, .. } => *keyword,
            _ => None,
        }
    }
}

impl fmt::Display for TokenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenKind::Root { letters, keyword } => match keyword {
                Some(k) => write!(f, "Root({} ⇒ {})", letters, k.glyph()),
                None => write!(f, "Root({} ?)", letters),
            },
            TokenKind::Identifier(s) => write!(f, "Ident({})", s),
            TokenKind::Number(n) => write!(f, "Num({})", n),
            TokenKind::Str(s) => write!(f, "Str({:?})", s),
            TokenKind::Colon => write!(f, "Colon"),
            TokenKind::Semicolon => write!(f, "Semicolon"),
            TokenKind::Comma => write!(f, "Comma"),
            TokenKind::Arrow => write!(f, "Arrow(->)"),
            TokenKind::Plus => write!(f, "Plus(+)"),
            TokenKind::Star => write!(f, "Star(*)"),
            TokenKind::Bang => write!(f, "Bang(!)"),
            TokenKind::BangBang => write!(f, "BangBang(!!)"),
            TokenKind::Question => write!(f, "Question(?)"),
            TokenKind::Punct(c) => write!(f, "Punct({})", c),
            TokenKind::Newline => write!(f, "Newline"),
            TokenKind::Eof => write!(f, "Eof"),
        }
    }
}

/// Analizador léxico de raíces triconsonánticas.
pub struct Lexer {
    chars: Vec<char>,
    pos: usize,
    line: usize,
    column: usize,
}

impl Lexer {
    /// Construye un lexer sobre una fuente de texto.
    pub fn new(source: &str) -> Self {
        Lexer {
            chars: source.chars().collect(),
            pos: 0,
            line: 1,
            column: 1,
        }
    }

    /// Tokeniza por completo la fuente. **Nunca falla.**
    pub fn tokenize(mut self) -> Vec<Token> {
        let mut tokens = Vec::new();
        while let Some(token) = self.next_token() {
            tokens.push(token);
        }
        tokens.push(Token {
            kind: TokenKind::Eof,
            line: self.line,
            column: self.column,
        });
        tokens
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        if c == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        Some(c)
    }

    fn next_token(&mut self) -> Option<Token> {
        loop {
            let c = self.peek()?;

            if c == '\n' {
                let (line, column) = (self.line, self.column);
                self.bump();
                return Some(Token {
                    kind: TokenKind::Newline,
                    line,
                    column,
                });
            }
            if c.is_whitespace() {
                self.bump();
                continue;
            }
            if c == '#' {
                while let Some(ch) = self.peek() {
                    if ch == '\n' {
                        break;
                    }
                    self.bump();
                }
                continue;
            }

            let (line, column) = (self.line, self.column);
            if is_hebrew_consonant(c) || is_hebrew_mark(c) {
                return Some(self.read_root(line, column));
            }
            if c.is_ascii_digit() {
                return Some(self.read_number(line, column));
            }
            if c.is_alphabetic() {
                return Some(self.read_identifier(line, column));
            }
            if c == '"' {
                return Some(self.read_string(line, column));
            }
            return Some(self.read_symbol(line, column));
        }
    }

    /// Lee una raíz: acumula consonantes y descarta los signos diacríticos.
    fn read_root(&mut self, line: usize, column: usize) -> Token {
        let mut letters = String::new();
        while let Some(c) = self.peek() {
            if is_hebrew_consonant(c) {
                letters.push(c);
                self.bump();
            } else if is_hebrew_mark(c) || is_geresh(c) {
                // El *nikud* y el geresh/gershayim no alteran la raíz.
                self.bump();
            } else {
                break;
            }
        }
        let keyword = Keyword::from_root(&letters);
        Token {
            kind: TokenKind::Root { letters, keyword },
            line,
            column,
        }
    }

    fn read_number(&mut self, line: usize, column: usize) -> Token {
        let mut buf = String::new();
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || c == '.' {
                buf.push(c);
                self.bump();
            } else {
                break;
            }
        }
        let value = buf.parse::<f64>().unwrap_or(0.0);
        Token {
            kind: TokenKind::Number(value),
            line,
            column,
        }
    }

    fn read_identifier(&mut self, line: usize, column: usize) -> Token {
        let mut buf = String::new();
        while let Some(c) = self.peek() {
            if c.is_alphanumeric() || c == '_' {
                buf.push(c);
                self.bump();
            } else {
                break;
            }
        }
        Token {
            kind: TokenKind::Identifier(buf),
            line,
            column,
        }
    }

    fn read_string(&mut self, line: usize, column: usize) -> Token {
        self.bump(); // comilla de apertura
        let mut buf = String::new();
        while let Some(c) = self.peek() {
            match c {
                '"' => {
                    self.bump();
                    break;
                }
                '\\' => {
                    self.bump();
                    if let Some(esc) = self.bump() {
                        buf.push(esc);
                    }
                }
                _ => {
                    buf.push(c);
                    self.bump();
                }
            }
        }
        Token {
            kind: TokenKind::Str(buf),
            line,
            column,
        }
    }

    fn read_symbol(&mut self, line: usize, column: usize) -> Token {
        let c = self.bump().unwrap_or('?');
        let kind = match c {
            ':' => TokenKind::Colon,
            ';' => TokenKind::Semicolon,
            ',' => TokenKind::Comma,
            '+' => TokenKind::Plus,
            '*' => TokenKind::Star,
            '?' => TokenKind::Question,
            '!' => {
                if self.peek() == Some('!') {
                    self.bump();
                    TokenKind::BangBang
                } else {
                    TokenKind::Bang
                }
            }
            '-' => {
                if self.peek() == Some('>') {
                    self.bump();
                    TokenKind::Arrow
                } else {
                    TokenKind::Punct('-')
                }
            }
            other => TokenKind::Punct(other),
        };
        Token { kind, line, column }
    }
}

/// ¿Es una consonante del bloque hebreo (alef `א` … tav `ת`)?
fn is_hebrew_consonant(c: char) -> bool {
    (0x05D0..=0x05EA).contains(&(c as u32))
}

/// ¿Es un signo diacrítico hebreo (*nikud*, cantilación)?
fn is_hebrew_mark(c: char) -> bool {
    (0x0591..=0x05C7).contains(&(c as u32))
}

/// ¿Es un apóstrofo hebreo (geresh `׳` / gershayim `״`)?
fn is_geresh(c: char) -> bool {
    matches!(c as u32, 0x05F3 | 0x05F4)
}



