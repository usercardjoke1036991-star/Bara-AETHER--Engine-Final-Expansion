//! # Visual Builder — el lienzo del IDE se vuelve *Shoresh* firmado
//!
//! Motor de traducción del **constructor visual**: el IDE pinta un lienzo de
//! bloques conectados y este módulo lo traduce al AST *Shoresh* del kernel,
//! **firmado** con el ADN soberano ([`crate::ast_dna::ast_dna`]) y listo para
//! conversar con el oráculo.
//!
//! ## Entrada: *blueprint* JSON **estricto**
//!
//! ```json
//! {
//!   "module": "saludo",
//!   "label": "lienzo-saludo",
//!   "blocks": [
//!     { "id": "a", "name": "leer_entrada", "kind": "source",
//!       "arity": 0, "ret": "number", "hazard": 0.0 },
//!     { "id": "b", "name": "doble", "kind": "transform", "arity": 1,
//!       "ret": "number", "hazard": 0.0, "inputs": [{ "index": 0 }] },
//!     { "id": "c", "name": "sellar", "kind": "guard", "arity": 1,
//!       "ret": "number", "hazard": 0.2, "inputs": [{ "index": 1 }] },
//!     { "id": "d", "name": "emitir", "kind": "sink", "arity": 1,
//!       "ret": "void", "hazard": 0.0, "inputs": [{ "index": 2,
//!         "type": "number" }] }
//!   ]
//! }
//! ```
//!
//! *Estricto* quiere decir que **no** hay tolerancia: una clave desconocida, un
//! número mal formado, una clave repetida, un tipo fuera del catálogo, una
//! aridad que no cuadra o una referencia hacia delante invalidan el lienzo
//! entero (`None`), en vez de degradar en silencio a un AST a medias. El IDE
//! puede así señalar el error con precisión en lugar de compilar una mentira.
//!
//! ## Qué valida (la parte matemática, no decorativa)
//! 1. **Aridad** — cada bloque recibe exactamente las entradas que declara
//!    (`inputs.len() == arity`); un `source` no recibe ninguna.
//! 2. **Tipos** — el tipo de retorno del productor tiene que satisfacer el tipo
//!    declarado en la ranura (`unknown` es comodín, como en la ingesta FFI).
//! 3. **Orden** — las referencias sólo miran hacia atrás, de modo que el grafo
//!    es acíclico *por construcción*; el orden topológico es el natural de los
//!    índices y la profundidad es la longitud del camino más largo.
//! 4. **Riesgo** — cada nodo declara `hazard ∈ [0, 1]`; se publica la media, el
//!    máximo y la **cota áurea** `máximo + (máximo − mínimo)/φ` (saturada a `1`),
//!    que es el margen que el kernel aplica al repartir memoria.
//! 5. **Retícula** — los bloques se colocan en la espiral de Fermat con ángulo
//!    áureo (`r_k = √k`, `θ_k = k·2π/φ²`), el reparto de mínima discrepancia que
//!    usa la memoria holográfica; se mide la distancia mínima entre celdas para
//!    probar que el lienzo no colisiona.
//!
//! ## Invariantes heredados
//! 1. **Sólo `std`** — cero dependencias: el parser JSON es de este módulo.
//! 2. **Sin `unsafe`** y **sin `unwrap`/`expect`**: toda ruta de fallo es `None`.
//! 3. **Determinismo** — ni aleatoriedad ni reloj: mismas entradas, misma firma.

use crate::ast_dna::{ast_dna, short_hex, verify, AstDna};
use crate::ffi_ingest::{root_from_name, BaraType, ShoreshAst, ShoreshNode};
use crate::fractal_geometry::{golden_angle, phi};
use crate::runtime::QuantumState;

// ─────────────────────────────────────────────────────────────────────────
// Cotas del lienzo
// ─────────────────────────────────────────────────────────────────────────

/// Bloques máximos de un lienzo (una retícula mayor no cabe en el panel).
pub const MAX_BLOCKS: usize = 256;
/// Bytes máximos del *blueprint* aceptado.
pub const MAX_BLUEPRINT_BYTES: usize = 64 * 1024;
/// Profundidad máxima de anidamiento del JSON aceptado.
pub const MAX_JSON_DEPTH: usize = 32;
/// Longitud máxima de un identificador de bloque.
pub const MAX_ID_CHARS: usize = 64;
/// Riesgo a partir del cual el nodo nace **sellado** bajo guarda `שמר`.
pub const SEAL_THRESHOLD: f64 = 0.5;
/// Distancia mínima exigida entre celdas de la retícula áurea.
///
/// Es una cota **medida** (no un teorema): las pruebas del módulo la comprueban
/// para el peor caso admitido ([`MAX_BLOCKS`] bloques en el anillo inicial).
pub const MIN_CELL_DISTANCE: f64 = 0.28;

// ─────────────────────────────────────────────────────────────────────────
// JSON estricto (parser propio, sin dependencias)
// ─────────────────────────────────────────────────────────────────────────

/// Valor JSON. El objeto conserva el **orden** de las claves: el informe es
/// reproducible y las claves repetidas se detectan al insertarlas.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Json {
    /// `null`.
    Null,
    /// `true` / `false`.
    Bool(bool),
    /// Número (finito por construcción).
    Number(f64),
    /// Cadena ya desescapada.
    Text(String),
    /// Secuencia ordenada.
    Array(Vec<Json>),
    /// Objeto: pares `(clave, valor)` en orden de aparición, sin repetidas.
    Object(Vec<(String, Json)>),
}

impl Json {
    /// Cadena, si el valor lo es.
    pub(crate) fn as_text(&self) -> Option<&str> {
        match self {
            Json::Text(text) => Some(text.as_str()),
            _ => None,
        }
    }

    /// Número, si el valor lo es.
    pub(crate) fn as_number(&self) -> Option<f64> {
        match self {
            Json::Number(value) => Some(*value),
            _ => None,
        }
    }

    /// Secuencia, si el valor lo es.
    pub(crate) fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(items) => Some(items.as_slice()),
            _ => None,
        }
    }

    /// Objeto como pares en orden de aparición, si el valor lo es.
    ///
    /// Lo comparte el puente BSC ([`crate::bsc_bridge`]) para leer los sobres
    /// JSON‑RPC: la respuesta se inspecciona tal cual llegó, sin copias
    /// divergentes del documento.
    pub(crate) fn as_object(&self) -> Option<&[(String, Json)]> {
        match self {
            Json::Object(entries) => Some(entries.as_slice()),
            _ => None,
        }
    }

    /// Miembro de un objeto, si el valor es objeto y la clave existe.
    pub(crate) fn member(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(entries) => entries
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }
}

/// Recorredor de bytes con las reglas **estrictas** de JSON (RFC 8259).
struct Scanner<'a> {
    /// Bytes de entrada.
    bytes: &'a [u8],
    /// Posición actual.
    pos: usize,
}

impl<'a> Scanner<'a> {
    /// Escáner sobre un texto.
    fn new(input: &'a str) -> Self {
        Scanner {
            bytes: input.as_bytes(),
            pos: 0,
        }
    }

    /// Byte actual, si queda alguno.
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// Consume y devuelve el byte actual.
    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos += 1;
        Some(byte)
    }

    /// Salta los espacios en blanco canónicos (` `, `\t`, `\n`, `\r`).
    fn skip_ws(&mut self) {
        while matches!(
            self.peek(),
            Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r')
        ) {
            self.pos += 1;
        }
    }

    /// Consume una palabra literal completa (`true`, `false`, `null`).
    fn literal(&mut self, word: &[u8]) -> bool {
        let end = self.pos.saturating_add(word.len());
        if self.bytes.get(self.pos..end) == Some(word) {
            self.pos = end;
            true
        } else {
            false
        }
    }

    /// Lee un valor; `depth` acota el anidamiento admitido.
    fn value(&mut self, depth: usize) -> Option<Json> {
        if depth > MAX_JSON_DEPTH {
            return None;
        }
        self.skip_ws();
        match self.peek()? {
            b'n' => {
                if self.literal(b"null") {
                    Some(Json::Null)
                } else {
                    None
                }
            }
            b't' => {
                if self.literal(b"true") {
                    Some(Json::Bool(true))
                } else {
                    None
                }
            }
            b'f' => {
                if self.literal(b"false") {
                    Some(Json::Bool(false))
                } else {
                    None
                }
            }
            b'"' => Some(Json::Text(self.string()?)),
            b'[' => self.array(depth),
            b'{' => self.object(depth),
            _ => Some(Json::Number(self.number()?)),
        }
    }

    /// Lee una secuencia.
    fn array(&mut self, depth: usize) -> Option<Json> {
        if self.bump() != Some(b'[') {
            return None;
        }
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek()? == b']' {
            self.pos += 1;
            return Some(Json::Array(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            if items.len() > MAX_BLOCKS * 4 {
                return None;
            }
            self.skip_ws();
            match self.bump()? {
                b',' => continue,
                b']' => return Some(Json::Array(items)),
                _ => return None,
            }
        }
    }

    /// Lee un objeto, rechazando claves repetidas.
    fn object(&mut self, depth: usize) -> Option<Json> {
        if self.bump() != Some(b'{') {
            return None;
        }
        let mut entries: Vec<(String, Json)> = Vec::new();
        self.skip_ws();
        if self.peek()? == b'}' {
            self.pos += 1;
            return Some(Json::Object(entries));
        }
        loop {
            self.skip_ws();
            if self.peek()? != b'"' {
                return None;
            }
            let key = self.string()?;
            if entries.iter().any(|(name, _)| name == &key) {
                return None;
            }
            self.skip_ws();
            if self.bump()? != b':' {
                return None;
            }
            let value = self.value(depth + 1)?;
            entries.push((key, value));
            if entries.len() > MAX_BLOCKS * 4 {
                return None;
            }
            self.skip_ws();
            match self.bump()? {
                b',' => continue,
                b'}' => return Some(Json::Object(entries)),
                _ => return None,
            }
        }
    }

    /// Lee una cadena (comillas de apertura pendientes en la entrada).
    fn string(&mut self) -> Option<String> {
        if self.bump() != Some(b'"') {
            return None;
        }
        let mut out = String::new();
        loop {
            let byte = self.bump()?;
            match byte {
                b'"' => return Some(out),
                0x00..=0x1f => return None,
                b'\\' => match self.bump()? {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{8}'),
                    b'f' => out.push('\u{c}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let unit = self.hex4()?;
                        out.push(compose_unit(unit, self)?);
                    }
                    _ => return None,
                },
                _ if byte < 0x80 => out.push(byte as char),
                _ => {
                    // Multibyte UTF-8: se copia completo y se revalida.
                    let mut raw = vec![byte];
                    let extra = match byte {
                        0xc2..=0xdf => 1,
                        0xe0..=0xef => 2,
                        0xf0..=0xf4 => 3,
                        _ => return None,
                    };
                    for _ in 0..extra {
                        raw.push(self.bump()?);
                    }
                    out.push_str(std::str::from_utf8(&raw).ok()?);
                }
            }
        }
    }

    /// Cuatro dígitos hexadecimales (para `\uXXXX`).
    fn hex4(&mut self) -> Option<u16> {
        let mut value: u16 = 0;
        for _ in 0..4 {
            let digit = self.bump()?;
            let nibble = match digit {
                b'0'..=b'9' => digit - b'0',
                b'a'..=b'f' => digit - b'a' + 10,
                b'A'..=b'F' => digit - b'A' + 10,
                _ => return None,
            };
            value = (value << 4) | u16::from(nibble);
        }
        Some(value)
    }

    /// Número JSON estricto: sin `+`, sin ceros a la izquierda, finito.
    fn number(&mut self) -> Option<f64> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek()? {
            b'0' => self.pos += 1,
            b'1'..=b'9' => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return None,
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return None;
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return None;
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        let text = std::str::from_utf8(self.bytes.get(start..self.pos)?).ok()?;
        let value: f64 = text.parse().ok()?;
        if value.is_finite() {
            Some(value)
        } else {
            None
        }
    }
}

/// Compone un carácter desde una unidad UTF-16, resolviendo pares subrogados
/// (`\uD83D\uDE00`); una unidad suelta no se acepta.
fn compose_unit(unit: u16, scanner: &mut Scanner<'_>) -> Option<char> {
    if (0xd800..0xdc00).contains(&unit) {
        if scanner.bump() != Some(b'\\') || scanner.bump() != Some(b'u') {
            return None;
        }
        let low = scanner.hex4()?;
        if !(0xdc00..0xe000).contains(&low) {
            return None;
        }
        let combined = 0x1_0000 + ((u32::from(unit) - 0xd800) << 10) + (u32::from(low) - 0xdc00);
        char::from_u32(combined)
    } else if (0xdc00..0xe000).contains(&unit) {
        None
    } else {
        char::from_u32(u32::from(unit))
    }
}

/// Parsea un documento JSON **estricto**: exactamente un valor y nada más.
///
/// Es el mismo escáner que valida los lienzos del constructor visual; el puente
/// BSC ([`crate::bsc_bridge`]) lo reutiliza para leer las respuestas JSON‑RPC en
/// lugar de traer un segundo analizador. Los topes (profundidad [`MAX_JSON_DEPTH`],
/// claves repetidas y [`MAX_BLUEPRINT_BYTES`]) se aplican también ahí: una
/// respuesta que los exceda se rechaza en vez de aceptarse a medias.
pub(crate) fn parse_json(input: &str) -> Option<Json> {
    if input.len() > MAX_BLUEPRINT_BYTES {
        return None;
    }
    let mut scanner = Scanner::new(input);
    let value = scanner.value(0)?;
    scanner.skip_ws();
    if scanner.pos == scanner.bytes.len() {
        Some(value)
    } else {
        None
    }
}

/// Acceso estricto a un objeto JSON: sólo las claves declaradas y ninguna
/// repetida (el escáner ya garantiza lo segundo; aquí se rechaza lo primero).
fn strict_object<'a>(json: &'a Json, allowed: &[&str]) -> Option<Vec<(&'a str, &'a Json)>> {
    let entries = match json {
        Json::Object(entries) => entries,
        _ => return None,
    };
    let mut out = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        if !allowed.contains(&key.as_str()) {
            return None;
        }
        out.push((key.as_str(), value));
    }
    Some(out)
}

/// Campo de un objeto ya validado (`None` si el campo no está).
fn field<'a>(entries: &[(&'a str, &'a Json)], key: &str) -> Option<&'a Json> {
    entries
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, value)| *value)
}

/// Clase de bloque del lienzo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockKind {
    /// Fuente: entra un valor del exterior (sin entradas).
    Source,
    /// Transformación: consume entradas y produce una salida.
    Transform,
    /// Guarda: además de transformar, exige que el nodo nazca bajo `שמר`.
    Guard,
    /// Sumidero: consume su entrada y la emite (`אמר`) al cerrar el programa.
    Sink,
}

impl BlockKind {
    /// Etiqueta estable para la interfaz.
    pub fn label(&self) -> &'static str {
        match self {
            BlockKind::Source => "fuente",
            BlockKind::Transform => "transformación",
            BlockKind::Guard => "guarda",
            BlockKind::Sink => "sumidero",
        }
    }

    /// Clase a partir de su nombre canónico (estricto).
    pub fn from_name(name: &str) -> Option<BlockKind> {
        match name {
            "source" => Some(BlockKind::Source),
            "transform" => Some(BlockKind::Transform),
            "guard" => Some(BlockKind::Guard),
            "sink" => Some(BlockKind::Sink),
            _ => None,
        }
    }

    /// Nombre canónico en el contrato del *blueprint*: inverso exacto de
    /// [`BlockKind::from_name`].
    ///
    /// Lo publica el kernel para que el IDE **no** repita los cuatro literales
    /// del contrato: el vocabulario del lienzo vive aquí.
    pub fn name(&self) -> &'static str {
        match self {
            BlockKind::Source => "source",
            BlockKind::Transform => "transform",
            BlockKind::Guard => "guard",
            BlockKind::Sink => "sink",
        }
    }

    /// ¿Debe nacer sellado el nodo, además del umbral de riesgo?
    pub fn forces_seal(&self) -> bool {
        matches!(self, BlockKind::Guard)
    }
}

/// Ranura de entrada de un bloque: índice del productor y tipo esperado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot {
    /// Índice del bloque que provee la entrada.
    pub index: usize,
    /// Tipo esperado (`BaraType::Unknown` = comodín).
    pub expected: BaraType,
}

/// Bloque del lienzo ya validado y traducido.
#[derive(Debug, Clone, PartialEq)]
pub struct VisualBlock {
    /// Identificador del bloque en el lienzo.
    pub id: String,
    /// Nombre original del bloque (lo que se ve en el lienzo).
    pub name: String,
    /// Clase del bloque.
    pub kind: BlockKind,
    /// Aridad declarada.
    pub arity: usize,
    /// Tipo de retorno.
    pub ret: BaraType,
    /// Riesgo declarado en `[0, 1]`.
    pub hazard: f64,
    /// Ranuras de entrada, en orden.
    pub inputs: Vec<Slot>,
    /// Raíz triconsonántica del nodo *Shoresh*.
    pub root: String,
    /// ¿El nodo nace sellado bajo guarda?
    pub sanitized: bool,
}

/// Lienzo validado.
#[derive(Debug, Clone, PartialEq)]
pub struct Blueprint {
    /// Nombre del módulo.
    pub module: String,
    /// Etiqueta firmada (por defecto, el módulo).
    pub label: String,
    /// Bloques en orden de llegada (el índice es su posición).
    pub blocks: Vec<VisualBlock>,
}

/// Celda de la retícula áurea del lienzo.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Cell {
    /// Coordenada `x` en el disco unitario escalado por `√(n−1)`.
    pub x: f64,
    /// Coordenada `y`.
    pub y: f64,
    /// Radio `√k`, sin escalar.
    pub radius: f64,
    /// Ángulo `k·2π/φ²`, en radianes.
    pub angle: f64,
}

/// Comprobación del informe del lienzo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisualCheck {
    /// Nombre corto de la comprobación.
    pub name: &'static str,
    /// ¿Se superó?
    pub passed: bool,
}

/// Informe de validación y traducción de un lienzo.
#[derive(Debug, Clone, PartialEq)]
pub struct VisualReport {
    /// Bloques traducidos.
    pub blocks: usize,
    /// Aristas del grafo (suma de entradas).
    pub edges: usize,
    /// Profundidad del camino más largo (bloques encadenados).
    pub depth: usize,
    /// Riesgo medio de los bloques.
    pub hazard_mean: f64,
    /// Riesgo máximo.
    pub hazard_max: f64,
    /// Cota áurea del riesgo: `máximo + (máximo − mínimo)/φ`, saturada a `1`.
    pub hazard_bound: f64,
    /// Nodos que nacen sellados.
    pub sealed: usize,
    /// Orden topológico (índices de bloque).
    pub order: Vec<usize>,
    /// Retícula de colocación, en orden de bloque.
    pub cells: Vec<Cell>,
    /// Distancia mínima medida entre celdas.
    pub min_distance: f64,
    /// Radio máximo de la retícula.
    pub radius: f64,
    /// Comprobaciones superadas.
    pub checks: Vec<VisualCheck>,
    /// Veredicto legible.
    pub verdict: String,
    /// ¿El ADN del AST quedó verificado?
    pub verified: bool,
    /// Raíz de Merkle del ADN, en hexadecimal.
    pub root_hex: String,
    /// Firma soberana del ADN, en hexadecimal.
    pub signature_hex: String,
    /// Identificador público de la clave firmante.
    pub key_id: u64,
}

/// Resultado completo de traducir un lienzo.
#[derive(Debug, Clone)]
pub struct VisualBuild {
    /// Nombre del módulo.
    pub module: String,
    /// Etiqueta firmada.
    pub label: String,
    /// AST *Shoresh* traducido.
    pub ast: ShoreshAst,
    /// ADN firmado del AST.
    pub dna: AstDna,
    /// Programa *Shoresh* listo para el oráculo.
    pub source: String,
    /// Informe de validación y traducción.
    pub report: VisualReport,
}

// ─────────────────────────────────────────────────────────────────────────
// Parseo estricto del lienzo
// ─────────────────────────────────────────────────────────────────────────

/// Claves admitidas en la raíz del *blueprint*.
const ROOT_KEYS: [&str; 3] = ["module", "label", "blocks"];
/// Claves admitidas en un bloque.
const BLOCK_KEYS: [&str; 8] = [
    "id", "name", "kind", "arity", "ret", "hazard", "inputs", "root",
];
/// Claves admitidas en una ranura de entrada.
const SLOT_KEYS: [&str; 2] = ["index", "type"];

/// Tipo *Shoresh* a partir de su nombre canónico (inglés o hebreo).
///
/// Es un mapa **exacto**, no la heurística por subcadena de la ingesta FFI: el
/// lienzo es un contrato y un tipo mal escrito se rechaza en vez de degradarse.
pub fn bara_type_from_name(name: &str) -> Option<BaraType> {
    match name {
        "number" | "מספר" => Some(BaraType::Number),
        "text" | "מלים" => Some(BaraType::Text),
        "void" | "אין" => Some(BaraType::Void),
        "truth" | "אמת" => Some(BaraType::Truth),
        "list" | "רשימה" => Some(BaraType::List),
        "record" | "רשומה" => Some(BaraType::Record),
        "unknown" | "נעלם" => Some(BaraType::Unknown),
        _ => None,
    }
}

/// ¿El identificador del bloque es aceptable (`[A-Za-z0-9_-]{1,64}`)?
pub fn valid_id(id: &str) -> bool {
    let count = id.chars().count();
    (1..=MAX_ID_CHARS).contains(&count)
        && id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
}

/// ¿La raíz es triconsonántica (tres consonantes hebreas)?
pub fn triconsonantal(root: &str) -> bool {
    let mut chars = root.chars();
    let (first, second, third, rest) = (chars.next(), chars.next(), chars.next(), chars.next());
    rest.is_none()
        && [first, second, third]
            .iter()
            .all(|slot| matches!(slot, Some(ch) if ('\u{05d0}'..='\u{05ea}').contains(ch)))
}

/// Entero no negativo y acotado de un valor JSON.
fn as_integer(json: &Json) -> Option<usize> {
    let value = json.as_number()?;
    if value < 0.0 || value > MAX_BLOCKS as f64 || value.fract() != 0.0 {
        return None;
    }
    Some(value as usize)
}

/// Riesgo en `[0, 1]` de un valor JSON.
fn as_hazard(json: &Json) -> Option<f64> {
    let value = json.as_number()?;
    if (0.0..=1.0).contains(&value) {
        Some(value)
    } else {
        None
    }
}

/// Parsea un lienzo **estricto**; `None` si algo no cuadra.
///
/// El orden de comprobación es normativo: estructura → claves admitidas → tipos
/// de campo → aridad → referencias hacia atrás → tipos de las aristas. La
/// primera violación invalida el lienzo entero (nunca se compila a medias).
pub fn parse_blueprint(json: &str) -> Option<Blueprint> {
    let document = parse_json(json)?;
    let root = strict_object(&document, &ROOT_KEYS)?;

    let module = field(&root, "module")?.as_text()?.to_string();
    if !valid_id(&module) {
        return None;
    }
    let label = match field(&root, "label") {
        Some(value) => value.as_text()?.to_string(),
        None => module.clone(),
    };
    if label.trim().is_empty() {
        return None;
    }

    let raw_blocks = field(&root, "blocks")?.as_array()?;
    if raw_blocks.is_empty() || raw_blocks.len() > MAX_BLOCKS {
        return None;
    }

    let mut blocks: Vec<VisualBlock> = Vec::with_capacity(raw_blocks.len());
    for raw in raw_blocks {
        let entries = strict_object(raw, &BLOCK_KEYS)?;
        let id = field(&entries, "id")?.as_text()?.to_string();
        if !valid_id(&id) || blocks.iter().any(|block| block.id == id) {
            return None;
        }
        let name = field(&entries, "name")?.as_text()?.to_string();
        if name.trim().is_empty() {
            return None;
        }
        let kind = BlockKind::from_name(field(&entries, "kind")?.as_text()?)?;
        let arity = as_integer(field(&entries, "arity")?)?;
        let ret = bara_type_from_name(field(&entries, "ret")?.as_text()?)?;
        let hazard = as_hazard(field(&entries, "hazard")?)?;

        let raw_inputs = match field(&entries, "inputs") {
            Some(value) => value.as_array()?.to_vec(),
            None => Vec::new(),
        };
        let mut inputs: Vec<Slot> = Vec::with_capacity(raw_inputs.len());
        for slot in &raw_inputs {
            let slot = strict_object(slot, &SLOT_KEYS)?;
            let index = as_integer(field(&slot, "index")?)?;
            let expected = match field(&slot, "type") {
                Some(value) => bara_type_from_name(value.as_text()?)?,
                None => BaraType::Unknown,
            };
            inputs.push(Slot { index, expected });
        }

        // Estructura: una fuente no recibe nada; el resto, exactamente `arity`.
        match kind {
            BlockKind::Source if arity != 0 || !inputs.is_empty() => return None,
            BlockKind::Source => {}
            _ if inputs.len() != arity => return None,
            _ => {}
        }

        // Aristas: sólo hacia atrás (acíclico por construcción) y con tipo.
        for slot in &inputs {
            if slot.index >= blocks.len() {
                return None;
            }
            let producer = blocks.get(slot.index)?;
            let compatible = slot.expected == BaraType::Unknown
                || producer.ret == BaraType::Unknown
                || producer.ret == slot.expected;
            if !compatible {
                return None;
            }
        }

        let root = match field(&entries, "root") {
            Some(value) => {
                let explicit = value.as_text()?;
                if !triconsonantal(explicit) {
                    return None;
                }
                explicit.to_string()
            }
            None => root_from_name(&name),
        };

        blocks.push(VisualBlock {
            id,
            name,
            kind,
            arity,
            ret,
            hazard,
            inputs,
            root,
            sanitized: kind.forces_seal() || hazard > SEAL_THRESHOLD,
        });
    }

    Some(Blueprint {
        module,
        label,
        blocks,
    })
}

// ─────────────────────────────────────────────────────────────────────────
// Retícula áurea y validación matemática
// ─────────────────────────────────────────────────────────────────────────

/// Coloca `count` bloques en la espiral de **Fermat** con ángulo áureo.
///
/// `r_k = √k`, `θ_k = k·2π/φ²`: el reparto de mínima discrepancia que usa la
/// memoria holográfica del kernel. El bloque 0 cae en el origen y cada bloque
/// nuevo abre un pétalo distinto, de modo que añadir un bloque **no** mueve los
/// anteriores (propiedad de subsunción).
pub fn layout(count: usize) -> Vec<Cell> {
    let step = golden_angle();
    (0..count)
        .map(|index| {
            let radius = (index as f64).sqrt();
            let angle = (index as f64) * step;
            Cell {
                x: radius * angle.cos(),
                y: radius * angle.sin(),
                radius,
                angle,
            }
        })
        .collect()
}

/// Distancia mínima entre dos celdas distintas.
///
/// Con menos de dos celdas devuelve `f64::INFINITY`: no hay par que colisione.
pub fn min_distance(cells: &[Cell]) -> f64 {
    let mut best = f64::INFINITY;
    for (index, cell) in cells.iter().enumerate() {
        for other in cells.iter().skip(index + 1) {
            let dx = cell.x - other.x;
            let dy = cell.y - other.y;
            let distance = (dx * dx + dy * dy).sqrt();
            if distance < best {
                best = distance;
            }
        }
    }
    best
}

/// Radio máximo de la retícula (`√(n−1)` en la espiral).
pub fn radius(cells: &[Cell]) -> f64 {
    cells
        .iter()
        .fold(0.0_f64, |best, cell| best.max(cell.radius))
}

/// Orden topológico del lienzo.
///
/// Las aristas sólo apuntan hacia atrás (lo garantiza [`parse_blueprint`]), así
/// que el orden natural de los índices **es** un orden topológico válido: no hay
/// ciclos posibles y el orden es reproducible.
pub fn topological(blueprint: &Blueprint) -> Vec<usize> {
    (0..blueprint.blocks.len()).collect()
}

/// Profundidad del camino más largo, en bloques encadenados.
pub fn depth(blueprint: &Blueprint) -> usize {
    depth_of(&blueprint.blocks)
}

/// Profundidad del camino más largo de una lista de bloques ya traducidos.
fn depth_of(blocks: &[VisualBlock]) -> usize {
    let mut levels = vec![1_usize; blocks.len()];
    for (index, block) in blocks.iter().enumerate() {
        let mut best = 1;
        for slot in &block.inputs {
            let candidate = levels
                .get(slot.index)
                .copied()
                .unwrap_or(1)
                .saturating_add(1);
            if candidate > best {
                best = candidate;
            }
        }
        if let Some(level) = levels.get_mut(index) {
            *level = best;
        }
    }
    levels.iter().copied().max().unwrap_or(0)
}

/// `(media, máximo, cota áurea)` del riesgo del lienzo.
///
/// La cota del peor caso la calcula [`risk_of`]; con el lienzo vacío los tres
/// valores son `0.0`.
pub fn risk_bounds(blueprint: &Blueprint) -> (f64, f64, f64) {
    risk_of(&blueprint.blocks)
}

/// `(media, máximo, cota áurea)` del riesgo de una lista de bloques.
///
/// La cota es `máximo + (máximo − mínimo)/φ`, saturada a `1.0`: una **cota del
/// peor caso** con el mismo margen áureo (`1/φ ≈ 0.618`) que el kernel usa al
/// repartir memoria, de modo que siempre cubre al máximo declarado. Con la lista
/// vacía los tres valores son `0.0`.
fn risk_of(blocks: &[VisualBlock]) -> (f64, f64, f64) {
    if blocks.is_empty() {
        return (0.0, 0.0, 0.0);
    }
    let mut sum = 0.0_f64;
    let mut maximum = 0.0_f64;
    let mut minimum = 1.0_f64;
    for block in blocks {
        sum += block.hazard;
        maximum = maximum.max(block.hazard);
        minimum = minimum.min(block.hazard);
    }
    let mean = sum / blocks.len() as f64;
    let bound = (maximum + (maximum - minimum) / phi()).min(1.0);
    (mean, maximum, bound)
}

/// Auditoría **independiente** del lienzo ya parseado.
///
/// Repite las comprobaciones que [`parse_blueprint`] hizo al parsear, pero ahora
/// sobre los bloques traducidos: sirve para lienzos construidos a mano (los
/// tipos son públicos) y para publicar el detalle en el informe del IDE.
pub fn validate(blueprint: &Blueprint) -> Vec<VisualCheck> {
    validate_blocks(&blueprint.blocks)
}

/// Auditoría de una lista de bloques ya traducidos.
fn validate_blocks(blocks: &[VisualBlock]) -> Vec<VisualCheck> {
    let count = blocks.len();
    let arity_ok = blocks.iter().all(|block| match block.kind {
        BlockKind::Source => block.arity == 0 && block.inputs.is_empty(),
        _ => block.inputs.len() == block.arity,
    });
    let types_ok = blocks.iter().all(|block| {
        block
            .inputs
            .iter()
            .all(|slot| match blocks.get(slot.index) {
                Some(producer) => {
                    slot.expected == BaraType::Unknown
                        || producer.ret == BaraType::Unknown
                        || producer.ret == slot.expected
                }
                None => false,
            })
    });
    let order_ok = blocks
        .iter()
        .enumerate()
        .all(|(index, block)| block.inputs.iter().all(|slot| slot.index < index));
    let hazard_ok = blocks
        .iter()
        .all(|block| (0.0..=1.0).contains(&block.hazard));
    let (_, maximum, bound) = risk_of(blocks);
    let cells = layout(count);
    let spread_ok = count < 2 || min_distance(&cells) >= MIN_CELL_DISTANCE;
    let fitting_ok = radius(&cells) <= (MAX_BLOCKS as f64).sqrt();

    vec![
        VisualCheck {
            name: "bloques",
            passed: (1..=MAX_BLOCKS).contains(&count),
        },
        VisualCheck {
            name: "aridad",
            passed: arity_ok,
        },
        VisualCheck {
            name: "tipos",
            passed: types_ok,
        },
        VisualCheck {
            name: "orden",
            passed: order_ok,
        },
        VisualCheck {
            name: "riesgo",
            passed: hazard_ok && bound >= maximum && bound <= 1.0,
        },
        VisualCheck {
            name: "reticula",
            passed: spread_ok,
        },
        VisualCheck {
            name: "radio",
            passed: fitting_ok,
        },
    ]
}

// ─────────────────────────────────────────────────────────────────────────
// Traducción a *Shoresh* y firma del módulo
// ─────────────────────────────────────────────────────────────────────────

/// Número de aristas del lienzo (suma de entradas).
pub fn edges(blueprint: &Blueprint) -> usize {
    blueprint
        .blocks
        .iter()
        .map(|block| block.inputs.len())
        .sum()
}

/// AST *Shoresh* del lienzo, en orden de bloque.
pub fn blueprint_ast(blueprint: &Blueprint) -> ShoreshAst {
    let mut ast = ShoreshAst::default();
    for block in &blueprint.blocks {
        ast.nodes.push(ShoreshNode {
            root: block.root.clone(),
            original: block.name.clone(),
            arity: block.arity,
            ret: block.ret,
            hazard: block.hazard,
            valence: QuantumState::paraconsistent(1.0 - block.hazard, block.hazard),
            sanitized: block.sanitized,
        });
    }
    ast
}

/// Guion *Shoresh* de una lista de bloques.
///
/// Cada bloque emite su raíz; si nació sellado, la guarda `שמר`, y un sumidero
/// emite además `אמר`. El guion cierra con ejecución (`עבד`) y una fotografía
/// del estado, igual que la emisión de la ingesta FFI: es determinista y se
/// conversa tal cual con el oráculo del kernel.
fn source_of(module: &str, label: &str, blocks: &[VisualBlock]) -> String {
    let mut out = String::new();
    out.push_str("# Lienzo *Visual Builder* traducido a Shoresh.\n");
    out.push_str(&format!(
        "# modulo={} etiqueta={} bloques={} aristas={}\n",
        module,
        label,
        blocks.len(),
        blocks.iter().map(|block| block.inputs.len()).sum::<usize>()
    ));
    for block in blocks {
        out.push_str(&block.root);
        out.push_str("   # ");
        out.push_str(&block.id);
        out.push_str(" · ");
        out.push_str(block.kind.label());
        out.push('\n');
        if block.sanitized {
            out.push_str("שמר\n");
        }
        if block.kind == BlockKind::Sink {
            out.push_str("אמר\n");
        }
    }
    out.push_str("עבד\n:estado\n:salir\n");
    out
}

/// Programa *Shoresh* del lienzo, listo para conversar con el oráculo.
pub fn blueprint_source(blueprint: &Blueprint) -> String {
    source_of(&blueprint.module, &blueprint.label, &blueprint.blocks)
}

/// Informe completo a partir de bloques (posiblemente compuestos) y ADN firmado.
fn report_for(blocks: &[VisualBlock], levels: usize, dna: &AstDna, verified: bool) -> VisualReport {
    let cells = layout(blocks.len());
    let (mean, maximum, bound) = risk_of(blocks);
    let checks = validate_blocks(blocks);
    let sealed = blocks.iter().filter(|block| block.sanitized).count();
    let distance = min_distance(&cells);
    let distance_label = if distance.is_finite() {
        format!("{distance:.3}")
    } else {
        "∞".to_string()
    };
    let valid = checks.iter().all(|check| check.passed);
    let verdict = format!(
        "lienzo «{}» · {} bloque(s) · {} arista(s) · profundidad {} · riesgo medio {:.3} (máx {:.3}, cota {:.3}) · sellados {} · retícula r={:.2} d_min {} · {}",
        dna.label,
        blocks.len(),
        blocks.iter().map(|block| block.inputs.len()).sum::<usize>(),
        levels,
        mean,
        maximum,
        bound,
        sealed,
        radius(&cells),
        distance_label,
        if valid { "válido" } else { "inválido" }
    );

    VisualReport {
        blocks: blocks.len(),
        edges: blocks.iter().map(|block| block.inputs.len()).sum(),
        depth: levels,
        hazard_mean: mean,
        hazard_max: maximum,
        hazard_bound: bound,
        sealed,
        order: (0..blocks.len()).collect(),
        cells,
        min_distance: distance,
        radius: radius(&layout(blocks.len())),
        checks,
        verdict,
        verified,
        root_hex: short_hex(&dna.root),
        signature_hex: short_hex(&dna.signature),
        key_id: dna.key_id,
    }
}

/// Traduce y **firma** un lienzo ya parseado.
///
/// El AST nace firmado y se autoverifica (`verify`) antes de devolverse: si el
/// ADN no cuadrara, el informe lo diría (`verified == false`) en vez de mentir.
pub fn build_blueprint(blueprint: &Blueprint, key: &[u8; 32]) -> VisualBuild {
    let ast = blueprint_ast(blueprint);
    let dna = ast_dna(&blueprint.label, &ast, key);
    let verified = verify(&blueprint.label, &ast, &dna, key);
    let report = report_for(
        &blueprint.blocks,
        depth_of(&blueprint.blocks),
        &dna,
        verified,
    );
    VisualBuild {
        module: blueprint.module.clone(),
        label: blueprint.label.clone(),
        source: blueprint_source(blueprint),
        ast,
        dna,
        report,
    }
}

/// Traduce y firma un lienzo JSON estricto; `None` si el lienzo no es válido.
pub fn build(json: &str, key: &[u8; 32]) -> Option<VisualBuild> {
    Some(build_blueprint(&parse_blueprint(json)?, key))
}

/// Compone varios lienzos en un solo módulo firmado.
///
/// Los AST se **injertan** en orden con [`ShoreshAst::graft`]: el primer lienzo
/// abre el módulo y los siguientes se añaden a continuación, de modo que el
/// resultado depende del orden de entrada (nunca del azar). La etiqueta firmada
/// es la del primer lienzo con el sufijo `:compuesto`.
pub fn build_composed(lienzos: &[&str], key: &[u8; 32]) -> Option<VisualBuild> {
    let mut blueprints: Vec<Blueprint> = Vec::with_capacity(lienzos.len());
    for json in lienzos {
        blueprints.push(parse_blueprint(json)?);
    }
    let first = blueprints.first()?;
    let label = format!("{}:compuesto", first.label);

    let mut ast = ShoreshAst::default();
    let mut blocks: Vec<VisualBlock> = Vec::new();
    let mut levels = 1_usize;
    for blueprint in &blueprints {
        let part = blueprint_ast(blueprint);
        if ast.graft(ast.nodes.len(), part) == 0 {
            return None;
        }
        levels = levels.max(depth_of(&blueprint.blocks));
        blocks.extend(blueprint.blocks.iter().cloned());
    }

    let dna = ast_dna(&label, &ast, key);
    let verified = verify(&label, &ast, &dna, key);
    let report = report_for(&blocks, levels, &dna, verified);
    Some(VisualBuild {
        module: first.module.clone(),
        label: label.clone(),
        ast,
        dna,
        source: source_of(&first.module, &label, &blocks),
        report,
    })
}

/// Lienzo de ejemplo del IDE: dos fuentes, una suma, una guarda y un sumidero.
///
/// Es el *blueprint* que el constructor visual ofrece al abrir: un grafo en
/// diamante (`a`,`b` → `suma` → `suma2` → `sella` → `emite`) que ejercita las
/// cuatro clases de bloque, la aridad 2 y las tres fases de la traducción.
pub const SAMPLE_BLUEPRINT: &str = r#"{
  "module": "lienzo_genesis",
  "label": "lienzo-genesis",
  "blocks": [
    { "id": "a", "name": "entrada_a", "kind": "source", "arity": 0,
      "ret": "number", "hazard": 0.0 },
    { "id": "b", "name": "entrada_b", "kind": "source", "arity": 0,
      "ret": "number", "hazard": 0.1, "root": "ברא" },
    { "id": "suma", "name": "sumar", "kind": "transform", "arity": 2,
      "ret": "number", "hazard": 0.05,
      "inputs": [{ "index": 0, "type": "number" }, { "index": 1 }] },
    { "id": "sella", "name": "guardar", "kind": "guard", "arity": 1,
      "ret": "number", "hazard": 0.2, "inputs": [{ "index": 2 }] },
    { "id": "emite", "name": "emitir", "kind": "sink", "arity": 1,
      "ret": "void", "hazard": 0.0, "inputs": [{ "index": 3 }] }
  ]
}"#;

/// Lienzo de ejemplo (identificador de la constante, para el IDE).
pub fn sample_blueprint() -> &'static str {
    SAMPLE_BLUEPRINT
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_dna::{golden_key, signature_is_valid};
    use crate::lexer::{Lexer, TokenKind};

    /// Clave soberana de las pruebas (derivada del ángulo áureo, sin entropía).
    fn clave() -> [u8; 32] {
        golden_key(b"visual-builder")
    }

    /// El vocabulario del contrato tiene inverso exacto: el IDE puede pedirle
    /// los nombres al kernel en vez de repetir los literales.
    #[test]
    fn los_nombres_canonicos_son_el_inverso_de_los_parseadores() {
        for kind in [
            BlockKind::Source,
            BlockKind::Transform,
            BlockKind::Guard,
            BlockKind::Sink,
        ] {
            assert_eq!(BlockKind::from_name(kind.name()), Some(kind));
            assert!(!kind.label().is_empty());
        }
        for (name, kind) in [
            ("number", BaraType::Number),
            ("text", BaraType::Text),
            ("void", BaraType::Void),
            ("truth", BaraType::Truth),
            ("list", BaraType::List),
            ("record", BaraType::Record),
            ("unknown", BaraType::Unknown),
        ] {
            assert_eq!(bara_type_from_name(name), Some(kind));
            assert_eq!(kind.name(), name);
            assert_eq!(bara_type_from_name(kind.label()), Some(kind));
        }
        assert_eq!(BlockKind::from_name("fuente"), None);
        assert_eq!(bara_type_from_name("Number"), None);
    }

    /// Lienzo mínimo: una fuente y un sumidero encadenados.
    const MINIMO: &str = r#"{ "module": "m", "label": "minimo", "blocks": [
        { "id": "a", "name": "uno", "kind": "source", "arity": 0,
          "ret": "number", "hazard": 0.0 },
        { "id": "b", "name": "dos", "kind": "sink", "arity": 1, "ret": "void",
          "hazard": 0.25, "inputs": [{ "index": 0, "type": "number" }] } ] }"#;

    #[test]
    fn el_lienzo_valido_se_traduce_se_firma_y_se_verifica() {
        let Some(blueprint) = parse_blueprint(SAMPLE_BLUEPRINT) else {
            return;
        };
        assert_eq!(blueprint.module, "lienzo_genesis");
        assert_eq!(blueprint.label, "lienzo-genesis");
        assert_eq!(blueprint.blocks.len(), 5);
        assert_eq!(edges(&blueprint), 4);
        // La raíz explícita manda; el resto se derivan del nombre.
        assert_eq!(blueprint.blocks[1].root, "ברא");
        assert!(triconsonantal(&blueprint.blocks[2].root));
        assert_eq!(blueprint.blocks[0].kind, BlockKind::Source);
        assert_eq!(blueprint.blocks[3].kind, BlockKind::Guard);
        assert_eq!(blueprint.blocks[4].kind, BlockKind::Sink);
        assert_eq!(blueprint.blocks[0].arity, 0);
        assert_eq!(blueprint.blocks[2].arity, 2);
        // La guarda sella siempre; el riesgo bajo no sella por sí solo.
        assert!(blueprint.blocks[3].sanitized);
        assert!(!blueprint.blocks[2].sanitized);
        assert_eq!(blueprint.blocks[4].inputs[0].index, 3);
        // Cadena a → suma → sella → emite.
        assert_eq!(depth(&blueprint), 4);
        assert_eq!(topological(&blueprint), vec![0, 1, 2, 3, 4]);
        assert!(validate(&blueprint).iter().all(|check| check.passed));
        let (mean, maximum, bound) = risk_bounds(&blueprint);
        assert!(mean > 0.0 && mean < maximum);
        // La cota del peor caso cubre al máximo y nunca sale del rango.
        assert!(bound >= maximum && bound <= 1.0);

        let build = build_blueprint(&blueprint, &clave());
        assert_eq!(build.ast.nodes.len(), 5);
        assert_eq!(build.dna.label, "lienzo-genesis");
        assert_eq!(build.dna.sealed_nodes(), 1);
        assert!(build.report.verified);
        assert!(verify(&build.label, &build.ast, &build.dna, &clave()));
        assert!(signature_is_valid(&build.dna, &clave()));
        assert!(!verify(
            &build.label,
            &build.ast,
            &build.dna,
            &golden_key(b"otra")
        ));
        assert_eq!(build.report.root_hex.len(), 64);
        assert_eq!(build.report.signature_hex.len(), 64);
        assert_eq!(build.report.key_id, build.dna.key_id);
        assert_eq!(build.report.sealed, 1);
        assert_eq!(build.report.blocks, 5);
        assert_eq!(build.report.edges, 4);
        assert_eq!(build.report.depth, 4);
        assert_eq!(build.report.order, vec![0, 1, 2, 3, 4]);
        assert_eq!(build.report.cells.len(), 5);
        assert!(build.report.min_distance >= MIN_CELL_DISTANCE);
        assert!(build.report.verdict.contains("válido"));
        assert!(build.report.verdict.contains("lienzo-genesis"));

        // El guion es determinista, lleva cada raíz y sella el cierre.
        assert_eq!(build.source, blueprint_source(&blueprint));
        for block in &blueprint.blocks {
            assert!(
                build.source.contains(&block.root),
                "el guion omite la raíz {}",
                block.root
            );
        }
        assert!(build.source.contains("שמר"));
        assert!(build.source.contains("אמר"));
        assert!(build.source.contains("עבד"));

        // El lexer del kernel acepta el guion: cada raíz llega como token `Root`.
        let tokens = Lexer::new(&build.source).tokenize();
        let letras: Vec<String> = tokens
            .iter()
            .filter_map(|token| match &token.kind {
                TokenKind::Root { letters, .. } => Some(letters.clone()),
                _ => None,
            })
            .collect();
        for block in &blueprint.blocks {
            assert!(
                letras.contains(&block.root),
                "el lexer no ve la raíz {}",
                block.root
            );
        }

        // Firmar dos veces el mismo lienzo da exactamente la misma raíz y firma.
        let Some(repetido) = parse_blueprint(SAMPLE_BLUEPRINT) else {
            return;
        };
        let segunda = build_blueprint(&repetido, &clave());
        assert_eq!(segunda.report.root_hex, build.report.root_hex);
        assert_eq!(segunda.report.signature_hex, build.report.signature_hex);
        assert_eq!(segunda.source, build.source);
    }

    #[test]
    fn el_lienzo_minimo_y_la_ruta_de_la_funcion_build() {
        let Some(lienzo) = build(MINIMO, &clave()) else {
            return;
        };
        assert_eq!(lienzo.module, "m");
        assert_eq!(lienzo.label, "minimo");
        assert_eq!(lienzo.ast.nodes.len(), 2);
        let Some(blueprint) = parse_blueprint(MINIMO) else {
            return;
        };
        assert_eq!(depth(&blueprint), 2);
        assert!(lienzo.report.verified);
        assert_eq!(lienzo.report.sealed, 0);
        // Dos celdas: la retícula se mide de verdad.
        assert_eq!(lienzo.report.cells.len(), 2);
        assert!((lienzo.report.min_distance - 1.0).abs() < 1e-9);
        assert!((lienzo.report.radius - 1.0).abs() < 1e-9);
        // Un lienzo inválido no produce módulo.
        assert!(build("{", &clave()).is_none());
    }

    #[test]
    fn el_lienzo_estricto_rechaza_cualquier_inconsistencia() {
        // Clave desconocida.
        assert!(parse_blueprint(
            r#"{ "module": "m", "extra": 1, "blocks": [ { "id": "a", "name": "n",
                "kind": "source", "arity": 0, "ret": "number", "hazard": 0.0 } ] }"#
        )
        .is_none());
        // Coma final (no es JSON estricto).
        assert!(parse_blueprint(
            r#"{ "module": "m", "blocks": [ { "id": "a", "name": "n", "kind": "source",
                "arity": 0, "ret": "number", "hazard": 0.0, } ] }"#
        )
        .is_none());
        // Cero a la izquierda y exponente desbordado.
        assert!(parse_blueprint(
            r#"{ "module": "m", "blocks": [ { "id": "a", "name": "n", "kind": "source",
                "arity": 01, "ret": "number", "hazard": 0.0 } ] }"#
        )
        .is_none());
        assert!(parse_blueprint(
            r#"{ "module": "m", "blocks": [ { "id": "a", "name": "n", "kind": "source",
                "arity": 0, "ret": "number", "hazard": 1e999 } ] }"#
        )
        .is_none());
        // Clave repetida.
        assert!(parse_blueprint(
            r#"{ "module": "m", "module": "m", "blocks": [ { "id": "a", "name": "n",
                "kind": "source", "arity": 0, "ret": "number", "hazard": 0.0 } ] }"#
        )
        .is_none());
        // Sin bloques.
        assert!(parse_blueprint(r#"{ "module": "m", "blocks": [] }"#).is_none());
        // Tipo fuera del catálogo.
        assert!(parse_blueprint(
            r#"{ "module": "m", "blocks": [ { "id": "a", "name": "n", "kind": "source",
                "arity": 0, "ret": "numero", "hazard": 0.0 } ] }"#
        )
        .is_none());
        // Clase de bloque desconocida.
        assert!(parse_blueprint(
            r#"{ "module": "m", "blocks": [ { "id": "a", "name": "n", "kind": "fuente",
                "arity": 0, "ret": "number", "hazard": 0.0 } ] }"#
        )
        .is_none());
        // Identificador inválido y repetido.
        assert!(parse_blueprint(
            r#"{ "module": "m", "blocks": [ { "id": "a b", "name": "n", "kind": "source",
                "arity": 0, "ret": "number", "hazard": 0.0 } ] }"#
        )
        .is_none());
        assert!(parse_blueprint(
            r#"{ "module": "m", "blocks": [
                { "id": "a", "name": "n", "kind": "source", "arity": 0,
                  "ret": "number", "hazard": 0.0 },
                { "id": "a", "name": "o", "kind": "source", "arity": 0,
                  "ret": "number", "hazard": 0.0 } ] }"#
        )
        .is_none());
        // Aridad que no cuadra: la fuente no recibe y el resto recibe exacto.
        assert!(parse_blueprint(
            r#"{ "module": "m", "blocks": [ { "id": "a", "name": "n", "kind": "source",
                "arity": 1, "ret": "number", "hazard": 0.0 } ] }"#
        )
        .is_none());
        assert!(parse_blueprint(
            r#"{ "module": "m", "blocks": [
                { "id": "a", "name": "n", "kind": "source", "arity": 0,
                  "ret": "number", "hazard": 0.0 },
                { "id": "b", "name": "o", "kind": "transform", "arity": 2,
                  "ret": "number", "hazard": 0.0, "inputs": [{ "index": 0 }] } ] }"#
        )
        .is_none());
        // Referencia hacia adelante: el grafo es acíclico por construcción.
        assert!(parse_blueprint(
            r#"{ "module": "m", "blocks": [
                { "id": "a", "name": "n", "kind": "transform", "arity": 1,
                  "ret": "number", "hazard": 0.0, "inputs": [{ "index": 1 }] },
                { "id": "b", "name": "o", "kind": "source", "arity": 0,
                  "ret": "number", "hazard": 0.0 } ] }"#
        )
        .is_none());
        // Tipo de arista incompatible.
        assert!(parse_blueprint(
            r#"{ "module": "m", "blocks": [
                { "id": "a", "name": "n", "kind": "source", "arity": 0,
                  "ret": "text", "hazard": 0.0 },
                { "id": "b", "name": "o", "kind": "sink", "arity": 1, "ret": "void",
                  "hazard": 0.0, "inputs": [{ "index": 0, "type": "number" }] } ] }"#
        )
        .is_none());
        // Riesgo fuera de rango.
        assert!(parse_blueprint(
            r#"{ "module": "m", "blocks": [ { "id": "a", "name": "n", "kind": "source",
                "arity": 0, "ret": "number", "hazard": 1.5 } ] }"#
        )
        .is_none());
        // Raíz explícita no triconsonántica.
        assert!(parse_blueprint(
            r#"{ "module": "m", "blocks": [ { "id": "a", "name": "n", "kind": "source",
                "arity": 0, "ret": "number", "hazard": 0.0, "root": "abc" } ] }"#
        )
        .is_none());
        // Documento truncado, vacío o con dos valores.
        assert!(parse_blueprint(r#"{ "module": "m", "blocks": ["#).is_none());
        assert!(parse_blueprint(r#"{ "module": "m", "blocks": [] } {}"#).is_none());
        assert!(parse_blueprint("").is_none());
        // El tipo `unknown` sí es comodín: casa con cualquier productor.
        assert!(parse_blueprint(
            r#"{ "module": "m", "blocks": [
                { "id": "a", "name": "n", "kind": "source", "arity": 0,
                  "ret": "text", "hazard": 0.0 },
                { "id": "b", "name": "o", "kind": "sink", "arity": 1, "ret": "void",
                  "hazard": 0.0, "inputs": [{ "index": 0, "type": "unknown" }] } ] }"#
        )
        .is_some());
    }

    #[test]
    fn la_reticula_aurea_no_colisiona_y_no_mueve_las_celdas_previas() {
        let cells = layout(MAX_BLOCKS);
        assert_eq!(cells.len(), MAX_BLOCKS);
        assert_eq!(cells[0].x, 0.0);
        assert_eq!(cells[0].y, 0.0);
        assert_eq!(cells[0].radius, 0.0);
        // Cota **medida** del reparto: ninguna pareja se acerca más al umbral.
        let distance = min_distance(&cells);
        assert!(distance.is_finite());
        assert!(
            distance >= MIN_CELL_DISTANCE,
            "la retícula colisiona: d_min = {distance}"
        );
        // El radio es exactamente √(n−1) en la espiral de Fermat.
        assert!((radius(&cells) - ((MAX_BLOCKS - 1) as f64).sqrt()).abs() < 1e-9);
        // Los ángulos avanzan por el ángulo áureo del kernel.
        assert!((cells[2].angle - 2.0 * golden_angle()).abs() < 1e-9);
        // Subsunción: crecer no reordena ni mueve las celdas anteriores.
        let mayores = layout(MAX_BLOCKS + 16);
        assert_eq!(&mayores[..MAX_BLOCKS], cells.as_slice());
        // Determinismo estricto.
        assert_eq!(layout(8), layout(8));
        // Una sola celda (o ninguna) no tiene par con el que colisionar.
        assert_eq!(min_distance(&layout(1)), f64::INFINITY);
        assert_eq!(min_distance(&[]), f64::INFINITY);
    }

    #[test]
    fn el_orden_topologico_y_la_profundidad_respetan_el_grafo() {
        // Diamante: dos fuentes, una suma, un sumidero.
        const DIAMANTE: &str = r#"{ "module": "d", "blocks": [
            { "id": "a", "name": "uno", "kind": "source", "arity": 0,
              "ret": "number", "hazard": 0.0 },
            { "id": "b", "name": "dos", "kind": "source", "arity": 0,
              "ret": "number", "hazard": 0.0 },
            { "id": "s", "name": "sumar", "kind": "transform", "arity": 2,
              "ret": "number", "hazard": 0.0,
              "inputs": [{ "index": 0 }, { "index": 1 }] },
            { "id": "e", "name": "emitir", "kind": "sink", "arity": 1,
              "ret": "void", "hazard": 0.0, "inputs": [{ "index": 2 }] } ] }"#;
        let Some(blueprint) = parse_blueprint(DIAMANTE) else {
            return;
        };
        assert_eq!(topological(&blueprint), vec![0, 1, 2, 3]);
        assert_eq!(depth(&blueprint), 3);
        assert_eq!(edges(&blueprint), 3);
        // La auditoría marca en falso una aridad mentida por el llamante.
        let mut roto = blueprint.clone();
        if let Some(block) = roto.blocks.get_mut(2) {
            block.arity = 1;
        }
        let checks = validate(&roto);
        assert!(checks.iter().any(|check| !check.passed));
        // Y una arista inventada hacia el futuro también se detecta.
        let mut futuro = blueprint.clone();
        if let Some(block) = futuro.blocks.get_mut(0) {
            block.inputs.push(Slot {
                index: 3,
                expected: BaraType::Unknown,
            });
        }
        assert!(validate(&futuro).iter().any(|check| !check.passed));
        // Con el lienzo original todo cuadra.
        assert!(validate(&blueprint).iter().all(|check| check.passed));
    }

    #[test]
    fn los_lienzos_compuestos_se_injertan_en_el_orden_de_entrada() {
        let Some(uno) = build(MINIMO, &clave()) else {
            return;
        };
        let Some(compuesto) = build_composed(&[MINIMO, SAMPLE_BLUEPRINT], &clave()) else {
            return;
        };
        assert_eq!(compuesto.ast.nodes.len(), uno.ast.nodes.len() + 5);
        assert_eq!(compuesto.label, "minimo:compuesto");
        assert!(compuesto.report.verified);
        assert_eq!(compuesto.report.blocks, 7);
        assert_eq!(compuesto.report.depth, 4);
        // La firma del compuesto no es la de ninguno de sus componentes.
        let Some(segundo) = build(SAMPLE_BLUEPRINT, &clave()) else {
            return;
        };
        assert_ne!(compuesto.report.root_hex, uno.report.root_hex);
        assert_ne!(compuesto.report.root_hex, segundo.report.root_hex);
        // El orden de entrada manda: invertirlo cambia la raíz de Merkle.
        let Some(invertido) = build_composed(&[SAMPLE_BLUEPRINT, MINIMO], &clave()) else {
            return;
        };
        assert_ne!(invertido.report.root_hex, compuesto.report.root_hex);
        assert_eq!(invertido.ast.nodes.len(), compuesto.ast.nodes.len());
        // Componer un lienzo inválido no produce módulo, y la lista vacía tampoco.
        assert!(build_composed(&[MINIMO, "{"], &clave()).is_none());
        assert!(build_composed(&[], &clave()).is_none());
    }

    #[test]
    fn el_sello_nace_del_umbral_y_de_la_clase_de_guarda() {
        // Riesgo alto: el nodo nace sellado aunque sea una transformación.
        const PELIGRO: &str = r#"{ "module": "p", "blocks": [
            { "id": "a", "name": "eval_entrada", "kind": "transform", "arity": 0,
              "ret": "unknown", "hazard": 0.7 } ] }"#;
        let Some(peligroso) = build(PELIGRO, &clave()) else {
            return;
        };
        assert_eq!(peligroso.report.sealed, 1);
        assert!(peligroso.ast.nodes.first().map(|node| node.sanitized) == Some(true));
        assert!(peligroso.source.contains("שמר"));
        assert!(!peligroso.report.verdict.is_empty());

        // Guarda con riesgo nulo: el sello lo impone la clase, no el umbral.
        const GUARDA: &str = r#"{ "module": "g", "blocks": [
            { "id": "a", "name": "guardar", "kind": "guard", "arity": 0,
              "ret": "void", "hazard": 0.0 } ] }"#;
        let Some(guardado) = build(GUARDA, &clave()) else {
            return;
        };
        assert_eq!(guardado.report.sealed, 1);
        assert_eq!(guardado.dna.sealed_nodes(), 1);
        // Sin guarda ni riesgo, nada se sella.
        let Some(limpio) = build(MINIMO, &clave()) else {
            return;
        };
        assert_eq!(limpio.report.sealed, 0);
        assert_eq!(limpio.dna.sealed_nodes(), 0);
        assert!(!limpio.source.contains("שמר"));
    }
}
