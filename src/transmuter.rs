//! # Transmutador universal de código externo — `transmuter.rs`
//!
//! Convierte un fragmento de **cualquier lenguaje** (JavaScript, Python, Rust,
//! Go, Java, C#, C, SQL, *shell*) en un AST *Shoresh* admisible, pasando cada
//! sentencia por la retícula tetravalente de Belnap **antes** de tocar el árbol.
//!
//! ## Las cuatro leyes del transmutador
//! 1. **Totalidad (A1)** — ninguna entrada produce un pánico. El texto se acota
//!    a [`MAX_FRAGMENT_BYTES`], la segmentación es lineal y todo lo que no se
//!    entiende se degrada a cuarentena explícita.
//! 2. **Purificación** — el AST resultante se somete a [`audit_ast`]; si no pasa
//!    las nueve reglas, [`Transmutation::is_admissible`] es `false` y el
//!    llamante **no debe** fusionarlo. Nunca se devuelve un árbol «a medias»
//!    como si fuera válido.
//! 3. **Belnap antes del árbol** — cada sentencia se clasifica en `⊤`, `⊥`,
//!    `⊤∧⊥` o `∅` con masas continuas. Sólo lo designado (`⊤` y `⊤∧⊥`) aporta
//!    evidencia; lo demás se retiene en la raíz `רחק` (cuarentena) como `⊥`.
//! 4. **Determinismo** — sin relojes, sin aleatoriedad, sin `HashMap`: el mismo
//!    fragmento produce byte a byte el mismo AST. Las raíces se acumulan en
//!    orden de primera aparición y **son únicas** (regla `raiz.unica` de la
//!    auditoría): un nodo por concepto, no un nodo por sentencia.
//!
//! ## Por qué un nodo por concepto
//! [`audit_ast`] exige que las raíces de un
//! parche sean distintas. Un fragmento con diez asignaciones no puede producir
//! diez nodos `אמר`. La solución es la conjunción de Belnap: la evidencia de
//! todas las asignaciones se funde con `∧` (`mín ⊤`, `máx ⊥`), que es
//! exactamente la operación conservadora correcta (basta una sentencia dudosa
//! para que el concepto completo arrastre esa duda).
//!
//! ## Ejemplo
//! ```
//! use bara::transmuter::transmute;
//!
//! let salida = transmute("def f(x):\n    return x + 1\n");
//! assert!(salida.is_admissible());
//! assert!(salida.report.accepted >= 1);
//! assert_eq!(salida.report.both + salida.report.true_count, salida.report.accepted);
//! ```

#![forbid(unsafe_code)]
#![deny(clippy::all)]

use crate::autopoietic::{audit_ast, BelnapValue, MAX_ARITY, SEAL_THRESHOLD};
use crate::ffi_ingest::{BaraType, ShoreshAst, ShoreshNode};
use crate::immunity_gateway::threat_of;
use crate::runtime::QuantumState;

/// Bytes máximos que se inspeccionan de un fragmento externo.
///
/// El excedente no se procesa (ni se copia): se marca `truncated` en el
/// informe. Así el coste está acotado aunque el llamante entregue gigabytes.
pub const MAX_FRAGMENT_BYTES: usize = 64 * 1024;

/// Sentencias máximas que se clasifican en una transmutación.
pub const MAX_STATEMENTS: usize = 256;

/// Longitud máxima del texto original que se conserva por nodo.
pub const MAX_ORIGINAL_CHARS: usize = 96;

/// Umbral de peligro (‰) a partir del cual una sentencia es `⊥` sin discusión.
pub const HOSTILE_PERMILLE: u32 = 500;

// ─────────────────────────────────────────────────────────────────────────
// Lenguaje de origen (sólo informativo: el análisis es agnóstico)
// ─────────────────────────────────────────────────────────────────────────

/// Lenguaje detectado del fragmento. No cambia la validez del análisis: la
/// segmentación y la retícula son universales. Se usa para la trazabilidad.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceLanguage {
    /// JavaScript / TypeScript.
    JavaScript,
    /// Python.
    Python,
    /// Rust.
    Rust,
    /// Go.
    Go,
    /// Java.
    Java,
    /// C#.
    CSharp,
    /// C / C++.
    C,
    /// SQL.
    Sql,
    /// *Shell* POSIX.
    Shell,
    /// No reconocido.
    Unknown,
}

impl SourceLanguage {
    /// Etiqueta estable y corta.
    pub const fn tag(self) -> &'static str {
        match self {
            SourceLanguage::JavaScript => "js",
            SourceLanguage::Python => "py",
            SourceLanguage::Rust => "rs",
            SourceLanguage::Go => "go",
            SourceLanguage::Java => "java",
            SourceLanguage::CSharp => "cs",
            SourceLanguage::C => "c",
            SourceLanguage::Sql => "sql",
            SourceLanguage::Shell => "sh",
            SourceLanguage::Unknown => "?",
        }
    }

    /// Nombre legible.
    pub const fn label(self) -> &'static str {
        match self {
            SourceLanguage::JavaScript => "JavaScript/TypeScript",
            SourceLanguage::Python => "Python",
            SourceLanguage::Rust => "Rust",
            SourceLanguage::Go => "Go",
            SourceLanguage::Java => "Java",
            SourceLanguage::CSharp => "C#",
            SourceLanguage::C => "C/C++",
            SourceLanguage::Sql => "SQL",
            SourceLanguage::Shell => "shell",
            SourceLanguage::Unknown => "desconocido",
        }
    }
}

/// Detección determinista por marcas léxicas. Ante la duda, `Unknown`: el
/// análisis no depende de acertar el lenguaje.
pub fn detect_language(fragment: &str) -> SourceLanguage {
    let text = fragment.to_lowercase();
    if text.starts_with("#!") && (text.contains("/bin/sh") || text.contains("/bin/bash")) {
        return SourceLanguage::Shell;
    }
    if text.contains("select ")
        || text.contains("insert into")
        || text.contains("update ")
        || text.contains("delete from")
        || text.contains("create table")
    {
        return SourceLanguage::Sql;
    }
    if text.contains("fn ") || text.contains("let mut ") || text.contains("impl ") {
        return SourceLanguage::Rust;
    }
    if text.contains("func ") || text.contains("package ") || text.contains(":=") {
        return SourceLanguage::Go;
    }
    if text.contains("using system") || text.contains("console.writeline") {
        return SourceLanguage::CSharp;
    }
    if text.contains("#include") || text.contains("int main(") {
        return SourceLanguage::C;
    }
    if text.contains("public class") || text.contains("system.out") {
        return SourceLanguage::Java;
    }
    if text.contains("def ") || text.contains("elif ") || text.contains("print(") {
        return SourceLanguage::Python;
    }
    if text.contains("function ")
        || text.contains("=>")
        || text.contains("const ")
        || text.contains("let ")
        || text.contains("console.log")
    {
        return SourceLanguage::JavaScript;
    }
    SourceLanguage::Unknown
}

// ─────────────────────────────────────────────────────────────────────────
// Conceptos *Shoresh* (raíces únicas del parche)
// ─────────────────────────────────────────────────────────────────────────

/// Concepto semántico al que se reduce una sentencia externa.
///
/// Cada concepto tiene una raíz triconsonántica **distinta**, de modo que el
/// parche cumple `raiz.unica` por construcción y no puede crecer sin cota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Concept {
    /// Asignación o declaración de variable.
    Assign,
    /// Condicional o bifurcación.
    Conditional,
    /// Bucle o control iterativo.
    Loop,
    /// Retorno de una función.
    Return,
    /// Definición de función, clase o tipo.
    Define,
    /// Importación, inclusión o llamada.
    Import,
    /// Comparación, aserción de igualdad o prueba.
    Compare,
    /// Expresión no clasificada (`∅`: no entra).
    Expression,
    /// Afirmación explícita.
    Assert,
    /// Negación explícita.
    Negate,
    /// Escritura o efecto de salida.
    Output,
    /// Concatenación o unión de datos.
    Join,
    /// Apertura de recurso.
    Open,
    /// Cierre de recurso.
    Close,
    /// Coincidencia de patrón.
    Match,
    /// Iteración o paso.
    Iterate,
    /// Error o excepción.
    Error,
    /// Lectura de entrada.
    Read,
    /// Frontera del fragmento (marca de truncamiento).
    Fence,
    /// Cuarentena: lo que no se purifica.
    Quarantine,
}

impl Concept {
    /// Raíz triconsonántica hebrea del concepto.
    pub const fn root(self) -> &'static str {
        match self {
            Concept::Assign => "אמר",
            Concept::Conditional => "פצל",
            Concept::Loop => "חזר",
            Concept::Return => "שלח",
            Concept::Define => "בנה",
            Concept::Import => "קרא",
            Concept::Compare => "בדק",
            Concept::Expression => "חשב",
            Concept::Assert => "אמת",
            Concept::Negate => "שקר",
            Concept::Output => "כתב",
            Concept::Join => "צרף",
            Concept::Open => "פתח",
            Concept::Close => "סגר",
            Concept::Match => "זהה",
            Concept::Iterate => "עבר",
            Concept::Error => "נפל",
            Concept::Read => "ראה",
            Concept::Fence => "גדר",
            Concept::Quarantine => "רחק",
        }
    }

    /// Tipo de retorno declarado (nunca [`BaraType::Unknown`]).
    pub const fn ret(self) -> BaraType {
        match self {
            Concept::Compare | Concept::Assert | Concept::Negate | Concept::Match => {
                BaraType::Truth
            }
            Concept::Output | Concept::Join | Concept::Read => BaraType::Text,
            Concept::Error | Concept::Quarantine | Concept::Fence => BaraType::Truth,
            Concept::Assign
            | Concept::Conditional
            | Concept::Loop
            | Concept::Return
            | Concept::Define
            | Concept::Import
            | Concept::Expression
            | Concept::Open
            | Concept::Close
            | Concept::Iterate => BaraType::Number,
        }
    }

    /// Masa de falsedad inherente al concepto en `[0, 1]`.
    ///
    /// No es pesimismo: es la parte `⊥` que el concepto ya trae consigo. Los
    /// bucles y la E/S pueden no terminar o fallar, así que nacen con masa de
    /// falsedad alta y quedan como `⊤∧⊥` (designados, pero sellados si el
    /// riesgo supera [`SEAL_THRESHOLD`]).
    pub const fn falsity(self) -> f64 {
        match self {
            Concept::Assign | Concept::Assert => 0.05,
            Concept::Return | Concept::Compare => 0.10,
            Concept::Join => 0.20,
            Concept::Read => 0.25,
            Concept::Import | Concept::Match => 0.35,
            Concept::Close | Concept::Fence => 0.40,
            Concept::Conditional | Concept::Expression => 0.45,
            Concept::Loop | Concept::Iterate | Concept::Define => 0.55,
            Concept::Negate | Concept::Open | Concept::Output => 0.60,
            Concept::Error => 0.70,
            Concept::Quarantine => 1.0,
        }
    }

    /// Riesgo estructural base en `[0, 1]`.
    pub const fn hazard(self) -> f64 {
        match self {
            Concept::Assert => 0.05,
            Concept::Assign | Concept::Return | Concept::Compare => 0.10,
            Concept::Join | Concept::Read => 0.15,
            Concept::Match | Concept::Import => 0.25,
            Concept::Conditional | Concept::Expression | Concept::Close => 0.35,
            Concept::Fence | Concept::Loop | Concept::Iterate => 0.40,
            Concept::Define => 0.45,
            Concept::Negate => 0.55,
            Concept::Output | Concept::Open => 0.60,
            Concept::Error => 0.70,
            Concept::Quarantine => 1.0,
        }
    }

    /// Etiqueta del concepto para la trazabilidad.
    pub const fn tag(self) -> &'static str {
        match self {
            Concept::Assign => "asignacion",
            Concept::Conditional => "condicional",
            Concept::Loop => "bucle",
            Concept::Return => "retorno",
            Concept::Define => "definicion",
            Concept::Import => "importacion",
            Concept::Compare => "comparacion",
            Concept::Expression => "expresion",
            Concept::Assert => "afirmacion",
            Concept::Negate => "negacion",
            Concept::Output => "salida",
            Concept::Join => "union",
            Concept::Open => "apertura",
            Concept::Close => "cierre",
            Concept::Match => "coincidencia",
            Concept::Iterate => "iteracion",
            Concept::Error => "error",
            Concept::Read => "lectura",
            Concept::Fence => "frontera",
            Concept::Quarantine => "cuarentena",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Informe y resultado
// ─────────────────────────────────────────────────────────────────────────

/// Informe forense de una transmutación. Todos los campos son deterministas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransmutationReport {
    /// Lenguaje detectado (informativo).
    pub language: SourceLanguage,
    /// Sentencias no vacías que se clasificaron.
    pub statements: usize,
    /// Sentencias designadas (`⊤` o `⊤∧⊥`) que aportaron evidencia.
    pub accepted: usize,
    /// Sentencias no designadas (`⊥` o `∅`): cuarentena.
    pub rejected: usize,
    /// Nodos de cuarentena emitidos (`0` o `1`).
    pub quarantined: usize,
    /// Recuento de sentencias `⊤`.
    pub true_count: usize,
    /// Recuento de sentencias `⊥`.
    pub false_count: usize,
    /// Recuento de sentencias `⊤∧⊥`.
    pub both: usize,
    /// Recuento de sentencias `∅`.
    pub neither: usize,
    /// Nodos sellados bajo guarda `שמר` (riesgo sobre el umbral).
    pub sealed: usize,
    /// El fragmento excedió [`MAX_FRAGMENT_BYTES`] o [`MAX_STATEMENTS`].
    pub truncated: bool,
    /// Hubo bytes no UTF‑8 (se leyeron con reemplazo).
    pub lossy: bool,
    /// El AST resultante pasó las nueve reglas de [`audit_ast`].
    pub audit_passed: bool,
    /// Reglas cumplidas.
    pub audit_passed_rules: usize,
    /// Reglas totales.
    pub audit_total_rules: usize,
}

/// Resultado de transmutar un fragmento.
#[derive(Debug, Clone)]
pub struct Transmutation {
    /// AST *Shoresh* purificado (posiblemente vacío).
    pub ast: ShoreshAst,
    /// Informe de la operación.
    pub report: TransmutationReport,
}

impl Transmutation {
    /// ¿Se puede fusionar este AST en el núcleo?
    ///
    /// Exige que haya al menos un nodo y que la auditoría completa pase. Un
    /// fragmento vacío o ilegible devuelve `false`: no se inventa un axioma.
    pub fn is_admissible(&self) -> bool {
        self.report.audit_passed && !self.ast.nodes.is_empty()
    }
}

/// Evidencia tetravalente de una sentencia.
#[derive(Debug, Clone, Copy)]
struct Evidence {
    truth: f64,
    falsity: f64,
    hazard: f64,
    arity: usize,
}

/// Acumulador por concepto: conjuga la evidencia con `∧` (`mín ⊤`, `máx ⊥`).
#[derive(Debug, Clone)]
struct Accumulator {
    concept: Concept,
    truth: f64,
    falsity: f64,
    hazard: f64,
    arity: usize,
    count: usize,
    first: String,
}

impl Accumulator {
    fn new(concept: Concept) -> Accumulator {
        Accumulator {
            concept,
            truth: 1.0,
            falsity: 0.0,
            hazard: concept.hazard(),
            arity: 0,
            count: 0,
            first: String::new(),
        }
    }

    fn merge(&mut self, evidence: Evidence, statement: &str) {
        self.truth = self.truth.min(evidence.truth);
        self.falsity = self.falsity.max(evidence.falsity);
        self.hazard = self.hazard.max(evidence.hazard);
        self.arity = self.arity.max(evidence.arity);
        self.count = self.count.saturating_add(1);
        if self.first.is_empty() {
            self.first = snippet(statement);
        }
    }

    fn node(&self, language: SourceLanguage) -> ShoreshNode {
        let suffix = if self.count > 1 {
            format!(" (+{})", self.count - 1)
        } else {
            String::new()
        };
        let hazard = self.hazard.clamp(0.0, 1.0);
        ShoreshNode {
            root: self.concept.root().to_string(),
            original: format!(
                "extern:{}:{}:{}{}",
                language.tag(),
                self.concept.tag(),
                self.first,
                suffix
            ),
            arity: self.arity.min(MAX_ARITY),
            ret: self.concept.ret(),
            hazard,
            valence: QuantumState::paraconsistent(
                self.truth.clamp(0.0, 1.0),
                self.falsity.clamp(0.0, 1.0),
            ),
            sanitized: hazard > SEAL_THRESHOLD,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Entrada pública
// ─────────────────────────────────────────────────────────────────────────

/// Transmuta un fragmento de texto de cualquier lenguaje.
///
/// Es **total**: siempre devuelve un resultado. Un fragmento vacío produce un
/// AST vacío con `audit_passed = false`; uno ilegible produce un único nodo de
/// cuarentena sellado (`⊥`). Ninguna entrada provoca un pánico.
///
/// Es **acotado**: si el fragmento excede [`MAX_FRAGMENT_BYTES`] o
/// [`MAX_STATEMENTS`] sentencias, se recorta y el AST termina con la cerca
/// `גדר`, declarada en `report.truncated`.
pub fn transmute(fragment: &str) -> Transmutation {
    let language = detect_language(fragment);
    let (bounded, truncated) = bounded_prefix(fragment, MAX_FRAGMENT_BYTES);
    analyze(language, bounded, truncated, false)
}

/// Núcleo compartido por [`transmute`] y [`transmute_bytes`].
///
/// Recibe el texto ya acotado y las banderas de la frontera: `truncated` si el
/// origen se recortó por bytes y `lossy` si hubo que sustituir UTF‑8. La
/// segmentación, la retícula y la cerca son idénticas en ambos caminos, de modo
/// que los bytes no tienen una puerta trasera distinta a la del texto.
fn analyze(
    language: SourceLanguage,
    fragment: &str,
    truncated: bool,
    lossy: bool,
) -> Transmutation {
    let mut statements = match segment(fragment) {
        Ok(statements) => statements,
        Err(_) => return quarantine_only(language, truncated, lossy, "fragmento ilegible"),
    };
    let truncated = truncated || statements.len() > MAX_STATEMENTS;
    if truncated {
        statements.truncate(MAX_STATEMENTS);
    }

    let mut accumulators: Vec<Accumulator> = Vec::new();
    let mut quarantine: Option<Accumulator> = None;
    let mut report = TransmutationReport {
        language,
        statements: statements.len(),
        accepted: 0,
        rejected: 0,
        quarantined: 0,
        true_count: 0,
        false_count: 0,
        both: 0,
        neither: 0,
        sealed: 0,
        truncated,
        lossy,
        audit_passed: false,
        audit_passed_rules: 0,
        audit_total_rules: 0,
    };

    for statement in &statements {
        let concept = classify(statement);
        let mille = threat_of(statement.as_bytes()).mille.min(1000);
        let danger = f64::from(mille) / 1000.0;
        let (truth, falsity) = evidence_of(concept, danger);
        let value = BelnapValue::from_masses(truth, falsity);
        match value {
            BelnapValue::True => report.true_count = report.true_count.saturating_add(1),
            BelnapValue::False => report.false_count = report.false_count.saturating_add(1),
            BelnapValue::Both => report.both = report.both.saturating_add(1),
            BelnapValue::Neither => report.neither = report.neither.saturating_add(1),
        }

        let arity = arity_of(statement);
        if value.is_designated() {
            report.accepted = report.accepted.saturating_add(1);
            let evidence = Evidence {
                truth,
                falsity,
                hazard: (concept.hazard() + danger * 0.25).clamp(0.0, 1.0),
                arity,
            };
            match accumulators
                .iter_mut()
                .find(|accumulator| accumulator.concept == concept)
            {
                Some(accumulator) => accumulator.merge(evidence, statement),
                None => {
                    let mut accumulator = Accumulator::new(concept);
                    accumulator.merge(evidence, statement);
                    accumulators.push(accumulator);
                }
            }
        } else {
            report.rejected = report.rejected.saturating_add(1);
            let evidence = Evidence {
                truth: 0.0,
                falsity: 1.0,
                hazard: 1.0,
                arity,
            };
            match quarantine.as_mut() {
                Some(accumulator) => accumulator.merge(evidence, statement),
                None => {
                    let mut accumulator = Accumulator::new(Concept::Quarantine);
                    accumulator.merge(evidence, statement);
                    quarantine = Some(accumulator);
                }
            }
        }
    }

    let mut nodes: Vec<ShoreshNode> = accumulators
        .iter()
        .map(|accumulator| accumulator.node(language))
        .collect();
    if let Some(accumulator) = &quarantine {
        nodes.push(accumulator.node(language));
        report.quarantined = 1;
    }
    if truncated {
        let mut fence = Accumulator::new(Concept::Fence);
        fence.truth = 0.0;
        fence.falsity = 0.0;
        fence.count = 1;
        fence.first = format!("limite:{MAX_FRAGMENT_BYTES}b/{MAX_STATEMENTS}s");
        nodes.push(fence.node(language));
    }

    finish(report, nodes)
}

/// Transmuta bytes arbitrarios (UTF‑8 tolerante y acotado).
///
/// Los bytes inválidos se sustituyen y se marca `lossy`; el exceso de tamaño se
/// recorta **antes** de decodificar, deja la cerca `גדר` y se declara en
/// `truncated`, igual que en [`transmute`]. Nunca se falla por codificación.
pub fn transmute_bytes(fragment: &[u8]) -> Transmutation {
    let (slice, truncated) = if fragment.len() > MAX_FRAGMENT_BYTES {
        match fragment.get(..MAX_FRAGMENT_BYTES) {
            Some(prefix) => (prefix, true),
            None => (fragment, true),
        }
    } else {
        (fragment, false)
    };
    let lossy = std::str::from_utf8(slice).is_err();
    let text = String::from_utf8_lossy(slice);
    analyze(detect_language(&text), &text, truncated, lossy)
}

/// AST de cuarentena: un único nodo `רחק` sellado con `⊥`.
fn quarantine_only(
    language: SourceLanguage,
    truncated: bool,
    lossy: bool,
    reason: &str,
) -> Transmutation {
    let mut accumulator = Accumulator::new(Concept::Quarantine);
    accumulator.merge(
        Evidence {
            truth: 0.0,
            falsity: 1.0,
            hazard: 1.0,
            arity: 0,
        },
        reason,
    );
    let report = TransmutationReport {
        language,
        statements: 0,
        accepted: 0,
        rejected: 1,
        quarantined: 1,
        true_count: 0,
        false_count: 1,
        both: 0,
        neither: 0,
        sealed: 0,
        truncated,
        lossy,
        audit_passed: false,
        audit_passed_rules: 0,
        audit_total_rules: 0,
    };
    finish(report, vec![accumulator.node(language)])
}

/// Cierra el informe con la auditoría real del AST.
fn finish(mut report: TransmutationReport, nodes: Vec<ShoreshNode>) -> Transmutation {
    let ast = ShoreshAst { nodes };
    let audit = audit_ast(&ast);
    let (passed_rules, total_rules) = audit.score();
    report.audit_passed = audit.passed();
    report.audit_passed_rules = passed_rules;
    report.audit_total_rules = total_rules;
    report.sealed = ast.nodes.iter().filter(|node| node.sanitized).count();
    Transmutation { ast, report }
}

// ─────────────────────────────────────────────────────────────────────────
// Segmentación lineal (sin analizador completo, sin pánico)
// ─────────────────────────────────────────────────────────────────────────

/// Fallo de segmentación: el fragmento no está balanceado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SegmentError {
    /// Delimitadores desbalanceados o comentario de bloque sin cerrar.
    Unbalanced,
    /// Cadena sin cerrar.
    Unterminated,
}

/// Divide un fragmento en sentencias.
///
/// Reconoce cadenas (`"`, `'`, `` ` ``), comentarios (`//`, `/* */`, `--`, `#`),
/// y separa por `;`, salto de línea o cierre de llave en el nivel superior. Es
/// **lineal** en el tamaño de la entrada y no asigna por sentencia más allá de
/// la propia sentencia.
fn segment(fragment: &str) -> Result<Vec<String>, SegmentError> {
    let mut out: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut stack: Vec<char> = Vec::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut line_comment = false;
    let mut block_comment = false;
    let mut chars = fragment.chars().peekable();

    while let Some(ch) = chars.next() {
        if line_comment {
            if ch == '\n' {
                line_comment = false;
                flush(&mut out, &mut current);
            }
            continue;
        }
        if block_comment {
            if ch == '*' && chars.peek() == Some(&'/') {
                chars.next();
                block_comment = false;
            }
            continue;
        }
        if let Some(end) = quote {
            current.push(ch);
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == end {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' | '`' => {
                quote = Some(ch);
                current.push(ch);
            }
            '#' => match chars.peek() {
                Some(next) if !next.is_ascii_alphanumeric() => line_comment = true,
                _ => current.push(ch),
            },
            '/' => match chars.peek() {
                Some('/') => {
                    chars.next();
                    line_comment = true;
                }
                Some('*') => {
                    chars.next();
                    block_comment = true;
                }
                _ => current.push(ch),
            },
            '-' => match chars.peek() {
                Some('-') => {
                    chars.next();
                    line_comment = true;
                }
                _ => current.push(ch),
            },
            '(' | '[' => {
                stack.push(ch);
                current.push(ch);
            }
            '{' => {
                stack.push(ch);
                current.push(ch);
                flush(&mut out, &mut current);
            }
            ')' | ']' | '}' => {
                let expected = match ch {
                    ')' => '(',
                    ']' => '[',
                    _ => '{',
                };
                if stack.pop() != Some(expected) {
                    return Err(SegmentError::Unbalanced);
                }
                current.push(ch);
                if stack.is_empty() {
                    flush(&mut out, &mut current);
                }
            }
            ';' if stack.is_empty() => flush(&mut out, &mut current),
            '\n' if stack.is_empty() => flush(&mut out, &mut current),
            _ => current.push(ch),
        }
    }
    if quote.is_some() {
        return Err(SegmentError::Unterminated);
    }
    if block_comment || !stack.is_empty() {
        return Err(SegmentError::Unbalanced);
    }
    flush(&mut out, &mut current);
    Ok(out)
}

/// Vuelca la sentencia actual si aporta contenido semántico.
fn flush(out: &mut Vec<String>, current: &mut String) {
    let trimmed = current.trim();
    if trimmed.chars().any(char::is_alphanumeric) {
        out.push(trimmed.to_string());
    }
    current.clear();
}

// ─────────────────────────────────────────────────────────────────────────
// Utilidades de análisis
// ─────────────────────────────────────────────────────────────────────────

/// Prefijo acotado por bytes, respetando límites de carácter UTF‑8.
fn bounded_prefix(text: &str, limit: usize) -> (&str, bool) {
    if text.len() <= limit {
        return (text, false);
    }
    let mut cut = limit;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    match text.get(..cut) {
        Some(prefix) => (prefix, true),
        None => ("", true),
    }
}

/// Normaliza una sentencia para la trazabilidad: una línea, sin controles.
fn snippet(text: &str) -> String {
    let mut out = String::new();
    let mut used = 0_usize;
    let mut last_space = false;
    for raw in text.chars() {
        let ch = if raw.is_control() { ' ' } else { raw };
        if ch == ' ' {
            if last_space || out.is_empty() {
                continue;
            }
            last_space = true;
        } else {
            last_space = false;
        }
        out.push(ch);
        used = used.saturating_add(1);
        if used >= MAX_ORIGINAL_CHARS {
            out.push('…');
            break;
        }
    }
    out.trim().to_string()
}

/// ¿El byte puede formar parte de un identificador ASCII?
fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Primera aparición de `needle` en `haystack` a partir de `from`.
fn find_from(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from > haystack.len() {
        return None;
    }
    let tail = haystack.get(from..)?;
    tail.windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| offset + from)
}

/// ¿Aparece la palabra con fronteras de identificador?
fn has_word(text: &str, word: &str) -> bool {
    let haystack = text.as_bytes();
    let needle = word.as_bytes();
    let mut start = 0_usize;
    while let Some(position) = find_from(haystack, needle, start) {
        let before_ok = position == 0 || !is_word_byte(haystack[position - 1]);
        let after = position + needle.len();
        let after_ok = after >= haystack.len() || !is_word_byte(haystack[after]);
        if before_ok && after_ok {
            return true;
        }
        start = position.saturating_add(1);
    }
    false
}

/// Primera palabra (minúsculas) de la sentencia, admitiendo `#`, `@` y `$`.
fn leading_word(text: &str) -> String {
    let mut out = String::new();
    for ch in text.trim_start().chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '#' | '@' | '$') {
            out.push(ch.to_ascii_lowercase());
        } else {
            break;
        }
    }
    out
}

/// ¿Hay una asignación (y no una comparación ni una flecha)?
fn has_assignment(text: &str) -> bool {
    if text.contains(":=")
        || text.contains("<-")
        || text.contains("+=")
        || text.contains("-=")
        || text.contains("*=")
        || text.contains("/=")
    {
        return true;
    }
    let bytes = text.as_bytes();
    let mut index = 0_usize;
    while let Some(byte) = bytes.get(index) {
        if *byte == b'=' {
            let previous = if index > 0 { bytes[index - 1] } else { b' ' };
            let next = bytes.get(index + 1).copied().unwrap_or(b' ');
            if previous != b'='
                && previous != b'!'
                && previous != b'<'
                && previous != b'>'
                && next != b'='
                && next != b'>'
            {
                return true;
            }
        }
        index = index.saturating_add(1);
    }
    false
}

/// ¿Hay una comparación explícita?
fn has_comparison(text: &str) -> bool {
    text.contains("==") || text.contains("!=") || text.contains("<=") || text.contains(">=")
}

/// Aridad aproximada: argumentos del primer paréntesis balanceado.
fn arity_of(statement: &str) -> usize {
    let open = match statement.find('(') {
        Some(position) => position,
        None => return 0,
    };
    let bytes = statement.as_bytes();
    let mut depth = 0_usize;
    let mut commas = 0_usize;
    let mut filled = false;
    let mut index = open;
    while let Some(byte) = bytes.get(index) {
        match *byte {
            b'(' => {
                depth = depth.saturating_add(1);
                if depth > 1 {
                    filled = true;
                }
            }
            b')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    break;
                }
            }
            b',' if depth == 1 => {
                commas = commas.saturating_add(1);
                filled = true;
            }
            other if depth == 1 && !other.is_ascii_whitespace() => filled = true,
            _ => {}
        }
        index = index.saturating_add(1);
    }
    if filled {
        commas.saturating_add(1)
    } else {
        0
    }
}

/// Masas `(⊤, ⊥)` de una sentencia antes de tocar el árbol.
///
/// * `⊥` inmediato si el peligro alcanza [`HOSTILE_PERMILLE`].
/// * `∅` para expresiones no clasificadas (no entran).
/// * `⊤∧⊥` cuando el concepto arrastra masa de falsedad alta (bucles, E/S).
fn evidence_of(concept: Concept, danger: f64) -> (f64, f64) {
    let danger = if danger.is_finite() {
        danger.clamp(0.0, 1.0)
    } else {
        1.0
    };
    let hostile = f64::from(HOSTILE_PERMILLE) / 1000.0;
    if danger >= hostile {
        return (0.0, 1.0);
    }
    if concept == Concept::Expression {
        return ((1.0 - danger).min(0.45), danger.max(0.45));
    }
    (
        (1.0 - danger * 0.5).clamp(0.0, 1.0),
        concept.falsity().max(danger),
    )
}

/// Reduce una sentencia a un [`Concept`] mediante marcas léxicas.
///
/// Es un heurístico **deliberadamente simple y total**: no pretende compilar el
/// lenguaje, sólo reconocer la forma del control de flujo, la asignación y la
/// E/S. Lo que no reconoce cae en [`Concept::Expression`] (`∅`) y no entra.
fn classify(statement: &str) -> Concept {
    let text = statement.to_lowercase();
    let word = leading_word(statement);
    let word = word.as_str();

    if has_word(&text, "if")
        || has_word(&text, "elif")
        || has_word(&text, "unless")
        || has_word(&text, "switch")
        || has_word(&text, "case")
        || has_word(&text, "when")
        || has_word(&text, "else")
        || has_word(&text, "match")
    {
        return Concept::Conditional;
    }
    if matches!(
        word,
        "for" | "while" | "loop" | "do" | "break" | "continue" | "goto" | "foreach"
    ) || has_word(&text, "foreach")
    {
        return Concept::Loop;
    }
    if matches!(word, "return" | "yield" | "throw" | "raise") {
        return Concept::Return;
    }
    if matches!(
        word,
        "fn" | "def"
            | "func"
            | "function"
            | "class"
            | "struct"
            | "impl"
            | "trait"
            | "interface"
            | "enum"
            | "type"
            | "lambda"
            | "async"
            | "pub"
            | "public"
            | "mod"
            | "namespace"
    ) || word.starts_with('@')
    {
        return Concept::Define;
    }
    if matches!(
        word,
        "import"
            | "from"
            | "use"
            | "include"
            | "#include"
            | "require"
            | "export"
            | "package"
            | "using"
            | "module"
    ) {
        return Concept::Import;
    }
    if matches!(
        word,
        "try" | "catch" | "finally" | "defer" | "await" | "resume" | "pass"
    ) {
        return Concept::Iterate;
    }
    if matches!(word, "open" | "fopen" | "openat") {
        return Concept::Open;
    }
    if matches!(word, "close" | "fclose") {
        return Concept::Close;
    }
    if matches!(word, "read" | "readline" | "recv" | "gets" | "scan") {
        return Concept::Read;
    }
    if matches!(
        word,
        "write" | "writeln" | "print" | "println" | "printf" | "echo" | "puts" | "send" | "log"
    ) || has_word(&text, "console.log")
    {
        return Concept::Output;
    }
    if matches!(word, "assert" | "check" | "expect" | "test") {
        return Concept::Assert;
    }
    if matches!(word, "not" | "neg" | "deny" | "reject") {
        return Concept::Negate;
    }
    if matches!(word, "error" | "err" | "fail" | "panic") {
        return Concept::Error;
    }
    if matches!(
        word,
        "select" | "insert" | "update" | "delete" | "create" | "drop" | "alter"
    ) {
        return Concept::Error;
    }
    if has_assignment(statement)
        || matches!(
            word,
            "let" | "var" | "const" | "mut" | "val" | "set" | "local" | "declare" | "auto"
        )
    {
        return Concept::Assign;
    }
    if has_comparison(statement) {
        return Concept::Compare;
    }
    if matches!(word, "join" | "concat" | "append" | "merge") || has_word(&text, "join") {
        return Concept::Join;
    }
    if statement.contains('(') {
        return Concept::Import;
    }
    Concept::Expression
}

// ─────────────────────────────────────────────────────────────────────────
// Pruebas unitarias de las piezas internas
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn el_segmentador_respeta_cadenas_y_comentarios() {
        let parts =
            segment("a = 1; /* b = 2; */ c = \"x;y\"; // d = 3\ne = 4;").unwrap_or_default();
        assert_eq!(parts, vec!["a = 1", "c = \"x;y\"", "e = 4"]);

        // Un comentario de línea no aporta sentencia, pero tampoco la rompe.
        assert_eq!(segment("#!/bin/sh\nx").unwrap_or_default(), vec!["x"]);
        // La llave de cierre separa la sentencia pendiente y queda adherida a
        // ella (es su delimitador, igual que el `)` de una llamada).
        assert_eq!(
            segment("if (x) { y(); }").unwrap_or_default(),
            vec!["if (x)", "y(); }"]
        );
        // El `;` dentro de un paréntesis no separa.
        assert_eq!(
            segment("f(a; b); g()").unwrap_or_default(),
            vec!["f(a; b)", "g()"]
        );
    }

    #[test]
    fn el_segmentador_es_total_ante_desequilibrios() {
        assert_eq!(segment("f("), Err(SegmentError::Unbalanced));
        assert_eq!(segment("f)"), Err(SegmentError::Unbalanced));
        assert_eq!(segment("x = \"a"), Err(SegmentError::Unterminated));
        assert_eq!(segment("/* abierto"), Err(SegmentError::Unbalanced));
        assert_eq!(segment("}"), Err(SegmentError::Unbalanced));
    }

    #[test]
    fn la_aridad_cuenta_argumentos_del_primer_parentesis() {
        assert_eq!(arity_of("sin parentesis"), 0);
        assert_eq!(arity_of("f()"), 0);
        assert_eq!(arity_of("f(a)"), 1);
        assert_eq!(arity_of("f(a, b)"), 2);
        assert_eq!(arity_of("f(g(a, b), c)"), 2);
        assert_eq!(arity_of("f(a,)"), 2);
    }

    #[test]
    fn la_asignacion_no_confunde_comparaciones() {
        assert!(has_assignment("x = 1"));
        assert!(has_assignment("x := 1"));
        assert!(has_assignment("x += 1"));
        assert!(has_assignment("x <- 1"));
        assert!(!has_assignment("x == 1"));
        assert!(!has_assignment("x != 1"));
        assert!(!has_assignment("x <= 1"));
        assert!(!has_assignment("x >= 1"));
        assert!(!has_assignment("x => 1"));
        assert!(!has_assignment("f(1)"));
    }

    #[test]
    fn la_palabra_exige_fronteras_de_identificador() {
        assert!(has_word("if x", "if"));
        assert!(has_word("else if", "if"));
        assert!(!has_word("verify", "if"));
        assert!(!has_word("iffy", "if"));
        assert!(!has_word("", "if"));
    }

    #[test]
    fn la_clasificacion_cubre_las_formas_basicas() {
        let cases = [
            ("if x { y(); }", Concept::Conditional),
            ("match x", Concept::Conditional),
            ("for i in 0..3", Concept::Loop),
            ("while x", Concept::Loop),
            ("return x", Concept::Return),
            ("def f(x):", Concept::Define),
            ("func main()", Concept::Define),
            ("public class A", Concept::Define),
            ("fn main()", Concept::Define),
            ("import os", Concept::Import),
            ("using System;", Concept::Import),
            ("x = 1", Concept::Assign),
            ("let x = 1", Concept::Assign),
            ("x == 1", Concept::Compare),
            ("join lista", Concept::Join),
            ("print(x)", Concept::Output),
            ("read(f)", Concept::Read),
            ("open(f)", Concept::Open),
            ("close(f)", Concept::Close),
            ("select 1", Concept::Error),
            ("x + y", Concept::Expression),
        ];
        for (statement, expected) in cases {
            assert_eq!(classify(statement), expected, "«{statement}»");
        }
    }

    #[test]
    fn la_evidencia_respeta_el_umbral_hostil() {
        assert_eq!(
            evidence_of(Concept::Assign, 0.0),
            (1.0, Concept::Assign.falsity()),
            "sin peligro, la verdad es plena y la falsedad es la inherente"
        );
        assert_eq!(
            evidence_of(Concept::Assign, f64::from(HOSTILE_PERMILLE) / 1000.0),
            (0.0, 1.0),
            "en el umbral, la sentencia ya es ⊥"
        );
        assert_eq!(
            evidence_of(Concept::Assign, f64::NAN),
            (0.0, 1.0),
            "un peligro no finito se trata como máximo"
        );

        // Una expresión suelta es ∅: ni designada ni hostil.
        let (truth, falsity) = evidence_of(Concept::Expression, 0.0);
        assert!(truth < 0.5);
        assert!(falsity >= 0.45);
        assert!(!BelnapValue::from_masses(truth, falsity).is_designated());

        // La E/S arrastra masa de falsedad: nace ⊤∧⊥ y sigue designada.
        let (truth, falsity) = evidence_of(Concept::Output, 0.4);
        let value = BelnapValue::from_masses(truth, falsity);
        assert!(value.is_designated());
        assert_eq!(value, BelnapValue::Both);
    }

    #[test]
    fn el_extracto_es_una_linea_acotada() {
        assert_eq!(snippet("  a\tb   c  "), "a b c");
        assert_eq!(snippet("\u{0}\u{1}"), "");

        let long = "x".repeat(MAX_ORIGINAL_CHARS + 50);
        let cut = snippet(&long);
        assert!(cut.ends_with('…'));
        assert!(cut.chars().count() <= MAX_ORIGINAL_CHARS + 1);
        assert!(cut.chars().count() > MAX_ORIGINAL_CHARS / 2);
    }

    #[test]
    fn el_prefijo_acotado_no_rompe_la_codificacion() {
        assert_eq!(bounded_prefix("abc", 5), ("abc", false));
        assert_eq!(bounded_prefix("abc", 3), ("abc", false));

        let (prefix, cut) = bounded_prefix("áé", 3);
        assert_eq!(prefix, "á", "cortó a mitad de carácter");
        assert!(cut);
    }

    #[test]
    fn la_busqueda_de_agujas_respeta_el_desplazamiento() {
        assert_eq!(find_from(b"abcabc", b"bc", 0), Some(1));
        assert_eq!(find_from(b"abcabc", b"bc", 2), Some(4));
        assert_eq!(find_from(b"abc", b"", 0), None);
        assert_eq!(find_from(b"abc", b"a", 4), None);
        assert_eq!(find_from(b"abc", b"zz", 0), None);
    }
}
