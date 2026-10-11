//! # Interactive REPL Oracle — `repl.rs`
//!
//! Oráculo conversacional de Bara: un bucle de línea de comandos donde el
//! desarrollador habla **en lenguaje natural o en raíces triconsonánticas**
//! (`ברא`, `שמר`, `חכם`…) y el motor responde con **compilación dinámica
//! inmediata** sobre el runtime paraconsistente, mientras un monitor `Δ⁻¹`
//! vigila el rebobinado temporal de cada turno.
//!
//! ## Qué hace cada turno
//! 1. **Interpreta** la consulta: `:comandos`, raíces hebreas o lengua natural.
//! 2. **Traduce** la lengua natural a un programa *Shoresh* mediante el léxico
//!    ([`LEXICON`]). Un verbo desconocido no es un error: se sintetiza una
//!    raíz nueva (`autopoiesis`) y el lenguaje crece.
//! 3. **Compila y ejecuta** al instante (medido en microsegundos) sobre el
//!    runtime, contando los eventos ontológicos emitidos.
//! 4. **Monitoriza** el motor temporal: deltas vivos, deltas revertidos y
//!    pulsos de rollback `Δ⁻¹` interceptados.
//!
//! El oráculo **nunca falla**: toda entrada produce un turno y una respuesta.

use crate::lexer::{Lexer, TokenKind};
use crate::runtime::{BaraRuntime, ExecutionEvent, QuantumState};
use crate::temporal_rollback::Marker;
use std::io::{self, IsTerminal, Write};
use std::time::Instant;

// ─────────────────────────────────────────────────────────────────────────
// Léxico natural → Shoresh
// ─────────────────────────────────────────────────────────────────────────

/// Léxico de lengua natural → raíz triconsonántica / operador.
const LEXICON: [(&str, &str); 30] = [
    ("crea", "ברא"),
    ("crear", "ברא"),
    ("creacion", "ברא"),
    ("manifiesta", "ברא"),
    ("manifestar", "ברא"),
    ("create", "ברא"),
    ("make", "ברא"),
    ("guarda", "שמר"),
    ("guardar", "שמר"),
    ("protege", "שמר"),
    ("sella", "שמר"),
    ("guard", "שמר"),
    ("seal", "שמר"),
    ("juzga", "שפט"),
    ("juzgar", "שפט"),
    ("evalua", "שפט"),
    ("compara", "שפט"),
    ("judge", "שפט"),
    ("compare", "שפט"),
    ("emite", "אמר"),
    ("emitir", "אמר"),
    ("muestra", "אמר"),
    ("dime", "אמר"),
    ("show", "אמר"),
    ("ejecuta", "עבד"),
    ("colapsa", "עבד"),
    ("run", "עבד"),
    ("sabio", "חכם"),
    ("optimiza", "חכם"),
    ("adapta", "חכם"),
];

/// Operadores que el léxico también puede invocar por nombre.
const OPERATORS: [(&str, &str); 5] = [
    ("entrelaza", "!!"),
    ("fusiona", "!!"),
    ("contradice", "!!"),
    ("entangle", "!!"),
    ("fusion", "!!"),
];

/// Palabras vacías que no generan raíz alguna.
const STOPWORDS: [&str; 22] = [
    "el", "la", "los", "las", "un", "una", "unos", "unas", "de", "del", "que", "y", "o", "con",
    "por", "para", "en", "es", "son", "the", "and", "with",
];

// ─────────────────────────────────────────────────────────────────────────
// Comandos meta e intención
// ─────────────────────────────────────────────────────────────────────────

/// Comando meta del oráculo (prefijo `:`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetaCommand {
    /// Muestra la ayuda.
    Help,
    /// Estado general del runtime.
    Status,
    /// Memoria holográfica.
    Memory,
    /// Diario temporal `Δ⁻¹`.
    Timeline,
    /// Registro cuántico nativo.
    Quantum,
    /// Malla de sincronización.
    Mesh,
    /// Programa Metal-IR.
    Metal,
    /// Certificado ZK.
    Zk,
    /// Rollback manual al último marcador.
    Undo,
    /// Termina la sesión.
    Quit,
    /// Comando desconocido (tolerado).
    Unknown(String),
}

impl MetaCommand {
    /// Interpreta un comando meta. Los acentos se pliegan y lo desconocido se
    /// tolera: nunca hay un error de sintaxis, sólo una respuesta.
    pub fn parse(raw: &str) -> MetaCommand {
        let name: String = raw
            .trim_start_matches(':')
            .trim()
            .chars()
            .map(fold_accent)
            .collect::<String>()
            .to_ascii_lowercase();
        match name.as_str() {
            "help" | "ayuda" | "?" => MetaCommand::Help,
            "status" | "estado" => MetaCommand::Status,
            "mem" | "memory" | "memoria" => MetaCommand::Memory,
            "time" | "timeline" | "tiempo" | "delta" => MetaCommand::Timeline,
            "q" | "quantum" | "cuantica" | "qubits" => MetaCommand::Quantum,
            "mesh" | "malla" => MetaCommand::Mesh,
            "metal" | "ir" | "hardware" => MetaCommand::Metal,
            "zk" | "proof" | "prueba" => MetaCommand::Zk,
            "undo" | "deshacer" | "rollback" => MetaCommand::Undo,
            "quit" | "exit" | "salir" | "q!" => MetaCommand::Quit,
            other => MetaCommand::Unknown(other.to_string()),
        }
    }

    /// Nombre canónico del comando.
    pub fn name(&self) -> &'static str {
        match self {
            MetaCommand::Help => "ayuda",
            MetaCommand::Status => "estado",
            MetaCommand::Memory => "memoria",
            MetaCommand::Timeline => "tiempo",
            MetaCommand::Quantum => "cuántica",
            MetaCommand::Mesh => "malla",
            MetaCommand::Metal => "metal",
            MetaCommand::Zk => "zk",
            MetaCommand::Undo => "deshacer",
            MetaCommand::Quit => "salir",
            MetaCommand::Unknown(_) => "desconocido",
        }
    }
}

/// Intención interpretada de una consulta.
#[derive(Debug, Clone)]
pub enum Intent {
    /// Raíces triconsonánticas listas para compilar.
    Roots(String),
    /// Comando meta.
    Meta(MetaCommand),
    /// Entrada vacía.
    Empty,
}

impl Intent {
    /// Etiqueta legible de la intención.
    pub fn label(&self) -> String {
        match self {
            Intent::Roots(_) => "shoresh".to_string(),
            Intent::Meta(command) => format!("meta:{}", command.name()),
            Intent::Empty => "silencio".to_string(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Turnos e informes
// ─────────────────────────────────────────────────────────────────────────

/// Un turno de conversación con el oráculo.
#[derive(Debug, Clone)]
pub struct OracleTurn {
    /// Consulta original.
    pub input: String,
    /// Intención interpretada.
    pub intent: String,
    /// Programa de raíces compilado.
    pub roots: String,
    /// Respuesta del oráculo.
    pub reply: String,
    /// Eventos ontológicos emitidos.
    pub events: usize,
    /// Duración de la compilación dinámica, en microsegundos.
    pub micros: u128,
    /// Axiomas nacidos por autopoiesis durante el turno.
    pub axioms: usize,
    /// Estado del monitor `Δ⁻¹`.
    pub monitor: String,
}

impl OracleTurn {
    /// Descripción de una línea del turno.
    pub fn describe(&self) -> String {
        format!(
            "⋯ {:<44} ⟶ {:<58} [{} · {} evento(s) · {} µs · axiomas+{}] · Δ⁻¹: {}",
            self.input,
            self.reply,
            self.intent,
            self.events,
            self.micros,
            self.axioms,
            self.monitor
        )
    }
}

/// Informe de una sesión completa con el oráculo.
#[derive(Debug, Clone, Default)]
pub struct OracleReport {
    /// Turnos conversados.
    pub turns: usize,
    /// Eventos ontológicos totales.
    pub events: usize,
    /// Pulsos de rollback `Δ⁻¹` observados.
    pub rollbacks: usize,
    /// Axiomas sintetizados durante la sesión.
    pub synthesized: usize,
    /// Tiempo total de compilación dinámica, en microsegundos.
    pub micros: u128,
    /// Raíces tocadas durante la sesión.
    pub roots: Vec<String>,
}

impl OracleReport {
    /// Descripción compacta de la sesión.
    pub fn label(&self) -> String {
        let unique: Vec<String> = {
            let mut held = self.roots.clone();
            held.sort();
            held.dedup();
            held
        };
        format!(
            "{} turno(s) · {} evento(s) · {} rollback(s) · {} axioma(s) nuevo(s) · {} µs de compilación dinámica · raíces: {}",
            self.turns,
            self.events,
            self.rollbacks,
            self.synthesized,
            self.micros,
            if unique.is_empty() {
                "<ninguna>".to_string()
            } else {
                unique.join(" ")
            }
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Traducción de lengua natural
// ─────────────────────────────────────────────────────────────────────────

/// Pliega un carácter acentuado a su forma ASCII básica.
fn fold_accent(c: char) -> char {
    match c {
        'á' | 'à' | 'ä' | 'â' | 'ã' => 'a',
        'é' | 'è' | 'ë' | 'ê' => 'e',
        'í' | 'ì' | 'ï' | 'î' => 'i',
        'ó' | 'ò' | 'ö' | 'ô' | 'õ' => 'o',
        'ú' | 'ù' | 'ü' | 'û' => 'u',
        'ñ' => 'n',
        other => other,
    }
}

/// Extrae las raíces hebreas presentes en un texto (modo *shoresh* directo).
pub fn hebrew_roots(text: &str) -> Vec<String> {
    Lexer::new(text)
        .tokenize()
        .into_iter()
        .filter_map(|token| match token.kind {
            TokenKind::Root { letters, .. } => Some(letters),
            _ => None,
        })
        .collect()
}

/// Traduce lengua natural a un programa de raíces *Shoresh*.
///
/// Devuelve `(programa, raíces usadas, raíces sintetizadas)`. Los verbos que
/// el léxico no conoce se convierten en **raíces nuevas** por autopoiesis: el
/// oráculo aprende el idioma del desarrollador en vez de rechazarlo.
pub fn natural_to_roots(text: &str) -> (String, Vec<String>, usize) {
    let direct = hebrew_roots(text);
    if !direct.is_empty() {
        let program = direct.iter().map(|root| format!("{} ", root)).collect();
        return (program, direct, 0);
    }

    let mut program = String::new();
    let mut used: Vec<String> = Vec::new();
    let mut synthesized = 0_usize;

    for word in text.split_whitespace() {
        let clean: String = word
            .chars()
            .filter(|c| c.is_alphanumeric())
            .map(fold_accent)
            .collect::<String>()
            .to_lowercase();
        if clean.is_empty() {
            continue;
        }
        if let Some((_, root)) = LEXICON.iter().find(|(term, _)| *term == clean.as_str()) {
            program.push_str(root);
            program.push(' ');
            used.push((*root).to_string());
            continue;
        }
        if let Some((_, operator)) = OPERATORS.iter().find(|(term, _)| *term == clean.as_str()) {
            program.push_str(operator);
            program.push(' ');
            used.push((*operator).to_string());
            continue;
        }
        if STOPWORDS.contains(&clean.as_str()) || clean.chars().count() < 4 {
            continue;
        }
        if synthesized < 3 {
            synthesized += 1;
            let root = crate::ffi_ingest::root_from_name(&clean);
            program.push_str(&root);
            program.push(' ');
            used.push(root);
        }
    }

    // Entrada puramente simbólica (`!!`, `!?`, `*+`): se conserva tal cual para
    // que el lexer la reconozca como operadores del lenguaje.
    if program.trim().is_empty() {
        let symbolic: String = text
            .chars()
            .filter(|c| matches!(c, '!' | '?' | '*' | '+'))
            .collect();
        if !symbolic.is_empty() {
            used.push(symbolic.clone());
            return (symbolic, used, 0);
        }
    }

    (program, used, synthesized)
}

/// Extrae los **turnos** de un manifiesto de texto.
///
/// Un manifiesto es un guion legible por humanos: se descartan las líneas
/// vacías y los comentarios `#` —tanto de línea completa como de cola—, de modo
/// que el documento puede documentarse en cualquier idioma sin que las notas
/// contaminen el programa compilado.
///
/// Devuelve cada línea significativa ya recortada, en el orden del documento.
pub fn manifest_lines(source: &str) -> Vec<String> {
    let mut lines = Vec::new();
    for raw in source.lines() {
        let without_comment = raw.split('#').next().unwrap_or("");
        let line = without_comment.trim();
        if line.is_empty() {
            continue;
        }
        lines.push(line.to_string());
    }
    lines
}

// ─────────────────────────────────────────────────────────────────────────
// El Oráculo
// ─────────────────────────────────────────────────────────────────────────

/// Cuenta los pulsos de rollback `Δ⁻¹` presentes en un tramo del log.
fn count_rollbacks(events: &[ExecutionEvent]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event, ExecutionEvent::Rollback { .. }))
        .count()
}

/// Oráculo REPL: conversa con el runtime paraconsistente.
pub struct Oracle<'a> {
    runtime: &'a mut BaraRuntime,
    turns: Vec<OracleTurn>,
    /// Marcas temporales: `(punto de rebobinado, altura de la pila)`.
    markers: Vec<(Marker, usize)>,
    interactive: bool,
}

impl<'a> Oracle<'a> {
    /// Enlaza un oráculo a un runtime vivo.
    pub fn new(runtime: &'a mut BaraRuntime) -> Self {
        Oracle {
            runtime,
            turns: Vec::new(),
            markers: Vec::new(),
            interactive: false,
        }
    }

    /// Marca la sesión como interactiva (leída de un terminal real).
    pub fn mark_interactive(&mut self, value: bool) {
        self.interactive = value;
    }

    /// ¿La sesión es interactiva?
    pub fn interactive_session(&self) -> bool {
        self.interactive
    }

    /// Turnos conversados hasta ahora.
    pub fn turns(&self) -> &[OracleTurn] {
        &self.turns
    }

    /// Interpreta una consulta y decide si es un *shoresh*, un comando meta o
    /// silencio.
    pub fn interpret(&self, input: &str) -> Intent {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Intent::Empty;
        }
        if trimmed.starts_with(':') {
            return Intent::Meta(MetaCommand::parse(trimmed));
        }
        let (program, _, _) = natural_to_roots(trimmed);
        if program.trim().is_empty() {
            Intent::Empty
        } else {
            Intent::Roots(program)
        }
    }

    /// Conversa un turno completo: interpreta, compila al instante y
    /// monitoriza el rebobinado temporal.
    pub fn converse(&mut self, input: &str) -> &OracleTurn {
        let intent = self.interpret(input);
        match &intent {
            Intent::Empty => {
                self.turns.push(OracleTurn {
                    input: input.trim().to_string(),
                    intent: intent.label(),
                    roots: String::new(),
                    reply: "⟅ silencio fértil: nada que compilar ⟆".to_string(),
                    events: 0,
                    micros: 0,
                    axioms: 0,
                    monitor: self.monitor(),
                });
            }
            Intent::Meta(command) => {
                let reply = self.handle_meta(command);
                self.turns.push(OracleTurn {
                    input: input.trim().to_string(),
                    intent: intent.label(),
                    roots: String::new(),
                    reply,
                    events: 0,
                    micros: 0,
                    axioms: 0,
                    monitor: self.monitor(),
                });
            }
            Intent::Roots(program) => {
                let program = program.clone();
                // Marca temporal previa: `:deshacer` rebobina exactamente aquí.
                let marker = self.runtime.timeline.mark();
                let stack_before = self.runtime.stack.len();
                let axioms_before = self.runtime.mutator.generation();
                let events_before = self.runtime.log().len();

                let start = Instant::now();
                let tokens = Lexer::new(&program).tokenize();
                self.runtime.execute(&tokens);
                let micros = start.elapsed().as_micros();

                // Todo estado que sobrevive al turno se registra como delta
                // reversible: cada turno del oráculo es rebobinable con `Δ⁻¹`.
                let survivors: Vec<QuantumState> = self
                    .runtime
                    .stack
                    .get(stack_before..)
                    .unwrap_or(&[])
                    .to_vec();
                let reversible = survivors.len();
                for state in survivors {
                    self.runtime.timeline.push(state);
                }

                let events = self.runtime.log().len().saturating_sub(events_before);
                let axioms = self
                    .runtime
                    .mutator
                    .generation()
                    .saturating_sub(axioms_before);
                let window = self
                    .runtime
                    .log()
                    .get(events_before..)
                    .unwrap_or(&[])
                    .to_vec();
                let rollbacks = count_rollbacks(&window);
                let top = self
                    .runtime
                    .peek()
                    .map(|state| state.label())
                    .unwrap_or_else(|| "<pila vacía>".to_string());

                let reply = if rollbacks > 0 {
                    format!(
                        "{} evento(s) · {} Δ reversibles · Δ⁻¹ interceptó {} paradoja(s) · cima={}",
                        events, reversible, rollbacks, top
                    )
                } else {
                    format!(
                        "{} evento(s) · {} Δ reversibles · cima={}",
                        events, reversible, top
                    )
                };

                self.markers.push((marker, stack_before));
                self.runtime.note(ExecutionEvent::Oracle {
                    input: input.trim().to_string(),
                    roots: program.trim().to_string(),
                    reply: format!("{} evento(s) · {} µs", events, micros),
                });
                self.turns.push(OracleTurn {
                    input: input.trim().to_string(),
                    intent: intent.label(),
                    roots: program.trim().to_string(),
                    reply,
                    events,
                    micros,
                    axioms,
                    monitor: self.monitor(),
                });
            }
        }
        self.turns
            .last()
            .expect("el turno acaba de ser registrado")
    }

    /// Estado del monitor temporal `Δ⁻¹`.
    fn monitor(&self) -> String {
        let deltas = self.runtime.timeline.deltas();
        let live = deltas.iter().filter(|delta| !delta.reverted).count();
        let reverted = deltas.len().saturating_sub(live);
        format!(
            "{} Δ viv@(s) · {} revertid@(s) · {} pulso(s) · pila={}",
            live,
            reverted,
            count_rollbacks(self.runtime.log()),
            self.runtime.stack.len()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Comandos meta
// ─────────────────────────────────────────────────────────────────────────

/// Texto de ayuda del oráculo.
const HELP: &str = "\
comandos del oráculo:
      :ayuda            esta ayuda
      :estado           estado general del runtime
      :memoria          nodos de la memoria holográfica
      :tiempo           diario temporal Δ⁻¹ (deltas vivos/revertidos)
      :cuántica         registro de qubits nativos y entrelazamientos
      :malla            nodos de la malla y hológrafo global
      :metal            programa Metal-IR y layout de registros
      :zk               certificado ZK del AST
      :deshacer         rollback Δ⁻¹ al último marcador
      :salir            cerrar la sesión
   y en lengua natural o en raíces: «crea un mundo con luz», «ברא שמר עבד», «entrelaza alef con bet»…";

impl<'a> Oracle<'a> {
    /// Responde a un comando meta.
    fn handle_meta(&mut self, command: &MetaCommand) -> String {
        match command {
            MetaCommand::Help => HELP.to_string(),
            MetaCommand::Status => format!(
                "pila={} · memoria={} nodo(s) (entropía={:.3}) · regiones={} ({} B) · axiomas={} gen#{} · qubits={} · malla={} peer(s) · timeline={} Δ",
                self.runtime.stack.len(),
                self.runtime.memory.len(),
                self.runtime.memory.entropy(),
                self.runtime.regions.len(),
                self.runtime.regions.total_bytes(),
                self.runtime.mutator.axioms().count(),
                self.runtime.mutator.generation(),
                self.runtime.qubits.len(),
                self.runtime.mesh.len(),
                self.runtime.timeline.deltas().len()
            ),
            MetaCommand::Memory => {
                let mut out = format!(
                    "memoria holográfica: {} nodo(s) · escrituras={} · entropía={:.3}",
                    self.runtime.memory.len(),
                    self.runtime.memory.writes(),
                    self.runtime.memory.entropy()
                );
                for node in self.runtime.memory.nodes() {
                    out.push_str(&format!(
                        "\n      ❖ «{}» key=0x{:016X} afinidad={:.4} {}",
                        node.label,
                        node.key,
                        node.affinity,
                        node.state.label()
                    ));
                }
                out
            }
            MetaCommand::Timeline => {
                let deltas = self.runtime.timeline.deltas();
                let mut out = format!("diario temporal: {} delta(s)", deltas.len());
                for delta in deltas {
                    out.push_str(&format!(
                        "\n      ⧗ #{:<2} {} · {} · {}",
                        delta.id,
                        delta.label,
                        delta.inv_label(),
                        if delta.reverted { "[Δ⁻¹]" } else { "[vivo]" }
                    ));
                }
                out
            }
            MetaCommand::Quantum => {
                let qubits = &self.runtime.qubits;
                let mut out = format!(
                    "registro cuántico: {} qubit(s) · {} enlace(s) · {} colapso(s)",
                    qubits.len(),
                    qubits.bindings().len(),
                    qubits.collapses()
                );
                for name in qubits.names() {
                    if let Some(qubit) = qubits.get(name) {
                        out.push_str(&format!(
                            "\n      ⌬ {} · valencia={}",
                            qubit.describe(),
                            qubit.valence().label()
                        ));
                    }
                }
                for binding in qubits.bindings() {
                    out.push_str(&format!("\n      ⧉ {}", binding.label()));
                }
                out
            }
            MetaCommand::Mesh => {
                let mesh = &self.runtime.mesh;
                format!(
                    "malla: {} peer(s) · época={} · entradas={} · hológrafo=0x{:016X} · convergido={} · deriva={:.4} · wire={} B",
                    mesh.len(),
                    mesh.epoch(),
                    mesh.entries(),
                    mesh.hologram(),
                    mesh.converged(),
                    mesh.drift(),
                    mesh.wire_bytes()
                )
            }
            MetaCommand::Metal => match &self.runtime.metal {
                Some(program) => format!(
                    "Metal-IR «{}» · vía={} · {} instrucción(es) · {} palabra(s) · {} · {}",
                    program.label,
                    program.device.label(),
                    program.len(),
                    program.words().len(),
                    program.signature(),
                    program.bypass.label()
                ),
                None => "sin programa de metal compilado todavía".to_string(),
            },
            MetaCommand::Zk => match &self.runtime.certificate {
                Some(certificate) => format!(
                    "certificado ZK «{}» · {} invariante(s) · verificado={}",
                    certificate.statement.label,
                    certificate.statement.n_constraints,
                    certificate.result.verified
                ),
                None => "sin certificado ZK emitido todavía".to_string(),
            },
            MetaCommand::Undo => self.undo(),
            MetaCommand::Quit => "sesión cerrada: el lenguaje respira, בָּרָא.".to_string(),
            MetaCommand::Unknown(name) => format!(
                "comando «:{}» desconocido (tolerado) · escribe :ayuda para la lista",
                name
            ),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Rollback manual y bucle de sesión
// ─────────────────────────────────────────────────────────────────────────

impl<'a> Oracle<'a> {
    /// Rollback manual `Δ⁻¹` al último marcador capturado.
    ///
    /// Revierte los deltas registrados desde la marca y recorta la pila del
    /// runtime a la altura que tenía entonces: el turno desaparece por completo
    /// sin dejar rastro inconsistente.
    fn undo(&mut self) -> String {
        match self.markers.pop() {
            Some((marker, stack_before)) => {
                let report = self.runtime.timeline.rollback_to(marker);
                self.runtime.stack.truncate(stack_before);
                self.runtime.note(ExecutionEvent::Rollback {
                    reverted: report.reverted,
                    micros: report.micros,
                    paradox: format!("oráculo: Δ⁻¹ manual al marcador #{}", marker.0),
                });
                format!(
                    "Δ⁻¹ rebobinó {} delta(s) en {} µs · pila restaurada a {}",
                    report.reverted,
                    report.micros,
                    self.runtime.stack.len()
                )
            }
            None => "no hay marcas activas: nada que rebobinar".to_string(),
        }
    }

    /// Informe acumulado de la sesión.
    pub fn report(&self) -> OracleReport {
        let mut report = OracleReport::default();
        for turn in &self.turns {
            report.turns += 1;
            report.events += turn.events;
            report.synthesized += turn.axioms;
            report.micros += turn.micros;
            for root in turn.roots.split_whitespace() {
                report.roots.push(root.to_string());
            }
        }
        report.rollbacks = count_rollbacks(self.runtime.log());
        report
    }

    /// Conversa un guion completo (modo determinista, sin terminal).
    pub fn run_script(&mut self, script: &[&str]) -> OracleReport {
        for input in script {
            let turn = self.converse(input).clone();
            println!("   ⋯ ברא› {}", turn.input);
            println!("      ⟶ {}", turn.reply);
            if !turn.roots.is_empty() {
                println!("      ⇢ shoresh compilado: {}", turn.roots);
            }
            println!(
                "      · intención={} · {} evento(s) · {} µs · axiomas+{} · Δ⁻¹: {}",
                turn.intent, turn.events, turn.micros, turn.axioms, turn.monitor
            );
            if matches!(self.interpret(&turn.input), Intent::Meta(MetaCommand::Quit)) {
                break;
            }
        }
        self.report()
    }

    /// Conversa un **manifiesto** completo leyendo sus turnos del texto.
    ///
    /// Los comentarios `#` y las líneas vacías se descartan (véase
    /// [`manifest_lines`]); cada turno restante se conversa en orden, con la
    /// misma salida que [`Oracle::run_script`]. Un manifiesto vacío no es un
    /// error: se tolera y se devuelve el informe acumulado.
    pub fn run_manifest(&mut self, source: &str) -> OracleReport {
        let lines = manifest_lines(source);
        if lines.is_empty() {
            println!("   (manifiesto vacío: nada que conversar)");
            return self.report();
        }
        let script: Vec<&str> = lines.iter().map(|line| line.as_str()).collect();
        println!("   ── manifiesto: {} turno(s) ──", script.len());
        self.run_script(&script)
    }

    /// Bucle interactivo real: lee de la entrada estándar hasta `:salir` o el
    /// fin de la entrada. Nunca falla: una lectura interrumpida cierra la
    /// sesión con elegancia.
    pub fn run(&mut self) -> OracleReport {
        self.mark_interactive(true);
        println!("   ── oráculo en vivo · escribe :ayuda o conversa en lengua natural ──");
        loop {
            print!("   ⋯ ברא› ");
            let _ = io::stdout().flush();

            let mut line = String::new();
            match io::stdin().read_line(&mut line) {
                Ok(0) => {
                    println!("      (fin de la entrada: el oráculo se disuelve)");
                    break;
                }
                Ok(_) => {}
                Err(_) => {
                    println!("      (lectura interrumpida: el oráculo tolera y se retira)");
                    break;
                }
            }

            let turn = self.converse(&line).clone();
            println!("      ⟶ {}", turn.reply);
            if !turn.roots.is_empty() {
                println!("      ⇢ shoresh: {}", turn.roots);
            }
            println!(
                "      · {} evento(s) · {} µs · axiomas+{} · Δ⁻¹: {}",
                turn.events, turn.micros, turn.axioms, turn.monitor
            );
            if matches!(self.interpret(&turn.input), Intent::Meta(MetaCommand::Quit)) {
                break;
            }
        }
        self.report()
    }
}

/// ¿Hay un terminal interactivo al otro lado de la entrada estándar?
pub fn interactive_available() -> bool {
    io::stdin().is_terminal()
}
