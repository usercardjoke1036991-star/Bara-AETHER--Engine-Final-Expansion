//! # Puente de sólo lectura kernel → IDE — Bara / AETHER‑Ω (FASE 3)
//!
//! El IDE necesita **ver** lo que el núcleo decidió sin poder tocarlo. Este
//! módulo es exactamente eso: un puente de **lectura** que proyecta el estado de
//! los tres subsistemas vivos —inmunidad adaptativa ([`crate::immune`]),
//! pasarela de burbujas ([`crate::immunity_gateway`]) y núcleo
//! ([`crate::runtime`])— en secciones JSON deterministas gobernadas por un
//! **contrato verificable** ([`Manifest`]).
//!
//! ## Por qué un contrato y no un `json()` suelto
//! Cada subsistema ya sabe proyectarse ([`ImmuneSystem::json`], …), pero un panel
//! del IDE no puede adivinar la forma del documento ni confiar en que la siga
//! teniendo. Aquí la forma **es un dato**: [`Manifest::canon`] declara las
//! secciones, su orden, su origen y su cota de bytes, y su huella (`sha256`) sólo
//! depende de ese contrato, nunca del estado leído. Un panel guarda esa huella
//! una vez y detecta cualquier deriva de esquema sin tocar el núcleo.
//!
//! ## Secciones canónicas (orden fijo)
//! | # | Sección | Origen leído | Contenido |
//! |---|---|---|---|
//! | 0 | `identidad` | ninguno (contrato puro) | esquema, versión, dominio y manifiesto |
//! | 1 | `inmunidad` | `&ImmuneSystem` | censo, contadores, repertorio y huellas |
//! | 2 | `pasarela` | `&Gateway` | puerta, censo de veredictos y **rabo** de burbujas |
//! | 3 | `nucleo` | `&BaraRuntime` | pila, axiomas, memoria, malla, certificado y log |
//!
//! ## Invariantes del módulo
//! 1. **Cero `unsafe`** (`#![forbid(unsafe_code)]`).
//! 2. **Sólo lectura** — toda función toma préstamos inmutables
//!    (`&ImmuneSystem`, `&Gateway`, `&BaraRuntime`). El compilador, no la
//!    disciplina, garantiza que el puente no puede mutar la soberanía: en este
//!    módulo no existe ninguna función que reciba `&mut`.
//! 3. **Totalidad (axioma A1)** — sin `unwrap`, `expect` ni `panic`: cada
//!    violación del contrato se devuelve como [`BridgeError`] tipado y mostrable.
//! 4. **Determinismo** — las huellas derivan sólo de `sha256` y del contenido
//!    leído. Ninguna marca de reloj entra en la instantánea: ni
//!    [`TemporalEngine::now_micros`](crate::temporal_rollback::TemporalEngine::now_micros)
//!    ni la descripción de un evento [`ExecutionEvent::Rollback`] (que lleva
//!    `micros`). Del log se proyecta el **nombre estable** de la variante.
//! 5. **Acotado** — ninguna sección supera [`MAX_SECTION_BYTES`] y el listado de
//!    burbujas es un rabo acotado ([`MAX_BUBBLES`]): el documento tiene un techo
//!    conocido y el panel del IDE nunca se ahoga.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

use std::fmt;

use crate::ast_dna::short_hex;
use crate::crypto_native::sha256;
use crate::immune::ImmuneSystem;
use crate::immunity_gateway::{Bubble, Gateway};
use crate::runtime::{BaraRuntime, ExecutionEvent, QuantumState};

// ─────────────────────────────────────────────────────────────────────────
// Límites del puente
// ─────────────────────────────────────────────────────────────────────────

/// Dominio de hash del puente (separa estas huellas de las del núcleo).
pub const BRIDGE_DOMAIN: &[u8] = b"bara:aether-omega:puente:v1";

/// Esquema del documento que consume el IDE.
pub const BRIDGE_SCHEMA: &str = "aether-omega/puente/1";

/// Versión del kernel que emite la instantánea.
pub const BRIDGE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Techo de secciones que admite una instantánea.
pub const MAX_SECTIONS: usize = 8;

/// Cota de bytes del cuerpo de una sección (64 KiB, igual que [`crate::immunity_gateway::MAX_PAYLOAD`]).
pub const MAX_SECTION_BYTES: usize = 64 * 1024;

/// Burbujas que se muestran en el rabo de la sección `pasarela`.
///
/// Es una **vista de cola**, no el registro completo: el registro íntegro sigue
/// disponible para el kernel en [`Gateway::bubbles`].
pub const MAX_BUBBLES: usize = 16;

// ─────────────────────────────────────────────────────────────────────────
// Secciones del puente
// ─────────────────────────────────────────────────────────────────────────

/// Sección canónica de la instantánea.
///
/// El orden de declaración **es** el orden canónico del documento: la variante
/// menor precede siempre a la mayor, y [`SectionKind::index`] lo hace explícito.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SectionKind {
    /// Contrato del puente: esquema, versión y manifiesto.
    Identidad,
    /// Inmunidad adaptativa (FASE 2).
    Inmunidad,
    /// Pasarela de burbujas.
    Pasarela,
    /// Núcleo: pila, memoria, malla y log.
    Nucleo,
}

impl SectionKind {
    /// Las cuatro secciones, **en orden canónico**.
    pub const ALL: [SectionKind; 4] = [
        SectionKind::Identidad,
        SectionKind::Inmunidad,
        SectionKind::Pasarela,
        SectionKind::Nucleo,
    ];

    /// Nombre de la sección en el documento.
    pub fn name(self) -> &'static str {
        match self {
            SectionKind::Identidad => "identidad",
            SectionKind::Inmunidad => "inmunidad",
            SectionKind::Pasarela => "pasarela",
            SectionKind::Nucleo => "nucleo",
        }
    }

    /// Glifo del panel (una letra por sección).
    pub fn glyph(self) -> &'static str {
        match self {
            SectionKind::Identidad => "∘",
            SectionKind::Inmunidad => "⛨",
            SectionKind::Pasarela => "⇥",
            SectionKind::Nucleo => "◉",
        }
    }

    /// Posición canónica (0–3).
    pub fn index(self) -> usize {
        match self {
            SectionKind::Identidad => 0,
            SectionKind::Inmunidad => 1,
            SectionKind::Pasarela => 2,
            SectionKind::Nucleo => 3,
        }
    }

    /// Sección a partir de su nombre: inverso exacto de [`Self::name`].
    pub fn from_name(name: &str) -> Option<SectionKind> {
        SectionKind::ALL
            .iter()
            .copied()
            .find(|kind| kind.name() == name)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Errores tipados del puente
// ─────────────────────────────────────────────────────────────────────────

/// Error tipado del puente: todo rechazo tiene un motivo mostrable.
///
/// El IDE recibe un motivo, nunca un documento a medias: o la instantánea
/// respeta el contrato entero, o no se entrega.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeError {
    /// El cuerpo de la sección está vacío.
    EmptyBody {
        /// Sección rechazada.
        kind: SectionKind,
    },
    /// El cuerpo no es un objeto JSON (`{…}`).
    MalformedBody {
        /// Sección rechazada.
        kind: SectionKind,
    },
    /// El cuerpo excede la cota de su sección.
    TooLarge {
        /// Sección rechazada.
        kind: SectionKind,
        /// Bytes medidos.
        bytes: usize,
        /// Cota aplicada.
        limit: usize,
    },
    /// La sección ya estaba en la instantánea.
    DuplicatedSection {
        /// Sección repetida.
        kind: SectionKind,
    },
    /// La sección llegó fuera del orden canónico.
    OutOfOrder {
        /// Sección ya presente que debía precederla.
        after: SectionKind,
        /// Sección que llegó tarde.
        found: SectionKind,
    },
    /// La instantánea excede el techo de secciones.
    TooManySections {
        /// Secciones pretendidas.
        sections: usize,
        /// Techo de secciones.
        limit: usize,
    },
    /// El manifiesto no declara esa sección.
    UnknownSection {
        /// Nombre solicitado.
        name: String,
    },
    /// El manifiesto declara una cota nula: no se podría leer nada.
    EmptyLimit {
        /// Sección con cota nula.
        kind: SectionKind,
    },
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BridgeError::EmptyBody { kind } => {
                write!(f, "la sección «{}» no tiene cuerpo", kind.name())
            }
            BridgeError::MalformedBody { kind } => write!(
                f,
                "el cuerpo de «{}» no es un objeto JSON",
                kind.name()
            ),
            BridgeError::TooLarge { kind, bytes, limit } => write!(
                f,
                "la sección «{}» mide {bytes} B y su cota es {limit} B",
                kind.name()
            ),
            BridgeError::DuplicatedSection { kind } => {
                write!(f, "la sección «{}» está repetida", kind.name())
            }
            BridgeError::OutOfOrder { after, found } => write!(
                f,
                "«{}» no puede seguir a «{}»: el orden canónico es identidad → inmunidad → pasarela → nucleo",
                found.name(),
                after.name()
            ),
            BridgeError::TooManySections { sections, limit } => {
                write!(f, "la instantánea pide {sections} secciones y el techo es {limit}")
            }
            BridgeError::UnknownSection { name } => {
                write!(f, "el manifiesto no declara la sección «{name}»")
            }
            BridgeError::EmptyLimit { kind } => {
                write!(f, "la sección «{}» tiene cota nula", kind.name())
            }
        }
    }
}

impl std::error::Error for BridgeError {}

// ─────────────────────────────────────────────────────────────────────────
// Utilidades JSON (mismas reglas que el núcleo: claves fijas, sin serde)
// ─────────────────────────────────────────────────────────────────────────

/// Escapa una cadena para JSON (comillas, barra inversa y controles).
fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ if (character as u32) < 0x20 => out.push('?'),
            _ => out.push(character),
        }
    }
    out
}

/// Booleano → literal JSON.
fn json_bool(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

/// Número en coma flotante con formato JSON estable (seis decimales fijos).
fn json_f64(value: f64) -> String {
    if !value.is_finite() {
        return "0.000000".to_string();
    }
    format!("{value:.6}")
}

/// Etiqueta opcional → JSON (`null` si ausente).
fn json_opt_str(value: Option<&str>) -> String {
    match value {
        Some(text) => format!("\"{}\"", json_escape(text)),
        None => "null".to_string(),
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Sección
// ─────────────────────────────────────────────────────────────────────────

/// Sección ya validada: un cuerpo JSON acotado y su huella.
///
/// Los campos son privados a propósito: no se puede construir una sección que
/// viole el contrato (vacía, no-JSON o por encima de su cota) sin pasar por
/// [`Section::new`], así que una `Section` existente **es** una sección válida.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    kind: SectionKind,
    body: String,
}

impl Section {
    /// Construye una sección validando el contrato: cuerpo no vacío, objeto
    /// JSON (`{…}`) y dentro de [`MAX_SECTION_BYTES`].
    pub fn new(kind: SectionKind, body: &str) -> Result<Section, BridgeError> {
        let trimmed = body.trim();
        if trimmed.is_empty() {
            return Err(BridgeError::EmptyBody { kind });
        }
        if !(trimmed.starts_with('{') && trimmed.ends_with('}')) {
            return Err(BridgeError::MalformedBody { kind });
        }
        if body.len() > MAX_SECTION_BYTES {
            return Err(BridgeError::TooLarge {
                kind,
                bytes: body.len(),
                limit: MAX_SECTION_BYTES,
            });
        }
        Ok(Section {
            kind,
            body: trimmed.to_string(),
        })
    }

    /// Sección a la que pertenece el cuerpo.
    pub fn kind(&self) -> SectionKind {
        self.kind
    }

    /// Nombre de la sección.
    pub fn name(&self) -> &'static str {
        self.kind.name()
    }

    /// Cuerpo JSON (siempre un objeto).
    pub fn body(&self) -> &str {
        &self.body
    }

    /// Tamaño del cuerpo en bytes.
    pub fn bytes(&self) -> usize {
        self.body.len()
    }

    /// Huella `sha256` del cuerpo **ligada a su nombre**: el mismo contenido en
    /// dos secciones distintas nunca comparte huella.
    pub fn digest(&self) -> [u8; 32] {
        let mut statement = Vec::with_capacity(BRIDGE_DOMAIN.len() + 48 + self.body.len());
        statement.extend_from_slice(BRIDGE_DOMAIN);
        statement.extend_from_slice(b":seccion:");
        statement.extend_from_slice(self.kind.name().as_bytes());
        statement.push(0x1f);
        statement.extend_from_slice(self.body.as_bytes());
        sha256(&statement)
    }

    /// Huella en hexadecimal (informes y panel).
    pub fn fingerprint(&self) -> String {
        short_hex(&self.digest())
    }

    /// Acta de una línea.
    pub fn label_text(&self) -> String {
        format!(
            "{} {} · {} B · huella {}",
            self.kind.glyph(),
            self.kind.name(),
            self.bytes(),
            self.fingerprint()
        )
    }

    /// JSON de la sección: metadatos + cuerpo **como valor** (sin recomillarlo).
    pub fn json(&self) -> String {
        let mut out = String::with_capacity(self.body.len() + 160);
        out.push_str("{\"seccion\":\"");
        out.push_str(self.kind.name());
        out.push_str("\",\"glifo\":\"");
        out.push_str(self.kind.glyph());
        out.push_str("\",\"bytes\":");
        out.push_str(&self.bytes().to_string());
        out.push_str(",\"huella\":\"");
        out.push_str(&self.fingerprint());
        out.push_str("\",\"cuerpo\":");
        out.push_str(&self.body);
        out.push('}');
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Manifiesto: el contrato que carga el IDE
// ─────────────────────────────────────────────────────────────────────────

/// Declaración de una sección dentro del manifiesto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionSpec {
    /// Sección declarada.
    pub kind: SectionKind,
    /// Cota de bytes del cuerpo.
    pub limit: usize,
    /// Origen leído (documental: de dónde sale el dato).
    pub source: &'static str,
}

/// Manifiesto del puente: **el contrato** que un panel del IDE carga una vez.
///
/// Su huella sólo depende del esquema, del orden de las secciones, de sus cotas
/// y de sus orígenes: es estable aunque el kernel cambie de estado. Un panel
/// compara esa huella al conectar y sabe de inmediato si el documento que va a
/// leer sigue siendo el que espera.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    sections: Vec<SectionSpec>,
}

impl Manifest {
    /// Manifiesto canónico: las cuatro secciones en orden, con su origen.
    pub fn canon() -> Manifest {
        Manifest {
            sections: vec![
                SectionSpec {
                    kind: SectionKind::Identidad,
                    limit: MAX_SECTION_BYTES,
                    source: "contrato",
                },
                SectionSpec {
                    kind: SectionKind::Inmunidad,
                    limit: MAX_SECTION_BYTES,
                    source: "immune::ImmuneSystem",
                },
                SectionSpec {
                    kind: SectionKind::Pasarela,
                    limit: MAX_SECTION_BYTES,
                    source: "immunity_gateway::Gateway",
                },
                SectionSpec {
                    kind: SectionKind::Nucleo,
                    limit: MAX_SECTION_BYTES,
                    source: "runtime::BaraRuntime",
                },
            ],
        }
    }

    /// Manifiesto a medida, validado: orden canónico, sin repeticiones, cotas
    /// positivas y dentro del techo de secciones.
    pub fn from_specs(specs: &[SectionSpec]) -> Result<Manifest, BridgeError> {
        if specs.len() > MAX_SECTIONS {
            return Err(BridgeError::TooManySections {
                sections: specs.len(),
                limit: MAX_SECTIONS,
            });
        }
        let mut previous: Option<SectionKind> = None;
        for spec in specs {
            if spec.limit == 0 {
                return Err(BridgeError::EmptyLimit { kind: spec.kind });
            }
            if let Some(last) = previous {
                if spec.kind == last {
                    return Err(BridgeError::DuplicatedSection { kind: spec.kind });
                }
                if spec.kind < last {
                    return Err(BridgeError::OutOfOrder {
                        after: last,
                        found: spec.kind,
                    });
                }
            }
            previous = Some(spec.kind);
        }
        Ok(Manifest {
            sections: specs.to_vec(),
        })
    }

    /// Secciones declaradas, en orden canónico.
    pub fn sections(&self) -> &[SectionSpec] {
        &self.sections
    }

    /// Número de secciones declaradas.
    pub fn len(&self) -> usize {
        self.sections.len()
    }

    /// ¿Manifiesto sin secciones?
    pub fn is_empty(&self) -> bool {
        self.sections.is_empty()
    }

    /// ¿Declara esta sección?
    pub fn contains(&self, kind: SectionKind) -> bool {
        self.spec(kind).is_some()
    }

    /// Declaración de una sección.
    pub fn spec(&self, kind: SectionKind) -> Option<&SectionSpec> {
        self.sections.iter().find(|spec| spec.kind == kind)
    }

    /// Cota de bytes declarada para una sección.
    pub fn limit(&self, kind: SectionKind) -> Option<usize> {
        self.spec(kind).map(|spec| spec.limit)
    }

    /// Origen declarado para una sección.
    pub fn source(&self, kind: SectionKind) -> Option<&'static str> {
        self.spec(kind).map(|spec| spec.source)
    }

    /// Huella del contrato (`sha256` del esquema y de las declaraciones).
    ///
    /// No depende de ningún estado leído: es la misma antes y después de una
    /// captura, y con el mismo esquema sobre cualquier kernel.
    pub fn digest(&self) -> [u8; 32] {
        let mut statement = Vec::with_capacity(BRIDGE_DOMAIN.len() + 256);
        statement.extend_from_slice(BRIDGE_DOMAIN);
        statement.extend_from_slice(b":manifiesto:");
        statement.extend_from_slice(BRIDGE_SCHEMA.as_bytes());
        for spec in &self.sections {
            statement.push(0x1f);
            statement.extend_from_slice(spec.kind.name().as_bytes());
            statement.extend_from_slice(&(spec.limit as u64).to_le_bytes());
            statement.extend_from_slice(spec.source.as_bytes());
        }
        sha256(&statement)
    }

    /// Huella del contrato en hexadecimal.
    pub fn fingerprint(&self) -> String {
        short_hex(&self.digest())
    }

    /// ¿La instantánea respeta este contrato? (secciones declaradas y cotas).
    pub fn conforms(&self, snapshot: &Snapshot) -> Result<(), BridgeError> {
        for section in snapshot.sections() {
            let limit = match self.limit(section.kind()) {
                Some(limit) => limit,
                None => {
                    return Err(BridgeError::UnknownSection {
                        name: section.name().to_string(),
                    })
                }
            };
            if section.bytes() > limit {
                return Err(BridgeError::TooLarge {
                    kind: section.kind(),
                    bytes: section.bytes(),
                    limit,
                });
            }
        }
        Ok(())
    }

    /// Acta de una línea.
    pub fn label_text(&self) -> String {
        let names: Vec<&str> = self.sections.iter().map(|spec| spec.kind.name()).collect();
        let ceiling = self
            .sections
            .iter()
            .map(|spec| spec.limit)
            .max()
            .unwrap_or(0);
        format!(
            "manifiesto ⟨{}⟩ · esquema {} · {} sección(es) [{}] · cota {} B",
            self.fingerprint(),
            BRIDGE_SCHEMA,
            self.len(),
            names.join(" → "),
            ceiling
        )
    }

    /// JSON del contrato: lo primero que lee un panel del IDE.
    pub fn json(&self) -> String {
        let mut out = String::with_capacity(224 + 128 * self.sections.len());
        out.push_str("{\"esquema\":\"");
        out.push_str(BRIDGE_SCHEMA);
        out.push_str("\",\"version\":\"");
        out.push_str(BRIDGE_VERSION);
        out.push_str("\",\"dominio\":\"bara:aether-omega:puente:v1\",\"huella\":\"");
        out.push_str(&self.fingerprint());
        out.push_str("\",\"cota_secciones\":");
        out.push_str(&MAX_SECTIONS.to_string());
        out.push_str(",\"secciones\":[");
        for (index, spec) in self.sections.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str("{\"nombre\":\"");
            out.push_str(spec.kind.name());
            out.push_str("\",\"glifo\":\"");
            out.push_str(spec.kind.glyph());
            out.push_str("\",\"orden\":");
            out.push_str(&spec.kind.index().to_string());
            out.push_str(",\"cota_bytes\":");
            out.push_str(&spec.limit.to_string());
            out.push_str(",\"origen\":\"");
            out.push_str(&json_escape(spec.source));
            out.push_str("\"}");
        }
        out.push_str("]}");
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Instantánea
// ─────────────────────────────────────────────────────────────────────────

/// Instantánea del kernel para el IDE: secciones ya validadas y su huella.
///
/// Una instantánea **completa** contiene las cuatro secciones canónicas. Se
/// puede componer a mano (sección a sección, para paneles parciales) o capturar
/// de golpe con [`Snapshot::capture`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Snapshot {
    sections: Vec<Section>,
}

impl Snapshot {
    /// Instantánea vacía.
    pub fn new() -> Snapshot {
        Snapshot {
            sections: Vec::new(),
        }
    }

    /// Añade una sección respetando techo, unicidad y orden canónico.
    pub fn push(&mut self, section: Section) -> Result<(), BridgeError> {
        if self.sections.len() >= MAX_SECTIONS {
            return Err(BridgeError::TooManySections {
                sections: self.sections.len() + 1,
                limit: MAX_SECTIONS,
            });
        }
        if let Some(last) = self.sections.last() {
            if section.kind == last.kind {
                return Err(BridgeError::DuplicatedSection { kind: section.kind });
            }
            if section.kind < last.kind {
                return Err(BridgeError::OutOfOrder {
                    after: last.kind,
                    found: section.kind,
                });
            }
        }
        self.sections.push(section);
        Ok(())
    }

    /// Lee los tres subsistemas vivos y compone la instantánea canónica.
    ///
    /// Sólo recibe préstamos inmutables: el puente no puede mutar la soberanía
    /// del núcleo ni por descuido.
    pub fn capture(
        immune: &ImmuneSystem,
        gateway: &Gateway,
        core: &BaraRuntime,
    ) -> Result<Snapshot, BridgeError> {
        let mut snapshot = Snapshot::new();
        snapshot.push(section_identity()?)?;
        snapshot.push(section_immunity(immune)?)?;
        snapshot.push(section_gateway(gateway)?)?;
        snapshot.push(section_kernel(core)?)?;
        Ok(snapshot)
    }

    /// Secciones capturadas, en orden canónico.
    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    /// Sección por tipo.
    pub fn section(&self, kind: SectionKind) -> Option<&Section> {
        self.sections.iter().find(|section| section.kind == kind)
    }

    /// Cuerpo de una sección (lo que el panel pinta).
    pub fn body(&self, kind: SectionKind) -> Option<&str> {
        self.section(kind).map(Section::body)
    }

    /// Número de secciones capturadas.
    pub fn len(&self) -> usize {
        self.sections.len()
    }

    /// ¿Instantánea sin secciones?
    pub fn is_empty(&self) -> bool {
        self.sections.is_empty()
    }

    /// Bytes totales de los cuerpos.
    pub fn bytes(&self) -> usize {
        self.sections.iter().map(Section::bytes).sum()
    }

    /// ¿Contiene esta sección?
    pub fn contains(&self, kind: SectionKind) -> bool {
        self.section(kind).is_some()
    }

    /// Secciones canónicas ausentes (vacío ⇒ instantánea completa).
    pub fn missing(&self) -> Vec<SectionKind> {
        SectionKind::ALL
            .iter()
            .copied()
            .filter(|kind| !self.contains(*kind))
            .collect()
    }

    /// ¿Están las cuatro secciones canónicas?
    pub fn is_complete(&self) -> bool {
        self.missing().is_empty()
    }

    /// ¿Respeta el contrato canónico? (secciones declaradas y cotas).
    pub fn conforms(&self) -> Result<(), BridgeError> {
        Manifest::canon().conforms(self)
    }

    /// Huella de la instantánea: **contenido-adictiva**.
    ///
    /// Depende del número de secciones, de su orden y de la huella de cada
    /// cuerpo, nunca del reloj: dos capturas del mismo estado coinciden, y
    /// cualquier cambio real en lo leído cambia la huella.
    pub fn digest(&self) -> [u8; 32] {
        let mut statement = Vec::with_capacity(BRIDGE_DOMAIN.len() + 160 + self.bytes());
        statement.extend_from_slice(BRIDGE_DOMAIN);
        statement.extend_from_slice(b":instantanea:");
        statement.extend_from_slice(&(self.sections.len() as u64).to_le_bytes());
        for section in &self.sections {
            statement.extend_from_slice(&section.digest());
            statement.extend_from_slice(&(section.bytes() as u64).to_le_bytes());
        }
        sha256(&statement)
    }

    /// Huella de la instantánea en hexadecimal.
    pub fn fingerprint(&self) -> String {
        short_hex(&self.digest())
    }

    /// Acta de una línea.
    pub fn label_text(&self) -> String {
        let names: Vec<&str> = self.sections.iter().map(|section| section.name()).collect();
        format!(
            "puente ⟨{}⟩ · esquema {} · {} sección(es) [{}] · {} B · manifiesto {}",
            self.fingerprint(),
            BRIDGE_SCHEMA,
            self.len(),
            names.join(" → "),
            self.bytes(),
            Manifest::canon().fingerprint()
        )
    }

    /// Catálogo de secciones (metadatos sin cuerpos): la barra lateral del IDE.
    ///
    /// Emite **una entrada por sección canónica** en orden: las capturadas con
    /// su tamaño y huella, las ausentes marcadas con `presente:false`. Así el
    /// panel dibuja siempre las mismas ranuras.
    pub fn catalog(&self) -> String {
        let mut out = String::with_capacity(96 + 128 * SectionKind::ALL.len());
        out.push('[');
        for (index, kind) in SectionKind::ALL.iter().copied().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str("{\"nombre\":\"");
            out.push_str(kind.name());
            out.push_str("\",\"glifo\":\"");
            out.push_str(kind.glyph());
            out.push_str("\",\"orden\":");
            out.push_str(&kind.index().to_string());
            match self.section(kind) {
                Some(section) => {
                    out.push_str(",\"presente\":true,\"bytes\":");
                    out.push_str(&section.bytes().to_string());
                    out.push_str(",\"huella\":\"");
                    out.push_str(&section.fingerprint());
                    out.push_str("\"}");
                }
                None => out.push_str(",\"presente\":false,\"bytes\":0,\"huella\":\"\"}"),
            }
        }
        out.push(']');
        out
    }

    /// Documento completo para el IDE: identidad del puente, secciones y huella.
    ///
    /// Las claves de `secciones` son las de [`SectionKind::name`] y su valor es
    /// el cuerpo de la sección **sin recomillar**: los paneles leen JSON anidado
    /// directamente.
    pub fn json(&self) -> String {
        let mut out = String::with_capacity(self.bytes() + 640);
        out.push_str("{\"esquema\":\"");
        out.push_str(BRIDGE_SCHEMA);
        out.push_str("\",\"version\":\"");
        out.push_str(BRIDGE_VERSION);
        out.push_str("\",\"huella\":\"");
        out.push_str(&self.fingerprint());
        out.push_str("\",\"manifiesto\":\"");
        out.push_str(&Manifest::canon().fingerprint());
        out.push_str("\",\"completa\":");
        out.push_str(json_bool(self.is_complete()));
        out.push_str(",\"bytes\":");
        out.push_str(&self.bytes().to_string());
        out.push_str(",\"secciones\":{");
        for (index, section) in self.sections.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push('"');
            out.push_str(section.name());
            out.push_str("\":");
            out.push_str(section.body());
        }
        out.push_str("},\"catalogo\":");
        out.push_str(&self.catalog());
        out.push('}');
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Constructores de sección (sólo lectura)
// ─────────────────────────────────────────────────────────────────────────

/// Sección `identidad`: el contrato del puente, sin leer ningún subsistema.
///
/// Es la única sección con función pura: no recibe nada y no depende del estado,
/// así que su huella **es** la firma del puente. Un panel la pide primero y
/// aprende de ella qué secciones existen, en qué orden y con qué cota.
pub fn section_identity() -> Result<Section, BridgeError> {
    let manifest = Manifest::canon();
    let mut body = String::with_capacity(768);
    body.push_str("{\"dominio\":\"bara:aether-omega:puente:v1\"");
    body.push_str(",\"solo_lectura\":true,\"muta_nucleo\":false,\"rechaza\":");
    // La puerta es abierta: no existe el verbo «rechazar».
    body.push_str(json_bool(false));
    body.push_str(",\"manifiesto\":");
    body.push_str(&manifest.json());
    body.push('}');
    Section::new(SectionKind::Identidad, &body)
}

/// Sección `inmunidad`: proyección del sistema adaptativo (FASE 2).
///
/// Enmarca la instantánea de [`ImmuneSystem::json`] con los agregados que un
/// panel dibuja de un golpe (afinidad media, tolerancia, capacidad) y con el
/// acta del sistema para el registro del IDE.
pub fn section_immunity(immune: &ImmuneSystem) -> Result<Section, BridgeError> {
    let repertoire = immune.repertoire();
    let mut body = String::with_capacity(1024 + 256 * repertoire.len());
    body.push_str("{\"huella\":\"");
    body.push_str(&immune.fingerprint());
    body.push_str("\",\"tolerancia\":");
    body.push_str(&json_f64(immune.tolerance()));
    body.push_str(",\"afinidad_media\":");
    body.push_str(&json_f64(repertoire.mean_affinity()));
    body.push_str(",\"capacidad\":");
    body.push_str(&repertoire.capacity().to_string());
    body.push_str(",\"repertorio_lleno\":");
    body.push_str(json_bool(repertoire.is_full()));
    body.push_str(",\"censo\":");
    body.push_str(&immune.census().json());
    body.push_str(",\"contadores\":");
    body.push_str(&immune.counters().json());
    body.push_str(",\"repertorio\":");
    body.push_str(&repertoire.json());
    body.push_str(",\"acta\":\"");
    body.push_str(&json_escape(&immune.label_text()));
    body.push_str("\"}");
    Section::new(SectionKind::Inmunidad, &body)
}

/// Sección `pasarela`: la puerta, su censo de veredictos y el **rabo** de burbujas.
///
/// El rabo muestra las últimas [`MAX_BUBBLES`] burbujas (vista de panel); el
/// recuento total, los bytes inertes y los nodos sellados son del registro
/// completo, de modo que el panel nunca confunda «lo que ve» con «lo que hay».
pub fn section_gateway(gateway: &Gateway) -> Result<Section, BridgeError> {
    let (innocuous, absorbed, neutralized, quarantined) = gateway.census();
    let total = gateway.bubbles.len();
    let inert_bytes: usize = gateway
        .bubbles
        .iter()
        .map(|bubble| bubble.inert.len())
        .sum();
    let sealed: usize = gateway.bubbles.iter().map(Bubble::sealed).sum();
    let markers: usize = gateway
        .bubbles
        .iter()
        .map(|bubble| bubble.markers.len())
        .sum();
    let start = total.saturating_sub(MAX_BUBBLES);

    let mut body = String::with_capacity(1024 + 640 * MAX_BUBBLES);
    body.push_str("{\"puerta_abierta\":");
    body.push_str(json_bool(gateway.door_is_open()));
    body.push_str(",\"rechaza\":");
    body.push_str(json_bool(gateway.policy.rejects_anything()));
    body.push_str(",\"censo\":{\"inocuas\":");
    body.push_str(&innocuous.to_string());
    body.push_str(",\"absorbidas\":");
    body.push_str(&absorbed.to_string());
    body.push_str(",\"neutralizadas\":");
    body.push_str(&neutralized.to_string());
    body.push_str(",\"cuarentena\":");
    body.push_str(&quarantined.to_string());
    body.push_str("},\"burbujas\":");
    body.push_str(&total.to_string());
    body.push_str(",\"bytes_inertes\":");
    body.push_str(&inert_bytes.to_string());
    body.push_str(",\"nodos_sellados\":");
    body.push_str(&sealed.to_string());
    body.push_str(",\"marcas\":");
    body.push_str(&markers.to_string());
    body.push_str(",\"regiones\":");
    body.push_str(&gateway.regions.len().to_string());
    body.push_str(",\"memoria\":");
    body.push_str(&gateway.memory.len().to_string());
    body.push_str(",\"cota_rabo\":");
    body.push_str(&MAX_BUBBLES.to_string());
    body.push_str(",\"rabo\":[");
    for (index, bubble) in gateway.bubbles[start..].iter().enumerate() {
        if index > 0 {
            body.push(',');
        }
        body.push_str("{\"id\":");
        body.push_str(&bubble.id.to_string());
        body.push_str(",\"etiqueta\":\"");
        body.push_str(&json_escape(&bubble.label));
        body.push_str("\",\"origen\":\"");
        body.push_str(&json_escape(&bubble.origin));
        body.push_str("\",\"orden\":");
        body.push_str(&bubble.sequence.to_string());
        body.push_str(",\"holograma\":\"");
        body.push_str(&bubble.hologram());
        body.push_str("\",\"bytes\":");
        body.push_str(&bubble.bytes.to_string());
        body.push_str(",\"nodos\":");
        body.push_str(&bubble.ast.nodes.len().to_string());
        body.push_str(",\"sellados\":");
        body.push_str(&bubble.sealed().to_string());
        body.push_str(",\"veredicto\":\"");
        body.push_str(&json_escape(bubble.verdict.label()));
        body.push_str("\",\"glifo\":\"");
        body.push_str(bubble.verdict.glyph());
        body.push_str("\",\"peligro\":");
        body.push_str(&bubble.danger.to_string());
        body.push_str(",\"marcas\":[");
        for (marker_index, marker) in bubble.markers.iter().enumerate() {
            if marker_index > 0 {
                body.push(',');
            }
            body.push('"');
            body.push_str(&json_escape(marker));
            body.push('"');
        }
        body.push_str("],\"estanca\":");
        body.push_str(json_bool(bubble.is_airtight()));
        body.push_str(",\"acta\":\"");
        body.push_str(&json_escape(&bubble.describe()));
        body.push_str("\"}");
    }
    body.push_str("]}");
    Section::new(SectionKind::Pasarela, &body)
}

/// Sección `nucleo`: el estado soberano, leído sin tocarlo.
///
/// Todo lo que un panel necesita para **entender** la soberanía —pila de
/// evaluación, memoria holográfica, axiomas sintetizados, regiones, qubits,
/// malla, certificado ZK, programa de metal y log ontológico— sin una sola
/// escritura. La marca de reloj del motor temporal queda fuera por diseño (es
/// **NO DETERMINISTA**): del motor se proyecta sólo la forma de su pila y su
/// diario.
pub fn section_kernel(core: &BaraRuntime) -> Result<Section, BridgeError> {
    let top = core.peek().map(QuantumState::label);
    let last = core.log().last().map(event_kind);
    let mut body = String::with_capacity(1792);
    body.push_str("{\"pila\":{\"profundidad\":");
    body.push_str(&core.stack.len().to_string());
    body.push_str(",\"cumbre\":");
    body.push_str(&json_opt_str(top.as_deref()));
    body.push_str("},\"memoria\":");
    body.push_str(&core.memory.len().to_string());
    body.push_str(",\"axiomas\":{\"generacion\":");
    body.push_str(&core.mutator.generation().to_string());
    body.push_str(",\"total\":");
    body.push_str(&core.mutator.axioms().count().to_string());
    body.push_str("},\"regiones\":");
    body.push_str(&core.regions.len().to_string());
    body.push_str(",\"tiempo\":{\"instantaneas\":");
    body.push_str(&core.timeline.stack().len().to_string());
    body.push_str(",\"deltas\":");
    body.push_str(&core.timeline.deltas().len().to_string());
    body.push_str("},\"qubits\":{\"vivos\":");
    body.push_str(&core.qubits.len().to_string());
    body.push_str(",\"colapsos\":");
    body.push_str(&core.qubits.collapses().to_string());
    body.push_str("},\"malla\":{\"nodos\":");
    body.push_str(&core.mesh.len().to_string());
    body.push_str(",\"epoca\":");
    body.push_str(&core.mesh.epoch().to_string());
    body.push_str("},\"certificado\":");
    match &core.certificate {
        Some(certificate) => {
            body.push_str("{\"presente\":true,\"etiqueta\":\"");
            body.push_str(&json_escape(&certificate.statement.label));
            body.push_str("\",\"restricciones\":");
            body.push_str(&certificate.statement.n_constraints.to_string());
            body.push_str(",\"verificado\":");
            body.push_str(json_bool(certificate.result.verified));
            body.push('}');
        }
        None => body.push_str("null"),
    }
    body.push_str(",\"metal\":");
    match &core.metal {
        Some(program) => {
            body.push_str("{\"presente\":true,\"etiqueta\":\"");
            body.push_str(&json_escape(&program.label));
            body.push_str("\",\"instrucciones\":");
            body.push_str(&program.len().to_string());
            body.push_str(",\"palabras\":");
            body.push_str(&program.words().len().to_string());
            body.push('}');
        }
        None => body.push_str("null"),
    }
    body.push_str(",\"log\":{\"eventos\":");
    body.push_str(&core.log().len().to_string());
    body.push_str(",\"tolerados\":");
    body.push_str(
        &core
            .log()
            .iter()
            .filter(|entry| matches!(entry, ExecutionEvent::Tolerated { .. }))
            .count()
            .to_string(),
    );
    body.push_str(",\"ultimo\":");
    body.push_str(&json_opt_str(last));
    body.push_str("}}");
    Section::new(SectionKind::Nucleo, &body)
}

/// Nombre estable de la variante de un evento del log ontológico.
///
/// Se proyecta el **nombre**, nunca la descripción: [`ExecutionEvent::Rollback`]
/// lleva `micros` (reloj de pared) y rompería el determinismo del puente. Un
/// panel que necesite el detalle completo lo pide directamente al núcleo.
fn event_kind(event: &ExecutionEvent) -> &'static str {
    match event {
        ExecutionEvent::Root { .. } => "Root",
        ExecutionEvent::Manifest { .. } => "Manifest",
        ExecutionEvent::Superpose { .. } => "Superpose",
        ExecutionEvent::Guard { .. } => "Guard",
        ExecutionEvent::Collapse { .. } => "Collapse",
        ExecutionEvent::Emit { .. } => "Emit",
        ExecutionEvent::Axiogenesis { .. } => "Axiogenesis",
        ExecutionEvent::Fold { .. } => "Fold",
        ExecutionEvent::Hologram { .. } => "Hologram",
        ExecutionEvent::Tolerated { .. } => "Tolerated",
        ExecutionEvent::Region { .. } => "Region",
        ExecutionEvent::ZkVerified { .. } => "ZkVerified",
        ExecutionEvent::Rollback { .. } => "Rollback",
        ExecutionEvent::Ingested { .. } => "Ingested",
        ExecutionEvent::QuantumSuperposed { .. } => "QuantumSuperposed",
        ExecutionEvent::Entangled { .. } => "Entangled",
        ExecutionEvent::QuantumCollapsed { .. } => "QuantumCollapsed",
        ExecutionEvent::MeshSynced { .. } => "MeshSynced",
        ExecutionEvent::MetalMapped { .. } => "MetalMapped",
        ExecutionEvent::Oracle { .. } => "Oracle",
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Pruebas
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Carga limpia: JSON inocente, sin una sola marca sospechosa.
    const LIMPIA: &str = "{\"evento\":\"saludo\",\"valor\":1}";

    /// Carga hostil declarada: ruta, inyección SQL y etiqueta de script.
    const HOSTIL: &str = "../$(rm -rf / && drop table usuarios) <script>";

    /// Pasarela con las cargas dadas, admitidas en orden determinista.
    fn pasarela(cargas: &[&str]) -> Gateway {
        let mut gateway = Gateway::new();
        for (indice, carga) in cargas.iter().enumerate() {
            gateway.admit("bucle:prueba", indice as u64, carga.as_bytes());
        }
        gateway
    }

    /// Núcleo con un estado apilado y su certificado ZK emitido.
    fn nucleo() -> BaraRuntime {
        let mut core = BaraRuntime::new();
        core.push(QuantumState::paraconsistent(0.75, 0.25));
        core.certify();
        core
    }

    /// Inmunidad que ya reconoció la carga hostil dos veces.
    fn inmunidad() -> ImmuneSystem {
        let mut sistema = ImmuneSystem::new();
        sistema.screen_bytes("bucle:prueba", 0, HOSTIL.as_bytes());
        sistema.screen_bytes("bucle:prueba", 1, HOSTIL.as_bytes());
        sistema
    }

    /// Sección exigida: si el puente la rechazase, el fallo lleva su motivo.
    fn exigir(resultado: Result<Section, BridgeError>) -> Option<Section> {
        match resultado {
            Ok(seccion) => Some(seccion),
            Err(error) => {
                assert!(error.to_string().is_empty(), "sección rechazada: {error}");
                None
            }
        }
    }

    /// Instantánea canónica del organismo de prueba, o `None` con el motivo.
    fn captura(sistema: &ImmuneSystem, puerta: &Gateway, core: &BaraRuntime) -> Option<Snapshot> {
        match Snapshot::capture(sistema, puerta, core) {
            Ok(instantanea) => Some(instantanea),
            Err(error) => {
                assert!(error.to_string().is_empty(), "captura rechazada: {error}");
                None
            }
        }
    }

    /// ¿Llaves equilibradas y comillas cerradas? (estructura mínima del JSON).
    fn equilibrado(json: &str) -> bool {
        let mut profundidad = 0_i64;
        let mut en_cadena = false;
        let mut escapado = false;
        for caracter in json.chars() {
            if escapado {
                escapado = false;
                continue;
            }
            match caracter {
                '\\' if en_cadena => escapado = true,
                '"' => en_cadena = !en_cadena,
                '{' if !en_cadena => profundidad += 1,
                '}' if !en_cadena => profundidad -= 1,
                _ => {}
            }
            if profundidad < 0 {
                return false;
            }
        }
        profundidad == 0 && !en_cadena
    }

    #[test]
    fn los_nombres_de_seccion_son_invertibles() {
        for (indice, kind) in SectionKind::ALL.iter().copied().enumerate() {
            assert_eq!(kind.index(), indice);
            assert_eq!(SectionKind::from_name(kind.name()), Some(kind));
            assert_eq!(kind.glyph().chars().count(), 1);
        }
        assert_eq!(SectionKind::from_name("inexistente"), None);
        // El orden de declaración es el orden canónico: la menor precede a la mayor.
        assert!(SectionKind::Identidad < SectionKind::Inmunidad);
        assert!(SectionKind::Inmunidad < SectionKind::Pasarela);
        assert!(SectionKind::Pasarela < SectionKind::Nucleo);
    }

    #[test]
    fn la_seccion_rechaza_cuerpos_invalidos_por_tipos() {
        assert_eq!(
            Section::new(SectionKind::Nucleo, "   "),
            Err(BridgeError::EmptyBody {
                kind: SectionKind::Nucleo
            })
        );
        assert_eq!(
            Section::new(SectionKind::Inmunidad, "[1,2]"),
            Err(BridgeError::MalformedBody {
                kind: SectionKind::Inmunidad
            })
        );

        let enorme = format!("{{\"relleno\":\"{}\"}}", "x".repeat(MAX_SECTION_BYTES));
        assert_eq!(
            Section::new(SectionKind::Pasarela, &enorme),
            Err(BridgeError::TooLarge {
                kind: SectionKind::Pasarela,
                bytes: enorme.len(),
                limit: MAX_SECTION_BYTES,
            })
        );

        // El borde exacto sí entra, y los espacios de fuera no cuentan como cuerpo.
        let justa = format!("{{\"relleno\":\"{}\"}}", "x".repeat(MAX_SECTION_BYTES - 14));
        assert_eq!(justa.len(), MAX_SECTION_BYTES);
        if let Some(seccion) = exigir(Section::new(SectionKind::Pasarela, &justa)) {
            assert_eq!(seccion.bytes(), MAX_SECTION_BYTES);
            assert_eq!(seccion.body(), justa);
            assert_eq!(seccion.kind(), SectionKind::Pasarela);
            assert_eq!(seccion.name(), "pasarela");
            assert_eq!(seccion.fingerprint().len(), 64);
            assert!(seccion.label_text().starts_with("⇥ pasarela"));
            let json = seccion.json();
            assert!(json.starts_with("{\"seccion\":\"pasarela\""));
            assert!(json.contains(&format!("\"bytes\":{}", MAX_SECTION_BYTES)));
            assert!(json.contains(&justa));
            assert!(equilibrado(&json));
        }
    }

    #[test]
    fn la_huella_de_la_seccion_liga_el_nombre() {
        let inmunidad_seccion = exigir(Section::new(SectionKind::Inmunidad, "{\"a\":1}"));
        let nucleo_seccion = exigir(Section::new(SectionKind::Nucleo, "{\"a\":1}"));
        if let (Some(uno), Some(otro)) = (inmunidad_seccion, nucleo_seccion) {
            // Mismo cuerpo, distinto nombre: la huella no puede confundirlos.
            assert_eq!(uno.body(), otro.body());
            assert_ne!(uno.digest(), otro.digest());
            assert_ne!(uno.fingerprint(), otro.fingerprint());
        }
        // Mismo cuerpo y mismo nombre ⇒ misma huella: el recorte no la altera.
        if let Some(repetida) = exigir(Section::new(SectionKind::Inmunidad, " {\"a\":1} ")) {
            if let Some(uno) = exigir(Section::new(SectionKind::Inmunidad, "{\"a\":1}")) {
                assert_eq!(uno, repetida);
                assert_eq!(uno.digest(), repetida.digest());
                assert_eq!(uno.label_text(), repetida.label_text());
            }
        }
    }

    #[test]
    fn la_instantanea_exige_orden_canonico_y_unicidad() {
        let mut instantanea = Snapshot::new();
        assert!(instantanea.is_empty());
        assert_eq!(instantanea.len(), 0);
        assert_eq!(instantanea.bytes(), 0);
        assert!(!instantanea.is_complete());
        assert_eq!(instantanea.missing(), SectionKind::ALL.to_vec());
        assert_eq!(instantanea.section(SectionKind::Identidad), None);
        assert_eq!(instantanea.body(SectionKind::Pasarela), None);

        let puerta = pasarela(&[LIMPIA, HOSTIL]);
        let sistema = inmunidad();
        let Some(inmunidad_seccion) = exigir(section_immunity(&sistema)) else {
            return;
        };
        let Some(pasarela_seccion) = exigir(section_gateway(&puerta)) else {
            return;
        };

        // El orden canónico avanza, no retrocede: una vez dentro pasarela, la
        // inmunidad que quedó atrás ya no entra.
        let mut retroceso = Snapshot::new();
        assert!(retroceso.push(pasarela_seccion.clone()).is_ok());
        assert_eq!(
            retroceso.push(inmunidad_seccion.clone()),
            Err(BridgeError::OutOfOrder {
                after: SectionKind::Pasarela,
                found: SectionKind::Inmunidad,
            })
        );
        assert_eq!(retroceso.len(), 1);
        assert_eq!(
            retroceso.missing(),
            vec![
                SectionKind::Identidad,
                SectionKind::Inmunidad,
                SectionKind::Nucleo
            ]
        );

        // En orden sí entra todo, y una sección repetida se rechaza sin ruido.
        assert!(instantanea.push(inmunidad_seccion.clone()).is_ok());
        assert_eq!(
            instantanea.push(inmunidad_seccion.clone()),
            Err(BridgeError::DuplicatedSection {
                kind: SectionKind::Inmunidad
            })
        );
        assert!(instantanea.push(pasarela_seccion.clone()).is_ok());
        assert_eq!(
            instantanea.push(pasarela_seccion),
            Err(BridgeError::DuplicatedSection {
                kind: SectionKind::Pasarela
            })
        );
        assert_eq!(instantanea.len(), 2);
        assert!(instantanea.contains(SectionKind::Pasarela));
        assert_eq!(
            instantanea.missing(),
            vec![SectionKind::Identidad, SectionKind::Nucleo]
        );
        assert!(instantanea.bytes() > 0);
        // El cuerpo proyectado es el de la pasarela leída, byte a byte.
        if let Some(esperado) = exigir(section_gateway(&puerta)) {
            assert_eq!(
                instantanea.body(SectionKind::Pasarela),
                Some(esperado.body())
            );
        }
        assert_eq!(
            instantanea
                .sections()
                .iter()
                .map(Section::kind)
                .collect::<Vec<_>>(),
            vec![SectionKind::Inmunidad, SectionKind::Pasarela]
        );
        assert!(!instantanea.is_complete());
    }

    #[test]
    fn el_manifiesto_es_estable_y_declara_sus_origenes() {
        let canonico = Manifest::canon();
        assert_eq!(canonico.len(), SectionKind::ALL.len());
        assert!(!canonico.is_empty());
        assert!(canonico.contains(SectionKind::Nucleo));
        assert_eq!(canonico.limit(SectionKind::Nucleo), Some(MAX_SECTION_BYTES));
        assert_eq!(canonico.source(SectionKind::Identidad), Some("contrato"));
        assert_eq!(
            canonico.source(SectionKind::Inmunidad),
            Some("immune::ImmuneSystem")
        );
        assert_eq!(
            canonico.source(SectionKind::Pasarela),
            Some("immunity_gateway::Gateway")
        );
        assert_eq!(
            canonico.source(SectionKind::Nucleo),
            Some("runtime::BaraRuntime")
        );
        assert_eq!(
            canonico.spec(SectionKind::Pasarela).map(|spec| spec.kind),
            Some(SectionKind::Pasarela)
        );
        assert_eq!(canonico.fingerprint().len(), 64);
        assert!(canonico
            .label_text()
            .contains("identidad → inmunidad → pasarela → nucleo"));
        assert!(equilibrado(&canonico.json()));
        assert!(canonico
            .json()
            .contains("\"esquema\":\"aether-omega/puente/1\""));

        // El contrato es estable: mismas declaraciones ⇒ misma huella.
        let repetido = match Manifest::from_specs(canonico.sections()) {
            Ok(manifiesto) => manifiesto,
            Err(error) => {
                assert!(
                    error.to_string().is_empty(),
                    "manifiesto rechazado: {error}"
                );
                return;
            }
        };
        assert_eq!(repetido, canonico);
        assert_eq!(repetido.digest(), canonico.digest());
    }

    #[test]
    fn el_manifiesto_rechaza_declaraciones_invalidas_por_tipos() {
        let nula = [SectionSpec {
            kind: SectionKind::Nucleo,
            limit: 0,
            source: "runtime::BaraRuntime",
        }];
        assert_eq!(
            Manifest::from_specs(&nula),
            Err(BridgeError::EmptyLimit {
                kind: SectionKind::Nucleo
            })
        );

        let repetida = [
            SectionSpec {
                kind: SectionKind::Identidad,
                limit: 8,
                source: "contrato",
            },
            SectionSpec {
                kind: SectionKind::Identidad,
                limit: 8,
                source: "contrato",
            },
        ];
        assert_eq!(
            Manifest::from_specs(&repetida),
            Err(BridgeError::DuplicatedSection {
                kind: SectionKind::Identidad
            })
        );

        let desordenada = [
            SectionSpec {
                kind: SectionKind::Nucleo,
                limit: 8,
                source: "runtime::BaraRuntime",
            },
            SectionSpec {
                kind: SectionKind::Identidad,
                limit: 8,
                source: "contrato",
            },
        ];
        assert_eq!(
            Manifest::from_specs(&desordenada),
            Err(BridgeError::OutOfOrder {
                after: SectionKind::Nucleo,
                found: SectionKind::Identidad,
            })
        );

        // El techo de secciones se comprueba antes que el orden.
        let excesiva: Vec<SectionSpec> = (0..=MAX_SECTIONS)
            .map(|indice| SectionSpec {
                kind: SectionKind::ALL[indice % SectionKind::ALL.len()],
                limit: 8,
                source: "prueba",
            })
            .collect();
        assert!(excesiva.len() > MAX_SECTIONS);
        assert_eq!(
            Manifest::from_specs(&excesiva),
            Err(BridgeError::TooManySections {
                sections: excesiva.len(),
                limit: MAX_SECTIONS,
            })
        );
    }

    #[test]
    fn el_manifiesto_valida_la_instantanea_por_cotas_y_secciones() {
        let estrecho: Vec<SectionSpec> = SectionKind::ALL
            .iter()
            .map(|kind| SectionSpec {
                kind: *kind,
                limit: 32,
                source: "prueba-estrecha",
            })
            .collect();
        let estrecho = match Manifest::from_specs(&estrecho) {
            Ok(manifiesto) => manifiesto,
            Err(error) => {
                assert!(
                    error.to_string().is_empty(),
                    "manifiesto rechazado: {error}"
                );
                return;
            }
        };

        let Some(instantanea) = captura(&inmunidad(), &pasarela(&[LIMPIA, HOSTIL]), &nucleo())
        else {
            return;
        };

        // El contrato canónico la acepta entera, sección a sección.
        assert!(Manifest::canon().conforms(&instantanea).is_ok());
        assert!(instantanea.conforms().is_ok());

        // Un contrato con cotas ínfimas la rechaza por la sección más temprana.
        let identidad_bytes = instantanea
            .section(SectionKind::Identidad)
            .map(Section::bytes)
            .unwrap_or(0);
        assert!(identidad_bytes > 32);
        assert_eq!(
            estrecho.conforms(&instantanea),
            Err(BridgeError::TooLarge {
                kind: SectionKind::Identidad,
                bytes: identidad_bytes,
                limit: 32,
            })
        );

        // Si sólo ahoga a una sección, señala exactamente a esa: el contrato
        // no culpa al vecino de lo que rompe uno.
        let ajustada: Vec<SectionSpec> = SectionKind::ALL
            .iter()
            .map(|kind| SectionSpec {
                kind: *kind,
                limit: if *kind == SectionKind::Inmunidad {
                    32
                } else {
                    MAX_SECTION_BYTES
                },
                source: "prueba-ajustada",
            })
            .collect();
        let ajustada = match Manifest::from_specs(&ajustada) {
            Ok(manifiesto) => manifiesto,
            Err(error) => {
                assert!(
                    error.to_string().is_empty(),
                    "manifiesto rechazado: {error}"
                );
                return;
            }
        };
        let inmunidad_bytes = instantanea
            .section(SectionKind::Inmunidad)
            .map(Section::bytes)
            .unwrap_or(0);
        assert!(inmunidad_bytes > 32);
        assert_eq!(
            ajustada.conforms(&instantanea),
            Err(BridgeError::TooLarge {
                kind: SectionKind::Inmunidad,
                bytes: inmunidad_bytes,
                limit: 32,
            })
        );
        assert!(Manifest::canon().conforms(&instantanea).is_ok());

        // Un contrato que no declara una sección la desconoce: no la omite. El
        // veredicto nombra a la primera sección que el contrato no contempla.
        let minimo = [SectionSpec {
            kind: SectionKind::Identidad,
            limit: MAX_SECTION_BYTES,
            source: "contrato",
        }];
        let minimo = match Manifest::from_specs(&minimo) {
            Ok(manifiesto) => manifiesto,
            Err(error) => {
                assert!(
                    error.to_string().is_empty(),
                    "manifiesto rechazado: {error}"
                );
                return;
            }
        };
        assert_eq!(
            minimo.conforms(&instantanea),
            Err(BridgeError::UnknownSection {
                name: "inmunidad".to_string()
            })
        );
    }

    #[test]
    fn la_captura_es_completa_y_no_muta_lo_leido() {
        let sistema = inmunidad();
        let puerta = pasarela(&[LIMPIA, HOSTIL]);
        let core = nucleo();
        let huella_inicial = sistema.fingerprint();
        let Some(instantanea) = captura(&sistema, &puerta, &core) else {
            return;
        };

        assert!(instantanea.is_complete());
        assert_eq!(instantanea.len(), SectionKind::ALL.len());
        assert!(instantanea.missing().is_empty());
        assert_eq!(instantanea.fingerprint().len(), 64);
        assert!(instantanea.bytes() <= instantanea.len() * MAX_SECTION_BYTES);
        assert!(instantanea.label_text().starts_with("puente ⟨"));
        for kind in SectionKind::ALL {
            assert!(instantanea.contains(kind));
            if let Some(seccion) = instantanea.section(kind) {
                assert_eq!(seccion.kind(), kind);
                assert_eq!(instantanea.body(kind), Some(seccion.body()));
                assert!(seccion.body().starts_with('{'));
                assert!(seccion.bytes() <= MAX_SECTION_BYTES);
                assert!(equilibrado(seccion.body()));
                assert!(seccion.label_text().contains(kind.name()));
            }
        }

        // Invariante de soberanía: leer no cambia nada de lo leído.
        assert_eq!(sistema.fingerprint(), huella_inicial);
        assert!(puerta.door_is_open());
        assert_eq!(puerta.bubbles.len(), 2);
        assert_eq!(core.stack.len(), 1);
        assert!(core.certificate.is_some());

        // Dos capturas seguidas del mismo estado vivo coinciden exactamente.
        let Some(repetida) = captura(&sistema, &puerta, &core) else {
            return;
        };
        assert_eq!(repetida, instantanea);
        assert_eq!(repetida.digest(), instantanea.digest());
    }

    #[test]
    fn el_puente_proyecta_el_log_sin_reloj() {
        let core = nucleo();
        let Some(primera) = exigir(section_kernel(&core)) else {
            return;
        };
        let Some(segunda) = exigir(section_kernel(&core)) else {
            return;
        };
        // Determinismo: la misma lectura da exactamente la misma sección.
        assert_eq!(primera, segunda);
        assert_eq!(primera.digest(), segunda.digest());
        assert!(!primera.body().contains("micros"));

        // Un rollback lleva reloj de pared: el puente proyecta su nombre, no su
        // duración (si no, la huella dejaría de ser reproducible).
        let mut con_rollback = nucleo();
        let eventos = con_rollback.log().len();
        con_rollback.note(ExecutionEvent::Rollback {
            reverted: 3,
            micros: 987_654,
            paradox: "contradicción retenida, jamás explosión".to_string(),
        });
        let Some(seccion) = exigir(section_kernel(&con_rollback)) else {
            return;
        };
        assert!(seccion.body().contains("\"ultimo\":\"Rollback\""));
        assert!(!seccion.body().contains("987654"));
        assert!(!seccion.body().contains("micros"));
        assert!(!seccion.body().contains("contradicción retenida"));
        assert!(seccion
            .body()
            .contains(&format!("\"eventos\":{}", eventos + 1)));

        // Dos núcleos idénticos difieren sólo por lo que el log dice, no por el reloj.
        assert_ne!(seccion.digest(), primera.digest());
        assert_ne!(seccion.body(), primera.body());
    }

    #[test]
    fn la_seccion_de_inmunidad_proyecta_el_censo_y_el_repertorio() {
        let sistema = inmunidad();
        let capacidad = sistema.repertoire().capacity();
        let Some(cuerpo) = exigir(section_immunity(&sistema)) else {
            return;
        };

        assert_eq!(cuerpo.kind(), SectionKind::Inmunidad);
        assert!(cuerpo
            .body()
            .contains(&format!("\"capacidad\":{capacidad}")));
        assert!(cuerpo.body().contains("\"repertorio_lleno\":false"));
        assert!(cuerpo.body().contains("\"afinidad_media\":"));
        assert!(cuerpo.body().contains("\"tolerancia\":"));
        assert!(cuerpo.body().contains("\"inmunizados\":1"));
        assert!(cuerpo.body().contains("\"neutralizados\":1"));
        assert!(cuerpo
            .body()
            .contains(&format!("\"huella\":\"{}\"", sistema.fingerprint())));
        assert!(cuerpo.body().contains("\"anticuerpos\":["));
        assert!(cuerpo.bytes() < MAX_SECTION_BYTES);
        assert!(equilibrado(cuerpo.body()));

        // Un sistema virgen también se lee: el puente no exige historia previa.
        let Some(virgen) = exigir(section_immunity(&ImmuneSystem::new())) else {
            return;
        };
        assert!(virgen.body().contains("\"neutralizados\":0"));
        assert!(virgen.body().contains("\"inmunizados\":0"));
        assert!(virgen.body().contains("\"anticuerpos\":[]"));
        assert_ne!(virgen.digest(), cuerpo.digest());
    }

    #[test]
    fn la_seccion_de_pasarela_acota_el_rabo() {
        use crate::immunity_gateway::BubbleVerdict;

        let cargas = [HOSTIL; MAX_BUBBLES + 4];
        let puerta = pasarela(&cargas);
        let total = puerta.bubbles.len();
        assert_eq!(total, MAX_BUBBLES + 4);
        assert_eq!(puerta.regions.len(), total);
        assert_eq!(puerta.memory.len(), total);

        let (inocuas, absorbidas, neutralizadas, cuarentena) = puerta.census();
        let sellados: usize = puerta.bubbles.iter().map(Bubble::sealed).sum();
        let inertes: usize = puerta.bubbles.iter().map(|bubble| bubble.inert.len()).sum();

        let Some(cuerpo) = exigir(section_gateway(&puerta)) else {
            return;
        };
        assert_eq!(cuerpo.kind(), SectionKind::Pasarela);
        assert!(cuerpo.body().contains("\"puerta_abierta\":true"));
        assert!(cuerpo.body().contains("\"rechaza\":false"));
        assert_eq!(inocuas + absorbidas + neutralizadas + cuarentena, total);
        assert!(cuerpo.body().contains(&format!("\"inocuas\":{inocuas}")));
        assert!(cuerpo
            .body()
            .contains(&format!("\"absorbidas\":{absorbidas}")));
        assert!(cuerpo
            .body()
            .contains(&format!("\"neutralizadas\":{neutralizadas}")));
        assert!(cuerpo
            .body()
            .contains(&format!("\"cuarentena\":{cuarentena}")));
        assert!(cuerpo.body().contains(&format!("\"burbujas\":{total}")));
        assert!(cuerpo.body().contains(&format!("\"regiones\":{total}")));
        assert!(cuerpo.body().contains(&format!("\"memoria\":{total}")));
        assert!(cuerpo
            .body()
            .contains(&format!("\"nodos_sellados\":{sellados}")));
        assert!(cuerpo
            .body()
            .contains(&format!("\"bytes_inertes\":{inertes}")));
        assert!(inertes > 0);

        // Ninguna burbuja hostil alcanza el núcleo y el ruido no lleva marcas.
        assert!(puerta
            .bubbles
            .iter()
            .all(|bubble| !bubble.verdict.reaches_core()));
        assert!(puerta.bubbles.iter().all(|bubble| bubble.is_airtight()));
        assert!(puerta.bubbles.iter().all(|bubble| bubble.danger > 0));

        // El rabo son las ÚLTIMAS burbujas: las primeras ya no se muestran.
        assert_eq!(cuerpo.body().matches("\"holograma\":").count(), MAX_BUBBLES);
        assert!(cuerpo
            .body()
            .contains(&format!("\"cota_rabo\":{MAX_BUBBLES}")));
        let ultima = total - 1;
        let primera_del_rabo = total - MAX_BUBBLES;
        assert!(cuerpo.body().contains(&format!("\"id\":{ultima}")));
        assert!(cuerpo
            .body()
            .contains(&format!("\"id\":{primera_del_rabo}")));
        assert!(!cuerpo
            .body()
            .contains(&format!("\"id\":{},", primera_del_rabo - 1)));
        assert!(cuerpo.body().contains(&format!(
            "\"veredicto\":\"{}\"",
            BubbleVerdict::Neutralized.label()
        )));
        assert!(equilibrado(cuerpo.body()));
        assert!(cuerpo.bytes() < MAX_SECTION_BYTES);

        // La puerta sigue entera: leer no drena burbujas ni regiones.
        assert_eq!(puerta.bubbles.len(), total);

        // Una carga limpia sí es inocua y la pasarela lo dice sin adornos.
        let limpia = pasarela(&[LIMPIA]);
        assert_eq!(
            limpia.bubbles.first().map(|bubble| bubble.verdict),
            Some(BubbleVerdict::Innocuous)
        );
        let Some(limpio) = exigir(section_gateway(&limpia)) else {
            return;
        };
        assert!(limpio.body().contains("\"inocuas\":1"));
        assert!(limpio.body().contains("\"neutralizadas\":0"));
        assert!(limpio.body().contains("\"estanca\":true"));
    }

    #[test]
    fn la_seccion_del_nucleo_refleja_la_soberania() {
        let core = nucleo();
        let Some(cuerpo) = exigir(section_kernel(&core)) else {
            return;
        };

        assert_eq!(cuerpo.kind(), SectionKind::Nucleo);
        assert!(cuerpo.body().contains("\"profundidad\":1"));
        assert!(cuerpo.body().contains("\"cumbre\":\""));
        assert!(cuerpo
            .body()
            .contains(&format!("\"memoria\":{}", core.memory.len())));
        assert!(cuerpo
            .body()
            .contains(&format!("\"regiones\":{}", core.regions.len())));
        assert!(cuerpo
            .body()
            .contains(&format!("\"instantaneas\":{}", core.timeline.stack().len())));
        assert!(cuerpo
            .body()
            .contains(&format!("\"deltas\":{}", core.timeline.deltas().len())));
        assert!(cuerpo
            .body()
            .contains(&format!("\"vivos\":{}", core.qubits.len())));
        assert!(cuerpo
            .body()
            .contains(&format!("\"colapsos\":{}", core.qubits.collapses())));
        assert!(cuerpo
            .body()
            .contains(&format!("\"nodos\":{}", core.mesh.len())));
        assert!(cuerpo
            .body()
            .contains(&format!("\"epoca\":{}", core.mesh.epoch())));
        assert!(cuerpo
            .body()
            .contains(&format!("\"generacion\":{}", core.mutator.generation())));
        assert!(cuerpo
            .body()
            .contains(&format!("\"total\":{}", core.mutator.axioms().count())));
        assert!(cuerpo.body().contains("\"certificado\":{\"presente\":true"));
        assert!(cuerpo.body().contains("\"etiqueta\":\"AST-Bara-génesis\""));
        assert!(cuerpo.body().contains("\"verificado\":true"));
        assert!(cuerpo.body().contains("\"log\":{\"eventos\":1"));
        assert!(cuerpo.body().contains("\"tolerados\":0"));
        assert!(cuerpo.body().contains("\"ultimo\":\"ZkVerified\""));
        // Un runtime virgen no tiene programa de metal: el hueco se declara.
        assert!(cuerpo.body().contains("\"metal\":null"));
        assert!(equilibrado(cuerpo.body()));
        assert!(cuerpo.bytes() < MAX_SECTION_BYTES);

        // Un núcleo recién nacido no tiene cumbre, certificado ni eventos: el
        // puente declara los huecos en vez de inventarlos.
        let Some(vacio) = exigir(section_kernel(&BaraRuntime::new())) else {
            return;
        };
        assert!(vacio.body().contains("\"profundidad\":0"));
        assert!(vacio.body().contains("\"cumbre\":null"));
        assert!(vacio.body().contains("\"certificado\":null"));
        assert!(vacio.body().contains("\"ultimo\":null"));
        assert!(vacio.body().contains("\"eventos\":0"));
        assert!(vacio.body().contains("\"regiones\":0"));
        assert_ne!(vacio.digest(), cuerpo.digest());
    }

    #[test]
    fn el_catalogo_dibuja_las_ranuras_canonicas() {
        let mut instantanea = Snapshot::new();
        let Some(identidad) = exigir(section_identity()) else {
            return;
        };
        assert!(instantanea.push(identidad).is_ok());
        let Some(pasarela_seccion) = exigir(section_gateway(&pasarela(&[HOSTIL]))) else {
            return;
        };
        assert!(instantanea.push(pasarela_seccion).is_ok());

        let catalogo = instantanea.catalog();
        assert!(equilibrado(&catalogo));
        assert_eq!(
            catalogo.matches("\"nombre\":").count(),
            SectionKind::ALL.len()
        );
        assert_eq!(
            catalogo.matches("\"orden\":").count(),
            SectionKind::ALL.len()
        );
        assert_eq!(catalogo.matches("\"presente\":true").count(), 2);
        assert_eq!(catalogo.matches("\"presente\":false").count(), 2);
        assert!(catalogo.contains("\"nombre\":\"identidad\""));
        assert!(catalogo.contains("\"nombre\":\"nucleo\""));

        assert_eq!(instantanea.len(), 2);
        assert!(!instantanea.is_complete());
        assert_eq!(
            instantanea.missing(),
            vec![SectionKind::Inmunidad, SectionKind::Nucleo]
        );
        assert!(instantanea.label_text().contains("identidad → pasarela"));

        let documento = instantanea.json();
        assert!(equilibrado(&documento));
        assert!(documento.contains("\"completa\":false"));
        // El cuerpo entra como valor, sin recomillarlo: JSON anidado de verdad.
        assert!(documento
            .contains("\"secciones\":{\"identidad\":{\"dominio\":\"bara:aether-omega:puente:v1\""));
        assert!(documento.contains("\"catalogo\":["));
        assert!(documento.contains(&format!(
            "\"manifiesto\":\"{}\"",
            Manifest::canon().fingerprint()
        )));
        assert!(documento.contains(&format!("\"huella\":\"{}\"", instantanea.fingerprint())));
        assert!(documento.contains(&format!("\"bytes\":{}", instantanea.bytes())));
    }
}
