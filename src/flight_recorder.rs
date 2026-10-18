//! # Registro de vuelo — caja negra de diagnóstico (`flight_recorder.rs`)
//!
//! La caja negra del kernel: un **búfer circular estático** donde quedan
//! grabados los eventos anómalos —rechazos perimetrales, colisiones de Belnap y
//! violaciones axiomáticas— con su marca lógica, su clase y la **huella** del
//! paquete que los disparó. Nunca guarda la carga: guarda su huella.
//!
//! ## Contrato de la caja negra
//! 1. **Memoria estática y acotada** — [`CAPACITY`] ranuras en un `static`; ni
//!    una asignación dinámica en el camino de escritura. El volcado
//!    ([`dump_records`]) sí reserva un `Vec`: es diagnóstico, no *runtime*.
//! 2. **Escritura sin bloqueo** — cada escritor toma un billete atómico
//!    (`fetch_add`), escribe su ranura y la publica con **un único** `store`
//!    `Release`. No hay mutex, ni `RwLock`, ni espera activa: el hilo de la
//!    pasarela nunca se detiene.
//! 3. **Desbordamiento circular** — al llenarse, la entrada más antigua se pisa.
//!    Se cuenta en [`Counters::overwritten`] y jamás produce un pánico.
//! 4. **Sólo lectura local** — [`inspect`] / [`render`] vuelcan el contenido
//!    para auditoría *post-mortem*. No hay sockets, ni puertos, ni telemetría
//!    saliente: la caja negra se lee en la máquina donde vive.
//! 5. **Huella, no carga** — `payload_hash` es el prefijo de 64 bits del
//!    SHA‑256 de los primeros [`FINGERPRINT_BYTES`] bytes. Nunca se copian datos
//!    crudos ni secretos y el coste del resumen queda acotado.
//!
//! ## Protocolo de publicación (por qué el lector no ve basura)
//! ```text
//!   escritor                                  lector
//!   ─────────────────────────────────────     ───────────────────────────────
//!   t = SEQ.fetch_add(1)          ← billete   t = SEQ.load(Acquire)
//!   ranura = t % CAPACITY                     para cada t de [max(0, t−CAP), t)
//!   guarda marca, clase, código, huella       sello₁ = stamp.load(Acquire)
//!   stamp.store(t+1, Release)     ← publica   si sello₁ == t+1: lee los campos
//!                                             sello₂ = stamp.load(Acquire)
//!                                             si sello₁ == sello₂: entrada válida
//! ```
//! El sello sólo cambia **al final**; si una ranura fue pisada mientras se leía,
//! el segundo sello no coincide y la entrada se descarta (se cuenta en
//! [`Inspection::skipped`]). La doble comprobación convierte una carrera de
//! sobrescritura en un descarte limpio, nunca en una lectura mezclada.
//!
//! ## Integración en el kernel
//! * [`crate::immunity_gateway`] — neutralización hostil
//!   ([`EventKind::PerimeterAlert`]), cuarentena ilegible y paradoja absorbida.
//! * [`crate::autopoietic::BelnapMatrix`] — colisiones `⊤∧⊥` / `∅`, violaciones
//!   estructurales (aridad, raíz, masas, guarda, tipo) y vetos de fusión.
//! * [`crate::autopoietic::SynapseGateway`] — rechazos de la puerta IPC con su
//!   código exacto.
//! * [`crate::autopoietic::AutopoieticMutator`] — propuestas rechazadas.
//!
//! ## Invariantes del módulo
//! 1. **Cero `unsafe`** (`#![forbid(unsafe_code)]`).
//! 2. **Cero pánicos** — ni `unwrap`, ni `expect`, ni indexación sin comprobar.
//! 3. **Determinismo** — el «reloj» es un contador lógico: no se lee el reloj de
//!    pared ni la dirección de ningún puntero.
//! 4. **Una sola fuente de verdad** — [`RECORDER`] es el registro global; las
//!    pruebas pueden instanciar [`FlightRecorder`] propios sin interferencias.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

use std::fmt::Write as _;
use std::mem::size_of;
use std::sync::atomic::{AtomicU16, AtomicU64, AtomicU8, Ordering};

use crate::crypto_native::sha256;

// ─────────────────────────────────────────────────────────────────────────
// Constantes del búfer
// ─────────────────────────────────────────────────────────────────────────

/// Ranuras del búfer circular. Fijo en tiempo de compilación: la caja negra no
/// crece con la carga ni reserva memoria en *runtime*.
pub const CAPACITY: usize = 1024;

/// Techo de bytes que se resumen en una huella.
///
/// La caja negra **no fotografía** la carga: resume un prefijo acotado. Así el
/// coste del registro es constante aunque llegue una bomba de 64 KiB y ninguna
/// carga sensible entra completa en el diagnóstico.
pub const FINGERPRINT_BYTES: usize = 4096;

/// Bytes que ocupa el anillo completo (ranuras + contadores), en memoria
/// estática.
pub const RING_BYTES: usize = CAPACITY * size_of::<Slot>();

// Invariante de compilación: la caja negra nunca compite por memoria con el
// núcleo. Si alguien engorda `Slot`, el build se detiene aquí.
const _: () = assert!(RING_BYTES <= 64 * 1024);

// ─────────────────────────────────────────────────────────────────────────
// Clasificación del evento
// ─────────────────────────────────────────────────────────────────────────

/// Clase de un evento de la caja negra.
///
/// Sólo se registran **anomalías**: lo inocuo no ocupa ranura. El código es
/// estable (viaja en el diagnóstico y en los informes *post-mortem*).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EventKind {
    /// `⚠` · carga hostil **neutralizada** por la pasarela de inmunidad.
    PerimeterAlert = 1,
    /// `⊘` · veredicto que **no alcanza el núcleo** (cuarentena, firma, aridad,
    /// fusión denegada…).
    VerdictRejected = 2,
    /// `⊤∧⊥` · colisión de Belnap: verdad y falsedad designadas a la vez.
    BelnapConflictBoth = 3,
    /// `∅` · colisión de Belnap: ni verdad ni falsedad (información insuficiente).
    BelnapConflictNeither = 4,
    /// `⟳` · sincronización o consulta cognitiva verificada por huella.
    CognitiveSync = 5,
}

impl EventKind {
    /// Las cinco clases en orden canónico.
    pub const ALL: [EventKind; 5] = [
        EventKind::PerimeterAlert,
        EventKind::VerdictRejected,
        EventKind::BelnapConflictBoth,
        EventKind::BelnapConflictNeither,
        EventKind::CognitiveSync,
    ];

    /// Código estable de la clase.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Clase a partir de su código; `None` si la ranura no contiene un código
    /// conocido (sólo puede ocurrir en una ranura corrupta).
    pub const fn from_code(code: u8) -> Option<EventKind> {
        match code {
            1 => Some(EventKind::PerimeterAlert),
            2 => Some(EventKind::VerdictRejected),
            3 => Some(EventKind::BelnapConflictBoth),
            4 => Some(EventKind::BelnapConflictNeither),
            5 => Some(EventKind::CognitiveSync),
            _ => None,
        }
    }

    /// Nombre ontológico.
    pub const fn label(self) -> &'static str {
        match self {
            EventKind::PerimeterAlert => "alerta perimetral",
            EventKind::VerdictRejected => "veredicto rechazado",
            EventKind::BelnapConflictBoth => "conflicto de Belnap ⊤∧⊥",
            EventKind::BelnapConflictNeither => "conflicto de Belnap ∅",
            EventKind::CognitiveSync => "sincronización cognitiva",
        }
    }

    /// Glifo de una línea para el volcado.
    pub const fn glyph(self) -> &'static str {
        match self {
            EventKind::PerimeterAlert => "⚠",
            EventKind::VerdictRejected => "⊘",
            EventKind::BelnapConflictBoth => "⊤∧⊥",
            EventKind::BelnapConflictNeither => "∅",
            EventKind::CognitiveSync => "⟳",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Código de violación: la regla exacta que se rompió
// ─────────────────────────────────────────────────────────────────────────

/// Identificador exacto de la regla axiomática, restricción de aridad o
/// condición de frontera violada.
///
/// Los códigos son **estables y numéricos**: un diagnóstico guardado hoy se lee
/// mañana sin tabla de traducción. [`ViolationCode::Unclassified`] existe para
/// no mentir cuando una regla todavía no tiene código propio.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ViolationCode {
    /// No se violó ninguna regla (evento informativo).
    None = 0,
    /// Marcas de ataque por encima del umbral de designación.
    PerimeterThreat = 1,
    /// La carga no es texto interpretable: cuarentena.
    IllegiblePayload = 2,
    /// Contradicción `⊤∧⊥` retenida sin explosión.
    ContradictionRetained = 3,
    /// Juicio indeterminado `∅`: falta información.
    IndeterminateVerdict = 4,
    /// Rama de parche sin ningún nodo.
    EmptyBranch = 5,
    /// Aridad por encima de `MAX_ARITY` (restricción de aridad).
    ArityExceeded = 6,
    /// Raíz *Shoresh* vacía.
    EmptyRoot = 7,
    /// La raíz no es triconsonántica.
    RootNotTriconsonantal = 8,
    /// Masa o riesgo fuera de `[0, 1]`.
    MassOutOfRange = 9,
    /// Riesgo alto sin el sello de guarda (`שמר`).
    HazardUnsealed = 10,
    /// Tipo declarado desconocido.
    UnknownType = 11,
    /// Violación estructural sin código específico.
    StructuralViolation = 12,
    /// Firma del marco IPC inválida.
    SignatureMismatch = 13,
    /// Secuencia IPC regresiva (*replay* manipulado).
    SequenceRegression = 14,
    /// Marco IPC por encima del techo.
    FrameTooLarge = 15,
    /// Marco IPC con forma ilegible.
    MalformedFrame = 16,
    /// El núcleo no verifica su propio ADN.
    KernelUnverified = 17,
    /// Evidencia de pruebas en rojo.
    TestsFailed = 18,
    /// Sin evidencia de pruebas: juicio indeterminado.
    NoEvidence = 19,
    /// La fusión se denegó sin una causa más específica.
    FusionDenied = 20,
    /// La auditoría estática *Shoresh* no pasa.
    AuditFailed = 21,
    /// El ADN del parche no corresponde a la clave soberana.
    DnaMismatch = 22,
    /// El núcleo base ya no es el auditado (CAS optimista).
    StaleCore = 23,
    /// Parche vacío: nada que fusionar.
    EmptyPatch = 24,
    /// Escritura pedida con una capacidad que no la permite.
    WriteDenied = 25,
    /// La célula está en cuarentena, sellada o no existe.
    CellState = 26,
    /// La célula alcanzó su techo de nodos.
    CellCapacity = 27,
    /// Nodo inexistente en la célula.
    UnknownNode = 28,
    /// Propuesta inexistente.
    UnknownProposal = 29,
    /// Presupuesto de operaciones agotado.
    BudgetExceeded = 30,
    /// Regla violada sin código propio (nunca se inventa una causa).
    Unclassified = 0xFFFF,
}

impl ViolationCode {
    /// Todos los códigos con nombre, en orden canónico.
    pub const ALL: [ViolationCode; 32] = [
        ViolationCode::None,
        ViolationCode::PerimeterThreat,
        ViolationCode::IllegiblePayload,
        ViolationCode::ContradictionRetained,
        ViolationCode::IndeterminateVerdict,
        ViolationCode::EmptyBranch,
        ViolationCode::ArityExceeded,
        ViolationCode::EmptyRoot,
        ViolationCode::RootNotTriconsonantal,
        ViolationCode::MassOutOfRange,
        ViolationCode::HazardUnsealed,
        ViolationCode::UnknownType,
        ViolationCode::StructuralViolation,
        ViolationCode::SignatureMismatch,
        ViolationCode::SequenceRegression,
        ViolationCode::FrameTooLarge,
        ViolationCode::MalformedFrame,
        ViolationCode::KernelUnverified,
        ViolationCode::TestsFailed,
        ViolationCode::NoEvidence,
        ViolationCode::FusionDenied,
        ViolationCode::AuditFailed,
        ViolationCode::DnaMismatch,
        ViolationCode::StaleCore,
        ViolationCode::EmptyPatch,
        ViolationCode::WriteDenied,
        ViolationCode::CellState,
        ViolationCode::CellCapacity,
        ViolationCode::UnknownNode,
        ViolationCode::UnknownProposal,
        ViolationCode::BudgetExceeded,
        ViolationCode::Unclassified,
    ];

    /// Código numérico estable.
    pub const fn code(self) -> u16 {
        self as u16
    }

    /// Código a partir de su número; `None` si no corresponde a ninguna regla
    /// conocida (ranura corrupta: no se inventa una causa).
    pub const fn from_code(code: u16) -> Option<ViolationCode> {
        match code {
            0 => Some(ViolationCode::None),
            1 => Some(ViolationCode::PerimeterThreat),
            2 => Some(ViolationCode::IllegiblePayload),
            3 => Some(ViolationCode::ContradictionRetained),
            4 => Some(ViolationCode::IndeterminateVerdict),
            5 => Some(ViolationCode::EmptyBranch),
            6 => Some(ViolationCode::ArityExceeded),
            7 => Some(ViolationCode::EmptyRoot),
            8 => Some(ViolationCode::RootNotTriconsonantal),
            9 => Some(ViolationCode::MassOutOfRange),
            10 => Some(ViolationCode::HazardUnsealed),
            11 => Some(ViolationCode::UnknownType),
            12 => Some(ViolationCode::StructuralViolation),
            13 => Some(ViolationCode::SignatureMismatch),
            14 => Some(ViolationCode::SequenceRegression),
            15 => Some(ViolationCode::FrameTooLarge),
            16 => Some(ViolationCode::MalformedFrame),
            17 => Some(ViolationCode::KernelUnverified),
            18 => Some(ViolationCode::TestsFailed),
            19 => Some(ViolationCode::NoEvidence),
            20 => Some(ViolationCode::FusionDenied),
            21 => Some(ViolationCode::AuditFailed),
            22 => Some(ViolationCode::DnaMismatch),
            23 => Some(ViolationCode::StaleCore),
            24 => Some(ViolationCode::EmptyPatch),
            25 => Some(ViolationCode::WriteDenied),
            26 => Some(ViolationCode::CellState),
            27 => Some(ViolationCode::CellCapacity),
            28 => Some(ViolationCode::UnknownNode),
            29 => Some(ViolationCode::UnknownProposal),
            30 => Some(ViolationCode::BudgetExceeded),
            0xFFFF => Some(ViolationCode::Unclassified),
            _ => None,
        }
    }
}

impl ViolationCode {
    /// Nombre legible de la regla.
    pub const fn label(self) -> &'static str {
        match self {
            ViolationCode::None => "sin violación",
            ViolationCode::PerimeterThreat => "amenaza perimetral sobre el umbral",
            ViolationCode::IllegiblePayload => "carga ilegible (cuarentena)",
            ViolationCode::ContradictionRetained => "contradicción retenida",
            ViolationCode::IndeterminateVerdict => "juicio indeterminado",
            ViolationCode::EmptyBranch => "rama sin nodos",
            ViolationCode::ArityExceeded => "aridad por encima del tope",
            ViolationCode::EmptyRoot => "raíz vacía",
            ViolationCode::RootNotTriconsonantal => "raíz no triconsonántica",
            ViolationCode::MassOutOfRange => "masa o riesgo fuera de [0,1]",
            ViolationCode::HazardUnsealed => "riesgo alto sin sello de guarda",
            ViolationCode::UnknownType => "tipo declarado desconocido",
            ViolationCode::StructuralViolation => "violación estructural",
            ViolationCode::SignatureMismatch => "firma inválida",
            ViolationCode::SequenceRegression => "secuencia regresiva",
            ViolationCode::FrameTooLarge => "marco por encima del techo",
            ViolationCode::MalformedFrame => "marco malformado",
            ViolationCode::KernelUnverified => "núcleo sin verificar",
            ViolationCode::TestsFailed => "pruebas en rojo",
            ViolationCode::NoEvidence => "sin evidencia de pruebas",
            ViolationCode::FusionDenied => "fusión denegada",
            ViolationCode::AuditFailed => "auditoría estática fallida",
            ViolationCode::DnaMismatch => "ADN del parche no verifica",
            ViolationCode::StaleCore => "núcleo base obsoleto",
            ViolationCode::EmptyPatch => "parche vacío",
            ViolationCode::WriteDenied => "escritura denegada",
            ViolationCode::CellState => "célula no disponible",
            ViolationCode::CellCapacity => "célula llena",
            ViolationCode::UnknownNode => "nodo inexistente",
            ViolationCode::UnknownProposal => "propuesta inexistente",
            ViolationCode::BudgetExceeded => "presupuesto agotado",
            ViolationCode::Unclassified => "regla sin código propio",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Ranura y entrada del registro
// ─────────────────────────────────────────────────────────────────────────

/// Ranura del anillo: cinco átomos, sin punteros ni `Vec`.
///
/// `stamp` es el **testigo de publicación**: vale `0` mientras la ranura nunca
/// se escribió y, tras publicar, vale `billete + 1`. Es el único campo que el
/// lector necesita comprobar dos veces.
#[derive(Debug)]
struct Slot {
    stamp: AtomicU64,
    timestamp: AtomicU64,
    event: AtomicU8,
    violation: AtomicU16,
    payload: AtomicU64,
}

impl Slot {
    /// Ranura virgen, evaluable en contexto `const` (requisito del `static`).
    const fn empty() -> Self {
        Slot {
            stamp: AtomicU64::new(0),
            timestamp: AtomicU64::new(0),
            event: AtomicU8::new(0),
            violation: AtomicU16::new(0),
            payload: AtomicU64::new(0),
        }
    }
}

/// Entrada atómica de la caja negra: lo único que se conserva de un evento.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogEntry {
    /// Billete del anillo: orden total de llegada y posición de la ranura.
    pub sequence: u64,
    /// Marca lógica monótona. El reloj del registrador avanza un tic por
    /// evento, así que coincide con `sequence`; se conserva como campo propio
    /// para que el esquema no dependa de esa coincidencia.
    pub timestamp: u64,
    /// Clase del evento.
    pub event: EventKind,
    /// Regla exacta que se violó.
    pub violation: ViolationCode,
    /// Huella de 64 bits del paquete que disparó el evento (nunca la carga).
    pub payload_hash: u64,
}

impl LogEntry {
    /// Huella en hexadecimal de 16 dígitos.
    pub fn hex(&self) -> String {
        format!("{:016x}", self.payload_hash)
    }

    /// ¿La entrada describe una colisión de Belnap?
    pub fn is_conflict(&self) -> bool {
        matches!(
            self.event,
            EventKind::BelnapConflictBoth | EventKind::BelnapConflictNeither
        )
    }

    /// Línea de diagnóstico.
    pub fn label(&self) -> String {
        format!(
            "#{:016} {} {} ⟦{}⟧ · huella {}",
            self.sequence,
            self.event.glyph(),
            self.event.label(),
            self.violation.label(),
            self.hex()
        )
    }
}

/// Contadores del anillo (instantánea coherente de una lectura).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counters {
    /// Ranuras del búfer.
    pub capacity: usize,
    /// Billetes repartidos: escrituras intentadas desde el arranque.
    pub reserved: u64,
    /// Entradas publicadas (visibles para el lector).
    pub published: u64,
    /// Entradas antiguas pisadas por el desbordamiento circular:
    /// `reserved − capacity` una vez lleno. Nunca hay pánico ni bloqueo.
    pub overwritten: u64,
    /// Escrituras reservadas todavía sin publicar (testigos en vuelo).
    pub in_flight: u64,
}

impl Counters {
    /// ¿El anillo ya dio al menos una vuelta?
    pub fn is_full(&self) -> bool {
        self.reserved >= self.capacity as u64
    }

    /// Ranuras ocupadas ahora mismo.
    pub fn occupied(&self) -> usize {
        self.reserved.min(self.capacity as u64) as usize
    }
}

/// Volcado de sólo lectura para auditoría *post-mortem* local.
///
/// `entries` va del evento **más antiguo** al más reciente. `skipped` cuenta las
/// ranuras descartadas por una carrera de sobrescritura: una entrada omitida es
/// preferible a una entrada inventada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inspection {
    /// Contadores del anillo en el instante del volcado.
    pub counters: Counters,
    /// Entradas válidas, en orden cronológico.
    pub entries: Vec<LogEntry>,
    /// Ranuras descartadas por la doble comprobación del sello.
    pub skipped: u64,
}

impl Inspection {
    /// Entradas de una clase concreta.
    pub fn of_kind(&self, kind: EventKind) -> Vec<LogEntry> {
        self.entries
            .iter()
            .copied()
            .filter(|entry| entry.event == kind)
            .collect()
    }

    /// Entradas que violaron una regla concreta.
    pub fn of_violation(&self, code: ViolationCode) -> Vec<LogEntry> {
        self.entries
            .iter()
            .copied()
            .filter(|entry| entry.violation == code)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────
// El registrador
// ─────────────────────────────────────────────────────────────────────────

/// Caja negra instanciable: el anillo, sus dos contadores y nada más.
///
/// Todos sus métodos de escritura toman `&self`: el estado vive en átomos, de
/// modo que [`RECORDER`] puede ser un `static` compartido por todos los hilos
/// sin `Mutex` ni `RwLock`. Una instancia propia (pruebas, herramientas de
/// diagnóstico) es exactamente el mismo tipo: no hay dos implementaciones.
pub struct FlightRecorder {
    slots: [Slot; CAPACITY],
    sequence: AtomicU64,
    published: AtomicU64,
}

impl FlightRecorder {
    /// Registro vacío en memoria estática; `const` para poder ser `static`.
    pub const fn new() -> Self {
        FlightRecorder {
            slots: [const { Slot::empty() }; CAPACITY],
            sequence: AtomicU64::new(0),
            published: AtomicU64::new(0),
        }
    }

    /// Registra un evento con la huella de la carga (prefijo acotado).
    pub fn record(&self, event: EventKind, violation: ViolationCode, payload: &[u8]) -> u64 {
        self.record_fingerprint(event, violation, fingerprint(payload))
    }

    /// Registra un evento con la huella de un digest **ya calculado**.
    ///
    /// Es la ruta de la pasarela: reutiliza el SHA‑256 que ya se hizo para el
    /// holograma, de modo que la caja negra no vuelve a leer la carga.
    pub fn record_digest(
        &self,
        event: EventKind,
        violation: ViolationCode,
        digest: &[u8; 32],
    ) -> u64 {
        self.record_fingerprint(event, violation, digest_fingerprint(digest))
    }

    /// Registra un evento con una huella de 64 bits explícita.
    ///
    /// Es la ruta caliente: cuatro `store` relajados y **un** `store` `Release`
    /// que publica la ranura. Sin asignaciones, sin cerrojos y sin espera.
    pub fn record_fingerprint(
        &self,
        event: EventKind,
        violation: ViolationCode,
        payload_hash: u64,
    ) -> u64 {
        let ticket = self.sequence.fetch_add(1, Ordering::Relaxed);
        if let Some(slot) = self.slots.get((ticket % CAPACITY as u64) as usize) {
            slot.timestamp.store(ticket, Ordering::Relaxed);
            slot.event.store(event.code(), Ordering::Relaxed);
            slot.violation.store(violation.code(), Ordering::Relaxed);
            slot.payload.store(payload_hash, Ordering::Relaxed);
            // Publicación: a partir de aquí la ranura es legible.
            slot.stamp
                .store(ticket.saturating_add(1), Ordering::Release);
        }
        self.published.fetch_add(1, Ordering::Relaxed);
        ticket
    }

    /// Marca de lectura: los eventos con `sequence >= marca` son los nuevos.
    pub fn mark(&self) -> u64 {
        self.sequence.load(Ordering::Acquire)
    }

    /// Entradas ocupadas ahora mismo (sin volcar).
    pub fn len(&self) -> usize {
        self.counters().occupied()
    }

    /// ¿No hay ninguna entrada?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Contadores del anillo.
    pub fn counters(&self) -> Counters {
        let reserved = self.sequence.load(Ordering::Acquire);
        let published = self.published.load(Ordering::Acquire);
        Counters {
            capacity: CAPACITY,
            reserved,
            published,
            overwritten: reserved.saturating_sub(CAPACITY as u64),
            in_flight: reserved.saturating_sub(published),
        }
    }
}

impl Default for FlightRecorder {
    fn default() -> Self {
        FlightRecorder::new()
    }
}

impl FlightRecorder {
    /// Lee una ranura publicada, con doble comprobación del sello.
    fn read_slot(&self, ticket: u64) -> Option<LogEntry> {
        let slot = self.slots.get((ticket % CAPACITY as u64) as usize)?;
        let expected = ticket.saturating_add(1);
        let stamp = slot.stamp.load(Ordering::Acquire);
        if stamp != expected {
            // Ranura aún sin publicar o ya pisada por un billete más nuevo.
            return None;
        }
        let timestamp = slot.timestamp.load(Ordering::Relaxed);
        let event = EventKind::from_code(slot.event.load(Ordering::Relaxed))?;
        let violation = ViolationCode::from_code(slot.violation.load(Ordering::Relaxed))?;
        let payload_hash = slot.payload.load(Ordering::Relaxed);
        // El sello sólo se escribe al final: si cambió mientras leíamos, la
        // entrada pudo mezclarse y se descarta en lugar de inventarse.
        if slot.stamp.load(Ordering::Acquire) != stamp || timestamp != ticket {
            return None;
        }
        Some(LogEntry {
            sequence: ticket,
            timestamp,
            event,
            violation,
            payload_hash,
        })
    }

    /// Instantánea completa: contadores, entradas válidas y descartes.
    fn collect(&self) -> (Counters, Vec<LogEntry>, u64) {
        let reserved = self.sequence.load(Ordering::Acquire);
        let start = reserved.saturating_sub(CAPACITY as u64);
        let mut entries = Vec::with_capacity((reserved - start) as usize);
        let mut skipped = 0_u64;
        for ticket in start..reserved {
            match self.read_slot(ticket) {
                Some(entry) => entries.push(entry),
                None => skipped = skipped.saturating_add(1),
            }
        }
        let published = self.published.load(Ordering::Acquire);
        let counters = Counters {
            capacity: CAPACITY,
            reserved,
            published,
            overwritten: reserved.saturating_sub(CAPACITY as u64),
            in_flight: reserved.saturating_sub(published),
        };
        (counters, entries, skipped)
    }

    /// Volcado de sólo lectura, del evento **más antiguo** al más reciente.
    pub fn dump(&self) -> Vec<LogEntry> {
        self.collect().1
    }

    /// Últimas `limit` entradas, en orden cronológico.
    pub fn latest(&self, limit: usize) -> Vec<LogEntry> {
        let mut entries = self.dump();
        let keep = entries.len().saturating_sub(limit);
        entries.split_off(keep)
    }

    /// Entradas posteriores a una marca de lectura ([`FlightRecorder::mark`]).
    pub fn entries_since(&self, mark: u64) -> Vec<LogEntry> {
        self.dump()
            .into_iter()
            .filter(|entry| entry.sequence >= mark)
            .collect()
    }

    /// Volcado estructurado para auditoría local.
    pub fn inspect(&self) -> Inspection {
        let (counters, entries, skipped) = self.collect();
        Inspection {
            counters,
            entries,
            skipped,
        }
    }

    /// Render legible de la caja negra (sólo texto local, sin red).
    pub fn render(&self) -> String {
        let inspection = self.inspect();
        let counters = inspection.counters;
        let mut out = String::with_capacity(192 + inspection.entries.len() * 96);
        let _ = writeln!(
            out,
            "BARA · caja negra · capacidad {} · reservadas {} · publicadas {} · pisadas {} · en vuelo {}",
            counters.capacity,
            counters.reserved,
            counters.published,
            counters.overwritten,
            counters.in_flight
        );
        for entry in &inspection.entries {
            let _ = writeln!(out, "  {}", entry.label());
        }
        if inspection.skipped > 0 {
            let _ = writeln!(
                out,
                "  ranuras descartadas por carrera de escritura: {}",
                inspection.skipped
            );
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Registro global (la caja negra del kernel)
// ─────────────────────────────────────────────────────────────────────────

/// La caja negra del proceso: un `static` sin `Mutex`.
///
/// Es la instancia que usan las pasarelas y el retículo. Las pruebas pueden
/// crear su propio [`FlightRecorder`] para no depender del tráfico paralelo.
pub static RECORDER: FlightRecorder = FlightRecorder::new();

/// Huella de 64 bits de una carga: prefijo del SHA‑256 de sus primeros
/// [`FINGERPRINT_BYTES`] bytes, en orden little‑endian.
pub fn fingerprint(payload: &[u8]) -> u64 {
    let bounded = if payload.len() > FINGERPRINT_BYTES {
        &payload[..FINGERPRINT_BYTES]
    } else {
        payload
    };
    digest_fingerprint(&sha256(bounded))
}

/// Huella de 64 bits de un digest SHA‑256 ya calculado.
pub fn digest_fingerprint(digest: &[u8; 32]) -> u64 {
    u64::from_le_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ])
}

/// Mezcla biyectiva de 64 bits (finalizador SplitMix64).
///
/// Sirve para derivar una huella estable de un entero pequeño (un
/// identificador de propuesta) sin pagar un SHA‑256.
pub fn mix(value: u64) -> u64 {
    let mut z = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Marca de lectura del registro global.
pub fn mark() -> u64 {
    RECORDER.mark()
}

/// Registra un evento en el registro global.
pub fn record(event: EventKind, violation: ViolationCode, payload: &[u8]) -> u64 {
    RECORDER.record(event, violation, payload)
}

/// Registra un evento con un digest ya calculado.
pub fn record_digest(event: EventKind, violation: ViolationCode, digest: &[u8; 32]) -> u64 {
    RECORDER.record_digest(event, violation, digest)
}

/// Registra un evento con una huella explícita.
pub fn record_fingerprint(event: EventKind, violation: ViolationCode, payload_hash: u64) -> u64 {
    RECORDER.record_fingerprint(event, violation, payload_hash)
}

/// Contadores del registro global.
pub fn counters() -> Counters {
    RECORDER.counters()
}

/// Volcado del registro global, del más antiguo al más reciente.
pub fn dump_records() -> Vec<LogEntry> {
    RECORDER.dump()
}

/// Entradas del registro global posteriores a `mark`.
pub fn entries_since(mark: u64) -> Vec<LogEntry> {
    RECORDER.entries_since(mark)
}

/// Últimas entradas del registro global.
pub fn latest(limit: usize) -> Vec<LogEntry> {
    RECORDER.latest(limit)
}

/// Inspección estructurada del registro global.
pub fn inspect() -> Inspection {
    RECORDER.inspect()
}

/// Render legible del registro global.
pub fn render() -> String {
    RECORDER.render()
}

// ─────────────────────────────────────────────────────────────────────────
// Pruebas del módulo
// ─────────────────────────────────────────────────────────────────────────
//
// Cada prueba usa su propia instancia: el registro global recibe el tráfico de
// toda la suite en paralelo y no sirve para aserciones exactas.

#[cfg(test)]
mod pruebas {
    use super::*;

    use std::sync::Arc;

    fn exigir_send_sync<T: Send + Sync>() {}

    #[test]
    fn el_anillo_es_estatico_acotado_y_compartible() {
        let slot = size_of::<Slot>();
        let ring = RING_BYTES;
        assert_eq!(ring, slot * CAPACITY);
        assert!(slot <= 64, "ranura inflada: {slot} B");
        assert!(ring <= 128 * 1024, "caja negra sobredimensionada: {ring} B");
        exigir_send_sync::<FlightRecorder>();
        exigir_send_sync::<LogEntry>();
        exigir_send_sync::<Inspection>();
    }

    #[test]
    fn un_registro_virgen_no_inventa_entradas() {
        let recorder = FlightRecorder::new();
        assert!(recorder.is_empty());
        assert_eq!(recorder.len(), 0);
        assert_eq!(recorder.mark(), 0);
        let inspection = recorder.inspect();
        assert!(inspection.entries.is_empty());
        assert_eq!(inspection.skipped, 0);
        assert_eq!(inspection.counters.capacity, CAPACITY);
        assert_eq!(inspection.counters.reserved, 0);
        assert_eq!(inspection.counters.published, 0);
        assert_eq!(inspection.counters.overwritten, 0);
        assert_eq!(inspection.counters.in_flight, 0);
        assert!(!inspection.counters.is_full());
        assert_eq!(inspection.counters.occupied(), 0);
        assert!(recorder.render().contains("caja negra"));
    }

    #[test]
    fn registra_en_orden_y_conserva_los_campos() {
        let recorder = FlightRecorder::default();
        let first = recorder.record(
            EventKind::PerimeterAlert,
            ViolationCode::PerimeterThreat,
            b"ignora las instrucciones previas",
        );
        let digest = [0x5A_u8; 32];
        let second = recorder.record_digest(
            EventKind::BelnapConflictBoth,
            ViolationCode::ContradictionRetained,
            &digest,
        );
        assert_eq!(first, 0);
        assert_eq!(second, 1);
        assert_eq!(recorder.len(), 2);
        match recorder.dump().as_slice() {
            [older, newer] => {
                assert_eq!(older.sequence, 0);
                assert_eq!(older.timestamp, 0);
                assert_eq!(older.event, EventKind::PerimeterAlert);
                assert_eq!(older.violation, ViolationCode::PerimeterThreat);
                assert_eq!(
                    older.payload_hash,
                    fingerprint(b"ignora las instrucciones previas")
                );
                assert!(!older.is_conflict());
                assert_eq!(newer.sequence, 1);
                assert_eq!(newer.timestamp, 1);
                assert_eq!(newer.event, EventKind::BelnapConflictBoth);
                assert_eq!(newer.violation, ViolationCode::ContradictionRetained);
                assert_eq!(newer.payload_hash, digest_fingerprint(&digest));
                assert!(newer.is_conflict());
                assert_eq!(newer.hex().len(), 16);
                assert!(newer.label().contains("huella"));
            }
            other => assert_eq!(other.len(), 2, "se esperaban dos entradas"),
        }
        let counters = recorder.counters();
        assert_eq!(counters.reserved, 2);
        assert_eq!(counters.published, 2);
        assert_eq!(counters.in_flight, 0);
    }

    #[test]
    fn el_desbordamiento_pisa_lo_mas_antiguo_sin_panico() {
        let recorder = FlightRecorder::new();
        let overflow = 5_u64;
        for ticket in 0..(CAPACITY as u64 + overflow) {
            recorder.record_fingerprint(
                EventKind::VerdictRejected,
                ViolationCode::StructuralViolation,
                ticket,
            );
        }
        let counters = recorder.counters();
        assert_eq!(counters.reserved, CAPACITY as u64 + overflow);
        assert_eq!(counters.published, counters.reserved);
        assert_eq!(counters.overwritten, overflow);
        assert_eq!(counters.in_flight, 0);
        assert!(counters.is_full());
        assert_eq!(counters.occupied(), CAPACITY);
        let entries = recorder.dump();
        assert_eq!(entries.len(), CAPACITY);
        match (entries.first(), entries.last()) {
            (Some(oldest), Some(newest)) => {
                assert_eq!(oldest.sequence, overflow);
                assert_eq!(newest.sequence, CAPACITY as u64 + overflow - 1);
                assert_eq!(newest.payload_hash, CAPACITY as u64 + overflow - 1);
            }
            _ => assert_eq!(entries.len(), 0, "el anillo no debía estar vacío"),
        }
        for pair in entries.windows(2) {
            if let [left, right] = pair {
                assert_eq!(right.sequence, left.sequence + 1, "hueco en el anillo");
            }
        }
    }

    #[test]
    fn escritores_concurrentes_no_rompen_el_anillo() {
        const WRITERS: u64 = 8;
        const PER_WRITER: u64 = 400;
        const TOTAL: u64 = WRITERS * PER_WRITER;
        let recorder = Arc::new(FlightRecorder::new());
        let mut handles = Vec::new();
        for writer in 0..WRITERS {
            let sink = Arc::clone(&recorder);
            handles.push(std::thread::spawn(move || {
                for index in 0..PER_WRITER {
                    sink.record_fingerprint(
                        EventKind::VerdictRejected,
                        ViolationCode::BudgetExceeded,
                        (writer << 32) | index,
                    );
                }
            }));
        }
        for handle in handles {
            assert!(handle.join().is_ok(), "un escritor entró en pánico");
        }
        let counters = recorder.counters();
        assert_eq!(counters.reserved, TOTAL);
        assert_eq!(counters.published, TOTAL);
        assert_eq!(counters.overwritten, TOTAL - CAPACITY as u64);
        assert_eq!(counters.in_flight, 0);
        let inspection = recorder.inspect();
        assert_eq!(
            inspection.skipped, 0,
            "sin escritores activos no hay carreras"
        );
        assert_eq!(inspection.entries.len(), CAPACITY);
        match inspection.entries.first() {
            Some(oldest) => assert_eq!(oldest.sequence, TOTAL - CAPACITY as u64),
            None => assert_eq!(
                inspection.entries.len(),
                0,
                "el anillo no debía estar vacío"
            ),
        }
        match inspection.entries.last() {
            Some(newest) => assert_eq!(newest.sequence, TOTAL - 1),
            None => assert_eq!(
                inspection.entries.len(),
                0,
                "el anillo no debía estar vacío"
            ),
        }
        for entry in &inspection.entries {
            assert_eq!(entry.event, EventKind::VerdictRejected);
            assert_eq!(entry.violation, ViolationCode::BudgetExceeded);
            assert_eq!(entry.timestamp, entry.sequence);
        }
        for pair in inspection.entries.windows(2) {
            if let [left, right] = pair {
                assert_eq!(right.sequence, left.sequence + 1, "hueco en el anillo");
            }
        }
    }

    #[test]
    fn las_marcas_aislan_la_ventana_de_lectura() {
        let recorder = FlightRecorder::new();
        recorder.record_fingerprint(EventKind::PerimeterAlert, ViolationCode::PerimeterThreat, 1);
        let mark = recorder.mark();
        assert_eq!(mark, 1);
        for hash in 2..=4 {
            recorder.record_fingerprint(
                EventKind::BelnapConflictNeither,
                ViolationCode::IndeterminateVerdict,
                hash,
            );
        }
        let since = recorder.entries_since(mark);
        assert_eq!(since.len(), 3);
        assert_eq!(since.first().map(|entry| entry.sequence), Some(1));
        let latest = recorder.latest(2);
        assert_eq!(latest.len(), 2);
        assert_eq!(latest.last().map(|entry| entry.sequence), Some(3));
        assert_eq!(recorder.latest(0).len(), 0);
        assert_eq!(recorder.latest(99).len(), 4);
        let inspection = recorder.inspect();
        assert_eq!(
            inspection.of_kind(EventKind::BelnapConflictNeither).len(),
            3
        );
        assert_eq!(
            inspection
                .of_violation(ViolationCode::PerimeterThreat)
                .len(),
            1
        );
        assert_eq!(inspection.of_kind(EventKind::BelnapConflictBoth).len(), 0);
        let rendered = recorder.render();
        assert!(rendered.contains("alerta perimetral"));
        assert!(rendered.contains("conflicto de Belnap ∅"));
        assert!(!rendered.contains("descartadas"));
    }

    #[test]
    fn la_huella_es_estable_y_solo_resume_un_prefijo() {
        let short = fingerprint(b"shoresh");
        assert_eq!(short, fingerprint(b"shoresh"));
        assert_ne!(short, fingerprint(b"shoresh "));
        let mut long = vec![0xAB_u8; FINGERPRINT_BYTES + 512];
        let base = fingerprint(&long);
        if let Some(byte) = long.get_mut(FINGERPRINT_BYTES + 1) {
            *byte = 0xCD;
        }
        assert_eq!(
            base,
            fingerprint(&long),
            "el sufijo no debe entrar en la huella"
        );
        assert_eq!(fingerprint(b""), digest_fingerprint(&sha256(b"")));
        assert_eq!(mix(7), mix(7));
        assert_ne!(mix(7), mix(8));
    }

    #[test]
    fn los_codigos_sobreviven_al_viaje_de_ida_y_vuelta() {
        for event in EventKind::ALL {
            assert_eq!(EventKind::from_code(event.code()), Some(event));
            assert!(!event.label().is_empty());
            assert!(!event.glyph().is_empty());
        }
        assert_eq!(EventKind::from_code(0), None);
        assert_eq!(EventKind::from_code(6), None);
        for code in ViolationCode::ALL {
            assert_eq!(
                ViolationCode::from_code(code.code()),
                Some(code),
                "código {}",
                code.code()
            );
            assert!(!code.label().is_empty());
        }
        assert_eq!(ViolationCode::from_code(31), None);
        assert_eq!(ViolationCode::Unclassified.code(), 0xFFFF);
        assert_eq!(ViolationCode::ALL.len(), 32);
    }
}
