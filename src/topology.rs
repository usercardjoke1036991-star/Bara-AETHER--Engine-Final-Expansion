//! # Enrutamiento topológico estático y contracción de memoria (Tzimtzum)
//!
//! Este módulo resuelve **dónde** circula la información dentro del kernel y
//! **cómo se comprime** al cruzar de una capa a otra. Ambas cosas se deciden
//! *antes de ejecutar nada*: el enrutamiento vive en el sistema de tipos y la
//! contracción vive en el *layout* de memoria.
//!
//! ```text
//!   nivel 0  Sovereign ──┐  FixedRoute<Sovereign, Periphery>  (0 bytes)
//!   nivel 1  Periphery ◀─┘──┬  FixedRoute<Periphery, Cell>     (0 bytes)
//!   nivel 2  Cell      ◀────┘──┬  FixedRoute<Cell, Observer>   (0 bytes)
//!   nivel 3  Observer  ◀───────┘
//!            │            │              │
//!            ▼            ▼              ▼
//!        Contracted   Contracted     Contracted      ← bloque Tzimtzum contiguo
//!        [Row; n]     [Row; n]       [Row; n]          (64 B por fila = 1 línea L1)
//! ```
//!
//! ## FASE 0.1 — Canales fijos, sin tabla de rutas
//! * [`FixedRoute`] es un tipo genérico **ZST**: `size_of::<FixedRoute<A, B>>()`
//!   es `0` y su coste de construcción es nulo. No hay `HashMap` de destinos, ni
//!   `match` sobre identificadores, ni cola genérica: la arista es el tipo.
//! * Las capas son los niveles [`Rung`] del kernel ([`Sovereign`],
//!   [`Periphery`], [`Cell`], [`Observer`]). Cada una declara su `Above` y su
//!   `Below`, y `FixedRoute<From, To>` sólo existe cuando
//!   `From::Below = To` **y** `To::Above = From`. Esa doble igualdad es lo que
//!   hace imposible expresar un ciclo: `FixedRoute<Cell, Sovereign>` no compila
//!   (`Cell::Below` es `Observer`), así que la unidireccionalidad descendente no
//!   es una convención revisable, es una propiedad del tipo.
//! * [`Spine`] encadena los tres descensos del kernel y sigue siendo ZST: el
//!   procesador no recorre ninguna estructura para atravesarlo.
//!
//! ## FASE 0.2 — Contracción por Tzimtzum
//! * [`Record`] es el átomo que cruza capas: `#[repr(C)]` con los campos
//!   ordenados por tamaño descendente (`u64`, `u32`, `u16`, `u8`, `u8`) para que
//!   la suma de sus campos **sea** su tamaño: `16` bytes exactos, sin huecos ni
//!   relleno de cola.
//! * [`Row`] agrupa [`LANES`] registros: `4 × 16 = 64` bytes, exactamente una
//!   línea de caché L1. Contraer un AST en filas es, literalmente, convertirlo en
//!   líneas de caché.
//! * La precisión se paga con cuantización explícita ([`quantize`]): las masas y
//!   el riesgo pasan a `u16` de punto fijo. La contracción es **idempotente**
//!   (`contracted()` dos veces devuelve el mismo bloque y la misma huella), lo
//!   que la hace segura en cualquier punto de la jerarquía.
//! * [`Contracted`] es el sobre contiguo que transporta las filas (acotado por
//!   [`WIRE_BYTES`]) con huella [`Contracted::digest`] calculada una sola vez.
//!
//! ## Invariantes del módulo
//! 1. **Cero `unsafe`** (`#![forbid(unsafe_code)]`).
//! 2. **Totalidad (axioma A1)** — ni `unwrap`, ni `expect`, ni `panic`: lo que no
//!    cabe en el bloque se cuenta y se descarta ([`ContractStats::spilled`]).
//! 3. **Determinismo** — sólo hashes SHA‑256 y punto fijo; ninguna decisión
//!    depende de la dirección de un puntero ni del reloj.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

use std::marker::PhantomData;
use std::mem::{align_of, size_of};

use crate::ast_dna::{self, short_hex};
use crate::crypto_native::sha256;
use crate::ffi_ingest::ShoreshNode;

// ─────────────────────────────────────────────────────────────────────────
// Constantes de layout
// ─────────────────────────────────────────────────────────────────────────

/// Tamaño canónico de una línea de caché L1 en las arquitecturas objetivo.
pub const CACHE_LINE: usize = 64;

/// Bytes exactos de un [`Record`] contraído (`u64 + u32 + u16 + u8 + u8`).
pub const RECORD_BYTES: usize = 16;

/// Registros por fila: `CACHE_LINE / RECORD_BYTES`.
pub const LANES: usize = CACHE_LINE / RECORD_BYTES;

/// Capacidad del sobre contraído, en bytes (ocho filas de caché).
pub const WIRE_BYTES: usize = CACHE_LINE * 8;

/// Escala del punto fijo usado para contraer masas y riesgo a `u16`.
pub const QUANT_SCALE: f64 = 65535.0;

/// Cuantiza un valor real en `[0, 1]` a punto fijo `u16`.
///
/// Es **total**: `NaN` y los infinitos se recortan a `0`, y cualquier valor
/// fuera de rango se satura. La cuantización es la operación que paga el coste
/// de la contracción: se pierde precisión sub‑`1/65535` y se gana contigüidad.
pub fn quantize(value: f64) -> u16 {
    if !value.is_finite() {
        return 0;
    }
    let clamped = value.clamp(0.0, 1.0);
    let scaled = (clamped * QUANT_SCALE).round();
    if scaled < 0.0 {
        0
    } else if scaled > QUANT_SCALE {
        QUANT_SCALE as u16
    } else {
        scaled as u16
    }
}

/// Devuelve el valor real `[0, 1]` de un punto fijo cuantizado.
pub fn dequantize(fixed: u16) -> f64 {
    f64::from(fixed) / QUANT_SCALE
}

/// Tamaño real del registro contraído (comprobado en las pruebas).
pub const fn record_bytes() -> usize {
    size_of::<Record>()
}

/// Alineación real del registro contraído: fijada por su campo `u64`.
pub const fn record_align() -> usize {
    align_of::<Record>()
}

// ─────────────────────────────────────────────────────────────────────────
// Contracción por Tzimtzum: layout contiguo, sin padding
// ─────────────────────────────────────────────────────────────────────────

/// Dominio de hash del sobre contraído (evita colisiones con otras huellas).
pub const CONTRACTION_DOMAIN: &[u8] = b"bara:aether-omega:tzimtzum:v1";

/// Átomo de información que cruza capas.
///
/// El orden de los campos es **normativo**: `u32, u32, u16, u16, u16, u8, u8`
/// suma 16 bytes y su alineación natural es 4, de modo que el compilador no
/// necesita insertar relleno alguno entre campos ni al final. La prueba
/// `registro_sin_padding` fija esta propiedad: si alguien reordena los campos,
/// la suite lo detecta antes de que la caché se degrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct Record {
    /// Número de orden del nodo dentro del flujo (marco de 32 bits).
    pub sequence: u32,
    /// Código del tipo de retorno ([`ast_dna::type_code`]).
    pub code: u32,
    /// Masa de verdad en punto fijo `[0, 65535]`.
    pub truth_q: u16,
    /// Masa de falsedad en punto fijo `[0, 65535]`.
    pub falsity_q: u16,
    /// Riesgo del nodo en punto fijo `[0, 65535]`.
    pub hazard_q: u16,
    /// Aridad (número de parámetros, acotada a un byte).
    pub arity: u8,
    /// Índice de la raíz triconsonántica dentro del flujo (no el texto).
    pub kind: u8,
}

impl Record {
    /// Contrae un nodo *Shoresh* en un registro cuantizado.
    pub fn from_node(node: &ShoreshNode, sequence: u64, kind: u8) -> Self {
        let (truth, falsity) = node.valence.belnap();
        Record {
            sequence: (sequence & 0xFFFF_FFFF) as u32,
            code: u32::from(ast_dna::type_code(node.ret)),
            truth_q: quantize(truth),
            falsity_q: quantize(falsity),
            hazard_q: quantize(node.hazard),
            arity: if node.arity > u8::MAX as usize {
                u8::MAX
            } else {
                node.arity as u8
            },
            kind,
        }
    }

    /// Serialización canónica little‑endian (16 bytes, sin relleno).
    pub const fn bytes(&self) -> [u8; RECORD_BYTES] {
        let mut out = [0u8; RECORD_BYTES];
        let sequence = self.sequence.to_le_bytes();
        let code = self.code.to_le_bytes();
        let truth = self.truth_q.to_le_bytes();
        let falsity = self.falsity_q.to_le_bytes();
        let hazard = self.hazard_q.to_le_bytes();
        let mut index = 0;
        while index < 4 {
            out[index] = sequence[index];
            out[index + 4] = code[index];
            index += 1;
        }
        out[8] = truth[0];
        out[9] = truth[1];
        out[10] = falsity[0];
        out[11] = falsity[1];
        out[12] = hazard[0];
        out[13] = hazard[1];
        out[14] = self.arity;
        out[15] = self.kind;
        out
    }

    /// Lectura canónica little‑endian.
    pub const fn from_bytes(raw: &[u8; RECORD_BYTES]) -> Self {
        let mut sequence = [0u8; 4];
        let mut code = [0u8; 4];
        let mut index = 0;
        while index < 4 {
            sequence[index] = raw[index];
            code[index] = raw[index + 4];
            index += 1;
        }
        Record {
            sequence: u32::from_le_bytes(sequence),
            code: u32::from_le_bytes(code),
            truth_q: u16::from_le_bytes([raw[8], raw[9]]),
            falsity_q: u16::from_le_bytes([raw[10], raw[11]]),
            hazard_q: u16::from_le_bytes([raw[12], raw[13]]),
            arity: raw[14],
            kind: raw[15],
        }
    }

    /// Riesgo real en `[0, 1]`.
    pub fn hazard(&self) -> f64 {
        dequantize(self.hazard_q)
    }

    /// Masa de verdad real en `[0, 1]`.
    pub fn truth(&self) -> f64 {
        dequantize(self.truth_q)
    }

    /// Masa de falsedad real en `[0, 1]`.
    pub fn falsity(&self) -> f64 {
        dequantize(self.falsity_q)
    }

    /// ¿El registro queda por debajo de la guarda `שמר` del kernel?
    pub fn is_guarded(&self) -> bool {
        self.hazard() <= crate::autopoietic::SEAL_THRESHOLD
    }

    /// ¿Sigue siendo un átomo admisible (aridad y masas en rango)?
    pub fn is_sound(&self) -> bool {
        usize::from(self.arity) <= crate::autopoietic::MAX_ARITY
    }
}

/// Registro neutro usado para inicializar filas (evita repetir literales).
const ZERO_RECORD: Record = Record {
    sequence: 0,
    code: 0,
    truth_q: 0,
    falsity_q: 0,
    hazard_q: 0,
    arity: 0,
    kind: 0,
};

/// Fila contraída: [`LANES`] registros contiguos, exactamente una línea de caché.
///
/// Cargar una fila es cargar **una** línea L1 y obtener cuatro nodos: ése es el
/// dividendo de la contracción *Tzimtzum*.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Row {
    /// Registros de la fila, en orden de flujo.
    pub lanes: [Record; LANES],
}

impl Row {
    /// Fila vacía (todos los registros a cero).
    pub const fn empty() -> Self {
        Row {
            lanes: [ZERO_RECORD; LANES],
        }
    }

    /// Registro en la posición `lane`, o `None` si se sale de la fila.
    pub const fn lane(&self, lane: usize) -> Option<Record> {
        if lane < LANES {
            Some(self.lanes[lane])
        } else {
            None
        }
    }

    /// Coloca un registro en una posición; `false` si la posición no existe.
    pub fn place(&mut self, lane: usize, record: Record) -> bool {
        match self.lanes.get_mut(lane) {
            Some(slot) => {
                *slot = record;
                true
            }
            None => false,
        }
    }

    /// Bytes contiguos de la fila (una línea de caché, sin huecos).
    pub const fn bytes(&self) -> [u8; CACHE_LINE] {
        let mut out = [0u8; CACHE_LINE];
        let mut index = 0;
        while index < LANES {
            let raw = self.lanes[index].bytes();
            let mut byte = 0;
            while byte < RECORD_BYTES {
                out[index * RECORD_BYTES + byte] = raw[byte];
                byte += 1;
            }
            index += 1;
        }
        out
    }

    /// Reconstruye la fila desde sus bytes (total: cualquier entrada vale).
    pub const fn from_bytes(raw: &[u8; CACHE_LINE]) -> Self {
        let mut lanes = [ZERO_RECORD; LANES];
        let mut index = 0;
        while index < LANES {
            let mut chunk = [0u8; RECORD_BYTES];
            let mut byte = 0;
            while byte < RECORD_BYTES {
                chunk[byte] = raw[index * RECORD_BYTES + byte];
                byte += 1;
            }
            lanes[index] = Record::from_bytes(&chunk);
            index += 1;
        }
        Row { lanes }
    }

    /// Huella de la línea de caché.
    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.bytes())
    }
}

impl std::fmt::Debug for Row {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Row")
            .field("bytes", &CACHE_LINE)
            .field("digest", &short_hex(&self.digest()[..4]))
            .finish()
    }
}

/// Filas que caben en el sobre contraído.
pub const ROW_CAPACITY: usize = WIRE_BYTES / CACHE_LINE;

/// Sobre contraído: filas contiguas más el número de filas ocupadas.
///
/// Es la única estructura que viaja entre capas. Su memoria es un bloque plano
/// (`[u8; WIRE_BYTES]`) seguido de un contador: nada de punteros, nada de `Vec`,
/// nada de reubicación — la copia entre niveles es un recorrido lineal y
/// predecible para el *prefetcher* del procesador.
#[derive(Clone, PartialEq, Eq)]
pub struct Contracted {
    bytes: [u8; WIRE_BYTES],
    rows: u8,
}

impl Default for Contracted {
    fn default() -> Self {
        Contracted::new()
    }
}

impl Contracted {
    /// Sobre vacío.
    pub fn new() -> Self {
        Contracted {
            bytes: [0u8; WIRE_BYTES],
            rows: 0,
        }
    }

    /// Filas que admite el sobre.
    pub const fn capacity(&self) -> usize {
        ROW_CAPACITY
    }

    /// Filas ocupadas.
    pub const fn len(&self) -> usize {
        self.rows as usize
    }

    /// ¿No viaja ninguna fila?
    pub const fn is_empty(&self) -> bool {
        self.rows == 0
    }

    /// Bytes del sobre (siempre el bloque completo: densidad fija de caché).
    pub const fn bytes(&self) -> usize {
        WIRE_BYTES
    }

    /// Añade una fila; `false` si el sobre está lleno (nunca hay reasignación).
    pub fn push_row(&mut self, row: Row) -> bool {
        let index = usize::from(self.rows);
        if index >= ROW_CAPACITY {
            return false;
        }
        let raw = row.bytes();
        let base = index * CACHE_LINE;
        self.bytes[base..base + CACHE_LINE].copy_from_slice(&raw);
        self.rows += 1;
        true
    }

    /// Fila en la posición `index`, o `None` si está fuera del sobre.
    pub fn row(&self, index: usize) -> Option<Row> {
        let chunk = self.chunk(index)?;
        Some(Row::from_bytes(&chunk))
    }

    /// Copia local de la línea `index` (alineada al bloque contraído).
    fn chunk(&self, index: usize) -> Option<[u8; CACHE_LINE]> {
        if index >= usize::from(self.rows) {
            return None;
        }
        let base = index * CACHE_LINE;
        let mut out = [0u8; CACHE_LINE];
        out.copy_from_slice(&self.bytes[base..base + CACHE_LINE]);
        Some(out)
    }

    /// Iterador sobre las filas ocupadas, en orden de flujo.
    pub fn rows(&self) -> impl Iterator<Item = Row> + '_ {
        (0..usize::from(self.rows)).filter_map(move |index| self.row(index))
    }

    /// Vista de sólo lectura de las filas ocupadas (bytes contiguos).
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.rows) * CACHE_LINE]
    }

    /// Ocupación del sobre en `[0, 1]`.
    pub fn fill(&self) -> f64 {
        usize::from(self.rows) as f64 / ROW_CAPACITY as f64
    }

    /// Contracción **idempotente**: re‑cuantizar un sobre contraído lo deja igual.
    pub fn contracted(&self) -> Self {
        let mut out = Contracted::new();
        for row in self.rows() {
            let mut tight = Row::empty();
            let mut lane = 0;
            while lane < LANES {
                if let Some(record) = row.lane(lane) {
                    let reborn = Record {
                        truth_q: quantize(record.truth()),
                        falsity_q: quantize(record.falsity()),
                        hazard_q: quantize(record.hazard()),
                        ..record
                    };
                    tight.place(lane, reborn);
                }
                lane += 1;
            }
            if !out.push_row(tight) {
                break;
            }
        }
        out
    }

    /// Huella del sobre: dominio + bloque completo + filas ocupadas.
    pub fn digest(&self) -> [u8; 32] {
        let mut statement = Vec::with_capacity(CONTRACTION_DOMAIN.len() + WIRE_BYTES + 1);
        statement.extend_from_slice(CONTRACTION_DOMAIN);
        statement.extend_from_slice(&self.bytes);
        statement.push(self.rows);
        sha256(&statement)
    }

    /// Huella corta para trazas del IDE.
    pub fn fingerprint(&self) -> String {
        short_hex(&self.digest()[..8])
    }
}

impl std::fmt::Debug for Contracted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Contracted")
            .field("rows", &usize::from(self.rows))
            .field("capacity", &ROW_CAPACITY)
            .field("fingerprint", &self.fingerprint())
            .finish()
    }
}

/// Balance de una contracción: lo que entró, lo que cupo y lo que se quedó fuera.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContractStats {
    /// Nodos ofrecidos a la contracción.
    pub nodes: usize,
    /// Filas ocupadas del sobre.
    pub rows: usize,
    /// Nodos descartados por falta de espacio (nunca se reasigna memoria).
    pub spilled: usize,
    /// Líneas de caché ocupadas.
    pub cache_lines: usize,
    /// Bytes contiguos ocupados.
    pub bytes: usize,
    /// Huella del sobre resultante.
    pub digest: [u8; 32],
}

impl ContractStats {
    /// ¿Entró todo? (contracción sin derrame).
    pub fn is_lossless(&self) -> bool {
        self.spilled == 0
    }

    /// Nodos contraídos por línea de caché (el dividendo medible del *Tzimtzum*).
    pub fn lanes_per_line(&self) -> f64 {
        if self.cache_lines == 0 {
            0.0
        } else {
            self.nodes as f64 / self.cache_lines as f64
        }
    }

    /// Acta de una línea.
    pub fn label(&self) -> String {
        format!(
            "Tzimtzum · {} nodos · {} filas · {} B · {} líneas L1 · {:.2} nodos/línea · derrama {} · {}",
            self.nodes,
            self.rows,
            self.bytes,
            self.cache_lines,
            self.lanes_per_line(),
            self.spilled,
            short_hex(&self.digest[..4])
        )
    }

    /// Proyección JSON para el panel del IDE.
    pub fn json(&self) -> String {
        format!(
            "{{\"nodes\":{},\"rows\":{},\"spilled\":{},\"cache_lines\":{},\"bytes\":{},\"lossless\":{},\"digest\":\"{}\"}}",
            self.nodes,
            self.rows,
            self.spilled,
            self.cache_lines,
            self.bytes,
            self.is_lossless(),
            short_hex(&self.digest[..8])
        )
    }
}

/// Índice de raíz del registro: pliegue determinista de la raíz triconsonántica.
///
/// El sobre no transporta texto (sería incompatible con su densidad): transporta
/// el pliegue de la raíz, que basta para reconstruir la identidad en el lado
/// receptor sin arrastrar `String` alguna por la jerarquía.
pub fn root_index(root: &str) -> u8 {
    (ast_dna::root_fold(root) % 256) as u8
}

/// Contrae una lista de nodos en un sobre contiguo.
///
/// Los nodos se cuantizan, se empaquetan de [`LANES`] en [`LANES`] dentro de
/// filas de una línea de caché y, si el sobre se llena, los nodos restantes se
/// **cuentan** ([`ContractStats::spilled`]) en lugar de forzar una reserva.
pub fn contract(nodes: &[ShoreshNode], sequence: u64) -> (Contracted, ContractStats) {
    let mut block = Contracted::new();
    let mut spilled = 0usize;
    let mut offset = 0usize;

    for chunk in nodes.chunks(LANES) {
        let mut row = Row::empty();
        for (lane, node) in chunk.iter().enumerate() {
            let ordinal = sequence.wrapping_add((offset + lane) as u64);
            row.place(
                lane,
                Record::from_node(node, ordinal, root_index(&node.root)),
            );
        }
        if !block.push_row(row) {
            spilled += chunk.len();
        }
        offset += chunk.len();
    }

    let stats = ContractStats {
        nodes: nodes.len(),
        rows: block.len(),
        spilled,
        cache_lines: block.len(),
        bytes: block.as_slice().len(),
        digest: block.digest(),
    };
    (block, stats)
}

/// Despliega un sobre en sus registros, en orden de flujo.
pub fn expand(block: &Contracted) -> Vec<Record> {
    block.rows().flat_map(|row| row.lanes).collect()
}

/// Contrae el estado actual del núcleo (sólo lectura: el soberano no se toca).
pub fn solidify(kernel: crate::autopoietic::KernelRead<'_>) -> (Contracted, ContractStats) {
    contract(kernel.nodes(), kernel.revision())
}

// ─────────────────────────────────────────────────────────────────────────
// Jerarquía de capas: descenso garantizado por el sistema de tipos
// ─────────────────────────────────────────────────────────────────────────

/// Capa del kernel con un lugar fijo en la jerarquía.
///
/// `Above` y `Below` se declaran **en la propia capa**, no en la arista. Eso
/// convierte el grafo en una cadena y hace que una arista sólo exista cuando las
/// dos declaraciones coinciden: un ciclo no es «desaconsejado», es inexpresable.
pub trait Rung: 'static {
    /// Capa inmediatamente superior.
    type Above: Rung;
    /// Capa inmediatamente inferior.
    type Below: Rung;
    /// Profundidad (0 = núcleo soberano).
    const LEVEL: u8;
    /// Nombre ontológico de la capa.
    const NAME: &'static str;
}

/// Nivel 0 — el núcleo soberano: origen de todo flujo, no recibe de nadie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sovereign;

/// Nivel 1 — la periferia de confianza (pasarelas, *gateways*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Periphery;

/// Nivel 2 — las células *sandbox* efímeras.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cell;

/// Nivel 3 — los observadores: terminal del descenso, jamás ascienden.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observer;

impl Rung for Sovereign {
    type Above = Sovereign;
    type Below = Periphery;
    const LEVEL: u8 = 0;
    const NAME: &'static str = "soberano";
}

impl Rung for Periphery {
    type Above = Sovereign;
    type Below = Cell;
    const LEVEL: u8 = 1;
    const NAME: &'static str = "periferia";
}

impl Rung for Cell {
    type Above = Periphery;
    type Below = Observer;
    const LEVEL: u8 = 2;
    const NAME: &'static str = "célula";
}

impl Rung for Observer {
    type Above = Cell;
    type Below = Observer;
    const LEVEL: u8 = 3;
    const NAME: &'static str = "observador";
}

/// Arista fija entre dos capas consecutivas de la jerarquía.
///
/// Es un tipo de **tamaño cero**: no hay tabla de rutas en memoria, ni índice
/// que resolver, ni cola que consultar. El destino de un bloque es una
/// propiedad del tipo de la arista, de modo que el compilador puede resolverlo
/// —y eliminarlo— sin dejar rastro en el binario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedRoute<From, To> {
    path: PhantomData<fn(From) -> To>,
}

impl<From, To> Default for FixedRoute<From, To> {
    /// La arista por defecto es **la única arista**: no hay estado que inicializar.
    fn default() -> Self {
        FixedRoute { path: PhantomData }
    }
}

impl<From, To> FixedRoute<From, To>
where
    From: Rung<Below = To>,
    To: Rung<Above = From>,
{
    /// Construye la única arista válida entre `From` y `To`.
    ///
    /// Sólo existe esta implementación y exige la doble declaración de
    /// adyacencia: **no hay constructor para saltos hacia arriba ni para saltos
    /// no adyacentes**.
    pub const fn new() -> Self {
        FixedRoute { path: PhantomData }
    }

    /// Nivel de origen.
    pub const fn from_level(&self) -> u8 {
        From::LEVEL
    }

    /// Nivel de destino.
    pub const fn to_level(&self) -> u8 {
        To::LEVEL
    }

    /// Nombre de la capa de origen.
    pub const fn from_name(&self) -> &'static str {
        From::NAME
    }

    /// Nombre de la capa de destino.
    pub const fn to_name(&self) -> &'static str {
        To::NAME
    }

    /// ¿La arista desciende exactamente un nivel?
    pub const fn descends(&self) -> bool {
        To::LEVEL == From::LEVEL + 1
    }

    /// Contracción *Tzimtzum* al cruzar la frontera.
    ///
    /// El sobre se re‑cuantiza y sale idéntico si ya venía contraído: la frontera
    /// no acumula error (idempotencia) y jamás toca la memoria del origen.
    pub fn flow(&self, block: Contracted) -> Contracted {
        block.contracted()
    }

    /// Encadena el descenso al nivel siguiente, siempre hacia abajo.
    pub fn then<Next>(self) -> FixedRoute<To, Next>
    where
        To: Rung<Below = Next>,
        Next: Rung<Above = To>,
    {
        FixedRoute::new()
    }

    /// Descripción de la arista para trazas y paneles del IDE.
    pub fn hop(&self) -> RouteHop {
        RouteHop {
            from_level: From::LEVEL,
            from: From::NAME,
            to_level: To::LEVEL,
            to: To::NAME,
        }
    }
}

/// Salto de la jerarquía, tal como lo consume el IDE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteHop {
    /// Nivel de origen.
    pub from_level: u8,
    /// Capa de origen.
    pub from: &'static str,
    /// Nivel de destino.
    pub to_level: u8,
    /// Capa de destino.
    pub to: &'static str,
}

impl RouteHop {
    /// ¿El salto baja exactamente una capa?
    pub fn descends(&self) -> bool {
        self.to_level == self.from_level + 1
    }

    /// Representación de una línea.
    pub fn label(&self) -> String {
        format!(
            "L{} {} → L{} {}",
            self.from_level, self.from, self.to_level, self.to
        )
    }
}

/// Columna vertebral del flujo: los tres descensos del kernel, encadenados.
///
/// Como cada arista es ZST, [`Spine`] también lo es: atravesar la jerarquía
/// completa no consume memoria ni un solo ciclo de *lookup*. Las pruebas fijan
/// `size_of::<Spine>() == 0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spine {
    sovereign_to_periphery: FixedRoute<Sovereign, Periphery>,
    periphery_to_cell: FixedRoute<Periphery, Cell>,
    cell_to_observer: FixedRoute<Cell, Observer>,
}

impl Default for Spine {
    fn default() -> Self {
        Spine::assemble()
    }
}

impl Spine {
    /// Ensambla la columna vertebral completa.
    pub const fn assemble() -> Self {
        Spine {
            sovereign_to_periphery: FixedRoute::new(),
            periphery_to_cell: FixedRoute::new(),
            cell_to_observer: FixedRoute::new(),
        }
    }

    /// Conduce un sobre desde el soberano hasta el observador, capa a capa.
    pub fn descend(&self, block: Contracted) -> Contracted {
        let level_one = self.sovereign_to_periphery.flow(block);
        let level_two = self.periphery_to_cell.flow(level_one);
        self.cell_to_observer.flow(level_two)
    }

    /// Traza de la cadena: cuatro niveles, tres saltos.
    pub fn trace(&self) -> [RouteHop; 3] {
        [
            self.sovereign_to_periphery.hop(),
            self.periphery_to_cell.hop(),
            self.cell_to_observer.hop(),
        ]
    }

    /// Plan de ruta consumible por el IDE.
    pub fn plan(&self) -> RoutePlan {
        RoutePlan {
            hops: self.trace().to_vec(),
            depth: Observer::LEVEL - Sovereign::LEVEL,
            static_only: true,
        }
    }

    /// Acta de la traza, línea a línea.
    pub fn report(&self) -> Vec<String> {
        self.trace().iter().map(RouteHop::label).collect()
    }
}

/// Plan de ruta completo: la topología del kernel vista por el IDE.
///
/// `static_only` es siempre `true`: no existe variante dinámica, porque no
/// existe tabla que consultar. El plan es una **descripción** de lo que el
/// compilador ya decidió, nunca una configuración que el runtime pueda cambiar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePlan {
    /// Saltos de la jerarquía, en orden de descenso.
    pub hops: Vec<RouteHop>,
    /// Profundidad total (soberano → observador).
    pub depth: u8,
    /// ¿El enrutamiento es enteramente estático? (invariante: siempre `true`).
    pub static_only: bool,
}

impl RoutePlan {
    /// ¿Todos los saltos descienden exactamente un nivel, sin excepción?
    ///
    /// Es la comprobación de aciclicidad del plan: niveles estrictamente
    /// crecientes ⇒ imposible volver a una capa ya visitada.
    pub fn is_acyclic(&self) -> bool {
        let mut previous: Option<u8> = None;
        for hop in &self.hops {
            if !hop.descends() {
                return false;
            }
            if let Some(level) = previous {
                if hop.from_level != level {
                    return false;
                }
            }
            previous = Some(hop.to_level);
        }
        self.hops.len() == usize::from(self.depth)
    }

    /// Capas por las que pasa el flujo, de arriba abajo.
    pub fn ladder(&self) -> Vec<&'static str> {
        let mut out = Vec::with_capacity(self.hops.len() + 1);
        if let Some(first) = self.hops.first() {
            out.push(first.from);
        }
        for hop in &self.hops {
            out.push(hop.to);
        }
        out
    }

    /// Acta de una línea.
    pub fn label(&self) -> String {
        format!(
            "topología estática · profundidad {} · {} saltos · acíclica {} · [{}]",
            self.depth,
            self.hops.len(),
            self.is_acyclic(),
            self.ladder().join(" ▸ ")
        )
    }

    /// Proyección JSON para el panel del IDE.
    pub fn json(&self) -> String {
        let hops: Vec<String> = self
            .hops
            .iter()
            .map(|hop| {
                format!(
                    "{{\"from\":\"{}\",\"to\":\"{}\",\"from_level\":{},\"to_level\":{}}}",
                    hop.from, hop.to, hop.from_level, hop.to_level
                )
            })
            .collect();
        format!(
            "{{\"static_only\":{},\"depth\":{},\"acyclic\":{},\"hops\":[{}]}}",
            self.static_only,
            self.depth,
            self.is_acyclic(),
            hops.join(",")
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Medidas de layout y utilidades de la jerarquía
// ─────────────────────────────────────────────────────────────────────────

/// Número de líneas de caché necesarias para `bytes` (redondeo hacia arriba).
pub fn cache_lines_for(bytes: usize) -> usize {
    bytes.div_ceil(CACHE_LINE)
}

/// Filas necesarias para `records` registros.
pub fn rows_for(records: usize) -> usize {
    records.div_ceil(LANES)
}

/// Filas que admite un sobre para `records` registros (acotado a la capacidad).
pub fn capacity_check(records: usize) -> bool {
    rows_for(records) <= ROW_CAPACITY
}

/// Informe de layout: la contracción vista como números verificables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutReport {
    /// Bytes por registro.
    pub record_bytes: usize,
    /// Alineación del registro.
    pub record_align: usize,
    /// Bytes por fila (= línea de caché).
    pub row_bytes: usize,
    /// Registros por fila.
    pub lanes: usize,
    /// Capacidad del sobre, en bytes.
    pub wire_bytes: usize,
    /// Capacidad del sobre, en filas.
    pub rows: usize,
    /// ¿Hay relleno entre campos? (invariante: `false`).
    pub padded: bool,
}

impl LayoutReport {
    /// Mide el layout real del proceso en curso.
    pub fn measure() -> Self {
        LayoutReport {
            record_bytes: size_of::<Record>(),
            record_align: align_of::<Record>(),
            row_bytes: size_of::<Row>(),
            lanes: LANES,
            wire_bytes: size_of::<Contracted>(),
            rows: ROW_CAPACITY,
            padded: size_of::<Record>() != RECORD_BYTES || size_of::<Row>() != CACHE_LINE,
        }
    }

    /// ¿El layout es contiguo y está alineado a la línea de caché?
    pub fn is_tight(&self) -> bool {
        !self.padded
            && self.row_bytes == CACHE_LINE
            && self.record_bytes == RECORD_BYTES
            && self.lanes * self.record_bytes == self.row_bytes
    }

    /// Acta de una línea.
    pub fn label(&self) -> String {
        format!(
            "layout · registro {} B (alineación {}) · fila {} B = {} × {} B = 1 línea L1 · sobre {} B / {} filas · contiguo {}",
            self.record_bytes,
            self.record_align,
            self.row_bytes,
            self.lanes,
            self.record_bytes,
            self.wire_bytes,
            self.rows,
            self.is_tight()
        )
    }
}

/// Plan de ruta de la jerarquía canónica del kernel.
pub fn hierarchy() -> RoutePlan {
    Spine::assemble().plan()
}

/// Descenso completo de un sobre por la jerarquía canónica.
pub fn descend_hierarchy(block: Contracted) -> Contracted {
    Spine::assemble().descend(block)
}

// ─────────────────────────────────────────────────────────────────────────
// Espacio métrico del AST
// ─────────────────────────────────────────────────────────────────────────

/// Nodos que entran en una carta. El resto se cuenta y no se mide.
pub const CHART_CAP: usize = 32;

/// Tope de la distancia topológica. Ningún par supera este valor.
pub const METRIC_CAP: u32 = 64;

/// Bytes de raíz que entran en el punto. El corte respeta fronteras UTF-8.
const ROOT_BYTES: usize = 16;

/// Punto del AST en el espacio discreto: índice, residuo de `𝔽ₚ` y raíz acotada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricPoint {
    /// Posición en el documento, acotada por [`CHART_CAP`].
    pub index: u16,
    /// Residuo del polinomio del nodo, o pliegue de la raíz si no hay nodo.
    pub residue: u64,
    /// Aridad cuantizada.
    pub arity: u16,
    root: [u8; ROOT_BYTES],
    root_len: u8,
}

impl MetricPoint {
    /// Raíz empaquetada. Vacía si el corte no llegó a formar texto.
    pub fn root(&self) -> &str {
        let end = usize::from(self.root_len);
        self.root
            .get(..end)
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
            .unwrap_or("")
    }
}

/// Carta métrica de un AST: como máximo [`CHART_CAP`] puntos, en orden.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AstChart {
    points: [MetricPoint; CHART_CAP],
    len: u16,
    spilled: u16,
}

impl AstChart {
    /// Carta vacía.
    pub const fn empty() -> Self {
        Self {
            points: [MetricPoint {
                index: 0,
                residue: 0,
                arity: 0,
                root: [0; ROOT_BYTES],
                root_len: 0,
            }; CHART_CAP],
            len: 0,
            spilled: 0,
        }
    }

    /// Puntos vivos, en orden de documento.
    pub fn points(&self) -> &[MetricPoint] {
        let end = usize::from(self.len).min(CHART_CAP);
        self.points.get(..end).unwrap_or(&[])
    }

    /// Cuántos puntos entraron.
    pub fn len(&self) -> u16 {
        self.len
    }

    /// ¿La carta no midió ningún punto?
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Nodos que no cupieron.
    pub fn spilled(&self) -> u16 {
        self.spilled
    }

    /// Pares con el mismo residuo de `𝔽ₚ` en posiciones distintas.
    pub fn overlaps(&self) -> u16 {
        let mut count = 0u16;
        let points = self.points();
        for (index, left) in points.iter().enumerate() {
            let rest = points.get(index.saturating_add(1)..).unwrap_or(&[]);
            for right in rest {
                if left.residue == right.residue {
                    count = count.saturating_add(1);
                }
            }
        }
        count
    }

    /// Carta de nodos *Shoresh*. El residuo es la identidad polinómica.
    pub fn from_nodes(nodes: &[ShoreshNode]) -> Self {
        let mut chart = Self::empty();
        for node in nodes {
            if !chart.push(node_point(chart.len, node)) {
                chart.spilled = chart.spilled.saturating_add(1);
            }
        }
        chart
    }

    /// Carta de raíces sueltas. El residuo es el pliegue `φ` de cada una.
    pub fn from_roots(roots: &[&str]) -> Self {
        let mut chart = Self::empty();
        for root in roots {
            if !chart.push(root_point(chart.len, root)) {
                chart.spilled = chart.spilled.saturating_add(1);
            }
        }
        chart
    }

    fn push(&mut self, point: MetricPoint) -> bool {
        let Some(slot) = self.points.get_mut(usize::from(self.len)) else {
            return false;
        };
        *slot = point;
        self.len = self.len.saturating_add(1);
        true
    }
}

fn pack_root(root: &str) -> ([u8; ROOT_BYTES], u8) {
    let mut bytes = [0u8; ROOT_BYTES];
    let mut len = 0usize;
    for ch in root.chars() {
        let mut buf = [0u8; 4];
        let encoded = ch.encode_utf8(&mut buf);
        let next = len.saturating_add(encoded.len());
        if next > ROOT_BYTES {
            break;
        }
        if let Some(slot) = bytes.get_mut(len..next) {
            slot.copy_from_slice(encoded.as_bytes());
            len = next;
        }
    }
    (bytes, u8::try_from(len).unwrap_or(0))
}

fn node_point(index: u16, node: &ShoreshNode) -> MetricPoint {
    let (root, root_len) = pack_root(&node.root);
    MetricPoint {
        index,
        residue: ast_dna::node_identity(node).0,
        arity: u16::try_from(node.arity).unwrap_or(u16::MAX),
        root,
        root_len,
    }
}

fn root_point(index: u16, root: &str) -> MetricPoint {
    let (packed, root_len) = pack_root(root);
    MetricPoint {
        index,
        residue: ast_dna::root_fold(root),
        arity: 0,
        root: packed,
        root_len,
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    use crate::ast_dna::golden_key;
    use crate::autopoietic::{KernelCore, MAX_ARITY};
    use crate::ffi_ingest::{BaraType, ShoreshAst, ShoreshNode};
    use crate::runtime::QuantumState;

    const SEED: &[u8] = b"bara-topologia-pruebas";

    fn nodo(root: &str, arity: usize, hazard: f64) -> ShoreshNode {
        ShoreshNode {
            root: root.to_string(),
            original: "funcion".to_string(),
            arity,
            ret: BaraType::Number,
            hazard,
            valence: QuantumState::paraconsistent(1.0, 0.0),
            sanitized: hazard <= crate::autopoietic::SEAL_THRESHOLD,
        }
    }

    fn raiz(indice: usize) -> String {
        let base = 0x05D0_u32;
        let mut out = String::new();
        for salto in 0..3 {
            let code = base + ((indice + salto * 7) % 27) as u32;
            if let Some(ch) = char::from_u32(code) {
                out.push(ch);
            }
        }
        out
    }

    fn muestra(cuantos: usize) -> Vec<ShoreshNode> {
        (0..cuantos)
            .map(|i| nodo(&raiz(i), i % 3, (i as f64) / 8.0))
            .collect()
    }

    fn nucleo() -> KernelCore {
        let ast = ShoreshAst {
            nodes: vec![nodo(&raiz(0), 1, 0.25), nodo(&raiz(1), 2, 0.5)],
        };
        KernelCore::genesis("topologia", ast, &golden_key(SEED))
    }

    #[test]
    fn registro_sin_padding() {
        // La suma de los campos es el tamaño: no hay huecos que la caché pague.
        let campos = size_of::<u32>() * 2 + size_of::<u16>() * 3 + size_of::<u8>() * 2;
        assert_eq!(campos, RECORD_BYTES);
        assert_eq!(size_of::<Record>(), RECORD_BYTES);
        assert_eq!(record_bytes(), 16);
        assert_eq!(align_of::<Record>(), 4);
        assert_eq!(record_align(), 4);
        assert_eq!(LayoutReport::measure().record_bytes, RECORD_BYTES);
        assert!(LayoutReport::measure().is_tight());
    }

    #[test]
    fn fila_es_una_linea_de_cache() {
        assert_eq!(LANES, 4);
        assert_eq!(size_of::<Row>(), CACHE_LINE);
        assert_eq!(size_of::<Row>(), LANES * RECORD_BYTES);
        assert_eq!(size_of::<Row>(), 64);

        let mut fila = Row::empty();
        assert!(fila.place(3, Record::from_node(&nodo(&raiz(2), 2, 0.25), 7, 9)));
        assert!(!fila.place(LANES, Record::default()));
        assert!(fila.lane(LANES).is_none());
        assert_eq!(fila.bytes(), Row::bytes(&fila));
        assert_eq!(Row::from_bytes(&fila.bytes()), fila);
    }

    #[test]
    fn serializacion_de_registro_es_canonica() {
        let registro = Record {
            sequence: 258,
            code: 3,
            truth_q: 65535,
            falsity_q: 1,
            hazard_q: 32768,
            arity: 8,
            kind: 200,
        };
        let bytes = registro.bytes();
        assert_eq!(bytes.len(), RECORD_BYTES);
        assert_eq!(bytes[14], 8);
        assert_eq!(bytes[15], 200);
        assert_eq!(Record::from_bytes(&bytes), registro);
        assert_eq!(registro.truth(), 1.0);
        assert!(registro.falsity() > 0.0 && registro.falsity() < 0.001);
        assert!(registro.is_sound());
        assert!(!registro.is_guarded());
    }

    #[test]
    fn cuantizacion_es_total_y_saturada() {
        assert_eq!(quantize(f64::NAN), 0);
        assert_eq!(quantize(f64::INFINITY), 0);
        assert_eq!(quantize(-3.0), 0);
        assert_eq!(quantize(2.0), 65535);
        assert_eq!(quantize(0.0), 0);
        assert_eq!(dequantize(65535), 1.0);
        // El punto fijo no acumula error: re-cuantizar devuelve el mismo entero.
        for valor in [0.0_f64, 0.1, 0.25, 0.5, 0.75, 0.9, 1.0] {
            let fijo = quantize(valor);
            assert_eq!(quantize(dequantize(fijo)), fijo);
            assert!((dequantize(fijo) - valor).abs() < 1.0 / 65535.0);
        }
    }

    #[test]
    fn contraccion_de_ast_en_una_linea() {
        let nodos = muestra(3);
        let (sobre, acta) = contract(&nodos, 0);
        assert_eq!(acta.nodes, 3);
        assert_eq!(acta.rows, 1);
        assert_eq!(acta.cache_lines, 1);
        assert_eq!(acta.bytes, CACHE_LINE);
        assert!(acta.is_lossless());
        assert_eq!(sobre.len(), 1);
        assert!(!sobre.is_empty());
        assert_eq!(sobre.bytes(), WIRE_BYTES);
        assert_eq!(sobre.fill(), 1.0 / ROW_CAPACITY as f64);

        let registros = expand(&sobre);
        assert_eq!(registros.len(), LANES);
        assert_eq!(registros[0].kind, root_index(&nodos[0].root));
        assert!((registros[0].hazard() - nodos[0].hazard).abs() < 1.0 / 65535.0);
        assert!((registros[0].truth() - 1.0).abs() < f64::EPSILON);
        // Los huecos de la fila son registros neutros, no basura.
        assert_eq!(registros[LANES - 1].code, 0);
    }

    // @@T4B@@

    #[test]
    fn sobre_sin_reasignacion_y_derrame_contado() {
        let (lleno, acta) = contract(&muestra(ROW_CAPACITY * LANES), 0);
        assert_eq!(lleno.len(), ROW_CAPACITY);
        assert_eq!(acta.spilled, 0);
        assert!(acta.is_lossless());
        assert_eq!(acta.lanes_per_line(), 4.0);
        assert_eq!(lleno.as_slice().len(), WIRE_BYTES);

        let (desbordado, acta) = contract(&muestra(ROW_CAPACITY * LANES + 5), 0);
        assert_eq!(desbordado.len(), ROW_CAPACITY);
        assert_eq!(acta.spilled, 5);
        assert!(!acta.is_lossless());
        assert!(acta.label().contains("derrama 5"));
        assert!(acta.json().contains("\"lossless\":false"));

        // Fuera de la capacidad no hay fila que devolver, ni hueco que leer.
        assert!(lleno.row(ROW_CAPACITY).is_none());
        assert_eq!(rows_for(5), 2);
        assert_eq!(cache_lines_for(CACHE_LINE), 1);
        assert_eq!(cache_lines_for(CACHE_LINE + 1), 2);
        assert!(capacity_check(ROW_CAPACITY * LANES));
        assert!(!capacity_check(ROW_CAPACITY * LANES + 1));
    }

    #[test]
    fn contraccion_idempotente_en_toda_la_jerarquia() {
        let (sobre, _) = contract(&muestra(6), 3);
        let huella = sobre.digest();
        assert_eq!(sobre.contracted().digest(), huella);
        assert_eq!(descend_hierarchy(sobre.clone()).digest(), huella);
        assert_eq!(Spine::assemble().descend(sobre.clone()), sobre);
        assert_eq!(sobre.fingerprint().len(), 16);
    }

    #[test]
    fn rutas_estaticas_no_ocupan_memoria() {
        let arista = FixedRoute::<Sovereign, Periphery>::new();
        assert_eq!(std::mem::size_of_val(&arista), 0);
        assert_eq!(size_of::<FixedRoute<Periphery, Cell>>(), 0);
        assert_eq!(size_of::<FixedRoute<Cell, Observer>>(), 0);
        assert_eq!(size_of::<Spine>(), 0);
        assert_eq!(std::mem::size_of_val(&Spine::assemble()), 0);

        assert_eq!(arista.from_level(), 0);
        assert_eq!(arista.to_level(), 1);
        assert_eq!(arista.from_name(), "soberano");
        assert_eq!(arista.to_name(), "periferia");
        assert!(arista.descends());

        // Cada arista es un tipo propio: no comparten tabla, no comparten estado.
        assert_ne!(
            std::any::TypeId::of::<FixedRoute<Sovereign, Periphery>>(),
            std::any::TypeId::of::<FixedRoute<Periphery, Cell>>()
        );
        assert_eq!(arista.hop().label(), "L0 soberano → L1 periferia");
        // La arista no guarda estado alguno: la construida y la neutra coinciden.
        assert_eq!(arista, FixedRoute::<Sovereign, Periphery>::default());
    }

    #[test]
    fn descenso_unidireccional_encadenado() {
        let primera = FixedRoute::<Sovereign, Periphery>::new();
        let segunda = primera.then::<Cell>();
        let tercera = segunda.then::<Observer>();
        assert!(segunda.descends());
        assert!(tercera.descends());
        assert_eq!(tercera.from_level(), 2);
        assert_eq!(tercera.to_level(), 3);

        let plan = hierarchy();
        assert!(plan.static_only);
        assert!(plan.is_acyclic());
        assert_eq!(plan.depth, 3);
        assert_eq!(plan.hops.len(), 3);
        assert_eq!(
            plan.ladder(),
            vec!["soberano", "periferia", "célula", "observador"]
        );
        assert!(plan.json().contains("\"static_only\":true"));
        assert!(plan.json().contains("\"acyclic\":true"));
        assert!(plan.label().contains("profundidad 3"));

        let saltos = Spine::assemble().report();
        assert_eq!(saltos.len(), 3);
        assert!(saltos[0].contains("periferia"));
        assert!(saltos[2].contains("observador"));
    }

    #[test]
    fn el_soberano_se_contrae_sin_ser_tocado() {
        let kernel = nucleo();
        let antes = kernel.digest();
        let (sobre, acta) = solidify(kernel.read());
        assert_eq!(acta.nodes, 2);
        assert_eq!(acta.rows, 1);
        assert_eq!(acta.bytes, CACHE_LINE);
        assert!(acta.is_lossless());
        // El núcleo sigue íntegro: contraer es leer, jamás escribir.
        assert!(kernel.verify());
        assert_eq!(kernel.digest(), antes);
        assert_eq!(kernel.nodes().len(), 2);
        assert_eq!(kernel.revision(), 0);

        let (repetido, _) = solidify(kernel.read());
        assert_eq!(repetido.digest(), sobre.digest());
        let registros = expand(&sobre);
        assert_eq!(registros[0].sequence, 0);
        assert_eq!(registros[1].sequence, 1);
        assert_eq!(registros[1].arity, 2);
    }

    #[test]
    fn atomos_fuera_de_rango_se_saturan_sin_panico() {
        // Justo por encima del techo: se contrae igual, pero deja de ser admisible.
        let excesivo = nodo(&raiz(3), MAX_ARITY + 4, 1.7);
        let registro = Record::from_node(&excesivo, u64::MAX, root_index(&excesivo.root));
        assert_eq!(usize::from(registro.arity), MAX_ARITY + 4);
        assert!(!registro.is_sound());
        assert_eq!(registro.sequence, u32::MAX);
        assert!(!registro.is_guarded());
        // El registro saturado sigue siendo un átomo legible y reversible.
        assert_eq!(Record::from_bytes(&registro.bytes()), registro);

        // Una aridad impensable se satura al byte en vez de desbordar.
        let absurdo = nodo(&raiz(4), 900, 0.25);
        let saturado = Record::from_node(&absurdo, 0, root_index(&absurdo.root));
        assert_eq!(usize::from(saturado.arity), u8::MAX as usize);
        assert!(saturado.is_guarded());
        assert!(!saturado.is_sound());

        let mut fila = Row::empty();
        assert!(fila.place(0, registro));
        assert_eq!(fila.lane(0), Some(registro));
        if let Some(leido) = fila.lane(0) {
            assert!(!leido.is_sound());
        }
        assert!(fila.lane(LANES + 7).is_none());
    }
}
