//! # Metal-IR Hardware Interface — `metal_ir.rs`
//!
//! Traductor de bajo nivel del AST de Bara a un **IR de metal**: mapea cada
//! instrucción (raíz triconsonántica u operador) directamente a un *layout*
//! abstracto de registros CPU/GPU, sin pasar por el driver del sistema
//! operativo.
//!
//! ## Cadena de traducción
//! ```text
//! AST (raíces + operadores)
//!      │  MetalMapper::lower
//!      ▼
//! MetalOp[]  ──►  rangos de vida  ──►  linear-scan  ──►  RegAllocation
//!      │                                                    │
//!      ▼  MetalOp::encode                                   ▼
//!  palabras u32 (ISA de 32 bits)                 registros físicos + derrames
//!      │
//!      ▼  DriverBypass
//!  descriptor de anillo MMIO (bypass del driver)
//! ```
//!
//! ## Rutas de hardware
//! * **CPU** — operaciones escalares en `R`/`F`; instrucciones vectoriales a
//!   4 carriles.
//! * **GPU** — las mismas operaciones con enmascarado de 32 carriles
//!   (`V` + registro de predicado `P`).
//!
//! El *bypass* del driver se modela como un descriptor MMIO de anillo
//! (`DriverBypass`): la cola de despacho se escribe directamente en el
//! *layout* abstracto y cada operación evita una ida y vuelta al núcleo del
//! sistema operativo. El modelo es determinista y **no toca hardware real**:
//! la simulación es honesta y auto-contenida (`std` puro).

use crate::lexer::{Keyword, Token, TokenKind};
use crate::memory_region::Device;
use std::collections::BTreeMap;

/// Máscara de bits disponibles para el inmediato de una instrucción.
const IMM_MASK: u32 = 0x07FF;

// ─────────────────────────────────────────────────────────────────────────
// Layout abstracto de registros
// ─────────────────────────────────────────────────────────────────────────

/// Clase de registro del layout abstracto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegisterClass {
    /// Enteros generales (`R`).
    Gpr,
    /// Coma flotante (`F`).
    Fpr,
    /// Vectoriales / SIMD (`V`).
    Vector,
    /// Predicados y máscaras de carril (`P`).
    Predicate,
    /// Especiales: descriptor, reloj, barrera, contador (`S`).
    Special,
}

impl RegisterClass {
    /// Todas las clases, en orden canónico.
    pub fn all() -> [RegisterClass; 5] {
        [
            RegisterClass::Gpr,
            RegisterClass::Fpr,
            RegisterClass::Vector,
            RegisterClass::Predicate,
            RegisterClass::Special,
        ]
    }

    /// Prefijo legible de la clase (`R`, `F`, `V`, `P`, `S`).
    pub fn label(&self) -> &'static str {
        match self {
            RegisterClass::Gpr => "R",
            RegisterClass::Fpr => "F",
            RegisterClass::Vector => "V",
            RegisterClass::Predicate => "P",
            RegisterClass::Special => "S",
        }
    }

    /// Glifo del log ontológico.
    pub fn glyph(&self) -> &'static str {
        match self {
            RegisterClass::Gpr => "▦",
            RegisterClass::Fpr => "≈",
            RegisterClass::Vector => "⋮⋮",
            RegisterClass::Predicate => "⊕",
            RegisterClass::Special => "⌗",
        }
    }

    /// Banco físico correspondiente a la clase.
    pub fn bank(&self) -> &'static RegisterBank {
        LAYOUT
            .iter()
            .find(|b| b.class == *self)
            .unwrap_or(&LAYOUT[0])
    }

    /// Número de registros de la clase.
    pub fn slots(&self) -> usize {
        self.bank().regs
    }
}

/// Banco de registros: descriptor de una clase física.
#[derive(Debug, Clone, Copy)]
pub struct RegisterBank {
    /// Clase de registro.
    pub class: RegisterClass,
    /// Número de registros.
    pub regs: usize,
    /// Anchura en bytes.
    pub width: usize,
    /// Alineación natural en bytes.
    pub alignment: usize,
    /// `true` si es un banco de enmascarado (SIMD).
    pub masking: bool,
}

impl RegisterBank {
    /// Bytes totales del banco.
    pub fn bytes(&self) -> usize {
        self.regs * self.width
    }

    /// Descripción legible del banco.
    pub fn label(&self) -> String {
        format!(
            "{}·{} × {}B (align {}B){}",
            self.class.label(),
            self.regs,
            self.width,
            self.alignment,
            if self.masking { " · enmascarado" } else { "" }
        )
    }
}

/// **Layout abstracto de hardware** de Bara: cuatro bancos de CPU más un banco
/// vectorial pensado para el despacho en GPU (32 carriles por registro).
pub const LAYOUT: [RegisterBank; 5] = [
    RegisterBank {
        class: RegisterClass::Gpr,
        regs: 32,
        width: 8,
        alignment: 8,
        masking: false,
    },
    RegisterBank {
        class: RegisterClass::Fpr,
        regs: 16,
        width: 8,
        alignment: 8,
        masking: false,
    },
    RegisterBank {
        class: RegisterClass::Vector,
        regs: 16,
        width: 32,
        alignment: 32,
        masking: true,
    },
    RegisterBank {
        class: RegisterClass::Predicate,
        regs: 8,
        width: 1,
        alignment: 1,
        masking: true,
    },
    RegisterBank {
        class: RegisterClass::Special,
        regs: 4,
        width: 8,
        alignment: 8,
        masking: false,
    },
];

/// Capacidad total del layout abstracto, en registros.
pub fn capacity() -> usize {
    LAYOUT.iter().map(|b| b.regs).sum()
}

/// Bytes totales del layout abstracto.
pub fn layout_bytes() -> usize {
    LAYOUT.iter().map(|b| b.bytes()).sum()
}

/// Registro físico del layout abstracto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalReg {
    /// Clase a la que pertenece.
    pub class: RegisterClass,
    /// Índice dentro del banco.
    pub index: usize,
}

impl PhysicalReg {
    /// Nombre convencional (`R07`, `V12`, `P1`).
    pub fn label(&self) -> String {
        format!("{}{:02}", self.class.label(), self.index)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Rangos de vida y asignación de registros
// ─────────────────────────────────────────────────────────────────────────

/// Intervalo de vida de un registro virtual, medido en índices de instrucción.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveRange {
    /// Identificador virtual (SSA).
    pub virt: usize,
    /// Clase de registro requerida.
    pub class: RegisterClass,
    /// Índice de la instrucción que lo define.
    pub birth: usize,
    /// Índice de la última instrucción que lo consume.
    pub death: usize,
}

impl LiveRange {
    /// Longitud del intervalo, en instrucciones cubiertas.
    pub fn span(&self) -> usize {
        self.death.saturating_sub(self.birth) + 1
    }
}

/// Asignación de registros: virtual → físico, con derrames y presión.
#[derive(Debug, Clone, Default)]
pub struct RegAllocation {
    mapping: BTreeMap<usize, PhysicalReg>,
    spills: Vec<usize>,
    bank_usage: BTreeMap<RegisterClass, usize>,
    pressure: f64,
    spill_bytes: usize,
}

impl RegAllocation {
    /// **Linear scan**: recorre los rangos por nacimiento y libera los muertos.
    ///
    /// Si un banco se agota, el virtual **no** provoca un error: se cuenta como
    /// derrame (`spill`) y se resuelve con ranuras estáticas, coherente con el
    /// modelo de memoria determinista de Bara.
    pub fn allocate(ranges: &[LiveRange]) -> Self {
        let mut order: Vec<usize> = (0..ranges.len()).collect();
        order.sort_by_key(|&i| (ranges[i].birth, ranges[i].virt));

        let mut in_use: BTreeMap<RegisterClass, Vec<bool>> = RegisterClass::all()
            .iter()
            .map(|class| (*class, vec![false; class.slots()]))
            .collect();
        let mut active: Vec<(usize, PhysicalReg)> = Vec::new();
        let mut mapping: BTreeMap<usize, PhysicalReg> = BTreeMap::new();
        let mut spills: Vec<usize> = Vec::new();
        let mut max_live = 0_usize;

        for &index in &order {
            let range = ranges[index];
            // Expira los rangos ya muertos antes del nacimiento actual.
            active.retain(|(death, phys)| {
                if *death <= range.birth {
                    if let Some(flags) = in_use.get_mut(&phys.class) {
                        if let Some(slot) = flags.get_mut(phys.index) {
                            *slot = false;
                        }
                    }
                    false
                } else {
                    true
                }
            });

            let class = range.class;
            let capacity = class.slots();
            let flags = in_use.entry(class).or_insert_with(|| vec![false; capacity]);
            match flags.iter().position(|used| !used) {
                Some(slot) => {
                    flags[slot] = true;
                    let phys = PhysicalReg { class, index: slot };
                    mapping.insert(range.virt, phys);
                    active.push((range.death, phys));
                }
                None => spills.push(range.virt),
            }
            max_live = max_live.max(active.len());
        }

        let mut bank_usage: BTreeMap<RegisterClass, usize> = BTreeMap::new();
        for phys in mapping.values() {
            *bank_usage.entry(phys.class).or_insert(0) += 1;
        }
        let total = capacity();
        let pressure = if total == 0 {
            0.0
        } else {
            max_live as f64 / total as f64
        };

        RegAllocation {
            mapping,
            spill_bytes: spills.len() * 8,
            spills,
            bank_usage,
            pressure,
        }
    }

    /// Registro físico asignado a un virtual.
    pub fn physical(&self, virt: usize) -> Option<&PhysicalReg> {
        self.mapping.get(&virt)
    }

    /// Número de registros físicos ocupados.
    pub fn allocated(&self) -> usize {
        self.mapping.len()
    }

    /// Número de derrames.
    pub fn spilled(&self) -> usize {
        self.spills.len()
    }

    /// Bytes de ranuras estáticas consumidos por los derrames.
    pub fn spill_bytes(&self) -> usize {
        self.spill_bytes
    }

    /// Presión de registros: vivos máximos / capacidad total.
    pub fn pressure(&self) -> f64 {
        self.pressure
    }

    /// Ocupación del *layout* en `[0,1]`.
    pub fn occupancy(&self) -> f64 {
        (1.0 - self.pressure).clamp(0.0, 1.0)
    }

    /// Registros ocupados en una clase.
    pub fn usage(&self, class: RegisterClass) -> usize {
        self.bank_usage.get(&class).copied().unwrap_or(0)
    }

    /// Uso por banco, en orden de clase.
    pub fn bank_usage(&self) -> impl Iterator<Item = (RegisterClass, usize)> + '_ {
        RegisterClass::all()
            .into_iter()
            .map(move |class| (class, self.usage(class)))
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Metal-IR: opcodes e instrucciones
// ─────────────────────────────────────────────────────────────────────────

/// Opcode del Metal-IR. Cada operador del AST se traduce a uno de ellos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetalOpcode {
    /// Reserva de una región (génesis / autopoiesis).
    Alloc,
    /// Carga desde memoria (literales, cadenas).
    Load,
    /// Escritura en memoria (emisión).
    Store,
    /// Copia / materialización de inmediato.
    Move,
    /// Suma paraconsistente (disyunción `+`).
    Add,
    /// Producto paraconsistente (conjunción `*`).
    Mul,
    /// Fusión multiplicar-sumada (superposición adaptativa).
    Fma,
    /// Diferencia exclusiva (juicio por conjunción `שפט`).
    Xor,
    /// Reordenamiento de carriles (barajado SIMD).
    Shuffle,
    /// Máscara de predicado (colapso observacional).
    Predicate,
    /// Barrera de sincronización (guarda `שמר`).
    Barrier,
    /// Valla de orden total (fusión `!!`, paradoja).
    Fence,
    /// Confirmación del resultado en el descriptor de anillo.
    Commit,
    /// Retorno del control al anfitrión.
    Return,
}

impl MetalOpcode {
    /// Todos los opcodes, en orden canónico.
    pub fn all() -> [MetalOpcode; 14] {
        [
            MetalOpcode::Alloc,
            MetalOpcode::Load,
            MetalOpcode::Store,
            MetalOpcode::Move,
            MetalOpcode::Add,
            MetalOpcode::Mul,
            MetalOpcode::Fma,
            MetalOpcode::Xor,
            MetalOpcode::Shuffle,
            MetalOpcode::Predicate,
            MetalOpcode::Barrier,
            MetalOpcode::Fence,
            MetalOpcode::Commit,
            MetalOpcode::Return,
        ]
    }

    /// Mnemónico legible.
    pub fn label(&self) -> &'static str {
        match self {
            MetalOpcode::Alloc => "ALLOC",
            MetalOpcode::Load => "LOAD",
            MetalOpcode::Store => "STORE",
            MetalOpcode::Move => "MOVE",
            MetalOpcode::Add => "ADD",
            MetalOpcode::Mul => "MUL",
            MetalOpcode::Fma => "FMA",
            MetalOpcode::Xor => "XOR",
            MetalOpcode::Shuffle => "SHFL",
            MetalOpcode::Predicate => "PRED",
            MetalOpcode::Barrier => "BAR",
            MetalOpcode::Fence => "FENCE",
            MetalOpcode::Commit => "COMMIT",
            MetalOpcode::Return => "RET",
        }
    }

    /// Código numérico de 6 bits usado por el codificador.
    pub fn code(&self) -> u32 {
        match self {
            MetalOpcode::Alloc => 0,
            MetalOpcode::Load => 1,
            MetalOpcode::Store => 2,
            MetalOpcode::Move => 3,
            MetalOpcode::Add => 4,
            MetalOpcode::Mul => 5,
            MetalOpcode::Fma => 6,
            MetalOpcode::Xor => 7,
            MetalOpcode::Shuffle => 8,
            MetalOpcode::Predicate => 9,
            MetalOpcode::Barrier => 10,
            MetalOpcode::Fence => 11,
            MetalOpcode::Commit => 12,
            MetalOpcode::Return => 13,
        }
    }

    /// Banco de destino que consume la operación.
    pub fn dst_class(&self) -> RegisterClass {
        match self {
            MetalOpcode::Fma | MetalOpcode::Shuffle => RegisterClass::Vector,
            MetalOpcode::Predicate => RegisterClass::Predicate,
            MetalOpcode::Barrier | MetalOpcode::Fence | MetalOpcode::Commit => {
                RegisterClass::Special
            }
            MetalOpcode::Return => RegisterClass::Special,
            _ => RegisterClass::Gpr,
        }
    }

    /// Latencia estimada, en ciclos.
    pub fn latency(&self) -> u32 {
        match self {
            MetalOpcode::Alloc => 8,
            MetalOpcode::Load => 4,
            MetalOpcode::Store => 1,
            MetalOpcode::Move => 1,
            MetalOpcode::Add => 1,
            MetalOpcode::Mul => 3,
            MetalOpcode::Fma => 4,
            MetalOpcode::Xor => 1,
            MetalOpcode::Shuffle => 2,
            MetalOpcode::Predicate => 1,
            MetalOpcode::Barrier => 12,
            MetalOpcode::Fence => 20,
            MetalOpcode::Commit => 6,
            MetalOpcode::Return => 1,
        }
    }

    /// ¿Es una barrera o valla (operación de orden)?
    pub fn is_barrier(&self) -> bool {
        matches!(
            self,
            MetalOpcode::Barrier | MetalOpcode::Fence | MetalOpcode::Commit
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Operandos e instrucciones
// ─────────────────────────────────────────────────────────────────────────

/// Operando del Metal-IR.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Operand {
    /// Registro virtual (SSA).
    Virt(usize),
    /// Inmediato de 11 bits.
    Immediate(i64),
    /// Registro físico ya asignado.
    Physical(PhysicalReg),
}

impl Operand {
    /// Índice codificable (los inmediatos no ocupan campo de registro).
    pub fn index(&self) -> u32 {
        match self {
            Operand::Virt(v) => (*v as u32) & 0x1F,
            Operand::Immediate(_) => 31,
            Operand::Physical(p) => (p.index as u32) & 0x1F,
        }
    }

    /// Etiqueta legible del operando.
    pub fn label(&self) -> String {
        match self {
            Operand::Virt(v) => format!("v{}", v),
            Operand::Immediate(i) => format!("#{}", i),
            Operand::Physical(p) => p.label(),
        }
    }
}

/// Una instrucción del Metal-IR.
#[derive(Debug, Clone)]
pub struct MetalOp {
    /// Operación a ejecutar.
    pub opcode: MetalOpcode,
    /// Registro virtual de destino.
    pub dst: Option<usize>,
    /// Registros virtuales leídos.
    pub src: Vec<usize>,
    /// Inmediato, si procede.
    pub imm: Option<i64>,
    /// Carriles activos.
    pub lanes: u32,
    /// Origen en el AST (raíz u operador).
    pub origin: String,
    /// Latencia de la instrucción, en ciclos.
    pub cycles: u32,
}

impl MetalOp {
    /// Máscara de carriles (`1` en cada carril activo).
    pub fn lane_mask(&self) -> u32 {
        if self.lanes >= 32 {
            u32::MAX
        } else {
            (1_u32 << self.lanes) - 1
        }
    }

    /// **Codificación de 32 bits**:
    /// `[31:26] opcode · [25:21] dst · [20:16] src0 · [15:11] carriles · [10:0] inmediato`.
    pub fn encode(&self) -> u32 {
        let dst = self.dst.unwrap_or(31) as u32 & 0x1F;
        let src0 = self.src.first().copied().unwrap_or(31) as u32 & 0x1F;
        let lanes = self.lanes.clamp(1, 31) & 0x1F;
        let imm = (self.imm.unwrap_or(0) as u32) & IMM_MASK;
        (self.opcode.code() << 26) | (dst << 21) | (src0 << 16) | (lanes << 11) | imm
    }

    /// Descripción legible de la instrucción.
    pub fn describe(&self) -> String {
        let destination = match self.dst {
            Some(virt) => format!("v{}", virt),
            None => "—".to_string(),
        };
        let sources: Vec<String> = self.src.iter().map(|virt| format!("v{}", virt)).collect();
        format!(
            "0x{:08X}  {:<7} {:<5} ⇐ [{}] carriles={} ← {}",
            self.encode(),
            self.opcode.label(),
            destination,
            sources.join(", "),
            self.lanes,
            self.origin
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Bypass del driver y despacho
// ─────────────────────────────────────────────────────────────────────────

/// Latencia media de una ida y vuelta al driver del SO (nanosegundos).
const DRIVER_ROUNDTRIP_NS: u64 = 1_240;

/// Ruta de **bypass del driver**: descriptor de anillo MMIO.
///
/// En lugar de encolar cada operación en el sistema operativo, el Metal-IR
/// publica el descriptor directamente en el *layout* abstracto y el anillo se
/// consume por lotes. El modelo es simulado y determinista.
#[derive(Debug, Clone)]
pub struct DriverBypass {
    /// Descriptor de la cola (huella del programa codificado).
    pub descriptor: u64,
    /// Entradas del anillo de despacho (potencia de dos).
    pub ring_entries: u32,
    /// Llamadas al driver evitadas.
    pub avoided_syscalls: usize,
    /// Latencia total ahorrada, en nanosegundos.
    pub latency_saved_ns: u64,
    /// Base del mapeo directo simulado (12 bits bajos reservados al offset).
    pub mmio_base: u64,
}

impl DriverBypass {
    /// Deriva la ruta de bypass a partir de las palabras codificadas.
    pub fn from_words(words: &[u32], ops: usize) -> Self {
        let mut bytes = Vec::with_capacity(words.len() * 4);
        for word in words {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        let descriptor = fnv1a(&bytes);
        let ring = ops.clamp(8, 256).next_power_of_two() as u32;
        DriverBypass {
            descriptor,
            ring_entries: ring,
            avoided_syscalls: ops,
            latency_saved_ns: ops as u64 * DRIVER_ROUNDTRIP_NS,
            mmio_base: descriptor & 0xFFFF_FFFF_F000,
        }
    }

    /// Descripción legible de la ruta.
    pub fn label(&self) -> String {
        format!(
            "anillo×{} · descriptor=0x{:016X} · base_mmio=0x{:012X} · {} syscalls evitadas · {:.3} ms ahorrados",
            self.ring_entries,
            self.descriptor,
            self.mmio_base,
            self.avoided_syscalls,
            self.latency_saved_ns as f64 / 1_000_000.0
        )
    }
}

/// Informe de despacho simulado del programa de metal.
#[derive(Debug, Clone)]
pub struct DispatchReport {
    /// Oleadas de despacho.
    pub waves: usize,
    /// Carriles por oleada.
    pub lanes: u32,
    /// Ciclos totales acumulados.
    pub cycles: u32,
    /// Ocupación del *layout* de registros, en `[0,1]`.
    pub occupancy: f64,
    /// Llamadas al driver evitadas.
    pub bypassed_syscalls: usize,
    /// Palabras codificadas emitidas.
    pub words: usize,
    /// Operaciones de orden (barreras/vallas/confirmaciones).
    pub barriers: usize,
}

impl DispatchReport {
    /// Descripción legible del despacho.
    pub fn label(&self) -> String {
        format!(
            "{} oleada(s) × {} carril(es) · {} ciclos · ocupación={:.1}% · {} barreras · {} palabras · {} syscalls evitadas",
            self.waves,
            self.lanes,
            self.cycles,
            self.occupancy * 100.0,
            self.barriers,
            self.words,
            self.bypassed_syscalls
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Programa de metal
// ─────────────────────────────────────────────────────────────────────────

/// Programa Metal-IR completo: instrucciones, *layout* de registros, ruta de
/// bypass y palabras codificadas.
#[derive(Debug, Clone)]
pub struct MetalProgram {
    /// Etiqueta del programa.
    pub label: String,
    /// Ruta de hardware objetivo.
    pub device: Device,
    /// Instrucciones del IR.
    pub ops: Vec<MetalOp>,
    /// Rangos de vida de los registros virtuales.
    pub ranges: Vec<LiveRange>,
    /// Asignación de registros (virtual → físico).
    pub allocation: RegAllocation,
    /// Ruta de bypass del driver.
    pub bypass: DriverBypass,
    words: Vec<u32>,
}

impl MetalProgram {
    /// Palabras codificadas de la ISA de 32 bits.
    pub fn words(&self) -> &[u32] {
        &self.words
    }

    /// Número de instrucciones.
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// ¿Programa vacío?
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Descriptor del programa (huella de las palabras codificadas).
    pub fn descriptor(&self) -> u64 {
        self.bypass.descriptor
    }

    /// Número máximo de carriles activos.
    pub fn lanes(&self) -> u32 {
        self.ops.iter().map(|op| op.lanes).max().unwrap_or(1)
    }

    /// Operaciones de orden (barreras, vallas y confirmaciones).
    pub fn barriers(&self) -> usize {
        self.ops.iter().filter(|op| op.opcode.is_barrier()).count()
    }

    /// Registro físico asignado a un virtual.
    pub fn physical_of(&self, virt: usize) -> Option<PhysicalReg> {
        self.allocation.physical(virt).copied()
    }

    /// Histograma de opcodes, en orden canónico.
    pub fn signature(&self) -> String {
        let mut parts = Vec::new();
        for opcode in MetalOpcode::all() {
            let count = self.ops.iter().filter(|op| op.opcode == opcode).count();
            if count > 0 {
                parts.push(format!("{}×{}", opcode.label(), count));
            }
        }
        if parts.is_empty() {
            "(programa vacío)".to_string()
        } else {
            parts.join(" · ")
        }
    }

    /// Despacho simulado del programa.
    pub fn dispatch(&self) -> DispatchReport {
        let lanes = self.lanes().max(1);
        let ops = self.ops.len();
        let waves = ops.div_ceil(lanes as usize);
        DispatchReport {
            waves: waves.max(1),
            lanes,
            cycles: self.ops.iter().map(|op| op.cycles).sum(),
            occupancy: self.allocation.occupancy(),
            bypassed_syscalls: self.bypass.avoided_syscalls,
            words: self.words.len(),
            barriers: self.barriers(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Traductor AST → Metal-IR
// ─────────────────────────────────────────────────────────────────────────

/// Carriles asignados a una operación según la ruta de hardware.
fn lanes_for(device: Device, opcode: MetalOpcode) -> u32 {
    match (device, opcode.dst_class()) {
        (Device::Gpu, RegisterClass::Vector) => 32,
        (Device::Cpu, RegisterClass::Vector) => 4,
        (Device::Gpu, RegisterClass::Gpr) => 8,
        _ => 1,
    }
}

/// Estado interno de la traducción.
struct Lowering {
    device: Device,
    ops: Vec<MetalOp>,
    ranges: Vec<LiveRange>,
    next_virt: usize,
    last: Option<usize>,
}

impl Lowering {
    fn new(device: Device) -> Self {
        Lowering {
            device,
            ops: Vec::new(),
            ranges: Vec::new(),
            next_virt: 0,
            last: None,
        }
    }

    /// Emite una instrucción encadenada al valor anterior.
    fn emit(&mut self, opcode: MetalOpcode, origin: String, imm: Option<i64>) {
        let index = self.ops.len();
        let dst = self.next_virt;
        self.next_virt += 1;

        let mut src = Vec::new();
        if let Some(previous) = self.last {
            src.push(previous);
            if let Some(range) = self.ranges.iter_mut().find(|r| r.virt == previous) {
                range.death = index;
            }
        }
        self.ranges.push(LiveRange {
            virt: dst,
            class: opcode.dst_class(),
            birth: index,
            death: index,
        });
        self.ops.push(MetalOp {
            opcode,
            dst: Some(dst),
            src,
            imm,
            lanes: lanes_for(self.device, opcode),
            origin,
            cycles: opcode.latency(),
        });
        self.last = Some(dst);
    }

    /// Traduce un token del AST a una o ninguna instrucción.
    fn step(&mut self, token: &Token) {
        match &token.kind {
            TokenKind::Root { letters, keyword } => {
                let (opcode, imm) = match keyword {
                    Some(Keyword::Manifest) => (MetalOpcode::Alloc, Some(64)),
                    Some(Keyword::Synthesize) => (MetalOpcode::Fma, None),
                    Some(Keyword::Guard) => (MetalOpcode::Barrier, None),
                    Some(Keyword::Execute) => (MetalOpcode::Predicate, None),
                    Some(Keyword::Emit) => (MetalOpcode::Store, None),
                    Some(Keyword::Judge) => (MetalOpcode::Xor, None),
                    // Raíz desconocida: autopoiesis ⇒ reserva dinámica.
                    None => (MetalOpcode::Alloc, Some(0)),
                };
                let meaning = keyword.map(|k| k.meaning()).unwrap_or("autopoiesis");
                self.emit(opcode, format!("raíz {} ⇒ {}", letters, meaning), imm);
            }
            TokenKind::Number(value) => self.emit(
                MetalOpcode::Move,
                format!("número {}", value),
                Some(*value as i64),
            ),
            TokenKind::Str(text) => {
                let imm = (fnv1a(text.as_bytes()) & 0x1FF) as i64;
                self.emit(MetalOpcode::Load, format!("cadena «{}»", text), Some(imm));
            }
            TokenKind::Identifier(name) => {
                let imm = (fnv1a(name.as_bytes()) & 0x1FF) as i64;
                self.emit(MetalOpcode::Load, format!("ident {}", name), Some(imm));
            }
            // Fusión paraconsistente: valla de orden total.
            TokenKind::BangBang => self.emit(
                MetalOpcode::Fence,
                "fusión !! ⇒ valla de orden".to_string(),
                None,
            ),
            TokenKind::Bang | TokenKind::Question => self.emit(
                MetalOpcode::Predicate,
                "colapso observacional".to_string(),
                None,
            ),
            TokenKind::Star => self.emit(
                MetalOpcode::Mul,
                "conjunción * (meet de Belnap)".to_string(),
                None,
            ),
            TokenKind::Plus => self.emit(
                MetalOpcode::Shuffle,
                "disyunción + (join por carril)".to_string(),
                None,
            ),
            TokenKind::Newline | TokenKind::Eof => {}
            other => self.emit(MetalOpcode::Move, format!("{}", other), None),
        }
    }

    /// Añade el cierre del descriptor y materializa el programa.
    fn finish(mut self, label: &str) -> MetalProgram {
        self.emit(
            MetalOpcode::Commit,
            "confirmación en el descriptor de anillo".to_string(),
            None,
        );
        self.emit(
            MetalOpcode::Return,
            "retorno al anfitrión".to_string(),
            None,
        );
        let allocation = RegAllocation::allocate(&self.ranges);
        let words: Vec<u32> = self.ops.iter().map(|op| op.encode()).collect();
        let bypass = DriverBypass::from_words(&words, self.ops.len());
        MetalProgram {
            label: label.to_string(),
            device: self.device,
            ops: self.ops,
            ranges: self.ranges,
            allocation,
            bypass,
            words,
        }
    }
}

/// Traductor del AST de Bara al Metal-IR.
///
/// Es una función pura y determinista: los mismos tokens producen siempre el
/// mismo programa, el mismo *layout* de registros y el mismo descriptor.
pub struct MetalMapper;

impl MetalMapper {
    /// Traduce una secuencia de tokens a un programa de metal para `device`.
    pub fn lower(label: &str, device: Device, tokens: &[Token]) -> MetalProgram {
        let mut lowering = Lowering::new(device);
        for token in tokens {
            lowering.step(token);
        }
        lowering.finish(label)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Utilidades internas
// ─────────────────────────────────────────────────────────────────────────

/// Hash FNV-1a de 64 bits. Determinista y sin dependencias externas.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}
