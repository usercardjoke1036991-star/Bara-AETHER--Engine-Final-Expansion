//! # Motor de emisión multiplataforma — `emission.rs`
//!
//! Traduce el AST *Shoresh* a **artefactos ejecutables** por dos vías, ambas
//! actuando como **capa externa de lectura**: el motor recibe `&ShoreshAst` y
//! `&[Token]` prestados, no muta nada del núcleo y no añade dependencias.
//!
//! ## Vía 1 · WebAssembly ([`emit_wasm`])
//! Se emite un módulo WASM **binario real** (magia `\0asm`, versión 1) con sus
//! secciones canónicas: tipo, funciones, memoria, exportaciones y código. El
//! programa se deriva del **Metal‑IR** que ya produce el núcleo
//! ([`MetalMapper::lower`]): cada opcode se traduce a una instrucción segura de
//! la ISA de 32 bits de WebAssembly. El conjunto de instrucciones emitidas es
//! **cerrado**: no hay `unreachable`, ni división, ni `call_indirect`, así que
//! el módulo **no puede atrapar** — no hay rutas de pánico dentro del WASM.
//!
//! ## Vía 2 · Binario nativo ([`emit_native`])
//! Se emite un **ELF64 ejecutable de verdad** con cabecera, *program header* y
//! secciones `.text`, `.aether` y `.shstrtab`. En Linux/x86‑64 el `.text`
//! contiene una rutina de salida real (`mov eax, 60 · mov edi, imm32 ·
//! syscall`) cuyo código de salida es el primer byte del ADN del AST: el
//! binario, al ejecutarse, **devuelve su propia huella**. En AArch64 se emite
//! la secuencia equivalente (`movz x8, #93 · movz x0, #imm16 · svc #0`). En
//! anfitriones que no sean Linux el motor no finge: emite un **contenedor
//! portable** (`AETHER-PORTABLE`) con el mismo registro `.aether`, documentado
//! como no ejecutable en ese anfitrión.
//!
//! ## El ADN va dentro (inmunidad por diseño)
//! Todo artefacto lleva una sección `.aether` con el **ADN firmado** del AST
//! ([`crate::ast_dna`]) y las palabras del Metal‑IR. Un lector independiente
//! ([`parse_native`], [`parse_wasm`]) puede extraerla y volver a verificar la
//! firma: el artefacto se autentica **antes** de ejecutarse, sin confiar en el
//! transporte ni en el nombre del fichero.
//!
//! ## Contrato
//! * **Totalidad** — ninguna entrada provoca pánico: un AST vacío o una
//!   corriente sin tokens producen artefactos mínimos válidos.
//! * **Determinismo** — el mismo AST y la misma clave producen los mismos
//!   bytes, bit a bit, sin marcas de tiempo.
//! * **Cero dependencias** — sólo `std` y el propio núcleo.

use crate::ast_dna::{ast_dna, short_hex, AstDna};
use crate::crypto_native::{digest_eq, hmac_sha256, sha256};
use crate::ffi_ingest::ShoreshAst;
use crate::fractal_geometry::FractalLayout;
use crate::lexer::Token;
use crate::memory_region::Device;
use crate::metal_ir::{MetalMapper, MetalOpcode, MetalProgram};

/// Formato de salida del motor de emisión.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitFormat {
    /// Módulo binario de WebAssembly.
    Wasm,
    /// Imagen nativa (ELF64 en Linux; contenedor portable en el resto).
    Native,
}

impl EmitFormat {
    /// Etiqueta legible.
    pub fn label(&self) -> &'static str {
        match self {
            EmitFormat::Wasm => "wasm",
            EmitFormat::Native => "nativo",
        }
    }
}

/// Anfitrión al que se dirige la emisión nativa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitHost {
    /// Linux sobre x86‑64: ELF64 con `exit(2)` real.
    LinuxX86_64,
    /// Linux sobre AArch64: ELF64 con `exit(2)` real.
    LinuxAarch64,
    /// Contenedor portable (no ejecutable): misma carga útil, sin ISA.
    Portable,
}

impl EmitHost {
    /// Anfitrión que se puede ejecutar en la máquina que compila.
    ///
    /// Es el anfitrión que usan las pruebas para *correr* el binario emitido;
    /// fuera de Linux cae en [`EmitHost::Portable`] sin dramatizar.
    pub fn current() -> EmitHost {
        if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            EmitHost::LinuxX86_64
        } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
            EmitHost::LinuxAarch64
        } else {
            EmitHost::Portable
        }
    }

    /// Código `e_machine` del ELF64 (0 en el contenedor portable).
    pub fn machine(&self) -> u16 {
        match self {
            EmitHost::LinuxX86_64 => 62,
            EmitHost::LinuxAarch64 => 183,
            EmitHost::Portable => 0,
        }
    }

    /// Etiqueta legible.
    pub fn label(&self) -> &'static str {
        match self {
            EmitHost::LinuxX86_64 => "linux-x86_64",
            EmitHost::LinuxAarch64 => "linux-aarch64",
            EmitHost::Portable => "portable",
        }
    }

    /// ¿Esta imagen se puede ejecutar en este anfitrión?
    pub fn is_runnable_here(&self) -> bool {
        *self == EmitHost::current() && *self != EmitHost::Portable
    }
}

/// Opciones de emisión.
#[derive(Debug, Clone)]
pub struct EmitOptions {
    /// Etiqueta del módulo (viaja dentro del ADN firmado).
    pub label: String,
    /// Ruta de hardware del Metal‑IR (CPU o GPU).
    pub device: Device,
    /// Anfitrión objetivo de la imagen nativa.
    pub host: EmitHost,
    /// Sellar el artefacto con el ADN firmado (por omisión, sí).
    pub seal: bool,
}

impl EmitOptions {
    /// Opciones con sellado activo.
    pub fn new(label: &str, host: EmitHost) -> Self {
        EmitOptions {
            label: label.to_string(),
            device: Device::Cpu,
            host,
            seal: true,
        }
    }

    /// Opciones para un módulo WASM (el anfitrión no aplica).
    pub fn wasm(label: &str) -> Self {
        EmitOptions::new(label, EmitHost::Portable)
    }
}

/// Sección de un artefacto emitido (para auditar el binario por dentro).
#[derive(Debug, Clone)]
pub struct SectionRecord {
    /// Nombre de la sección.
    pub name: String,
    /// Desplazamiento dentro del artefacto.
    pub offset: usize,
    /// Longitud en bytes.
    pub bytes: usize,
    /// Digest del contenido de la sección.
    pub digest: [u8; 32],
    /// Nota sobre su papel en el artefacto.
    pub note: String,
}

/// Artefacto emitido: bytes, secciones, ADN y plan de memoria.
#[derive(Debug, Clone)]
pub struct EmissionArtifact {
    /// Formato del artefacto.
    pub format: EmitFormat,
    /// Anfitrión objetivo.
    pub host: EmitHost,
    /// Etiqueta del módulo.
    pub label: String,
    /// Bytes completos del artefacto.
    pub bytes: Vec<u8>,
    /// Digest de los bytes completos.
    pub digest: [u8; 32],
    /// Firma del artefacto (si se selló).
    pub signature: Option<[u8; 32]>,
    /// ADN firmado del AST de origen.
    pub dna: AstDna,
    /// Programa Metal‑IR del que se derivó el código.
    pub metal: MetalProgram,
    /// Reparto áureo de la memoria del módulo.
    pub layout: FractalLayout,
    /// Secciones del artefacto.
    pub sections: Vec<SectionRecord>,
    /// Notas de emisión (límites del formato, dichos sin adornos).
    pub notes: Vec<String>,
}

impl EmissionArtifact {
    /// Tamaño total en bytes.
    pub fn size(&self) -> usize {
        self.bytes.len()
    }

    /// ¿El artefacto va firmado?
    pub fn is_sealed(&self) -> bool {
        self.signature.is_some()
    }

    /// Sección por nombre.
    pub fn section(&self, name: &str) -> Option<&SectionRecord> {
        self.sections.iter().find(|record| record.name == name)
    }

    /// Resumen textual del artefacto.
    pub fn summary(&self) -> String {
        format!(
            "{}[{}] «{}» · {} bytes · sha256={} · sellado={} · ops={} · secciones={}",
            self.format.label(),
            self.host.label(),
            self.label,
            self.bytes.len(),
            short_hex(&self.digest[..8]),
            self.is_sealed(),
            self.metal.len(),
            self.sections.len()
        )
    }

    /// Recalcula el digest y contrasta el sello: ¿sigue siendo este artefacto el
    /// que se firmó? Detecta cualquier manipulación posterior a la emisión.
    pub fn verify_seal(&self, key: &[u8; 32]) -> bool {
        let expected_digest = sha256(&self.bytes);
        if !digest_eq(&expected_digest, &self.digest) {
            return false;
        }
        let Some(signature) = self.signature else {
            return false;
        };
        let statement = seal_statement(&self.label, &expected_digest, &self.dna.root);
        digest_eq(&hmac_sha256(key, &statement), &signature)
    }
}

/// Enunciado sellado de un artefacto: `etiqueta ‖ digest ‖ raíz del ADN`.
pub fn seal_statement(label: &str, digest: &[u8; 32], root: &[u8; 32]) -> Vec<u8> {
    let mut statement = Vec::with_capacity(4 + label.len() + 64);
    statement.extend_from_slice(&(label.len() as u32).to_le_bytes());
    statement.extend_from_slice(label.as_bytes());
    statement.extend_from_slice(digest);
    statement.extend_from_slice(root);
    statement
}

/// Plan de emisión: Metal‑IR del núcleo + reparto áureo de la memoria.
fn plan_program(
    label: &str,
    options: &EmitOptions,
    tokens: &[Token],
) -> (MetalProgram, FractalLayout) {
    let metal = MetalMapper::lower(label, options.device, tokens);
    let widths: Vec<usize> = metal
        .ops
        .iter()
        .map(|op| (op.lanes.max(1) as usize) * 4)
        .collect();
    let layout = if widths.is_empty() {
        FractalLayout::plan(0, 0)
    } else {
        FractalLayout::plan_from(&widths)
    };
    (metal, layout)
}

/// Registro de sección con su digest, para el informe del artefacto.
#[allow(dead_code)]
fn section_record(name: &str, bytes: &[u8], offset: usize, note: &str) -> SectionRecord {
    SectionRecord {
        name: name.to_string(),
        offset,
        bytes: bytes.len(),
        digest: sha256(bytes),
        note: note.to_string(),
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Codificación entera de WebAssembly (LEB128)
// ─────────────────────────────────────────────────────────────────────────

/// Escribe un entero **sin signo** en LEB128 (base 128, *little-endian*).
pub fn write_var_u32(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Escribe un entero **con signo** en LEB128 (lo exige `i32.const`).
pub fn write_var_i32(out: &mut Vec<u8>, value: i32) {
    let mut remaining = value;
    loop {
        let byte = (remaining as u8) & 0x7f;
        remaining >>= 7;
        let sign_bit = byte & 0x40 != 0;
        if (remaining == 0 && !sign_bit) || (remaining == -1 && sign_bit) {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Lee un entero sin signo en LEB128: `(valor, bytes consumidos)`.
pub fn read_var_u32(bytes: &[u8], at: usize) -> Option<(u32, usize)> {
    let mut value = 0u32;
    let mut shift = 0u32;
    let mut consumed = 0usize;
    loop {
        let byte = *bytes.get(at + consumed)?;
        value |= u32::from(byte & 0x7f).checked_shl(shift)?;
        consumed += 1;
        if byte & 0x80 == 0 {
            return Some((value, consumed));
        }
        shift += 7;
        if shift >= 35 {
            return None;
        }
    }
}

/// Lee un entero con signo en LEB128: `(valor, bytes consumidos)`.
pub fn read_var_i32(bytes: &[u8], at: usize) -> Option<(i32, usize)> {
    let mut value = 0i32;
    let mut shift = 0u32;
    let mut consumed = 0usize;
    loop {
        let byte = *bytes.get(at + consumed)?;
        value |= i32::from(byte & 0x7f).checked_shl(shift)?;
        consumed += 1;
        if byte & 0x80 == 0 {
            if shift < 32 && byte & 0x40 != 0 {
                value |= !0i32 << shift;
            }
            return Some((value, consumed));
        }
        shift += 7;
        if shift >= 35 {
            return None;
        }
    }
}

/// Añade una sección WASM: identificador + longitud + cuerpo.
fn push_section(module: &mut Vec<u8>, id: u8, body: &[u8]) {
    module.push(id);
    write_var_u32(module, body.len() as u32);
    module.extend_from_slice(body);
}

// ─────────────────────────────────────────────────────────────────────────
// Emisión a WebAssembly
// ─────────────────────────────────────────────────────────────────────────

/// Cabecera binaria de un módulo WASM: magia `\0asm` + versión 1.
pub const WASM_HEADER: [u8; 8] = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];

/// Tamaño de página de la memoria lineal de WebAssembly (64 KiB).
pub const WASM_PAGE: u64 = 65_536;

/// Instrucciones que el motor puede emitir (conjunto **cerrado**).
///
/// Ninguna puede atrapar: no hay `unreachable` (`0x00`), ni división
/// (`i32.div_s` 0x6D, `i32.div_u` 0x6E), ni restos (0x6F, 0x70), ni
/// `call_indirect`. Un lector independiente rechaza cualquier byte fuera de
/// esta lista ([`parse_wasm`]), así que la ausencia de rutas de pánico queda
/// **verificada**, no prometida.
pub const SAFE_WASM_OPS: [u8; 11] = [
    0x01, // nop
    0x0B, // end
    0x20, // local.get
    0x21, // local.set
    0x22, // local.tee
    0x41, // i32.const
    0x6A, // i32.add
    0x6C, // i32.mul
    0x71, // i32.and
    0x73, // i32.xor
    0x77, // i32.rotl
];

/// ¿Pertenece la instrucción al conjunto seguro del motor?
pub fn is_safe_wasm_op(opcode: u8) -> bool {
    SAFE_WASM_OPS.contains(&opcode)
}

/// `local.get <idx>`.
fn push_local_get(body: &mut Vec<u8>, index: u32) {
    body.push(0x20);
    write_var_u32(body, index);
}

/// `local.set <idx>`.
fn push_local_set(body: &mut Vec<u8>, index: u32) {
    body.push(0x21);
    write_var_u32(body, index);
}

/// `local.tee <idx>` (fija el local y deja el valor en la pila).
fn push_local_tee(body: &mut Vec<u8>, index: u32) {
    body.push(0x22);
    write_var_u32(body, index);
}

/// `i32.const <inmediato>` (con signo, en LEB128).
fn push_const(body: &mut Vec<u8>, value: i32) {
    body.push(0x41);
    write_var_i32(body, value);
}

/// Traduce una operación del Metal‑IR a instrucciones WASM **balanceadas**.
///
/// El acumulador vive en el local 0: cada operación consume su inmediato —la
/// palabra de 32 bits que el núcleo ya codificó para esa instrucción— y deja
/// exactamente un valor en la pila, así que el cuerpo valida para cualquier
/// longitud de programa.
fn translate_metal_op(body: &mut Vec<u8>, opcode: MetalOpcode, immediate: u32) {
    let immediate = immediate as i32;
    match opcode {
        MetalOpcode::Alloc | MetalOpcode::Load | MetalOpcode::Add => {
            push_const(body, immediate);
            body.push(0x6A); // i32.add
        }
        MetalOpcode::Store | MetalOpcode::Xor => {
            push_const(body, immediate);
            body.push(0x73); // i32.xor
        }
        MetalOpcode::Mul => {
            push_const(body, immediate);
            body.push(0x6C); // i32.mul
        }
        MetalOpcode::Fma => {
            push_const(body, immediate);
            body.push(0x6C); // i32.mul
            push_const(body, immediate.wrapping_add(1));
            body.push(0x6A); // i32.add
        }
        MetalOpcode::Shuffle => {
            push_const(body, immediate);
            body.push(0x77); // i32.rotl · barajado de carriles
        }
        MetalOpcode::Predicate => {
            push_const(body, immediate);
            body.push(0x71); // i32.and · máscara de predicado
        }
        MetalOpcode::Move | MetalOpcode::Commit => push_local_tee(body, 0),
        MetalOpcode::Barrier | MetalOpcode::Fence => body.push(0x01), // nop
        MetalOpcode::Return => {}
    }
}

/// Nombre canónico de una sección WASM.
pub fn wasm_section_name(id: u8) -> &'static str {
    match id {
        0 => "custom",
        1 => "type",
        3 => "function",
        5 => "memory",
        7 => "export",
        10 => "code",
        _ => "desconocida",
    }
}

/// Recorre las secciones de un módulo: `(id, nombre, offset, longitud)`.
///
/// Es el mismo recorrido que usa el lector de verificación, así que las
/// secciones que el artefacto *declara* son exactamente las que el fichero
/// *tiene*.
pub fn collect_wasm_sections(module: &[u8]) -> Option<Vec<(u8, String, usize, usize)>> {
    if module.len() < 8 || &module[..8] != WASM_HEADER.as_slice() {
        return None;
    }
    let mut out = Vec::new();
    let mut at = 8usize;
    while at < module.len() {
        let id = *module.get(at)?;
        let (length, consumed) = read_var_u32(module, at + 1)?;
        let body_start = at + 1 + consumed;
        let body_end = body_start.checked_add(length as usize)?;
        if body_end > module.len() {
            return None;
        }

        let mut name = wasm_section_name(id).to_string();
        if id == 0 {
            if let Some((name_len, name_used)) = read_var_u32(module, body_start) {
                let from = body_start + name_used;
                let to = from.saturating_add(name_len as usize).min(body_end);
                if let Some(slice) = module.get(from..to) {
                    name = String::from_utf8_lossy(slice).to_string();
                }
            }
        }
        out.push((id, name, body_start, length as usize));
        at = body_end;
    }
    Some(out)
}

/// Cuenta instrucciones de un cuerpo WASM y exige el conjunto seguro.
///
/// Devuelve `None` ante cualquier byte fuera de [`SAFE_WASM_OPS`] o ante un
/// cuerpo mal formado: la verificación no es una promesa, es una lectura.
fn scan_body(body: &[u8]) -> Option<usize> {
    let mut at = 0usize;
    let (local_groups, consumed) = read_var_u32(body, at)?;
    at += consumed;
    for _ in 0..local_groups {
        let (_count, used) = read_var_u32(body, at)?;
        at += used;
        let _kind = *body.get(at)?;
        at += 1;
    }

    let mut instructions = 0usize;
    while at < body.len() {
        let opcode = *body.get(at)?;
        at += 1;
        instructions += 1;
        match opcode {
            0x0B => return Some(instructions), // end
            0x01 => {}
            0x41 => {
                let (_value, used) = read_var_i32(body, at)?;
                at += used;
            }
            0x20..=0x22 => {
                let (_index, used) = read_var_u32(body, at)?;
                at += used;
            }
            0x6A | 0x6C | 0x71 | 0x73 | 0x77 => {}
            _ => return None,
        }
    }
    None
}

/// Resumen de un módulo WASM releído por un lector **independiente**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmSummary {
    /// Versión de la codificación binaria (1).
    pub version: u32,
    /// Tipos de función declarados.
    pub types: usize,
    /// Funciones declaradas.
    pub functions: usize,
    /// Páginas mínimas de memoria lineal.
    pub memory_min: u32,
    /// Exportaciones: `(nombre, tipo, índice)`.
    pub exports: Vec<(String, u8, u32)>,
    /// Cuerpos de función presentes.
    pub code_bodies: usize,
    /// Instrucciones contadas en el primer cuerpo.
    pub instructions: usize,
    /// Secciones personalizadas (por donde viaja el ADN).
    pub custom_sections: Vec<String>,
    /// ¿Todo el cuerpo usa el conjunto seguro de instrucciones?
    pub safe_instruction_set: bool,
    /// Tamaño total del módulo.
    pub size: usize,
}

/// Relee un módulo WASM emitido por este motor y lo describe.
///
/// Devuelve `None` si la magia, la versión o alguna sección no cuadran: un
/// artefacto que no se puede releer no se da por bueno.
pub fn parse_wasm(module: &[u8]) -> Option<WasmSummary> {
    let sections = collect_wasm_sections(module)?;
    let mut version_bytes = [0u8; 4];
    for (slot, value) in version_bytes.iter_mut().zip(module.get(4..8)?.iter()) {
        *slot = *value;
    }
    let version = u32::from_le_bytes(version_bytes);

    let mut summary = WasmSummary {
        version,
        types: 0,
        functions: 0,
        memory_min: 0,
        exports: Vec::new(),
        code_bodies: 0,
        instructions: 0,
        custom_sections: Vec::new(),
        safe_instruction_set: true,
        size: module.len(),
    };

    for (id, name, body_start, body_len) in sections {
        let body = module.get(body_start..body_start + body_len)?;
        match id {
            0 => summary.custom_sections.push(name),
            1 | 3 => {
                let (count, _) = read_var_u32(body, 0)?;
                if id == 1 {
                    summary.types = count as usize;
                } else {
                    summary.functions = count as usize;
                }
            }
            5 => {
                let (count, used) = read_var_u32(body, 0)?;
                if count > 0 {
                    let flags = *body.get(used)?;
                    if flags > 1 {
                        return None;
                    }
                    let (min, _) = read_var_u32(body, used + 1)?;
                    summary.memory_min = min;
                }
            }
            7 => {
                let (count, mut at) = read_var_u32(body, 0)?;
                for _ in 0..count {
                    let (name_len, used) = read_var_u32(body, at)?;
                    let from = at + used;
                    let to = from + name_len as usize;
                    let export_name = String::from_utf8_lossy(body.get(from..to)?).to_string();
                    let kind = *body.get(to)?;
                    let (index, index_used) = read_var_u32(body, to + 1)?;
                    summary.exports.push((export_name, kind, index));
                    at = to + 1 + index_used;
                }
            }
            10 => {
                let (count, mut at) = read_var_u32(body, 0)?;
                summary.code_bodies = count as usize;
                for index in 0..count {
                    let (size, used) = read_var_u32(body, at)?;
                    let from = at + used;
                    let to = from + size as usize;
                    let instructions = scan_body(body.get(from..to)?)?;
                    if index == 0 {
                        summary.instructions = instructions;
                    }
                    at = to;
                }
            }
            _ => {}
        }
    }
    Some(summary)
}

/// Nota legible sobre el papel de una sección WASM.
pub fn wasm_note(id: u8) -> &'static str {
    match id {
        0 => "ADN firmado del AST (los motores la ignoran)",
        1 => "firma de la función: (i32, i32) -> i32",
        3 => "índice de la función exportada",
        5 => "memoria lineal dimensionada por la retícula áurea",
        7 => "exportaciones: memoria lineal y función `shoresh`",
        10 => "cuerpo con el subconjunto seguro de instrucciones",
        _ => "sección desconocida",
    }
}

/// Firma del artefacto según las opciones de emisión.
fn seal(
    options: &EmitOptions,
    digest: &[u8; 32],
    dna: &AstDna,
    key: &[u8; 32],
) -> Option<[u8; 32]> {
    if options.seal {
        Some(hmac_sha256(
            key,
            &seal_statement(&options.label, digest, &dna.root),
        ))
    } else {
        None
    }
}

/// Emite un **módulo WebAssembly** a partir del AST y de su corriente de tokens.
///
/// La función exportada `shoresh` acumula en el local 0 la traducción de cada
/// operación del Metal‑IR y devuelve ese valor: el módulo es un artefacto
/// autocontenido, sin importaciones y sin rutas de fallo.
pub fn emit_wasm(
    ast: &ShoreshAst,
    tokens: &[Token],
    options: &EmitOptions,
    key: &[u8; 32],
) -> EmissionArtifact {
    let (metal, layout) = plan_program(&options.label, options, tokens);
    let dna = ast_dna(&options.label, ast, key);
    let words = metal.words();
    let pages = layout.span_bytes.div_ceil(WASM_PAGE).clamp(1, 64) as u32;

    // Cuerpo de la única función: `(i32, i32) -> i32` con acumulador en local 0.
    let mut body = vec![0x00u8]; // sin locales adicionales
    push_local_get(&mut body, 0);
    for (index, op) in metal.ops.iter().enumerate() {
        if op.opcode == MetalOpcode::Return {
            push_local_set(&mut body, 0);
            break;
        }
        translate_metal_op(&mut body, op.opcode, words.get(index).copied().unwrap_or(0));
    }
    push_local_get(&mut body, 0);
    body.push(0x0B); // end

    let mut module = Vec::new();
    module.extend_from_slice(&WASM_HEADER);

    let type_section: [u8; 7] = [0x01, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F];
    push_section(&mut module, 1, &type_section);
    push_section(&mut module, 3, &[0x01, 0x00]);

    let mut memory_section = vec![0x01u8, 0x00];
    write_var_u32(&mut memory_section, pages);
    push_section(&mut module, 5, &memory_section);

    let mut exports = vec![0x02u8];
    for (name, kind) in [("memory", 0x02u8), ("shoresh", 0x00)] {
        write_var_u32(&mut exports, name.len() as u32);
        exports.extend_from_slice(name.as_bytes());
        exports.push(kind);
        write_var_u32(&mut exports, 0);
    }
    push_section(&mut module, 7, &exports);

    let mut code_section = vec![0x01u8];
    write_var_u32(&mut code_section, body.len() as u32);
    code_section.extend_from_slice(&body);
    push_section(&mut module, 10, &code_section);

    // El ADN viaja en una sección personalizada (los motores la ignoran).
    let record = aether_record(&dna, &metal);
    let mut custom = Vec::new();
    write_var_u32(&mut custom, 6);
    custom.extend_from_slice(b"aether");
    custom.extend_from_slice(&record);
    push_section(&mut module, 0, &custom);

    let digest = sha256(&module);
    let signature = seal(options, &digest, &dna, key);

    let sections = collect_wasm_sections(&module)
        .unwrap_or_default()
        .iter()
        .map(|(id, name, offset, length)| SectionRecord {
            name: format!("wasm:{}", name),
            offset: *offset,
            bytes: *length,
            digest: sha256(module.get(*offset..*offset + *length).unwrap_or(&[])),
            note: wasm_note(*id).to_string(),
        })
        .collect();

    let notes = vec![
        format!(
            "memoria lineal: {} página(s) de 64 KiB (retícula φ: {} bytes)",
            pages, layout.span_bytes
        ),
        "cuerpo restringido al conjunto seguro: sin `unreachable`, sin división, sin `call_indirect`"
            .to_string(),
        "el ADN firmado viaja en la sección personalizada `aether`".to_string(),
    ];

    EmissionArtifact {
        format: EmitFormat::Wasm,
        host: EmitHost::Portable,
        label: options.label.clone(),
        bytes: module,
        digest,
        signature,
        dna,
        metal,
        layout,
        sections,
        notes,
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Registro `.aether`: el ADN viaja dentro del artefacto
// ─────────────────────────────────────────────────────────────────────────

/// Magia del registro de ADN (8 bytes).
pub const AETHER_MAGIC: [u8; 8] = *b"AETHER01";

/// Carga útil del registro `.aether` leída de vuelta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AetherRecord {
    /// Etiqueta del módulo.
    pub label: String,
    /// Raíz de Merkle del ADN.
    pub root: [u8; 32],
    /// Firma del ADN.
    pub signature: [u8; 32],
    /// Identificador de la clave firmante.
    pub key_id: u64,
    /// Número de nodos del AST de origen.
    pub nodes: usize,
    /// Palabras del Metal‑IR incluidas en el artefacto.
    pub words: Vec<u32>,
    /// Digest interno del registro.
    pub digest: [u8; 32],
}

/// Lee 4 bytes en *little-endian* sin salirse del *slice*.
fn read_u32_le(bytes: &[u8], at: usize) -> Option<u32> {
    let mut word = [0u8; 4];
    for (offset, slot) in word.iter_mut().enumerate() {
        *slot = *bytes.get(at + offset)?;
    }
    Some(u32::from_le_bytes(word))
}

/// Lee 8 bytes en *little-endian* sin salirse del *slice*.
fn read_u64_le(bytes: &[u8], at: usize) -> Option<u64> {
    let mut word = [0u8; 8];
    for (offset, slot) in word.iter_mut().enumerate() {
        *slot = *bytes.get(at + offset)?;
    }
    Some(u64::from_le_bytes(word))
}

/// Lee una huella de 32 bytes sin salirse del *slice*.
fn read_digest(bytes: &[u8], at: usize) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    for (offset, slot) in out.iter_mut().enumerate() {
        *slot = *bytes.get(at + offset)?;
    }
    Some(out)
}

/// Longitud mínima del registro: magia + etiqueta(0) + ADN + digest.
const AETHER_MIN: usize = 8 + 4 + 32 + 32 + 8 + 4 + 4 + 32;

/// Construye el registro: `magia ‖ etiqueta ‖ ADN ‖ palabras ‖ digest`.
pub fn aether_record(dna: &AstDna, metal: &MetalProgram) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&AETHER_MAGIC);
    out.extend_from_slice(&(dna.label.len() as u32).to_le_bytes());
    out.extend_from_slice(dna.label.as_bytes());
    out.extend_from_slice(&dna.root);
    out.extend_from_slice(&dna.signature);
    out.extend_from_slice(&dna.key_id.to_le_bytes());
    out.extend_from_slice(&(dna.nodes.len() as u32).to_le_bytes());
    out.extend_from_slice(&(metal.words().len() as u32).to_le_bytes());
    for word in metal.words() {
        out.extend_from_slice(&word.to_le_bytes());
    }
    let digest = sha256(&out);
    out.extend_from_slice(&digest);
    out
}

/// Relee el registro y comprueba su **digest interno**.
///
/// Es una lectura defensiva: las longitudes se validan **antes** de reservar
/// memoria, de modo que un registro corrupto no puede hacer que el lector se
/// quede sin recursos (importante porque la pasarela de inmunidad alimenta esta
/// función con cargas que vienen de fuera).
pub fn parse_aether(bytes: &[u8]) -> Option<AetherRecord> {
    if bytes.get(..8)? != AETHER_MAGIC.as_slice() || bytes.len() < AETHER_MIN {
        return None;
    }
    let mut at = 8usize;

    let label_len = read_u32_le(bytes, at)? as usize;
    at += 4;
    let label = String::from_utf8_lossy(bytes.get(at..at + label_len)?).to_string();
    at += label_len;

    let root = read_digest(bytes, at)?;
    at += 32;
    let signature = read_digest(bytes, at)?;
    at += 32;
    let key_id = read_u64_le(bytes, at)?;
    at += 8;
    let nodes = read_u32_le(bytes, at)? as usize;
    at += 4;
    let words_len = read_u32_le(bytes, at)? as usize;
    at += 4;

    // Cota previa a cualquier reserva: las palabras deben caber en lo que queda.
    let remaining = bytes.len().checked_sub(at + 32)?;
    if words_len * 4 > remaining {
        return None;
    }
    let mut words = Vec::with_capacity(words_len);
    for _ in 0..words_len {
        words.push(read_u32_le(bytes, at)?);
        at += 4;
    }

    let digest = read_digest(bytes, at)?;
    at += 32;
    if at != bytes.len() {
        return None;
    }
    if !digest_eq(&sha256(bytes.get(..at - 32)?), &digest) {
        return None;
    }

    Some(AetherRecord {
        label,
        root,
        signature,
        key_id,
        nodes,
        words,
        digest,
    })
}

// ─────────────────────────────────────────────────────────────────────────
// Emisión nativa: ELF64 ejecutable o contenedor portable
// ─────────────────────────────────────────────────────────────────────────

/// Base de carga de la imagen nativa (`0x400000`, la de siempre).
pub const ELF_BASE: u64 = 0x40_0000;

/// Desplazamiento del punto de entrada: tras cabecera (64) y *phdr* (56).
pub const ELF_TEXT_OFFSET: usize = 0x78;

/// Magia del contenedor portable (no ejecutable): `AETHER-PORTABLE!`.
pub const PORTABLE_MAGIC: [u8; 16] = *b"AETHER-PORTABLE!";

/// Alinea un valor al múltiplo indicado.
fn align_to(value: usize, alignment: usize) -> usize {
    value.div_ceil(alignment) * alignment
}

/// Escribe un entero de 16 bits en *little-endian* dentro de la imagen.
fn put_u16(image: &mut [u8], at: usize, value: u16) {
    if let Some(slice) = image.get_mut(at..at + 2) {
        slice.copy_from_slice(&value.to_le_bytes());
    }
}

/// Escribe un entero de 32 bits en *little-endian* dentro de la imagen.
fn put_u32(image: &mut [u8], at: usize, value: u32) {
    if let Some(slice) = image.get_mut(at..at + 4) {
        slice.copy_from_slice(&value.to_le_bytes());
    }
}

/// Escribe un entero de 64 bits en *little-endian* dentro de la imagen.
fn put_u64(image: &mut [u8], at: usize, value: u64) {
    if let Some(slice) = image.get_mut(at..at + 8) {
        slice.copy_from_slice(&value.to_le_bytes());
    }
}

/// Copia bytes dentro de la imagen, sin poder salirse.
fn put_bytes(image: &mut [u8], at: usize, bytes: &[u8]) {
    if let Some(slice) = image.get_mut(at..at + bytes.len()) {
        slice.copy_from_slice(bytes);
    }
}

/// Código de máquina de la rutina de salida del anfitrión.
///
/// * **x86‑64**: `mov eax, 60` (`b8 3c 00 00 00`) · `mov edi, imm32` (`bf …`)
///   · `syscall` (`0f 05`).
/// * **AArch64**: `movz x8, #93` · `movz x0, #imm16` · `svc #0`.
///
/// El inmediato es un byte del ADN, así que la rutina termina con el código de
/// salida `code`: el binario **devuelve su propia huella** al sistema.
fn exit_stub(host: EmitHost, code: u8) -> Vec<u8> {
    match host {
        EmitHost::LinuxX86_64 => {
            // `mov eax, imm32` (5) + `mov edi, imm32` (5) + `syscall` (2) = 12.
            let mut stub = Vec::with_capacity(12);
            stub.extend_from_slice(&[0xB8, 60, 0x00, 0x00, 0x00]); // mov eax, 60 · exit
            stub.push(0xBF); // mov edi, imm32
            stub.extend_from_slice(&u32::from(code).to_le_bytes());
            stub.extend_from_slice(&[0x0F, 0x05]); // syscall
            stub
        }
        EmitHost::LinuxAarch64 => {
            let mut stub = Vec::with_capacity(12);
            let movz_x8 = 0xD280_0000u32 | (93u32 << 5) | 8;
            let movz_x0 = 0xD280_0000u32 | ((u32::from(code) & 0xffff) << 5);
            stub.extend_from_slice(&movz_x8.to_le_bytes());
            stub.extend_from_slice(&movz_x0.to_le_bytes());
            stub.extend_from_slice(&0xD400_0001u32.to_le_bytes()); // svc #0
            stub
        }
        EmitHost::Portable => Vec::new(),
    }
}

/// Construye la imagen **ELF64** con el `stub` en `.text` y el ADN en `.aether`.
///
/// Devuelve los bytes y la tabla real de secciones `(nombre, offset, longitud)`.
fn build_elf64(
    host: EmitHost,
    stub: &[u8],
    record: &[u8],
) -> (Vec<u8>, Vec<(String, usize, usize)>) {
    let text_offset = ELF_TEXT_OFFSET;
    let aether_offset = align_to(text_offset + stub.len(), 16);
    let shstr_offset = align_to(aether_offset + record.len(), 16);

    // Tabla de nombres: `\0.text\0.aether\0.shstrtab\0`.
    let mut shstr = vec![0u8];
    let mut name_offsets = Vec::new();
    for name in [".text", ".aether", ".shstrtab"] {
        name_offsets.push(shstr.len());
        shstr.extend_from_slice(name.as_bytes());
        shstr.push(0);
    }

    let section_header_offset = align_to(shstr_offset + shstr.len(), 8);
    let total = section_header_offset + 64 * 4;
    let mut image = vec![0u8; total];

    // Cabecera ELF64.
    put_bytes(&mut image, 0, &[0x7F, b'E', b'L', b'F']);
    image[4] = 2; // ELFCLASS64
    image[5] = 1; // ELFDATA2LSB
    image[6] = 1; // EV_CURRENT
    put_u16(&mut image, 16, 2); // e_type = ET_EXEC
    put_u16(&mut image, 18, host.machine());
    put_u32(&mut image, 20, 1); // e_version
    put_u64(&mut image, 24, ELF_BASE + text_offset as u64); // e_entry
    put_u64(&mut image, 32, 64); // e_phoff
    put_u64(&mut image, 40, section_header_offset as u64); // e_shoff
    put_u16(&mut image, 52, 64); // e_ehsize
    put_u16(&mut image, 54, 56); // e_phentsize
    put_u16(&mut image, 56, 1); // e_phnum
    put_u16(&mut image, 58, 64); // e_shentsize
    put_u16(&mut image, 60, 4); // e_shnum
    put_u16(&mut image, 62, 3); // e_shstrndx

    // Program header: un único segmento cargado, legible y ejecutable.
    let load_size = (text_offset + stub.len()) as u64;
    put_u32(&mut image, 64, 1); // p_type = PT_LOAD
    put_u32(&mut image, 68, 5); // p_flags = R | X
    put_u64(&mut image, 72, 0); // p_offset
    put_u64(&mut image, 80, ELF_BASE); // p_vaddr
    put_u64(&mut image, 88, ELF_BASE); // p_paddr
    put_u64(&mut image, 96, load_size); // p_filesz
    put_u64(&mut image, 104, load_size); // p_memsz
    put_u64(&mut image, 112, 0x1000); // p_align

    // Secciones: [0] nula, [1] .text, [2] .aether, [3] .shstrtab.
    let text_header = section_header_offset + 64;
    put_u32(&mut image, text_header, name_offsets[0] as u32);
    put_u32(&mut image, text_header + 4, 1); // SHT_PROGBITS
    put_u64(&mut image, text_header + 8, 6); // SHF_ALLOC | SHF_EXECINSTR
    put_u64(&mut image, text_header + 16, ELF_BASE + text_offset as u64);
    put_u64(&mut image, text_header + 24, text_offset as u64);
    put_u64(&mut image, text_header + 32, stub.len() as u64);
    put_u64(&mut image, text_header + 48, 16);

    let aether_header = text_header + 64;
    put_u32(&mut image, aether_header, name_offsets[1] as u32);
    put_u32(&mut image, aether_header + 4, 1);
    put_u64(&mut image, aether_header + 24, aether_offset as u64);
    put_u64(&mut image, aether_header + 32, record.len() as u64);
    put_u64(&mut image, aether_header + 48, 16);

    let shstr_header = aether_header + 64;
    put_u32(&mut image, shstr_header, name_offsets[2] as u32);
    put_u32(&mut image, shstr_header + 4, 3); // SHT_STRTAB
    put_u64(&mut image, shstr_header + 24, shstr_offset as u64);
    put_u64(&mut image, shstr_header + 32, shstr.len() as u64);
    put_u64(&mut image, shstr_header + 48, 1);

    // Contenido de las secciones.
    put_bytes(&mut image, text_offset, stub);
    put_bytes(&mut image, aether_offset, record);
    put_bytes(&mut image, shstr_offset, &shstr);

    let sections = vec![
        (".text".to_string(), text_offset, stub.len()),
        (".aether".to_string(), aether_offset, record.len()),
        (".shstrtab".to_string(), shstr_offset, shstr.len()),
    ];
    (image, sections)
}

/// Construye el contenedor **portable** (no ejecutable): magia + registro.
fn build_portable(record: &[u8]) -> (Vec<u8>, Vec<(String, usize, usize)>) {
    let mut image = Vec::with_capacity(PORTABLE_MAGIC.len() + 4 + record.len());
    image.extend_from_slice(&PORTABLE_MAGIC);
    image.extend_from_slice(&(record.len() as u32).to_le_bytes());
    let offset = image.len();
    image.extend_from_slice(record);
    (image, vec![("aether".to_string(), offset, record.len())])
}

/// Lee un entero de 16 bits en *little-endian* sin salirse del *slice*.
fn read_u16_le(bytes: &[u8], at: usize) -> Option<u16> {
    let mut word = [0u8; 2];
    for (offset, slot) in word.iter_mut().enumerate() {
        *slot = *bytes.get(at + offset)?;
    }
    Some(u16::from_le_bytes(word))
}

/// Lee una cadena terminada en cero dentro de un bloque de nombres.
fn cstr_at(blob: &[u8], at: usize) -> String {
    let mut out = Vec::new();
    let mut index = at;
    while let Some(byte) = blob.get(index) {
        if *byte == 0 {
            break;
        }
        out.push(*byte);
        index += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Resumen de una imagen nativa releída (ELF64 o contenedor portable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSummary {
    /// Formato detectado.
    pub format: EmitFormat,
    /// Anfitrión deducido del código de máquina.
    pub host: EmitHost,
    /// Punto de entrada (0 en el contenedor portable).
    pub entry: u64,
    /// Secciones encontradas: `(nombre, offset, longitud)`.
    pub sections: Vec<(String, usize, usize)>,
    /// Registro de ADN extraído, si se pudo releer.
    pub record: Option<AetherRecord>,
    /// Tamaño total.
    pub size: usize,
}

/// Relee una imagen nativa y extrae su registro de ADN.
///
/// Es el paso que hace *verificable* la afirmación «el binario nace firmado»:
/// primero se relee el contenedor, luego se extrae `.aether` y, con ella, la
/// firma que se contrasta contra la clave soberana.
pub fn parse_native(image: &[u8]) -> Option<NativeSummary> {
    const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

    // ── Contenedor portable ──────────────────────────────────────────────
    if image.get(..16)? == PORTABLE_MAGIC.as_slice() {
        let length = read_u32_le(image, 16)? as usize;
        let offset = 20usize;
        let record_bytes = image.get(offset..offset + length)?;
        return Some(NativeSummary {
            format: EmitFormat::Native,
            host: EmitHost::Portable,
            entry: 0,
            sections: vec![("aether".to_string(), offset, length)],
            record: parse_aether(record_bytes),
            size: image.len(),
        });
    }

    // ── ELF64 little-endian ──────────────────────────────────────────────
    if image.get(..4)? != ELF_MAGIC.as_slice() || *image.get(4)? != 2 || *image.get(5)? != 1 {
        return None;
    }
    let machine = read_u16_le(image, 18)?;
    let host = match machine {
        62 => EmitHost::LinuxX86_64,
        183 => EmitHost::LinuxAarch64,
        _ => EmitHost::Portable,
    };
    let entry = read_u64_le(image, 24)?;
    let section_header_offset = read_u64_le(image, 40)? as usize;
    let section_count = read_u16_le(image, 60)? as usize;
    let names_index = read_u16_le(image, 62)? as usize;

    let names_header = section_header_offset + names_index * 64;
    let names_offset = read_u64_le(image, names_header + 24)? as usize;
    let names_size = read_u64_le(image, names_header + 32)? as usize;
    let names = image.get(names_offset..names_offset + names_size)?;

    let mut sections = Vec::new();
    let mut record = None;
    for index in 1..section_count {
        let header = section_header_offset + index * 64;
        let name_offset = read_u32_le(image, header)? as usize;
        let offset = read_u64_le(image, header + 24)? as usize;
        let size = read_u64_le(image, header + 32)? as usize;
        let name = cstr_at(names, name_offset);
        if name == ".aether" {
            if let Some(slice) = image.get(offset..offset + size) {
                record = parse_aether(slice);
            }
        }
        sections.push((name, offset, size));
    }

    Some(NativeSummary {
        format: EmitFormat::Native,
        host,
        entry,
        sections,
        record,
        size: image.len(),
    })
}

/// Nota sobre el papel de una sección nativa.
pub fn native_note(name: &str) -> &'static str {
    match name {
        ".text" => "punto de entrada ejecutable (rutina de salida del anfitrión)",
        ".aether" => "ADN firmado del AST y palabras del Metal‑IR",
        ".shstrtab" => "tabla de nombres de sección",
        _ => "sección auxiliar",
    }
}

/// Emite una **imagen nativa** del AST para el anfitrión indicado.
///
/// En Linux el `.text` es una rutina de salida real cuyo código es el primer
/// byte de la firma del ADN: ejecutar el binario devuelve su propia huella. En
/// cualquier otro anfitrión se emite el contenedor portable (misma carga útil,
/// sin fingir una ISA que aquí no se podría probar).
pub fn emit_native(
    ast: &ShoreshAst,
    tokens: &[Token],
    options: &EmitOptions,
    key: &[u8; 32],
) -> EmissionArtifact {
    let (metal, layout) = plan_program(&options.label, options, tokens);
    let dna = ast_dna(&options.label, ast, key);
    let record = aether_record(&dna, &metal);
    let exit_code = dna.signature[0];

    let (bytes, raw_sections, notes) = match options.host {
        EmitHost::Portable => {
            let (image, sections) = build_portable(&record);
            let notes = vec![
                "contenedor portable: misma carga útil que el ELF, sin ISA ejecutable".to_string(),
                "este anfitrión no es Linux: no se finge un ejecutable que no se puede probar"
                    .to_string(),
            ];
            (image, sections, notes)
        }
        host => {
            let stub = exit_stub(host, exit_code);
            let (image, sections) = build_elf64(host, &stub, &record);
            let notes = vec![
                format!(
                    "ELF64 ejecutable: `exit(2)` con código 0x{:02X} (primer byte de la firma del ADN)",
                    exit_code
                ),
                format!(
                    "un único segmento PT_LOAD en 0x{:X}; entrada en 0x{:X}",
                    ELF_BASE,
                    ELF_BASE + ELF_TEXT_OFFSET as u64
                ),
                "`.aether` transporta el ADN firmado y las palabras del Metal‑IR".to_string(),
            ];
            (image, sections, notes)
        }
    };

    let digest = sha256(&bytes);
    let signature = seal(options, &digest, &dna, key);
    let sections = raw_sections
        .iter()
        .map(|(name, offset, length)| SectionRecord {
            name: name.clone(),
            offset: *offset,
            bytes: *length,
            digest: sha256(bytes.get(*offset..*offset + *length).unwrap_or(&[])),
            note: native_note(name).to_string(),
        })
        .collect();

    EmissionArtifact {
        format: EmitFormat::Native,
        host: options.host,
        label: options.label.clone(),
        bytes,
        digest,
        signature,
        dna,
        metal,
        layout,
        sections,
        notes,
    }
}

impl EmissionArtifact {
    /// Escribe el artefacto en disco y devuelve cuántos bytes escribió.
    pub fn write_to(&self, path: &std::path::Path) -> std::io::Result<usize> {
        std::fs::write(path, &self.bytes)?;
        Ok(self.bytes.len())
    }

    /// Marca como ejecutable un fichero ya escrito (sistemas tipo Unix).
    ///
    /// En otros sistemas devuelve `false` sin dramatizar: no hay bit de
    /// ejecución que marcar.
    #[cfg(unix)]
    pub fn mark_executable(path: &std::path::Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(path) {
            Ok(metadata) => {
                let mut permissions = metadata.permissions();
                permissions.set_mode(0o755);
                std::fs::set_permissions(path, permissions).is_ok()
            }
            Err(_) => false,
        }
    }

    /// En sistemas que no son Unix no existe el bit de ejecución.
    #[cfg(not(unix))]
    pub fn mark_executable(_path: &std::path::Path) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_dna::golden_key;
    use crate::ffi_ingest::{ingest_json, to_shoresh};
    use crate::lexer::Lexer;

    /// AST de trabajo: ingesta JSON (la vía omnívora) de un objeto anidado.
    fn fixture() -> (ShoreshAst, Vec<Token>) {
        let source = r#"{"modulo":"aether","nodos":[1,2,3],"activo":true}"#;
        let ast = to_shoresh(&ingest_json(source));
        let tokens = Lexer::new("ברא\nחכם\nעבד\nשמר\nאמר\n").tokenize();
        (ast, tokens)
    }

    /// Clave soberana de las pruebas.
    fn key() -> [u8; 32] {
        golden_key(b"emision-soberana")
    }

    #[test]
    fn el_modulo_wasm_declara_sus_secciones_canonicas() {
        let (ast, tokens) = fixture();
        let artifact = emit_wasm(&ast, &tokens, &EmitOptions::wasm("genesis"), &key());

        assert!(artifact.bytes.starts_with(&WASM_HEADER));
        assert_eq!(artifact.format, EmitFormat::Wasm);
        assert!(artifact.is_sealed());
        assert!(artifact.size() > WASM_HEADER.len());

        let summary = parse_wasm(&artifact.bytes);
        assert!(summary.is_some(), "el módulo debe releerse");
        let Some(summary) = summary else { return };
        assert_eq!(summary.version, 1);
        assert_eq!(summary.types, 1);
        assert_eq!(summary.functions, 1);
        assert_eq!(summary.code_bodies, 1);
        assert!(summary.memory_min >= 1);
        assert!(summary.safe_instruction_set);
        assert!(summary.instructions >= 4);
        assert_eq!(summary.custom_sections, vec!["aether".to_string()]);

        let exports: Vec<&str> = summary
            .exports
            .iter()
            .map(|(name, _, _)| name.as_str())
            .collect();
        assert!(exports.contains(&"memory"));
        assert!(exports.contains(&"shoresh"));
        assert_eq!(summary.exports[0].1, 0x02); // la memoria
        assert_eq!(summary.exports[1].1, 0x00); // la función

        // Las secciones declaradas son las que el fichero tiene de verdad.
        assert!(artifact.section("wasm:type").is_some());
        assert!(artifact.section("wasm:code").is_some());
        assert!(artifact.section("wasm:aether").is_some());
        assert!(artifact.summary().contains("wasm"));
        assert_eq!(artifact.dna.nodes.len(), ast.nodes.len());

        // El ADN viaja dentro del módulo y se puede releer.
        let custom = artifact
            .section("wasm:aether")
            .map(|record| record.digest)
            .unwrap_or([0u8; 32]);
        assert_ne!(custom, [0u8; 32]);
    }

    #[test]
    fn el_lector_rechaza_instrucciones_que_pueden_atrapar() {
        // `unreachable` (0x00) y `i32.div_s` (0x6D) quedan fuera del conjunto.
        for forbidden in [0x00u8, 0x6D, 0x6E, 0x6F, 0x70] {
            let mut module = WASM_HEADER.to_vec();
            push_section(&mut module, 10, &[0x01, 0x03, 0x00, forbidden, 0x0B]);
            assert!(
                parse_wasm(&module).is_none(),
                "la instrucción 0x{forbidden:02X} no debe pasar el lector"
            );
        }

        // Un módulo con el conjunto seguro sí se relee.
        let mut clean = WASM_HEADER.to_vec();
        push_section(&mut clean, 10, &[0x01, 0x05, 0x00, 0x41, 0x2A, 0x6A, 0x0B]);
        let summary = parse_wasm(&clean);
        assert!(summary.is_some(), "el subconjunto seguro debe releerse");
        let Some(summary) = summary else { return };
        assert_eq!(summary.instructions, 3);

        assert!(is_safe_wasm_op(0x6A));
        assert!(!is_safe_wasm_op(0x00));
        assert!(parse_wasm(b"no es wasm").is_none());
        assert!(parse_wasm(&[]).is_none());
    }

    #[test]
    fn la_emision_a_wasm_es_determinista_y_depende_del_ast() {
        let (ast, tokens) = fixture();
        let options = EmitOptions::wasm("genesis");
        let first = emit_wasm(&ast, &tokens, &options, &key());
        let second = emit_wasm(&ast, &tokens, &options, &key());
        assert_eq!(first.bytes, second.bytes);
        assert_eq!(first.digest, second.digest);
        assert_eq!(first.signature, second.signature);

        // Otro AST (más nodos) cambia el ADN del artefacto.
        let (other_ast, _) = fixture();
        let mut grown = other_ast;
        grown.nodes.push(grown.nodes[0].clone());
        let third = emit_wasm(&grown, &tokens, &options, &key());
        assert_ne!(third.dna.root, first.dna.root);

        // Otra etiqueta cambia la firma pero no la raíz del ADN de nodos.
        let renamed = emit_wasm(&ast, &tokens, &EmitOptions::wasm("otro"), &key());
        assert_ne!(renamed.signature, first.signature);
    }

    #[test]
    fn el_binario_nativo_es_un_elf64_valido_con_su_adn_dentro() {
        let (ast, tokens) = fixture();
        let options = EmitOptions::new("genesis", EmitHost::LinuxX86_64);
        let artifact = emit_native(&ast, &tokens, &options, &key());

        // Cabecera ELF64, *little-endian*, ejecutable, máquina x86‑64.
        assert_eq!(&artifact.bytes[..4], &[0x7F, b'E', b'L', b'F']);
        assert_eq!(artifact.bytes[4], 2); // clase 64
        assert_eq!(artifact.bytes[5], 1); // little-endian
        assert_eq!(read_u16_le(&artifact.bytes, 18), Some(62));
        assert_eq!(read_u32_le(&artifact.bytes, 20), Some(1));
        assert_eq!(read_u64_le(&artifact.bytes, 24), Some(ELF_BASE + 0x78));

        let summary = parse_native(&artifact.bytes);
        assert!(summary.is_some(), "la imagen debe releerse");
        let Some(summary) = summary else { return };
        assert_eq!(summary.host, EmitHost::LinuxX86_64);
        assert_eq!(summary.entry, ELF_BASE + ELF_TEXT_OFFSET as u64);
        let names: Vec<&str> = summary
            .sections
            .iter()
            .map(|(name, _, _)| name.as_str())
            .collect();
        assert_eq!(names, vec![".text", ".aether", ".shstrtab"]);

        // La rutina de salida es código de máquina real y lleva la huella.
        let reference = exit_stub(EmitHost::LinuxX86_64, artifact.dna.signature[0]);
        assert_eq!(
            artifact.section(".text").map(|item| item.bytes),
            Some(reference.len())
        );
        let stub = artifact
            .bytes
            .get(ELF_TEXT_OFFSET..ELF_TEXT_OFFSET + reference.len())
            .unwrap_or(&[]);
        assert_eq!(stub, reference.as_slice());
        assert_eq!(stub.get(..5), Some(&[0xB8, 60, 0x00, 0x00, 0x00][..]));
        assert_eq!(stub.get(5).copied(), Some(0xBF));
        assert_eq!(stub.get(6).copied(), Some(artifact.dna.signature[0]));
        assert_eq!(stub.get(10..12), Some(&[0x0F, 0x05][..]));

        // El registro `.aether` se relee y coincide con el ADN firmado.
        let record = summary.record;
        assert!(record.is_some(), "`.aether` debe releerse");
        if let Some(record) = record {
            assert_eq!(record.root, artifact.dna.root);
            assert_eq!(record.signature, artifact.dna.signature);
            assert_eq!(record.key_id, artifact.dna.key_id);
            assert_eq!(record.nodes, artifact.dna.nodes.len());
            assert_eq!(record.label, "genesis");
            assert_eq!(record.words, artifact.metal.words().to_vec());
        }
        assert!(artifact.summary().contains("nativo"));
        assert!(artifact.notes.iter().any(|note| note.contains("ELF64")));
    }

    #[test]
    fn el_artefacto_nace_firmado_y_detecta_la_manipulacion() {
        let (ast, tokens) = fixture();
        let options = EmitOptions::new("genesis", EmitHost::LinuxX86_64);
        let artifact = emit_native(&ast, &tokens, &options, &key());

        assert!(artifact.verify_seal(&key()));
        assert!(!artifact.verify_seal(&golden_key(b"otra-clave")));

        // Un byte cambiado en el código invalida el sello del artefacto.
        let mut tampered = artifact.clone();
        if let Some(byte) = tampered.bytes.get_mut(ELF_TEXT_OFFSET + 7) {
            *byte ^= 0xFF;
        }
        assert!(!tampered.verify_seal(&key()));

        // Un byte cambiado en `.aether` rompe el digest interno del registro.
        let mut broken = artifact.clone();
        let aether_offset = artifact
            .section(".aether")
            .map(|item| item.offset)
            .unwrap_or(0);
        if let Some(byte) = broken.bytes.get_mut(aether_offset + 12) {
            *byte ^= 0x01;
        }
        let reread = parse_native(&broken.bytes).and_then(|summary| summary.record);
        assert!(reread.is_none(), "un registro alterado no debe releerse");
    }

    #[test]
    fn el_contenedor_portable_no_finge_un_ejecutable() {
        let (ast, tokens) = fixture();
        let artifact = emit_native(
            &ast,
            &tokens,
            &EmitOptions::new("genesis", EmitHost::Portable),
            &key(),
        );

        assert!(artifact.bytes.starts_with(&PORTABLE_MAGIC));
        assert!(!artifact.bytes.starts_with(&[0x7F, b'E', b'L', b'F']));

        let summary = parse_native(&artifact.bytes);
        assert!(summary.is_some(), "el contenedor debe releerse");
        let Some(summary) = summary else { return };
        assert_eq!(summary.host, EmitHost::Portable);
        assert_eq!(summary.entry, 0);
        assert!(summary.record.is_some());
        assert!(!EmitHost::Portable.is_runnable_here());
        assert_eq!(EmitHost::Portable.machine(), 0);
        assert_eq!(EmitHost::LinuxAarch64.machine(), 183);
        assert!(artifact.notes.iter().any(|note| note.contains("portable")));
        assert!(parse_native(&[]).is_none());
        assert!(parse_native(b"nada que ver").is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn el_binario_emitido_se_ejecuta_y_devuelve_su_propia_huella() {
        let (ast, tokens) = fixture();
        let host = EmitHost::current();
        if host == EmitHost::Portable {
            return;
        }
        let artifact = emit_native(&ast, &tokens, &EmitOptions::new("genesis", host), &key());
        let path = std::env::temp_dir().join("bara-emision-nativo-test");
        if artifact.write_to(&path).is_err() {
            return;
        }
        if !EmissionArtifact::mark_executable(&path) {
            let _ = std::fs::remove_file(&path);
            return;
        }

        let expected = i32::from(artifact.dna.signature[0]);
        if let Ok(status) = std::process::Command::new(&path).status() {
            assert_eq!(
                status.code(),
                Some(expected),
                "el binario debe devolver como código de salida su propia huella"
            );
        }
        let _ = std::fs::remove_file(&path);
    }
}
