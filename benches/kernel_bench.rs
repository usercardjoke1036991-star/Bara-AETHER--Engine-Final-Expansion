//! # Banco de metal y verificación de perfiles — Bara / AETHER‑Ω (FASE 6)
//!
//! Hermano de `tests/chaos_resilience.rs`: allí se demuestra que el núcleo
//! **sobrevive** al caos; aquí se mide **cuánto cuesta** ser inmune y se
//! comprueba que el coste no delata el secreto ni degrada con la escala.
//!
//! ## Por qué un arnés propio y no `criterion`
//! El kernel es soberano: no admite dependencias de desarrollo externas (el
//! `Cargo.lock` no contiene `criterion` y el banco debe compilar sin red). Todo
//! lo que sigue usa sólo `std`:
//!
//! * [`Stats`] resume muestras de tiempo con mediana y percentil 95.
//! * `batch` mide lotes (amortiza el reloj) y devuelve **ns por operación**.
//! * `first_touch` mide una operación aislada cuando lo caro es el montaje
//!   (por ejemplo, un sistema inmune recién creado).
//!
//! ## Los tres frentes de la Fase 6
//! 1. **Tiempo constante** — para entradas de **la misma longitud** pero de
//!    contenido distinto (calma frente a ataque, UTF‑8 válido frente a basura,
//!    `⊤` frente a `⊥`) la mediana no puede desviarse más de [`CT_CEILING`].
//!    Una fuga real de canal lateral produce desvíos de un orden de magnitud;
//!    el ruido de caché y de rama produce fracciones. La cota es holgada a
//!    propósito: distingue una fuga de una fluctuación, no maquilla la segunda.
//! 2. **Tzimtzum L1/L2** — el sobre contraído es un bloque plano de
//!    [`WIRE_BYTES`] bytes sin reubicación: [`contract`] debe llenar filas de
//!    exactamente [`CACHE_LINE`] bytes, no derramar dentro de la capacidad y
//!    costar **por nodo** lo mismo a 32 que a 1024 nodos (sin crecimiento
//!    superlineal). La concurrencia se valida con `std::thread::scope`: todos
//!    los hilos deben producir el **mismo digest** (determinismo). El coste por
//!    nodo es la mediana del hilo más lento, tomada cuando el hilo ya está en
//!    marcha: el arranque no entra en la cuenta, y un pico del planificador no
//!    tumba la mediana. Esa mediana no puede pasar de [`CONCURRENCY_CEILING`].
//! 3. **Perfiles de release** — se leen los dos manifiestos que declaran el
//!    perfil extremo (`BAR/.cargo/config.toml` y, si existe, el del workspace
//!    contenedor) y se exige que ambos digan lo mismo: `opt-level = 3`,
//!    `lto = true`, `codegen-units = 1`, `panic = "abort"`. En modo banco
//!    (`cargo bench`) se exige además que `debug_assertions` esté apagado.
//!
//! ## Reglas del banco
//! * **Cero `unsafe`** (`#![forbid(unsafe_code)]`).
//! * **Cero pánicos**: ni `unwrap` ni `expect`; cuando una medida no puede
//!   formarse se devuelve `Option` y el banco lo declara como fallo, no aborta.
//! * **Cero conclusiones por reloj de pared**: las cotas son **relativas**
//!   (dispersión entre dos cargas, coste por nodo entre dos escalas). Un
//!   runner lento desplaza todos los números y ninguna comprobación cambia.
//! * **Modo humo**: `cargo test --all-targets` ejecuta este binario sin el
//!   argumento `--bench`; entonces se hacen pocas muestras y se emite un
//!   aviso. La medición completa es `cargo bench --bench kernel_bench`.
//!
//! ## Uso
//! ```text
//! cargo bench  --bench kernel_bench
//! cargo test   --all-targets          # modo humo (rápido, invariantes iguales)
//! ```

#![forbid(unsafe_code)]
#![deny(clippy::all)]

use bara::autopoietic::{
    AutopoieticMutator, BelnapMatrix, BelnapValue, Evidence, KernelCore, Mutation, MAX_ARITY,
    SEAL_THRESHOLD,
};
use bara::crypto_native::sha256;
use bara::ffi_ingest::{BaraType, ShoreshAst, ShoreshNode};
use bara::immune::{ImmuneSystem, MAX_ANTIBODIES};
use bara::immunity_gateway::{is_legible, threat_of, Gateway, ATTACK_NEEDLES};
use bara::runtime::QuantumState;
use bara::topology::{
    contract, expand, Contracted, Record, Row, CACHE_LINE, LANES, RECORD_BYTES, ROW_CAPACITY,
    WIRE_BYTES,
};
use std::hint::black_box;
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────
// Constantes del banco: todas las cotas son relativas, nunca absolutas
// ─────────────────────────────────────────────────────────────────────────

/// Desvío máximo admitido entre dos cargas de **la misma longitud**.
///
/// No es 1.0 porque dos rutas de código distintas siempre difieren en
/// fracciones (predicción de ramas, líneas de caché); una fuga real de canal
/// lateral, en cambio, se delata en múltiplos.
const CT_CEILING: f64 = 4.0;

/// Degradación máxima del coste **por nodo** al multiplicar la escala por 32.
const SCALE_CEILING: f64 = 4.0;

/// Degradación máxima del coste por nodo al pasar de 1 hilo a N hilos.
const CONCURRENCY_CEILING: f64 = 8.0;

/// Longitud común de las cargas del frente de tiempo constante.
const CT_PAYLOAD: usize = 512;

/// Longitud de la carga del micro‑banco de hash (4 KiB).
const HASH_PAYLOAD: usize = 4 * 1024;

/// Valores exigidos al perfil de release extremo (idénticos en ambos manifiestos).
const PROFILE_EXPECTED: [(&str, &str); 4] = [
    ("opt-level", "3"),
    ("lto", "true"),
    ("codegen-units", "1"),
    ("panic", "\"abort\""),
];

/// Perfil del kernel soberano, incrustado: si alguien lo cambia, el banco lo ve
/// a la primera compilación (no depende del directorio de trabajo).
const KERNEL_PROFILE: &str = include_str!("../.cargo/config.toml");

// ─────────────────────────────────────────────────────────────────────────
// Medición: muestras → mediana y percentil 95
// ─────────────────────────────────────────────────────────────────────────

/// Muestras de tiempo por operación, en nanosegundos.
#[derive(Debug, Clone)]
struct Stats {
    ns: Vec<f64>,
}

impl Stats {
    /// Construye el resumen; `None` si no hay muestras o alguna es inválida.
    fn new(ns: Vec<f64>) -> Option<Stats> {
        if ns.is_empty() || ns.iter().any(|value| !value.is_finite() || *value < 0.0) {
            return None;
        }
        Some(Stats { ns })
    }

    /// Mediana de las muestras (robusta frente a picos del planificador).
    fn p50(&self) -> f64 {
        self.percentile(50)
    }

    /// Percentil 95: la cola que sufre un ataque de saturación real.
    fn p95(&self) -> f64 {
        self.percentile(95)
    }

    /// Mínimo observado.
    fn min(&self) -> f64 {
        self.ns.iter().copied().fold(f64::INFINITY, f64::min)
    }

    /// Máximo observado.
    fn max(&self) -> f64 {
        self.ns.iter().copied().fold(f64::NEG_INFINITY, f64::max)
    }

    /// Dispersión interna: máximo entre mínimo (siempre `≥ 1`).
    fn jitter(&self) -> f64 {
        let min = self.min();
        if min <= 0.0 {
            f64::INFINITY
        } else {
            self.max() / min
        }
    }

    /// Percentil `percent` en `[0, 100]` por rango más cercano.
    fn percentile(&self, percent: usize) -> f64 {
        let mut sorted = self.ns.clone();
        sorted.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));
        let last = sorted.len().saturating_sub(1);
        let index = sorted.len().saturating_mul(percent) / 100;
        sorted.get(index.min(last)).copied().unwrap_or(0.0)
    }
}

/// Mide `samples` lotes de `ops` operaciones y devuelve **ns por operación**.
///
/// El lote amortiza el coste del reloj; el calentamiento previo deja el código
/// en caché antes de la primera muestra.
fn batch(samples: usize, ops: u32, mut op: impl FnMut()) -> Option<Stats> {
    if samples == 0 || ops == 0 {
        return None;
    }
    for _ in 0..ops {
        op();
    }
    let mut ns = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        for _ in 0..ops {
            op();
        }
        ns.push(start.elapsed().as_nanos() as f64 / f64::from(ops));
    }
    Stats::new(ns)
}

/// Mide una operación aislada por muestra (el montaje queda fuera del reloj).
fn first_touch(samples: usize, mut op: impl FnMut() -> Duration) -> Option<Stats> {
    let mut ns = Vec::with_capacity(samples);
    for _ in 0..samples {
        ns.push(op().as_nanos() as f64);
    }
    Stats::new(ns)
}

/// Desvío entre dos medianas: `max/min` (siempre `≥ 1`).
fn ct_ratio(left: &Stats, right: &Stats) -> f64 {
    let a = left.p50();
    let b = right.p50();
    let floor = a.min(b);
    if floor <= 0.0 {
        f64::INFINITY
    } else {
        a.max(b) / floor
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Acta del banco: filas medidas y comprobaciones acumuladas
// ─────────────────────────────────────────────────────────────────────────

/// Hoja de resultados: no imprime nada que no haya medido o comprobado.
struct Sheet {
    checks: usize,
    failures: usize,
}

impl Sheet {
    fn new() -> Sheet {
        Sheet {
            checks: 0,
            failures: 0,
        }
    }

    /// Registra una comprobación; sólo las que fallan se imprimen.
    fn require(&mut self, condition: bool, message: &str) {
        self.checks += 1;
        if !condition {
            self.failures += 1;
            println!("  ✗ {message}");
        }
    }

    /// Encabezado de sección.
    fn header(&self, title: &str) {
        println!("\n── {title} ──");
    }

    /// Fila de medida. `ratio` es el desvío frente a la carga de referencia.
    fn line(&self, label: &str, stats: &Stats, unit: &str, ratio: Option<f64>) {
        match ratio {
            Some(ratio) => println!(
                "  {label:<34} {:>12.2} {unit:<10} p95 {:>12.2}   desvío {ratio:>5.2}×",
                stats.p50(),
                stats.p95()
            ),
            None => println!(
                "  {label:<34} {:>12.2} {unit:<10} p95 {:>12.2}   jitter {:.2}×",
                stats.p50(),
                stats.p95(),
                stats.jitter()
            ),
        }
    }

    /// ¿Todo verde?
    fn is_green(&self) -> bool {
        self.failures == 0
    }

    /// Cierre del acta.
    fn summary(&self) {
        if self.is_green() {
            println!("\n{} comprobaciones · todo verde", self.checks);
        } else {
            println!(
                "\n{} comprobaciones · {} FALLO(S)",
                self.checks, self.failures
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Cargas y nodos del banco (deterministas, sin `rand`)
// ─────────────────────────────────────────────────────────────────────────

/// Carga benigna de longitud exacta: JSON ASCII (UTF‑8 válido por construcción).
fn carga_calma(largo: usize) -> Vec<u8> {
    const BASE: &[u8] = b"{\"evento\":\"latido\",\"raiz\":\"emet\",\"valor\":42}";
    BASE.iter().copied().cycle().take(largo).collect()
}

/// Carga hostil de longitud exacta: agujas de ataque conocidas, sin bytes de
/// control, para que la única diferencia frente a [`carga_calma`] sea el
/// **contenido** y no el tamaño.
fn carga_hostil(largo: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(largo);
    let mut needles = ATTACK_NEEDLES
        .iter()
        .map(|(_, needle, _)| *needle)
        .filter(|needle| needle.is_ascii())
        .cycle();
    while out.len() < largo {
        if let Some(needle) = needles.next() {
            out.extend_from_slice(needle.as_bytes());
        }
        out.push(b'x');
    }
    out.truncate(largo);
    out
}

/// Raíz triconsonántica distinta para cada índice (base 27 sobre `א..ת`).
fn raiz(mut indice: usize) -> String {
    let letras: Vec<char> = ('\u{05d0}'..='\u{05ea}').collect();
    let tamano = letras.len();
    let mut out = String::with_capacity(3);
    for _ in 0..3 {
        let hueco = indice % tamano;
        indice /= tamano;
        out.push(letras.get(hueco).copied().unwrap_or('\u{05d0}'));
    }
    out
}

/// Nodos *Shoresh* estructuralmente admisibles (`⊤`, riesgo bajo, aridad legal).
fn nodos(cantidad: usize) -> Vec<ShoreshNode> {
    (0..cantidad)
        .map(|indice| ShoreshNode {
            root: raiz(indice),
            original: format!("bench_{indice}"),
            arity: indice % (MAX_ARITY + 1),
            ret: BaraType::Number,
            hazard: SEAL_THRESHOLD * 0.5,
            valence: QuantumState::paraconsistent(0.875, 0.125),
            sanitized: false,
        })
        .collect()
}

/// Nodo contradictorio `⊤∧⊥` con estructura admisible.
fn nodo_contradictorio(root: &str) -> ShoreshNode {
    ShoreshNode {
        root: root.to_string(),
        original: "bench_contradiccion".to_string(),
        arity: 2,
        ret: BaraType::Number,
        hazard: SEAL_THRESHOLD * 0.5,
        valence: QuantumState::paraconsistent(1.0, 1.0),
        sanitized: false,
    }
}

/// Núcleo génesis del banco (dos nodos sanos).
fn nucleo() -> KernelCore {
    KernelCore::genesis(
        "bench.kernel",
        ShoreshAst { nodes: nodos(2) },
        b"aether-omega-bench",
    )
}

// ─────────────────────────────────────────────────────────────────────────
// Frente 3 · perfiles de release
// ─────────────────────────────────────────────────────────────────────────

/// Cuerpo de una sección `[header]` del manifiesto (hasta la siguiente sección).
fn section_body<'m>(manifest: &'m str, header: &str) -> Option<&'m str> {
    let start = manifest.find(header)? + header.len();
    let rest = &manifest[start..];
    let end = rest.find("\n[").unwrap_or(rest.len());
    Some(&rest[..end])
}

/// ¿La sección declara exactamente los cuatro valores del perfil extremo?
fn declares_release(manifest: &str) -> bool {
    let Some(body) = section_body(manifest, "[profile.release]") else {
        return false;
    };
    PROFILE_EXPECTED.iter().all(|(key, value)| {
        body.lines().any(|line| {
            line.trim()
                .split_once('=')
                .map(|(name, rest)| name.trim() == *key && rest.trim() == *value)
                .unwrap_or(false)
        })
    })
}

/// Manifiesto del workspace contenedor, si esta compilación ocurre dentro de
/// él. En CI el kernel es su propia raíz y no existe: se omite la comparación.
fn workspace_manifest() -> Option<String> {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = here.parent()?.join("Cargo.toml");
    std::fs::read_to_string(path).ok()
}

/// Verifica que el perfil extremo está declarado en todas las raíces aplicables.
fn bench_profiles(sheet: &mut Sheet, bench_mode: bool) {
    sheet.header("Perfiles de release (opt-level=3 · lto · cgu=1 · panic=abort)");
    sheet.require(
        declares_release(KERNEL_PROFILE),
        "el perfil del kernel (.cargo/config.toml) no declara el contrato extremo",
    );
    match workspace_manifest() {
        Some(manifest) if manifest.contains("[profile.release]") => {
            sheet.require(
                declares_release(&manifest),
                "el perfil del workspace no coincide con el del kernel",
            );
            println!("  kernel y workspace declaran el mismo perfil extremo");
        }
        Some(_) => {
            println!("  manifiesto del workspace sin [profile.release]: nada que comparar")
        }
        None => {
            println!("  kernel soberano (sin manifiesto contenedor): sólo se audita el suyo")
        }
    }
    if bench_mode {
        sheet.require(
            !cfg!(debug_assertions),
            "cargo bench debe compilar en perfil bench/release (debug_assertions apagado)",
        );
        // `cargo bench` puede forzar `panic=unwind` en el binario de banco: lo
        // que se audita es el perfil **declarado** (arriba) y que la
        // optimización esté realmente activa (sin `debug_assertions`).
        println!(
            "  modo banco · debug_assertions={} · panic=abort en el binario={}",
            cfg!(debug_assertions),
            cfg!(panic = "abort")
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Frente 1 · latencia de las operaciones críticas y canales laterales
// ─────────────────────────────────────────────────────────────────────────

/// SHA‑256 sobre dos cargas del **mismo tamaño**: la compresión no puede
/// depender del contenido, así que cualquier desvío apreciable delata ruido o
/// una regresión en la ruta de hash.
fn bench_hash(sheet: &mut Sheet, samples: usize, ops: u32) {
    sheet.header("Constante de tiempo · SHA-256 (4 KiB, misma longitud)");
    let left = vec![b'A'; HASH_PAYLOAD];
    let right: Vec<u8> = (0..HASH_PAYLOAD).map(|index| (index % 251) as u8).collect();
    let a = batch(samples, ops, || {
        black_box(sha256(black_box(&left)));
    });
    let b = batch(samples, ops, || {
        black_box(sha256(black_box(&right)));
    });
    match (a, b) {
        (Some(a), Some(b)) => {
            let ratio = ct_ratio(&a, &b);
            sheet.line("sha256 · carga A / carga B", &a, "ns/4KiB", Some(ratio));
            let mib = HASH_PAYLOAD as f64 / (a.p50() * 1e-9) / (1024.0 * 1024.0);
            println!("  {mib:.1} MiB/s de digest nativo (mediana)");
            sheet.require(
                ratio <= CT_CEILING,
                "sha256: el contenido alteró la latencia más de lo admitido",
            );
        }
        _ => sheet.require(false, "sha256: no se pudieron formar las muestras"),
    }
}

/// Frontera: juicio de amenaza y legibilidad sobre cargas de igual longitud.
fn bench_periphery(sheet: &mut Sheet, samples: usize, ops: u32) {
    sheet.header("Constante de tiempo · frontera (misma longitud, distinto contenido)");
    let calma = carga_calma(CT_PAYLOAD);
    let hostil = carga_hostil(CT_PAYLOAD);
    // Basura **al final**: el validador UTF-8 recorre la misma longitud que en
    // la carga válida y sólo cambia el veredicto, no el trabajo previo.
    let mut invalido = vec![b'A'; CT_PAYLOAD];
    if let Some(last) = invalido.last_mut() {
        *last = 0xFF;
    }

    sheet.require(
        calma.len() == hostil.len() && hostil.len() == invalido.len(),
        "las cargas del frente de tiempo constante no comparten longitud",
    );
    sheet.require(
        threat_of(&calma).is_calm() && threat_of(&hostil).is_hostile(),
        "las cargas no representan calma y ataque",
    );
    sheet.require(
        is_legible(&calma) && !is_legible(&invalido),
        "la legibilidad no distingue UTF-8 válido de basura",
    );

    let calma_ns = batch(samples, ops, || {
        black_box(threat_of(black_box(&calma)));
    });
    let hostil_ns = batch(samples, ops, || {
        black_box(threat_of(black_box(&hostil)));
    });
    if let (Some(calma_ns), Some(hostil_ns)) = (calma_ns, hostil_ns) {
        let ratio = ct_ratio(&calma_ns, &hostil_ns);
        sheet.line(
            "threat_of · calma / ataque",
            &hostil_ns,
            "ns/512 B",
            Some(ratio),
        );
        sheet.require(
            ratio <= CT_CEILING,
            "threat_of: la calma y el ataque no cuestan lo mismo",
        );
    } else {
        sheet.require(false, "threat_of: no se pudieron formar las muestras");
    }

    let legible_ns = batch(samples, ops, || {
        black_box(is_legible(black_box(&calma)));
    });
    let basura_ns = batch(samples, ops, || {
        black_box(is_legible(black_box(&invalido)));
    });
    if let (Some(legible_ns), Some(basura_ns)) = (legible_ns, basura_ns) {
        let ratio = ct_ratio(&legible_ns, &basura_ns);
        sheet.line(
            "is_legible · válido / basura",
            &legible_ns,
            "ns/512 B",
            Some(ratio),
        );
        sheet.require(
            ratio <= CT_CEILING,
            "is_legible: la validez UTF-8 introdujo un canal de tiempo",
        );
    } else {
        sheet.require(false, "is_legible: no se pudieron formar las muestras");
    }

    let mut gateway = Gateway::new();
    let admit = batch(samples, 8, || {
        let bubble = gateway.admit("bench:gateway", 0, black_box(&hostil));
        black_box(bubble.danger);
    });
    if let Some(admit) = admit {
        sheet.line("Gateway::admit · hostil", &admit, "ns/burbuja", None);
    } else {
        sheet.require(false, "Gateway::admit: no se pudieron formar las muestras");
    }
    let (innocuous, absorbed, neutralized, quarantined) = gateway.census();
    sheet.require(gateway.door_is_open(), "la puerta dejó de estar abierta");
    sheet.require(
        neutralized + quarantined > 0,
        "la pasarela no neutralizó ni aisló ninguna carga hostil",
    );
    sheet.require(
        innocuous + absorbed + neutralized + quarantined == gateway.bubbles.len(),
        "el censo de la pasarela no cuadra con sus burbujas",
    );
}

/// Sistema inmune: primera exposición a una carga propia y a una hostil, con el
/// montaje **fuera** del reloj (lo caro no es el juicio, es el sistema nuevo).
fn bench_immune(sheet: &mut Sheet, samples: usize) {
    sheet.header("Constante de tiempo · sistema inmune (primera exposición)");
    let calma = carga_calma(CT_PAYLOAD);
    let hostil = carga_hostil(CT_PAYLOAD);

    let self_ns = first_touch(samples, || {
        let mut system = ImmuneSystem::new();
        let start = Instant::now();
        black_box(system.screen_bytes("bench:immune", 0, &calma));
        start.elapsed()
    });
    let foe_ns = first_touch(samples, || {
        let mut system = ImmuneSystem::new();
        let start = Instant::now();
        black_box(system.screen_bytes("bench:immune", 0, &hostil));
        start.elapsed()
    });
    match (self_ns, foe_ns) {
        (Some(self_ns), Some(foe_ns)) => {
            let ratio = ct_ratio(&self_ns, &foe_ns);
            sheet.line(
                "screen_bytes · propio / hostil",
                &foe_ns,
                "ns/juicio",
                Some(ratio),
            );
            sheet.require(
                ratio <= CT_CEILING,
                "el sistema inmune delata por tiempo si la carga es propia",
            );
        }
        _ => sheet.require(false, "sistema inmune: no se pudieron formar las muestras"),
    }

    let mut probe = ImmuneSystem::new();
    let response = probe.screen_bytes("bench:immune", 0, &hostil);
    sheet.require(
        !response.reaches_core(),
        "una carga hostil alcanzó el núcleo",
    );

    let mut saturated = ImmuneSystem::new();
    for sequence in 0..1024_u64 {
        black_box(saturated.screen_bytes("bench:immune", sequence, &hostil));
    }
    sheet.require(
        saturated.repertoire().len() <= MAX_ANTIBODIES,
        "el repertorio creció por encima de su cota bajo saturación",
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Frente 2 · Belnap: consenso, veto y coste del juicio
// ─────────────────────────────────────────────────────────────────────────

/// La retícula tetravalente no se promedia: el juicio con una contradicción
/// declarada congela y veta la fusión, siempre con el mismo resultado.
fn bench_belnap(sheet: &mut Sheet, samples: usize, ops: u32) {
    sheet.header("Belnap · retícula, consenso y veto determinista");
    let kernel = nucleo();
    let mut ast = ShoreshAst { nodes: nodos(3) };
    ast.nodes.push(nodo_contradictorio("דעת"));
    let evidence = Evidence::green("bench.belnap", 5);
    let first = BelnapMatrix::evaluate(kernel.read(), &ast, &evidence, true);
    let second = BelnapMatrix::evaluate(kernel.read(), &ast, &evidence, true);

    sheet.require(
        first.contradictions == 1,
        "el juicio no contó la contradicción",
    );
    sheet.require(
        first.periferia == BelnapValue::Both,
        "una contradicción no congeló la periferia en ⊤∧⊥",
    );
    sheet.require(
        !first.admits_fusion(),
        "el juicio admitió fusionar una contradicción",
    );
    sheet.require(
        BelnapMatrix::agreement(first.periferia, first.nucleo) == BelnapValue::True,
        "el tope informativo ⊤∧⊥ no aportó lo que afirmó el testigo del núcleo",
    );
    sheet.require(first == second, "el juicio no es determinista bit a bit");

    let lattice = batch(samples, ops, || {
        // `black_box` sobre la tabla impide que el compilador pliegue el ciclo
        // a una constante: sin esto se mediría el coste de no hacer nada.
        let corners = black_box([
            BelnapValue::True,
            BelnapValue::False,
            BelnapValue::Both,
            BelnapValue::Neither,
        ]);
        let mut value = corners[0];
        for other in corners {
            value = value
                .union(other)
                .conjunction(value)
                .consensus(other.complement());
        }
        black_box(value);
    });
    match lattice {
        Some(lattice) => {
            sheet.line("retícula · 12 operaciones", &lattice, "ns/ciclo", None);
            let cycles = 12.0 / (lattice.p50() * 1e-9);
            println!("  {cycles:.0} operaciones de retícula por segundo");
        }
        None => sheet.require(false, "retícula: no se pudieron formar las muestras"),
    }

    let judge = batch(samples, 16, || {
        black_box(BelnapMatrix::evaluate(kernel.read(), &ast, &evidence, true));
    });
    if let Some(judge) = judge {
        sheet.line(
            "BelnapMatrix::evaluate · 4 nodos",
            &judge,
            "ns/juicio",
            None,
        );
    } else {
        sheet.require(false, "BelnapMatrix::evaluate: sin muestras");
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Frente 2 · Tzimtzum: densidad de caché, escala y concurrencia
// ─────────────────────────────────────────────────────────────────────────

/// Un sobre lleno debe ocupar exactamente [`WIRE_BYTES`] contiguos, sin derrame
/// dentro de su capacidad, y costar lo mismo por nodo a cualquier escala.
fn bench_topology(sheet: &mut Sheet, samples: usize, ops: u32) {
    sheet.header("Tzimtzum · contracción L1/L2 (layout contiguo, pérdida cero)");
    sheet.require(
        std::mem::size_of::<Record>() == RECORD_BYTES,
        "Record dejó de ocupar 16 bytes exactos (padding o reordenación)",
    );
    sheet.require(
        std::mem::size_of::<Row>() == CACHE_LINE,
        "Row dejó de ocupar exactamente una línea de caché",
    );
    sheet.require(
        std::mem::size_of::<Contracted>() <= WIRE_BYTES + CACHE_LINE,
        "Contracted añadió más relleno que una línea de caché",
    );

    let block_nodes = ROW_CAPACITY * LANES;
    let base = nodos(block_nodes);
    let (block, stats) = contract(&base, 7);
    sheet.require(stats.nodes == base.len(), "la contracción perdió nodos");
    sheet.require(stats.rows == block.len(), "el censo de filas no cuadra");
    sheet.require(
        stats.spilled == 0,
        "el sobre derramó dentro de su capacidad",
    );
    sheet.require(
        stats.is_lossless(),
        "la contracción no se declaró sin pérdida",
    );
    sheet.require(
        block.fill() == 1.0,
        "el sobre lleno no alcanzó densidad 1.0",
    );
    sheet.require(
        block.bytes() == WIRE_BYTES,
        "el sobre no ocupa su bloque fijo",
    );
    sheet.require(
        block.as_slice().len() == block.len() * CACHE_LINE,
        "las filas no son contiguas (hay huecos entre líneas)",
    );
    sheet.require(
        block.contracted() == block,
        "la contracción no es idempotente",
    );
    sheet.require(
        expand(&block).len() == base.len(),
        "el despliegue no devolvió todos los registros",
    );
    let row_roundtrip = block
        .row(0)
        .map(|row| Row::from_bytes(&row.bytes()) == row)
        .unwrap_or(false);
    sheet.require(row_roundtrip, "la fila no sobrevive al viaje por bytes");

    let contract_ns = batch(samples, ops, || {
        black_box(contract(black_box(&base), 7));
    });
    if let Some(contract_ns) = &contract_ns {
        sheet.line(
            "contract · 32 nodos (sobre lleno)",
            contract_ns,
            "ns/sobre",
            None,
        );
        println!(
            "  {:.3} ns/nodo · {:.2} nodos por línea L1",
            contract_ns.p50() / block_nodes as f64,
            LANES
        );
    } else {
        sheet.require(false, "contract: sin muestras");
    }

    let expand_ns = batch(samples, ops, || {
        black_box(expand(&block));
    });
    if let Some(expand_ns) = &expand_ns {
        sheet.line("expand · 32 registros", expand_ns, "ns/sobre", None);
    } else {
        sheet.require(false, "expand: sin muestras");
    }

    let digest_ns = batch(samples, ops, || {
        black_box(block.digest());
    });
    if let Some(digest_ns) = &digest_ns {
        sheet.line("digest · sobre de 512 B", digest_ns, "ns/sobre", None);
    } else {
        sheet.require(false, "digest: sin muestras");
    }

    let idem_ns = batch(samples, ops, || {
        black_box(block.contracted());
    });
    if let Some(idem_ns) = &idem_ns {
        sheet.line("contracted · re-cuantización", idem_ns, "ns/sobre", None);
    } else {
        sheet.require(false, "contracted: sin muestras");
    }

    // Escala ×32: el sobre no crece (capacidad fija), los nodos sobrantes se
    // **cuentan** como derrame; el coste por nodo no puede dispararse.
    let big = nodos(block_nodes * 32);
    let (_, big_stats) = contract(&big, 7);
    sheet.require(
        big_stats.rows == ROW_CAPACITY,
        "el sobre de escala no conservó su capacidad fija",
    );
    sheet.require(
        big_stats.spilled == big.len() - block_nodes,
        "el derrame no se contó exactamente",
    );
    let big_ns = batch(samples, ops, || {
        black_box(contract(black_box(&big), 7));
    });
    if let (Some(contract_ns), Some(big_ns)) = (contract_ns, big_ns) {
        let per_node_base = contract_ns.p50() / block_nodes as f64;
        let per_node_big = big_ns.p50() / big.len() as f64;
        sheet.line(
            "contract · 1024 nodos (derrame contado)",
            &big_ns,
            "ns/sobre",
            None,
        );
        println!("  {per_node_big:.3} ns/nodo a 1024 vs {per_node_base:.3} ns/nodo a 32");
        sheet.require(
            per_node_big <= per_node_base * SCALE_CEILING,
            "el coste por nodo degradó de forma superlineal al crecer la escala",
        );
    } else {
        sheet.require(false, "contract a escala: sin muestras");
    }
}

/// Concurrencia: cada hilo contrae el mismo bloque por su cuenta. El digest es
/// la prueba de que no hay estado compartido ni entrelazado invisible.
///
/// El reloj arranca dentro del hilo, después de un calentamiento. Así el coste
/// de crear el hilo —fijo, y enorme frente a 4 sobres en un runner de dos
/// núcleos— no se cuela en los ns/nodo. Varias rondas y la mediana dejan fuera
/// un solo pico del planificador.
fn bench_concurrency(sheet: &mut Sheet, threads: usize, blocks: usize, rounds: usize) {
    sheet.header("Tzimtzum · concurrencia de nodos (mismo digest, sin degradación)");
    let base = nodos(ROW_CAPACITY * LANES);
    let reference = contract(&base, 7).1;
    let per_block = base.len().max(1);
    let blocks_u32 = u32::try_from(blocks).unwrap_or(u32::MAX);

    let serial = batch(rounds, blocks_u32, || {
        black_box(contract(black_box(&base), 7));
    });

    let mut joined = rounds > 0;
    let mut same = rounds > 0;
    let mut slowest = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let round = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(threads);
            for _ in 0..threads {
                handles.push(scope.spawn(|| {
                    black_box(contract(&base, 7));
                    let start = Instant::now();
                    let mut digest = [0_u8; 32];
                    for _ in 0..blocks {
                        let (block, stats) = contract(&base, 7);
                        digest = stats.digest;
                        black_box(block);
                    }
                    let nodes = blocks.max(1).saturating_mul(per_block);
                    let ns_per_node = start.elapsed().as_nanos() as f64 / nodes as f64;
                    (digest, ns_per_node)
                }));
            }
            handles
                .into_iter()
                .filter_map(|handle| handle.join().ok())
                .collect::<Vec<([u8; 32], f64)>>()
        });
        joined &= round.len() == threads;
        same &= round.iter().all(|(digest, _)| *digest == reference.digest);
        let mut peak = 0.0_f64;
        let mut saw = false;
        for (_, ns) in &round {
            if !saw || *ns > peak {
                peak = *ns;
                saw = true;
            }
        }
        if saw {
            slowest.push(peak);
        }
    }

    sheet.require(joined, "un hilo del banco terminó sin digest (¿pánico?)");
    sheet.require(
        same,
        "los hilos no produjeron el mismo digest: hay estado compartido",
    );

    match (serial, Stats::new(slowest)) {
        (Some(serial), Some(parallel)) => {
            let serial_ns = serial.p50() / per_block as f64;
            let parallel_ns = parallel.p50();
            sheet.require(
                serial_ns > 0.0 && parallel_ns <= serial_ns * CONCURRENCY_CEILING,
                "la concurrencia degradó el coste por nodo más de lo admitido",
            );
            println!(
                "  {threads} hilos × {blocks} sobres · {rounds} rondas · {serial_ns:.3} ns/nodo en serie · {parallel_ns:.3} ns/nodo en paralelo"
            );
        }
        _ => sheet.require(false, "concurrencia: sin muestras"),
    }
    println!(
        "  digest común {:02x}{:02x}{:02x}{:02x}",
        reference.digest[0], reference.digest[1], reference.digest[2], reference.digest[3]
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Núcleo y sandbox: lectura soberana y coste del aislamiento
// ─────────────────────────────────────────────────────────────────────────

/// Lectura, verificación y digest del núcleo: la ruta que ningún ataque puede
/// reescribir, medida en el mismo régimen que el resto.
fn bench_kernel(sheet: &mut Sheet, samples: usize) {
    sheet.header("Núcleo soberano · lectura, verificación y digest");
    let kernel = nucleo();
    let digest = kernel.digest();
    let read = batch(samples, 256, || {
        black_box(kernel.read().verified());
    });
    let digest_ns = batch(samples, 128, || {
        black_box(kernel.digest());
    });
    match (read, digest_ns) {
        (Some(read), Some(digest_ns)) => {
            sheet.line("KernelRead::verified", &read, "ns/lectura", None);
            sheet.line("KernelCore::digest", &digest_ns, "ns/digest", None);
        }
        _ => sheet.require(false, "núcleo: no se pudieron formar las muestras"),
    }
    sheet.require(kernel.verify(), "el núcleo no verifica su propio ADN");
    sheet.require(
        kernel.digest() == digest,
        "el digest del núcleo no es estable",
    );
    sheet.require(
        kernel.revision() == 0,
        "el banco alteró la revisión del núcleo",
    );
}

/// Sandbox: alta, sello y purga de una célula, y coste del aislamiento. El
/// núcleo se mide antes y después: la célula no puede haberlo tocado.
fn bench_sandbox(sheet: &mut Sheet, samples: usize) {
    sheet.header("Sandbox suicida · ciclo de célula y coste de aislamiento");
    let kernel = nucleo();
    let digest = kernel.digest();

    let mut lifecycle = Vec::with_capacity(samples);
    let mut purged = true;
    for _ in 0..samples {
        let mut mutator = AutopoieticMutator::new(b"bench-sandbox");
        let cell = mutator.open_cell(kernel.read());
        let start = Instant::now();
        let _ = mutator.apply(cell, &Mutation::Seal { index: 0 });
        purged &= mutator.release(cell);
        lifecycle.push(start.elapsed().as_nanos() as f64);
    }
    if let Some(stats) = Stats::new(lifecycle) {
        sheet.line("ciclo de célula (sello + purga)", &stats, "ns/célula", None);
    } else {
        sheet.require(false, "sandbox: sin muestras de ciclo");
    }
    sheet.require(purged, "la purga del sandbox dejó células vivas");

    let mut isolations = Vec::with_capacity(samples);
    let mut clean = true;
    for _ in 0..samples {
        let mut mutator = AutopoieticMutator::new(b"bench-sandbox");
        let cell = mutator.open_cell(kernel.read());
        let start = Instant::now();
        let report = mutator.isolate(cell);
        isolations.push(start.elapsed().as_nanos() as f64);
        clean &= matches!(&report, Ok(report) if report.is_clean());
    }
    if let Some(stats) = Stats::new(isolations) {
        sheet.line("isolate · célula limpia", &stats, "ns/aislamiento", None);
    } else {
        sheet.require(false, "sandbox: sin muestras de aislamiento");
    }
    sheet.require(clean, "el aislamiento de una célula limpia no es limpio");
    sheet.require(kernel.digest() == digest, "el sandbox tocó el núcleo");
    sheet.require(
        kernel.revision() == 0,
        "el sandbox cambió la revisión del núcleo",
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Entrada: modo banco completo o modo humo (`cargo test --all-targets`)
// ─────────────────────────────────────────────────────────────────────────

fn main() -> ExitCode {
    let bench_mode = std::env::args().any(|arg| arg == "--bench");
    let (samples, ops) = if bench_mode { (64, 32) } else { (16, 8) };

    println!("Bara / AETHER-Ω · banco de metal (Fase 6)");
    if bench_mode {
        println!("modo banco · {samples} muestras × {ops} operaciones por muestra");
    } else {
        println!("modo humo · {samples} muestras × {ops} operaciones por muestra");
        println!("la medición completa es `cargo bench --bench kernel_bench`");
    }

    let mut sheet = Sheet::new();
    bench_profiles(&mut sheet, bench_mode);
    bench_hash(&mut sheet, samples, ops);
    bench_periphery(&mut sheet, samples, ops);
    bench_immune(&mut sheet, samples);
    bench_belnap(&mut sheet, samples, ops);
    bench_topology(&mut sheet, samples, ops);
    bench_concurrency(&mut sheet, 4, if bench_mode { 64 } else { 4 }, samples);
    bench_kernel(&mut sheet, samples);
    bench_sandbox(&mut sheet, samples);
    sheet.summary();

    if sheet.is_green() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
