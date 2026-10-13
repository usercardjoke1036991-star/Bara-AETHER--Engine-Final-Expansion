//! # Suite de geometría absoluta — Bara / AETHER‑Ω (Fase 3)
//!
//! Verifica el **reparto espacial armónico** del núcleo: pasos de Fibonacci y
//! orden áureo `i·φ` sobre la memoria holográfica y sobre la tabla de regiones,
//! enlazando el *crate* `bara` (nunca módulos sueltos).
//!
//! ## Principios de la suite
//! * **Cero dependencias externas** — sólo `std` y el propio núcleo.
//! * **Cota áurea** — la fragmentación medida **nunca** supera `1 − 1/φ`, y el
//!   peor caso del reparto por potencias de dos (`50 %`) queda dominado.
//! * **Determinismo** — el mismo contenido produce siempre la misma retícula.
//! * **Totalidad** — entradas extremas (índices saturados) se *toleran*.

use bara::fractal_geometry::{
    fib_ceil, fib_series, fibonacci, golden_angle, golden_order, golden_slots, harmonic_series,
    padding_bound, phi, pow2_ceil, FractalLayout, FIB_SATURATION_INDEX, POW2_PADDING_BOUND,
};
use bara::lexer::Lexer;
use bara::memory_region::{RegionId, RegionKind, RegionTable};
use bara::runtime::{node_width, BaraRuntime, QuantumState};

/// Programa génesis: idéntico al del binario `bara` (13 tokens ontológicos).
const GENESIS: &str = "\
ברא
חכם
עבד
ברא
ברא
!!
עבד
שמר
נצח
עבד
אמר
שפט
אמר
";

/// Ejecuta el génesis completo sobre un runtime virgen.
fn genesis_runtime() -> BaraRuntime {
    let mut runtime = BaraRuntime::new();
    runtime.execute(&Lexer::new(GENESIS).tokenize());
    runtime
}

// ─────────────────────────────────────────────────────────────────────────
// 1 · Proporciones y series (aritmética del reparto)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn las_proporciones_y_series_del_nucleo_son_exactas_y_totales() {
    // φ es la raíz de x² = x + 1, y el ángulo áureo es 2π/φ² = π(3 − √5).
    let phi = phi();
    assert!((phi * phi - (phi + 1.0)).abs() < 1e-12);
    assert!((golden_angle() - 2.399_963_229_728_653).abs() < 1e-12);
    assert!((padding_bound() - 0.381_966_011_250_105).abs() < 1e-12);

    // La serie de Fibonacci, exacta hasta el índice de saturación.
    assert_eq!(
        fib_series(12),
        vec![0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89]
    );
    assert_eq!(
        fibonacci(FIB_SATURATION_INDEX - 1),
        12_200_160_415_121_876_738
    );

    // Totalidad: ni el índice máximo ni el tamaño máximo desbordan o panican.
    assert_eq!(fibonacci(usize::MAX), u64::MAX);
    assert_eq!(fib_ceil(usize::MAX), u64::MAX);
    assert_eq!(fib_ceil(0), 1);
    assert_eq!(pow2_ceil(0), 1);

    // Determinismo estricto de todas las series.
    assert_eq!(fib_series(24), fib_series(24));
    assert_eq!(golden_order(24), golden_order(24));
    assert_eq!(golden_slots(24), golden_slots(24));
    assert_eq!(harmonic_series(6), harmonic_series(6));

    // La serie armónica es estrictamente creciente y empieza en 1.
    let harmonic = harmonic_series(5);
    assert_eq!(harmonic.len(), 5);
    for window in harmonic.windows(2) {
        assert!(window[1] > window[0]);
    }
}

#[test]
fn el_paso_de_reticula_es_el_fibonacci_siguiente_y_no_recorta() {
    for bytes in [1usize, 2, 3, 7, 34, 35, 89, 90, 143, 144, 145, 1000, 65_535] {
        let stride = fib_ceil(bytes);
        // Nunca recorta: dos registros contiguos no pueden solaparse.
        assert!(stride >= bytes as u64, "paso {stride} < ancho {bytes}");
        // Y es realmente un número de Fibonacci.
        assert!(
            (0..=FIB_SATURATION_INDEX).any(|n| fibonacci(n) == stride),
            "{stride} no es un Fibonacci"
        );
    }
    // Coincide con el ancho cuando el registro ya es un Fibonacci.
    assert_eq!(fib_ceil(89), 89);
    assert_eq!(fib_ceil(144), 144);
    assert_eq!(fib_ceil(89 + 1), 144);
}

#[test]
fn la_cota_de_relleno_domina_al_cubo_potencia_de_dos() {
    // Peor caso empírico sobre anchos reales (1 B … 200 kB) para ambos repartos.
    let mut worst_golden = 0.0_f64;
    let mut worst_pow2 = 0.0_f64;
    for width in 1..=200_000usize {
        let stride = fib_ceil(width);
        let cube = pow2_ceil(width);
        worst_golden = worst_golden.max((stride - width as u64) as f64 / stride as f64);
        worst_pow2 = worst_pow2.max((cube - width as u64) as f64 / cube as f64);
    }

    // La retícula áurea nunca supera `1 − 1/φ` y su peor caso es *ajustado*.
    assert!(worst_golden <= padding_bound() + 1e-12, "cota violada");
    assert!(worst_golden > 0.38, "el peor caso debe acercarse a la cota");
    // El cubo potencia de dos sí llega al 50 %.
    assert!(worst_pow2 >= 0.49);
    assert!(worst_golden < worst_pow2);
    // La mejora publicada es `1 − (1 − 1/φ)/0.5 ≈ 23.6 %`.
    let layout = FractalLayout::plan(8, 3);
    assert!((layout.improvement - (1.0 - padding_bound() / POW2_PADDING_BOUND)).abs() < 1e-12);
    assert_eq!(layout.baseline_bound, 0.5);
}

// ─────────────────────────────────────────────────────────────────────────
// 2 · Retícula de la memoria holográfica
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn la_reticula_de_la_memoria_holografica_respeta_la_cota_aurea() {
    let mut runtime = BaraRuntime::new();
    for index in 0..64 {
        let label = format!("celda-{index:03}");
        runtime
            .memory
            .store(&label, QuantumState::superposition(0.6, 0.8));
    }

    let layout = runtime.memory.layout();
    assert_eq!(layout.nodes, 64);
    assert!(layout.within_bound(), "la cota áurea debe respetarse");
    assert_eq!(runtime.memory.fragmentation(), layout.fragmentation);

    // Cada nodo conoce su ranura, su paso es el Fibonacci de su ancho y el
    // ancho registrado coincide con el que publica el núcleo.
    for (position, (key, width)) in runtime.memory.grid().iter().enumerate() {
        assert_eq!(layout.stride_of(position), Some(fib_ceil(*width)));
        assert!(layout.stride_of(position).unwrap_or(0) >= *width as u64);
        let node = runtime
            .memory
            .recall_by_key(*key)
            .expect("todo nodo de la retícula está retenido");
        assert_eq!(
            runtime.memory.slot_of(&node.label),
            layout.slot_of(position)
        );
        assert_eq!(runtime.memory.slot_of_key(*key), layout.slot_of(position));
        assert_eq!(node_width(&node.label, &node.state), *width);
    }

    // Las ranuras son inyectivas y caben en la extensión de la retícula.
    let mut slots = layout.slots.clone();
    slots.sort_unstable();
    let distinct = {
        let mut copy = slots.clone();
        copy.dedup();
        copy.len()
    };
    assert_eq!(distinct, 64, "dos nodos no pueden compartir ranura");
    assert!(slots.iter().all(|slot| *slot < layout.span_bytes));

    // El total de la retícula es la suma de pasos de Fibonacci.
    assert_eq!(layout.span_bytes, layout.strides.iter().sum::<u64>());
    assert_eq!(
        layout.span_bytes - layout.payload_bytes,
        layout.padding_bytes
    );
    // Y la memoria está vacía: el reparto es total, sin pánicos.
    assert_eq!(FractalLayout::plan(0, 64).nodes, 0);
}

#[test]
fn la_escritura_idempotente_no_altera_la_reticula() {
    let mut runtime = BaraRuntime::new();
    let empty = runtime.memory.layout();
    assert_eq!(empty.nodes, 0);

    let key = runtime.memory.store("alef", QuantumState::classical(true));
    let single = runtime.memory.layout();
    assert_eq!(single.nodes, 1);
    assert_eq!(
        single.span_bytes,
        fib_ceil(node_width("alef", &QuantumState::classical(true)))
    );
    assert_eq!(single.fragmentation, 0.0, "un paso Fibonacci no fragmenta");

    // Reescribir el mismo contenido es una no-operación: la retícula no cambia.
    assert_eq!(
        runtime.memory.store("alef", QuantumState::classical(false)),
        key
    );
    assert_eq!(runtime.memory.layout(), single);
    assert_eq!(runtime.memory.grid().len(), 1);
    assert_eq!(runtime.memory.writes(), 1);

    // Un nodo nuevo sí la hace crecer, sin tocar la ranura del anterior.
    let _ = runtime
        .memory
        .store("bet", QuantumState::paraconsistent(0.5, 0.5));
    let grown = runtime.memory.layout();
    assert_eq!(grown.nodes, 2);
    assert_ne!(grown, single);
    let mut slots: Vec<u64> = runtime
        .memory
        .slots()
        .into_iter()
        .map(|(_, slot)| slot)
        .collect();
    slots.sort_unstable();
    slots.dedup();
    assert_eq!(slots.len(), 2);
}

#[test]
fn la_reticula_dispersa_los_vecinos_logicos() {
    // 48 nodos uniformes de 96 B ⇒ paso Fibonacci 144 B, relleno 1/3.
    let layout = FractalLayout::plan(48, 96);
    assert_eq!(layout.span_bytes, 48 * 144);
    assert_eq!(layout.padding_bytes, 48 * 48);
    assert!(layout.within_bound());
    assert_eq!(layout.stride_of(47), Some(144));

    // Dos nodos consecutivos (vecinos en el tiempo) no son vecinos en el
    // espacio: la retícula es holográfica, no secuencial.
    for index in 1..48 {
        let distance = layout.slots[index].abs_diff(layout.slots[index - 1]);
        assert!(distance >= 2, "ranuras contiguas en el nodo {index}");
    }
    assert!(layout
        .slots
        .iter()
        .all(|slot| *slot + 144 <= layout.span_bytes));
}

// ─────────────────────────────────────────────────────────────────────────
// 3 · Retícula de la tabla de regiones
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn las_regiones_comparten_la_misma_reticula_aurea() {
    let mut table = RegionTable::new();
    let specs = [
        ("pila", RegionKind::Stack, 34usize),
        ("tokens", RegionKind::Heap, 89),
        ("ast", RegionKind::Genesis, 144),
        ("amplitudes", RegionKind::Shared, 233),
        ("holo", RegionKind::Heap, 100),
    ];
    let ids: Vec<RegionId> = specs
        .iter()
        .map(|(name, kind, bytes)| table.introduce(*name, *kind, *bytes, None))
        .collect();

    let layout = table.fractal_layout();
    assert_eq!(layout.nodes, specs.len());
    assert_eq!(layout.payload_bytes, 600);
    assert!(layout.within_bound());
    assert_eq!(table.fragmentation(), layout.fragmentation);
    assert_eq!(
        layout.span_bytes,
        table
            .regions()
            .iter()
            .map(|r| fib_ceil(r.bytes))
            .sum::<u64>()
    );

    // Cada región viva conoce su ranura y ninguna comparte la de otra.
    let mut slots: Vec<u64> = Vec::new();
    for id in &ids {
        let slot = table.slot_of(*id).expect("región viva ⇒ ranura asignada");
        slots.push(slot);
    }
    slots.sort_unstable();
    slots.dedup();
    assert_eq!(slots.len(), ids.len());
    assert_eq!(table.slot_of(RegionId(9_999)), None);

    // Tabla vacía: reparto total sin pánicos.
    let empty = RegionTable::new();
    assert_eq!(empty.fractal_layout().nodes, 0);
    assert_eq!(empty.fragmentation(), 0.0);
}

// ─────────────────────────────────────────────────────────────────────────
// 4 · Génesis completo: la retícula queda congelada y es reproducible
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn el_genesis_conserva_una_reticula_reproducible() {
    let first = genesis_runtime();
    let second = genesis_runtime();

    // El génesis pobló la memoria holográfica (nodos `genesis:n`).
    assert!(!first.memory.is_empty(), "el génesis debe escribir memoria");

    // Determinismo: mismo contenido ⇒ misma retícula, byte a byte.
    assert_eq!(first.memory.layout(), second.memory.layout());
    assert_eq!(first.memory.fragmentation(), second.memory.fragmentation());
    assert_eq!(first.memory.slots(), second.memory.slots());

    // Invariantes de la retícula en un caso real.
    let layout = first.memory.layout();
    assert!(layout.within_bound());
    assert_eq!(layout.nodes, first.memory.grid().len());
    assert!(layout.improvement >= 0.23);
    assert!(!layout.label().is_empty());

    // La retícula de regiones del génesis también respeta la cota.
    let regions = first.regions.fractal_layout();
    if regions.nodes > 0 {
        assert!(regions.within_bound());
    }
    assert_eq!(regions, second.regions.fractal_layout());
}
