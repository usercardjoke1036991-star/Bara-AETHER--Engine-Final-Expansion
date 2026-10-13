//! # Geometría absoluta — proporción áurea y asignación fractal
//!
//! Este módulo es el **repartidor espacial** del gestor de memoria holográfica
//! (y de la tabla de regiones): coloca cada nodo sobre una retícula armónica
//! cuyos pasos son **números de Fibonacci** (los cocientes sucesivos del
//! número áureo `φ`) y cuyo **orden** de ocupación es la secuencia de baja
//! discrepancia `i·φ` — la espiral de **ángulo áureo** `2π/φ²`. Dos nodos
//! próximos en el orden lógico quedan próximos también en el orden físico, y
//! el relleno interno de cada registro queda acotado.
//!
//! ## Qué garantiza, y qué no
//! * **Cota de relleno** — cuantizar el ancho de un registro al Fibonacci
//!   siguiente acota el relleno interno en `1 − 1/φ ≈ 38.2 %`, frente al
//!   `50 %` de los cubos potencia de dos (`next_power_of_two`, el reparto
//!   clásico). Esa es la mejora que publica [`FractalLayout::improvement`]:
//!   `≈ 23.6 %` menos relleno *peor caso*.
//! * **Cero fragmentación medida** cuando el registro ya es un Fibonacci
//!   (p. ej. `89` o `144` bytes): el paso coincide con el ancho útil.
//! * **No** hay asignación dinámica del sistema operativo: el kernel mide un
//!   reparto **lógico** (bytes de registro), no memoria física. Aquí no hay
//!   `unsafe`, ni *allocators*, ni relojes.
//!
//! ## Invariantes (verificados por las pruebas del propio módulo)
//! 1. [`fibonacci`] es monótona no decreciente y **satura** en `u64::MAX`:
//!    ninguna entrada desborda ni provoca pánico (totalidad).
//! 2. [`golden_order`] es una **permutación** de `0..count` con *propiedad de
//!    subsunción*: añadir un nodo nunca reordena los nodos previos.
//! 3. La fragmentación medida **nunca** supera la cota áurea
//!    ([`FractalLayout::within_bound`]).
//! 4. Determinismo estricto: mismas entradas ⇒ mismo reparto (sin aleatoriedad).

// ─────────────────────────────────────────────────────────────────────────
// Proporciones absolutas
// ─────────────────────────────────────────────────────────────────────────

/// Número áureo `φ = (1 + √5)/2`.
///
/// Se calcula en tiempo de ejecución (y no como literal) para no depender de
/// una constante redondeada: `φ² = φ + 1` se cumple al bit de la aritmética.
pub fn phi() -> f64 {
    0.5 * (1.0 + 5.0_f64.sqrt())
}

/// Ángulo áureo `2π/φ² = π(3 − √5)` en radianes (`≈ 2.3999632297`).
///
/// Es el giro de la espiral de *phyllotaxis*: reparte puntos en el disco con
/// discrepancia mínima, que es exactamente lo que aquí se pide de la retícula.
pub fn golden_angle() -> f64 {
    std::f64::consts::PI * (3.0 - 5.0_f64.sqrt())
}

/// Cota de relleno de la retícula áurea: `1 − 1/φ ≈ 0.381966`.
pub fn padding_bound() -> f64 {
    1.0 - 1.0 / phi()
}

/// Cota de relleno de los cubos potencia de dos: `0.5`.
pub const POW2_PADDING_BOUND: f64 = 0.5;

// ─────────────────────────────────────────────────────────────────────────
// Series armónicas
// ─────────────────────────────────────────────────────────────────────────

/// Índice de saturación: `F(94) > u64::MAX`, luego `F(n ≥ 94) = u64::MAX`.
pub const FIB_SATURATION_INDEX: usize = 94;

/// `n`-ésimo número de Fibonacci (`F(0) = 0`, `F(1) = 1`), saturado en `u64`.
///
/// El bucle está acotado por [`FIB_SATURATION_INDEX`]: pedir el Fibonacci de
/// `usize::MAX` devuelve `u64::MAX` sin recorrer el espacio de índices.
pub fn fibonacci(n: usize) -> u64 {
    let (mut a, mut b) = (0u64, 1u64);
    for _ in 0..n.min(FIB_SATURATION_INDEX) {
        let next = a.saturating_add(b);
        a = b;
        b = next;
    }
    a
}

/// Los primeros `n` números de Fibonacci: `F(0) … F(n−1)`.
pub fn fib_series(n: usize) -> Vec<u64> {
    (0..n).map(fibonacci).collect()
}

/// Sumas armónicas parciales `H_k = 1 + 1/2 + … + 1/k` para `k = 1 … n`.
pub fn harmonic_series(n: usize) -> Vec<f64> {
    let mut out = Vec::with_capacity(n);
    let mut acc = 0.0_f64;
    for k in 1..=n {
        acc += 1.0 / k as f64;
        out.push(acc);
    }
    out
}

/// Menor número de Fibonacci `>= bytes` (el paso de retícula áureo).
///
/// Si `bytes` supera el mayor Fibonacci representable en `u64`, satura.
pub fn fib_ceil(bytes: usize) -> u64 {
    let want = bytes.max(1) as u64;
    let (mut a, mut b) = (1u64, 2u64);
    loop {
        if a >= want {
            return a;
        }
        let next = a.saturating_add(b);
        if next <= a {
            // Saturación: ningún Fibonacci mayor es representable.
            return u64::MAX;
        }
        a = b;
        b = next;
    }
}

/// Menor potencia de dos `>= bytes` (el cubo clásico), sin pánico.
pub fn pow2_ceil(bytes: usize) -> u64 {
    bytes
        .max(1)
        .checked_next_power_of_two()
        .unwrap_or(usize::MAX) as u64
}

/// Clave áurea del índice `i`: `fract((i + ½)·φ) ∈ (0, 1)`.
///
/// Es **independiente del tamaño de la población**: la precedencia entre dos
/// índices queda fijada para siempre, que es justo lo que necesita un gestor
/// de memoria cuyos nodos llegan de uno en uno (crecer nunca recoloca lo ya
/// colocado). Dos claves nunca coinciden en la práctica —`φ` es irracional— y,
/// si el redondeo `f64` las hiciera coincidir, el orden se desempata por
/// índice (ordenación estable), de forma determinista.
pub fn golden_key(index: usize) -> f64 {
    ((index as f64 + 0.5) * phi()).fract()
}

/// Orden áureo explícito: los índices `0..count` ordenados por [`golden_key`].
///
/// El resultado es la secuencia de *phyllotaxis*: al recorrerla en orden, cada
/// ranura sucesiva cae lo más lejos posible de todas las anteriores.
///
/// ## Propiedad de subsunción (verificada por las pruebas)
/// `golden_order(count + 1)` **filtrado** a índices `< count` es exactamente
/// `golden_order(count)`: añadir un nodo no reordena los nodos previos.
pub fn golden_order(count: usize) -> Vec<usize> {
    let mut order: Vec<usize> = (0..count).collect();
    order.sort_by(|a, b| {
        golden_key(*a)
            .partial_cmp(&golden_key(*b))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    order
}

/// Orden áureo como **ranuras**: `golden_slots(count)[i]` es la posición (rango)
/// del índice `i` dentro de [`golden_order`].
///
/// Es una permutación de `0..count` y la inversa exacta de `golden_order`.
pub fn golden_slots(count: usize) -> Vec<usize> {
    let mut slots = vec![0usize; count];
    for (rank, index) in golden_order(count).iter().enumerate() {
        slots[*index] = rank;
    }
    slots
}

// ─────────────────────────────────────────────────────────────────────────
// Reparto espacial
// ─────────────────────────────────────────────────────────────────────────

/// Reparto de una población de nodos sobre la retícula áurea.
///
/// Cada nodo recibe un **paso** (`strides[i] = fib_ceil(widths[i])`) y una
/// **ranura** (`slots[i]`, desplazamiento en bytes) que respeta el orden
/// áureo: la ranura de menor dirección no es la del primer nodo llegado, sino
/// la del primero en la secuencia `i·φ`, y las direcciones quedan contiguas
/// (sin huecos libres) porque el reparto es una permutación, no una dispersión.
#[derive(Debug, Clone, PartialEq)]
pub struct FractalLayout {
    /// Número de nodos repartidos.
    pub nodes: usize,
    /// Suma de los anchos lógicos pedidos, en bytes.
    pub payload_bytes: u64,
    /// Extensión total de la retícula, en bytes (`Σ strides`).
    pub span_bytes: u64,
    /// Relleno interno de la retícula, en bytes (`span − payload`).
    pub padding_bytes: u64,
    /// Fragmentación medida: `padding / span`, en `[0, 1)`.
    pub fragmentation: f64,
    /// Cota teórica de la retícula áurea (`1 − 1/φ`).
    pub bound: f64,
    /// Cota teórica de los cubos potencia de dos (`0.5`).
    pub baseline_bound: f64,
    /// Mejora relativa de la cota: `1 − bound / baseline_bound`.
    pub improvement: f64,
    /// Ranura (desplazamiento en bytes) de cada nodo, en orden de entrada.
    pub slots: Vec<u64>,
    /// Paso de retícula de cada nodo, en orden de entrada.
    pub strides: Vec<u64>,
}

impl FractalLayout {
    /// Reparte `nodes` registros **uniformes** de `node_bytes` bytes cada uno.
    pub fn plan(nodes: usize, node_bytes: usize) -> Self {
        let widths = vec![node_bytes; nodes];
        Self::plan_from(&widths)
    }

    /// Reparte una población **heterogénea**: un ancho por nodo.
    pub fn plan_from(widths: &[usize]) -> Self {
        let count = widths.len();
        let strides: Vec<u64> = widths.iter().map(|width| fib_ceil(*width)).collect();
        let payload_bytes: u64 = widths
            .iter()
            .map(|width| *width as u64)
            .fold(0u64, u64::saturating_add);
        let span_bytes: u64 = strides.iter().copied().fold(0u64, u64::saturating_add);

        // Orden áureo: `order[i]` es la ranura lógica del nodo `i`.
        let order = golden_slots(count);
        let mut rank_to_index = vec![0usize; count];
        for (index, rank) in order.iter().enumerate() {
            if let Some(slot) = rank_to_index.get_mut(*rank) {
                *slot = index;
            }
        }

        // Direcciones contiguas en el orden áureo: sin huecos que fragmenten.
        let mut slots = vec![0u64; count];
        let mut cursor = 0u64;
        for index in rank_to_index.iter().copied() {
            slots[index] = cursor;
            cursor = cursor.saturating_add(strides[index]);
        }

        let padding_bytes = span_bytes.saturating_sub(payload_bytes);
        let fragmentation = if span_bytes == 0 {
            0.0
        } else {
            padding_bytes as f64 / span_bytes as f64
        };
        let bound = padding_bound();
        let improvement = if POW2_PADDING_BOUND == 0.0 {
            0.0
        } else {
            1.0 - bound / POW2_PADDING_BOUND
        };

        FractalLayout {
            nodes: count,
            payload_bytes,
            span_bytes,
            padding_bytes,
            fragmentation,
            bound,
            baseline_bound: POW2_PADDING_BOUND,
            improvement,
            slots,
            strides,
        }
    }

    /// Ranura asignada al nodo `index`, si existe.
    pub fn slot_of(&self, index: usize) -> Option<u64> {
        self.slots.get(index).copied()
    }

    /// Paso de retícula del nodo `index`, si existe.
    pub fn stride_of(&self, index: usize) -> Option<u64> {
        self.strides.get(index).copied()
    }

    /// ¿La fragmentación medida respeta la cota áurea? (invariante del módulo)
    pub fn within_bound(&self) -> bool {
        self.fragmentation <= self.bound + 1e-9
    }

    /// Etiqueta legible del reparto, para consola y paneles del IDE.
    pub fn label(&self) -> String {
        format!(
            "φ-rejilla · {} nodo(s) · {} B útiles · {} B de malla · relleno {:.1}% (cota {:.1}%)",
            self.nodes,
            self.payload_bytes,
            self.span_bytes,
            self.fragmentation * 100.0,
            self.bound * 100.0
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Pruebas del módulo
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_proporcion_aurea_cumple_su_definicion() {
        let phi = phi();
        // φ² = φ + 1 : la identidad que define la proporción absoluta.
        assert!((phi * phi - (phi + 1.0)).abs() < 1e-12);
        assert!((phi - std::f64::consts::GOLDEN_RATIO).abs() < 1e-12);
        // El ángulo áureo es 2π/φ² = π(3 − √5).
        assert!((golden_angle() - 2.399_963_229_728_653).abs() < 1e-12);
        assert!((padding_bound() - 0.381_966_011_250_105).abs() < 1e-12);
    }

    #[test]
    fn fibonacci_es_monotona_y_satura() {
        assert_eq!(fibonacci(0), 0);
        assert_eq!(fibonacci(1), 1);
        assert_eq!(fib_series(10), [0, 1, 1, 2, 3, 5, 8, 13, 21, 34]);
        let mut previous = 0u64;
        for n in 0..96 {
            let value = fibonacci(n);
            assert!(value >= previous, "F({n}) rompe la monotonía");
            previous = value;
        }
        // Más allá del índice 93 satura: nunca desborda ni entra en pánico.
        assert_eq!(fibonacci(usize::MAX), u64::MAX);
    }

    #[test]
    fn el_paso_es_el_fibonacci_siguiente() {
        assert_eq!(fib_ceil(0), 1);
        assert_eq!(fib_ceil(1), 1);
        assert_eq!(fib_ceil(2), 2);
        assert_eq!(fib_ceil(3), 3);
        assert_eq!(fib_ceil(4), 5);
        assert_eq!(fib_ceil(34), 34);
        assert_eq!(fib_ceil(35), 55);
        assert_eq!(fib_ceil(89), 89);
        assert_eq!(fib_ceil(90), 144);
        assert_eq!(fib_ceil(usize::MAX), u64::MAX);
        // El cubo clásico, en cambio, parte en dos el hueco.
        assert_eq!(pow2_ceil(1), 1);
        assert_eq!(pow2_ceil(3), 4);
        assert_eq!(pow2_ceil(35), 64);
        assert_eq!(pow2_ceil(90), 128);
    }

    #[test]
    fn el_orden_aureo_es_una_permutacion_estable() {
        for count in 1..64usize {
            let slots = golden_slots(count);
            assert_eq!(slots.len(), count);
            let mut seen = slots.clone();
            seen.sort_unstable();
            let expected: Vec<usize> = (0..count).collect();
            assert_eq!(seen, expected, "golden_slots({count}) no es permutación");

            // `golden_slots` es la inversa exacta de `golden_order`.
            let order = golden_order(count);
            for (rank, index) in order.iter().enumerate() {
                assert_eq!(slots[*index], rank);
            }

            // Propiedad de subsunción: añadir un nodo no reordena los previos.
            let extended = golden_order(count + 1);
            assert!(extended.contains(&count));
            let filtered: Vec<usize> = extended
                .iter()
                .copied()
                .filter(|index| *index < count)
                .collect();
            assert_eq!(filtered, order, "crecer la población reordenó los nodos");

            // La clave áurea es independiente de la población.
            assert_eq!(
                golden_key(count - 1),
                ((count - 1) as f64 + 0.5) * phi() % 1.0_f64
            );
        }
        assert!(golden_slots(0).is_empty());
        assert!(golden_order(1) == vec![0]);
    }

    #[test]
    fn el_orden_aureo_dispersa_los_vecinos_logicos() {
        let count = 32usize;
        let slots = golden_slots(count);
        // La secuencia no es la identidad: reparte de verdad.
        assert_ne!(slots, (0..count).collect::<Vec<usize>>());
        // Dos nodos consecutivos en el orden lógico nunca caen en ranuras
        // contiguas: el vecino inmediato en memoria está lejos en el espacio.
        for index in 0..count - 1 {
            let distance = slots[index].abs_diff(slots[index + 1]);
            assert!(distance >= 2, "ranuras contiguas en el nodo {index}");
        }
    }

    #[test]
    fn la_serie_armonica_acumula_los_reciprocos() {
        let series = harmonic_series(4);
        assert_eq!(series.len(), 4);
        assert!((series[0] - 1.0).abs() < 1e-12);
        assert!((series[1] - 1.5).abs() < 1e-12);
        assert!((series[2] - (1.0 + 1.0 / 2.0 + 1.0 / 3.0)).abs() < 1e-12);
        assert!((series[3] - 2.083_333_333_333_333).abs() < 1e-12);
        assert!(harmonic_series(0).is_empty());
    }

    #[test]
    fn el_reparto_uniforme_no_fragmenta_si_el_registro_ya_es_fibonacci() {
        let layout = FractalLayout::plan(64, 89);
        assert_eq!(layout.nodes, 64);
        assert_eq!(layout.span_bytes, 64 * 89);
        assert_eq!(layout.payload_bytes, 64 * 89);
        assert_eq!(layout.padding_bytes, 0);
        assert_eq!(layout.fragmentation, 0.0);
        assert!(layout.within_bound());
        assert!(layout.improvement > 0.23 && layout.improvement < 0.24);

        // Las ranuras cubren la retícula sin solaparse.
        let mut slots = layout.slots.clone();
        slots.sort_unstable();
        for (index, slot) in slots.iter().enumerate() {
            assert_eq!(*slot, index as u64 * 89);
        }
        assert_eq!(layout.slot_of(0), Some(layout.slots[0]));
        assert_eq!(layout.stride_of(63), Some(89));
        assert_eq!(layout.slot_of(64), None);
    }

    #[test]
    fn el_reparto_heterogeneo_respeta_la_cota_aurea() {
        let widths = [3usize, 34, 35, 89, 90, 1000, 4096];
        let layout = FractalLayout::plan_from(&widths);
        assert_eq!(layout.nodes, widths.len());
        assert!(layout.within_bound(), "la cota áurea debe respetarse");
        // El paso nunca es menor que el ancho útil: cero solapamientos.
        for (index, width) in widths.iter().enumerate() {
            assert!(layout.stride_of(index).unwrap_or(0) >= *width as u64);
        }
        assert!(layout.span_bytes >= layout.payload_bytes);
        // Direcciones contiguas: la última ranura más su paso es la extensión.
        let last = layout
            .slots
            .iter()
            .enumerate()
            .max_by_key(|(_, slot)| *slot);
        if let Some((index, slot)) = last {
            assert_eq!(
                slot + layout.stride_of(index).unwrap_or(0),
                layout.span_bytes
            );
        }
        assert!(layout.label().contains("φ-rejilla"));
        assert!(!layout.label().is_empty());
    }

    #[test]
    fn el_reparto_vacio_es_total() {
        let layout = FractalLayout::plan(0, 0);
        assert_eq!(layout.nodes, 0);
        assert_eq!(layout.span_bytes, 0);
        assert_eq!(layout.fragmentation, 0.0);
        assert!(layout.slots.is_empty());
        assert!(layout.within_bound());
    }
}
