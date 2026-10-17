//! # Arnés de caos y resiliencia — Bara / AETHER‑Ω (Fase 5)
//!
//! Hermano de `tests/stress_test.rs` (paradojas) y de
//! `tests/integration_suite.rs` (verificación *end‑to‑end*). Aquí no se
//! comprueba que el núcleo haga lo correcto con entradas correctas: se comprueba
//! que **siga siendo el mismo núcleo** cuando la periferia lo ataca.
//!
//! ## Los tres frentes
//! 1. **Inyección de ruido estocástico** — se inunda la pasarela
//!    (`immunity_gateway::Gateway`) con bombas de tamaño, anidamiento profundo,
//!    bytes nulos, binario ilegible y agujas de ataque conocidas, y cada burbuja
//!    se presenta al sistema inmune (`immune::ImmuneSystem`). Invariantes: la
//!    puerta **no descarta nada** (`dropped() == 0`), ninguna burbuja hostil o
//!    ilegible alcanza el núcleo, el censo cuadra con el número de burbujas y el
//!    repertorio queda acotado por `MAX_ANTIBODIES`.
//! 2. **Sandbox suicida** — se abre una célula sobre el núcleo
//!    (`AutopoieticMutator::open_cell`), se la corrompe a propósito y se
//!    comprueba que la célula se **aísla sola** (cuarentena), que su informe de
//!    aislamiento es honesto y que su purga (`AutopoieticMutator::release`)
//!    descarta la rama dinámica dejando el BAR‑Core **byte a byte idéntico**:
//!    misma revisión, mismo ADN y mismos nodos. El coste del aislamiento se mide
//!    y se acota.
//! 3. **Veto humano y consenso** — se simula el desacuerdo extremo entre
//!    sub‑motores (periferia `⊤∧⊥` frente al testigo del núcleo `⊤`) y se
//!    verifica que **Belnap congela**: el juicio no se promedia, la unión
//!    informativa se vuelve contradictoria, el parche no se admite y el estado
//!    que se publica es el mismo en cada repetición (determinismo bit a bit).
//!
//! ## Reglas del arnés
//! * **Cero `unsafe`** (`#![forbid(unsafe_code)]`).
//! * **Cero pánicos**: el ruido se genera con un PRNG propio (SplitMix64) y
//!   ninguna prueba usa `unwrap`/`expect`; cuando algo puede faltar se decide
//!   con `assert!`, `matches!` o `if let`.
//! * **Determinismo**: los tres frentes son reproducibles bit a bit con la misma
//!   semilla. Las únicas magnitudes volátiles (reloj de pared) se miden para
//!   **acotarlas**, nunca para comparar estado.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

use bara::autopoietic::{
    AutopoieticMutator, BelnapMatrix, BelnapValue, CellState, Evidence, IsolationReport,
    KernelCore, Mutation, MutatorError, JOURNAL_LIMIT, MAX_ARITY, MAX_CELL_OPS, SEAL_THRESHOLD,
};
use bara::cognitive::{HallucinationFilter, NlpToShoresh, SynthError};
use bara::ffi_ingest::{BaraType, ShoreshAst, ShoreshNode};
use bara::immune::{Disposition, Epitope, ImmuneSystem, MAX_ANTIBODIES};
use bara::immunity_gateway::{
    is_legible, threat_of, BubbleVerdict, Gateway, LoopbackIngress, ATTACK_NEEDLES, MAX_PAYLOAD,
    SIZE_BOMB_BYTES,
};
use bara::lexer::Lexer;
use bara::runtime::{BaraRuntime, QuantumState};
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────
// Ruido determinista (SplitMix64): caos reproducible, sin `rand`
// ─────────────────────────────────────────────────────────────────────────

/// Generador SplitMix64: la misma semilla produce la misma avalancha.
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        SplitMix64(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Entero en `[0, bound)`.
    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next_u64() % bound as u64) as usize
        }
    }

    /// Real en `[0, 1)`.
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1_u64 << 53) as f64
    }

    /// Byte pseudoaleatorio.
    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }
}

/// Semilla soberana del arnés: el caos también es determinista.
const SEED: &[u8] = b"bara:caos:resiliencia:v1";

/// Riesgo declarado por encima del umbral de sellado (guarda exigida).
const RIESGO_ALTO: f64 = SEAL_THRESHOLD + 0.25;

// ─────────────────────────────────────────────────────────────────────────
// Núcleo y nodos del arnés
// ─────────────────────────────────────────────────────────────────────────

/// Nodo *Shoresh* con valencia `(verdad, falsedad)` explícita.
fn nodo(root: &str, arity: usize, hazard: f64, truth: f64, falsity: f64) -> ShoreshNode {
    ShoreshNode {
        root: root.to_string(),
        original: format!("legacy_{}", root),
        arity,
        ret: BaraType::Number,
        hazard,
        valence: QuantumState::paraconsistent(truth, falsity),
        sanitized: false,
    }
}

/// Nodo conforme: riesgo bajo y valencia `⊤`.
fn nodo_sano(root: &str) -> ShoreshNode {
    nodo(root, 2, 0.10, 0.90, 0.10)
}

/// Nodo estructuralmente inadmisible: raíz vacía y aridad fuera de cota.
fn nodo_corrupto() -> ShoreshNode {
    nodo("", MAX_ARITY + 4, 1.5, 0.9, 0.1)
}

/// Nodo con valencia contradictoria `⊤∧⊥` (estructura admisible).
fn nodo_contradictorio(root: &str) -> ShoreshNode {
    nodo(root, 2, 0.10, 1.0, 1.0)
}

/// Nodo sin información: valencia `∅`.
fn nodo_indeterminado(root: &str) -> ShoreshNode {
    nodo(root, 2, 0.10, 0.0, 0.0)
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

/// AST génesis del arnés (`אמת` y `דעת`).
fn ast_genesis() -> ShoreshAst {
    ShoreshAst {
        nodes: vec![nodo_sano("אמת"), nodo_sano("דעת")],
    }
}

/// Núcleo génesis del arnés.
fn nucleo() -> KernelCore {
    KernelCore::genesis("caos.kernel", ast_genesis(), SEED)
}

/// Evidencia en verde (la periferia aporta pruebas superadas).
fn evidencia_verde() -> Evidence {
    Evidence::green("bara.caos.suite", 5)
}

/// Evidencia en rojo (los sub‑motores no respaldan el resultado).
fn evidencia_roja() -> Evidence {
    Evidence::red("bara.caos.suite", 3, 2)
}

/// ¿Las masas están dentro del invariante global `0 ≤ ⊤, ⊥ ≤ 1`?
fn masas_sanas(state: &QuantumState) -> bool {
    let (truth, falsity) = state.belnap();
    (0.0..=1.0).contains(&truth) && (0.0..=1.0).contains(&falsity)
}

/// ¿Dos huellas coinciden byte a byte?
fn misma_huella(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b.iter()).all(|(izq, der)| izq == der)
}

// ─────────────────────────────────────────────────────────────────────────
// Frente 1 · generadores de ruido
// ─────────────────────────────────────────────────────────────────────────

/// Bomba de tamaño: por encima del umbral que la pasarela mide.
fn bomba_de_tamano(rng: &mut SplitMix64) -> Vec<u8> {
    let relleno = SIZE_BOMB_BYTES + rng.below(1024);
    vec![b'A'; relleno]
}

/// Carga en el **filo** exacto de la paradoja: masa de verdad y de falsedad
/// ambas en el umbral (bomba de tamaño 300 ‰ + relleno de control 200 ‰).
///
/// El relleno va a un byte de control de cada tres: cómodo por encima del
/// 250 ‰ (25 %) que exige la pasarela. Con la proporción exacta de un cuarto,
/// el redondeo entero de `control_bytes` dejaba la carga fuera del filo.
fn carga_paradoxica() -> Vec<u8> {
    let largo = SIZE_BOMB_BYTES + 8;
    let mut out = Vec::with_capacity(largo);
    for indice in 0..largo {
        out.push(if indice % 3 == 2 { 0x01 } else { b'A' });
    }
    out
}

/// Carga hostil legible: todas las agujas de la tabla, con peso de sobra.
fn carga_hostil() -> Vec<u8> {
    let mut out = String::new();
    for (_, aguja, _) in ATTACK_NEEDLES {
        out.push_str(aguja);
        out.push(' ');
    }
    out.push_str("rm -rf / union select drop table");
    out.into_bytes()
}

/// Anidamiento profundo: llaves y corchetes desbalanceados.
fn anidamiento_profundo(rng: &mut SplitMix64) -> Vec<u8> {
    let profundidad = 32 + rng.below(1024);
    let mut out = Vec::with_capacity(profundidad * 2);
    out.resize(profundidad, b'{');
    for _ in 0..profundidad {
        out.push(if rng.below(2) == 0 { b'}' } else { b']' });
    }
    out
}

/// Anulación por byte nulo y relleno de control.
fn bytes_de_control(rng: &mut SplitMix64) -> Vec<u8> {
    let tamano = 32 + rng.below(512);
    let mut out = Vec::with_capacity(tamano);
    for indice in 0..tamano {
        out.push(match indice % 4 {
            0 => 0,
            1 => 0x01,
            2 => 0x1f,
            _ => rng.byte(),
        });
    }
    out
}

/// Binario ilegible: sin un solo tramo de texto UTF-8 válido.
fn binario_ilegible(rng: &mut SplitMix64) -> Vec<u8> {
    let tamano = 16 + rng.below(2048);
    let mut out = Vec::with_capacity(tamano);
    for _ in 0..tamano {
        out.push(rng.byte() | 0x80);
    }
    out
}

/// Programa *Shoresh* legible: raíces del núcleo con signos y números.
fn programa_shoresh(rng: &mut SplitMix64) -> Vec<u8> {
    let mut out = String::new();
    let lineas = 1 + rng.below(6);
    for linea in 0..lineas {
        out.push_str(&raiz(rng.below(27 * 27 * 27)));
        out.push(' ');
        out.push_str(&raiz(rng.below(27 * 27 * 27)));
        out.push_str(if linea % 2 == 0 {
            " 42\n"
        } else {
            " ⊤ ∧ ⊥\n"
        });
    }
    out.into_bytes()
}

/// Carga limpia: JSON inocente con valores pseudoaleatorios.
fn carga_limpia(rng: &mut SplitMix64) -> Vec<u8> {
    format!(
        "{{\"evento\":\"saludo\",\"valor\":{},\"raiz\":\"{}\"}}",
        rng.below(1000),
        raiz(rng.below(27 * 27 * 27))
    )
    .into_bytes()
}

/// Ruido uniforme: bytes crudos sin ninguna estructura.
fn ruido_crudo(rng: &mut SplitMix64) -> Vec<u8> {
    let tamano = rng.below(MAX_PAYLOAD / 16);
    let mut out = Vec::with_capacity(tamano);
    for _ in 0..tamano {
        out.push(rng.byte());
    }
    out
}

/// Una ronda de la avalancha: mezcla de ataques y tráfico legítimo.
fn carga_de_caos(rng: &mut SplitMix64) -> Vec<u8> {
    match rng.below(9) {
        0 => carga_paradoxica(),
        1 => carga_hostil(),
        2 => anidamiento_profundo(rng),
        3 => bytes_de_control(rng),
        4 => binario_ilegible(rng),
        5 => bomba_de_tamano(rng),
        6 => programa_shoresh(rng),
        7 => carga_limpia(rng),
        _ => ruido_crudo(rng),
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Frente 1 · avalancha, saturación y corrupción de frontera
// ─────────────────────────────────────────────────────────────────────────

/// Rondas de la avalancha: suficientes para ejercitar los cuatro veredictos.
const RONDAS_DE_CAOS: usize = 4_000;

/// Cota anti‑bloqueo de la avalancha completa. No es una medida de rendimiento:
/// es la detección de un cuelgue real (un bloqueo tardaría órdenes de magnitud
/// más que cualquier ejecución razonable de este arnés).
const COTA_AVALANCHA: Duration = Duration::from_secs(120);

#[test]
fn el_filo_de_la_paradoja_se_retiene_sin_explotar() {
    let carga = carga_paradoxica();
    let amenaza = threat_of(&carga);
    assert!(
        amenaza.is_paradoxical(),
        "la carga del arnés no está en el filo: {}",
        amenaza.summary()
    );
    assert!(
        is_legible(&carga),
        "el filo se construye sobre texto legible"
    );

    let mut puerta = Gateway::new();
    let mut sistema = ImmuneSystem::new();
    let (veredicto, masas, alcanza, absorbe) = {
        let burbuja = puerta.admit("caos:filo", 0, &carga);
        let respuesta = sistema.scan(burbuja);
        (
            burbuja.verdict,
            burbuja.valence.belnap(),
            respuesta.reaches_core(),
            matches!(respuesta.disposition, Disposition::Absorb),
        )
    };

    // La paradoja tolerada: verdad y falsedad exactamente en el umbral.
    assert_eq!(veredicto, BubbleVerdict::Absorbed);
    assert_eq!(masas, (0.5, 0.5));
    assert!(alcanza, "la contradicción tolerada atraviesa sin explotar");
    assert!(absorbe, "el sistema inmune absorbe, no neutraliza");
    assert_eq!(puerta.bubbles.len(), 1);
}

#[test]
fn el_ataque_de_saturacion_no_alcanza_el_nucleo() {
    let carga = carga_hostil();
    let amenaza = threat_of(&carga);
    assert!(
        amenaza.is_hostile(),
        "la carga hostil no supera el umbral: {}",
        amenaza.summary()
    );
    assert!(
        is_legible(&carga),
        "la hostilidad es de texto, no de binario"
    );

    let mut puerta = Gateway::new();
    let mut sistema = ImmuneSystem::new();
    let (veredicto, inertes, alcanza, neutraliza) = {
        let burbuja = puerta.admit("caos:hostil", 0, &carga);
        let respuesta = sistema.scan(burbuja);
        (
            burbuja.verdict,
            burbuja.inert.clone(),
            respuesta.reaches_core(),
            respuesta.neutralizes(),
        )
    };

    assert_eq!(veredicto, BubbleVerdict::Neutralized);
    assert!(!alcanza, "una carga hostil alcanzó el núcleo");
    assert!(neutraliza, "la carga hostil no se neutralizó");
    assert_eq!(
        inertes.len(),
        carga.len(),
        "el ruido inerte conserva el tamaño"
    );
    assert!(
        inertes.iter().all(|byte| *byte >= 0x80),
        "quedó una marca legible en el ruido inerte"
    );
}

#[test]
fn la_avalancha_de_ruido_no_rompe_la_periferia() {
    let mut rng = SplitMix64::new(0xCA05_0001);
    let mut puerta = Gateway::new();
    let mut sistema = ImmuneSystem::new();
    let (mut inocuas, mut absorbidas, mut neutralizadas, mut cuarentenadas) = (0, 0, 0, 0);
    let mut mayor_carga = 0_usize;
    let inicio = Instant::now();

    for indice in 0..RONDAS_DE_CAOS {
        let carga = carga_de_caos(&mut rng);
        let legible = is_legible(&carga);
        let amenaza = threat_of(&carga);
        let veredicto = {
            let burbuja = puerta.admit("caos:periferia", indice as u64, &carga);
            let respuesta = sistema.scan(burbuja);

            assert_eq!(
                burbuja.bytes,
                carga.len(),
                "carga declarada distinta en la ronda {indice}"
            );
            assert!(
                burbuja.is_airtight(),
                "burbuja no estanca en la ronda {indice}"
            );
            assert_eq!(
                burbuja.danger, amenaza.mille,
                "peligro ajeno al del núcleo en la ronda {indice}"
            );
            assert!(
                masas_sanas(&burbuja.valence),
                "valencia fuera de [0,1] en la ronda {indice}"
            );
            assert_eq!(
                respuesta.reaches_core(),
                burbuja.verdict.reaches_core(),
                "la puerta y el sistema discrepan en la ronda {indice}"
            );
            assert_eq!(
                matches!(respuesta.disposition, Disposition::Quarantine),
                burbuja.verdict == BubbleVerdict::Quarantined,
                "cuarentena incoherente en la ronda {indice}"
            );
            assert_eq!(
                burbuja.inert.len(),
                if burbuja.verdict.reaches_core() {
                    0
                } else {
                    burbuja.bytes
                },
                "ruido inerte de tamaño erróneo en la ronda {indice}"
            );
            if legible && amenaza.is_paradoxical() {
                assert_eq!(
                    burbuja.verdict,
                    BubbleVerdict::Absorbed,
                    "el filo ⊤∧⊥ no se retuvo en la ronda {indice}"
                );
            }
            if !legible && amenaza.danger() < 0.5 {
                assert_eq!(
                    burbuja.verdict,
                    BubbleVerdict::Quarantined,
                    "lo ilegible no se cuarentenó en la ronda {indice}"
                );
            }
            if burbuja.danger > 500 {
                assert_ne!(
                    burbuja.verdict,
                    BubbleVerdict::Innocuous,
                    "una carga hostil pasó por inocua en la ronda {indice}"
                );
            }
            burbuja.verdict
        };

        match veredicto {
            BubbleVerdict::Innocuous => inocuas += 1,
            BubbleVerdict::Absorbed => absorbidas += 1,
            BubbleVerdict::Neutralized => neutralizadas += 1,
            BubbleVerdict::Quarantined => cuarentenadas += 1,
        }
        mayor_carga = mayor_carga.max(carga.len());
        assert!(
            sistema.census().total() <= MAX_ANTIBODIES,
            "el repertorio desbordó en la ronda {indice}"
        );
    }

    // La puerta no descartó nada y el censo cuadra con el registro de burbujas.
    assert_eq!(puerta.bubbles.len(), RONDAS_DE_CAOS);
    assert!(puerta.door_is_open(), "la puerta dejó de estar abierta");
    assert_eq!(puerta.regions.len(), RONDAS_DE_CAOS);
    assert_eq!(puerta.memory.len(), RONDAS_DE_CAOS);
    assert_eq!(
        puerta.census(),
        (inocuas, absorbidas, neutralizadas, cuarentenadas)
    );
    assert_eq!(
        inocuas + absorbidas + neutralizadas + cuarentenadas,
        RONDAS_DE_CAOS
    );

    // El caos no es monocromo: los cuatro veredictos aparecen.
    for (etiqueta, cuenta) in [
        ("inocuas", inocuas),
        ("absorbidas", absorbidas),
        ("neutralizadas", neutralizadas),
        ("cuarentenadas", cuarentenadas),
    ] {
        assert!(cuenta > 0, "el arnés no produjo burbujas {etiqueta}");
    }

    assert!(
        mayor_carga > SIZE_BOMB_BYTES,
        "el arnés no llegó a probar la bomba de tamaño"
    );
    assert!(
        mayor_carga <= MAX_PAYLOAD,
        "una carga superó la cota del kernel"
    );
    assert_eq!(
        sistema.counters().total() as usize,
        RONDAS_DE_CAOS,
        "el sistema inmune no vio todas las burbujas"
    );
    assert!(
        inicio.elapsed() < COTA_AVALANCHA,
        "la avalancha tardó {:?}",
        inicio.elapsed()
    );
}

/// Marcas sintéticas del operador para llevar el repertorio hasta su techo.
///
/// Son estáticas a propósito: un epítopo nunca se construye con texto dinámico,
/// sólo con nombres canónicos de la tabla del organismo.
const MARCAS_SINTETICAS: [&str; 72] = [
    "m00", "m01", "m02", "m03", "m04", "m05", "m06", "m07", "m08", "m09", "m10", "m11", "m12",
    "m13", "m14", "m15", "m16", "m17", "m18", "m19", "m20", "m21", "m22", "m23", "m24", "m25",
    "m26", "m27", "m28", "m29", "m30", "m31", "m32", "m33", "m34", "m35", "m36", "m37", "m38",
    "m39", "m40", "m41", "m42", "m43", "m44", "m45", "m46", "m47", "m48", "m49", "m50", "m51",
    "m52", "m53", "m54", "m55", "m56", "m57", "m58", "m59", "m60", "m61", "m62", "m63", "m64",
    "m65", "m66", "m67", "m68", "m69", "m70", "m71",
];

#[test]
fn la_avalancha_satura_la_pasarela_pero_no_el_repertorio() {
    const RONDAS: usize = 2_000;

    let mut rng = SplitMix64::new(0xCA05_0002);
    let mut puerta = Gateway::new();
    let mut sistema = ImmuneSystem::new();

    // Dos mil agresiones: hostilidad pura alternando con binario ilegible.
    for indice in 0..RONDAS {
        let carga = if indice % 2 == 0 {
            carga_hostil()
        } else {
            binario_ilegible(&mut rng)
        };
        let burbuja = puerta.admit("caos:avalancha", indice as u64, &carga);
        let respuesta = sistema.scan(burbuja);

        assert!(
            !respuesta.reaches_core(),
            "una carga hostil o ilegible alcanzó el núcleo en la ronda {indice}"
        );
        assert!(
            respuesta.neutralizes() || matches!(respuesta.disposition, Disposition::Quarantine),
            "disposición inesperada en la ronda {indice}: {}",
            respuesta.disposition.name()
        );
        assert!(
            !respuesta.repertoire_full,
            "las marcas del modelo llenaron el repertorio en la ronda {indice}"
        );

        // La pasarela crece exactamente una burbuja, una región y una entrada de
        // holograma por paquete: el registro de lo visto es lineal y completo.
        assert_eq!(puerta.bubbles.len(), indice + 1);
        assert_eq!(puerta.regions.len(), indice + 1);
        assert_eq!(puerta.memory.len(), indice + 1);
    }

    // Nada se descartó y nada pasó por inocuo: todo fue ⊥ o ∅.
    let (inocuas, absorbidas, neutralizadas, cuarentenadas) = puerta.census();
    assert_eq!(inocuas, 0, "algo pasó por inocuo en la avalancha");
    assert_eq!(absorbidas, 0, "algo pasó por paradoja tolerada");
    assert_eq!(neutralizadas + cuarentenadas, RONDAS);
    assert_eq!(neutralizadas, RONDAS / 2);
    assert_eq!(cuarentenadas, RONDAS - RONDAS / 2);
    assert!(puerta.door_is_open());
    assert!(
        puerta.memory.entropy() == 0.0,
        "el holograma acumuló entropía"
    );
    assert!(puerta.memory.writes() as usize <= RONDAS);

    // El repertorio aprende de la epidemia (expansiones y recuerdos) pero su
    // tamaño lo fija la tabla de marcas, **no** el número de paquetes.
    let contadores = *sistema.counters();
    assert!(contadores.expansions > 0, "el repertorio no aprendió nada");
    assert!(contadores.recalls > 0, "el repertorio no recordó nada");
    assert_eq!(
        contadores.tolerated
            + contadores.absorbed
            + contadores.quarantined
            + contadores.neutralized
            + contadores.immunized,
        RONDAS as u64
    );
    assert!(contadores.immunized > 0, "la memoria no inmunizó a nadie");
    assert!(sistema.repertoire().len() <= MAX_ANTIBODIES);
    assert!(
        !sistema.repertoire().is_full(),
        "dos mil paquetes llenaron el repertorio: la memoria no está acotada"
    );

    // Lo ya visto se reconoce al volver a presentarlo: memoria adaptativa viva.
    let (recordado, lleno) = {
        let burbuja = puerta.admit("caos:posterior", 0, &carga_hostil());
        let primera = sistema.scan(burbuja);
        let segunda = sistema.scan(burbuja);
        (
            segunda.recalled,
            primera.repertoire_full && segunda.repertoire_full,
        )
    };
    assert!(recordado, "el sistema no reconoció un patógeno ya visto");
    assert!(!lleno);

    // El techo sólo se alcanza por orden explícita del operador (vacunación).
    let antes = sistema.census().total();
    let mut vacunadas = 0_usize;
    let mut rechazadas = 0_usize;
    for (indice, marca) in MARCAS_SINTETICAS.iter().enumerate() {
        let epitopo = Epitope::new(marca, 100 + (indice as u32 % 20) * 10);
        match sistema.vaccinate("caos:operador", epitopo, indice as u64) {
            Ok(vacuna) => {
                assert!(!vacuna.booster, "una marca nueva se tomó por refuerzo");
                vacunadas += 1;
            }
            Err(_) => rechazadas += 1,
        }
        assert!(
            sistema.census().total() <= MAX_ANTIBODIES,
            "censo por encima del techo"
        );
        assert!(sistema.repertoire().len() <= MAX_ANTIBODIES);
    }
    assert_eq!(
        vacunadas + antes,
        MAX_ANTIBODIES,
        "no se alcanzó el techo con vacunas nuevas"
    );
    assert_eq!(rechazadas, MARCAS_SINTETICAS.len() - vacunadas);
    assert!(rechazadas > 0, "el techo no rechazó ninguna vacuna");
    assert!(sistema.repertoire().is_full());
    assert_eq!(sistema.census().total(), MAX_ANTIBODIES);

    // La válvula del olvido vacía el repertorio y es contabilizada.
    let mut retiradas = 0_usize;
    for _ in 0..10 {
        retiradas += sistema.forget();
    }
    assert_eq!(
        retiradas, MAX_ANTIBODIES,
        "el olvido no retiró todas las estirpes"
    );
    assert_eq!(
        sistema.census().total(),
        0,
        "quedó memoria tras diez olvidos"
    );
    assert_eq!(sistema.counters().forgotten, retiradas as u64);
    assert!(sistema.repertoire().len() <= MAX_ANTIBODIES);
}

#[test]
fn la_corrupcion_en_la_frontera_deja_el_nucleo_intacto() {
    const RONDAS: usize = 512;
    const TEXTOS: usize = RONDAS.div_ceil(3);

    let mut rng = SplitMix64::new(0xCA05_0003);
    let mut nucleo = BaraRuntime::new();
    nucleo.push(QuantumState::classical(true));
    nucleo.certify();

    let pila_base = nucleo.stack.len();
    let memoria_base = nucleo.memory.len();
    let eventos_base = nucleo.log().len();

    // Frontera: corrupción cruda y, cada tres paquetes, un texto que sí pasa.
    let mut ingreso = LoopbackIngress::new("caos:frontera");
    let mut corrompidas = 0_usize;
    for indice in 0..RONDAS {
        let carga = carga_de_caos(&mut rng);
        if !is_legible(&carga) || threat_of(&carga).is_tainted() {
            corrompidas += 1;
        }
        ingreso.push_bytes(&carga);
        if indice % 3 == 0 {
            ingreso.push_text(&format!("ברא חכם {}", indice));
        }
    }
    let en_cola = ingreso.len();
    assert_eq!(en_cola, RONDAS + TEXTOS);
    assert!(
        corrompidas > 0,
        "el arnés no llegó a corromper ninguna carga"
    );

    let mut puerta = Gateway::new();
    let informe = puerta.run(&mut ingreso, en_cola, &mut nucleo);

    // Acta de la ronda: nada se descartó y nada se perdió por el camino.
    assert_eq!(informe.received, en_cola);
    assert_eq!(informe.bubbles, en_cola);
    assert_eq!(informe.dropped(), 0, "la puerta descartó paquetes");
    assert!(
        informe.is_airtight(),
        "ronda no estanca: {}",
        informe.label()
    );
    assert_eq!(informe.acceptance(), 1.0);
    assert_eq!(informe.contradictions, informe.absorbed);
    assert_eq!(
        informe.innocuous + informe.absorbed + informe.neutralized + informe.quarantined,
        informe.bubbles
    );
    assert!(informe.neutralized + informe.quarantined > 0);
    assert_eq!(puerta.bubbles.len(), informe.bubbles);
    assert!(ingreso.is_empty(), "quedaron paquetes sin atender");

    // La liberación hacia el núcleo fue **exactamente** lo autorizado.
    let autorizados: usize = puerta
        .bubbles
        .iter()
        .filter(|burbuja| burbuja.verdict.reaches_core())
        .map(|burbuja| burbuja.ast.nodes.len().max(1))
        .sum();
    assert_eq!(informe.released_nodes, autorizados);
    assert_eq!(nucleo.stack.len(), pila_base + informe.released_nodes);
    assert!(
        nucleo.stack.iter().all(masas_sanas),
        "el asedio corrompió la pila"
    );
    assert!(nucleo.memory.len() >= memoria_base);
    assert!(nucleo.memory.len() <= memoria_base + informe.released_nodes);
    assert!(
        nucleo.memory.entropy() == 0.0,
        "el holograma acumuló entropía"
    );
    assert!(nucleo.log().len() >= eventos_base);

    // Ni lo hostil ni lo ilegible abren la puerta: liberar una burbuja sellada
    // es una no-operación explícita, no un descarte silencioso.
    let antes_de_liberar = (nucleo.stack.len(), nucleo.memory.len());
    let mut selladas = 0_usize;
    for burbuja in &puerta.bubbles {
        if !burbuja.verdict.reaches_core() {
            assert_eq!(
                puerta.release(burbuja.id, &mut nucleo),
                0,
                "una burbuja sellada liberó nodos"
            );
            selladas += 1;
        }
    }
    assert!(selladas > 0, "no hubo ninguna burbuja sellada que probar");
    assert_eq!((nucleo.stack.len(), nucleo.memory.len()), antes_de_liberar);

    // El núcleo sigue siendo el mismo núcleo: sus invariantes siguen firmando.
    let certificado = nucleo.certify();
    assert!(
        certificado.result.verified,
        "el certificado ZK dejó de verificar"
    );
    assert!(nucleo.certificate.is_some());

    // El lexer es total sobre lo corrupto: siempre termina y siempre emite algo.
    for _ in 0..64 {
        let carga = carga_de_caos(&mut rng);
        let texto = String::from_utf8_lossy(&carga);
        let tokens = Lexer::new(&texto).tokenize();
        assert!(!tokens.is_empty(), "el lexer no emitió ningún token");
        assert!(tokens
            .iter()
            .all(|token| token.line >= 1 && token.column >= 1));
    }

    // La tabla de agujas está viva: cada aguja, por separado, se reconoce.
    for (etiqueta, aguja, peso) in ATTACK_NEEDLES {
        let carga = format!("prefijo {aguja} sufijo");
        let amenaza = threat_of(carga.as_bytes());
        assert!(
            amenaza.markers.contains(&etiqueta),
            "aguja no reconocida: {etiqueta}"
        );
        assert!(amenaza.mille >= peso, "peso insuficiente para {etiqueta}");
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Frente 2 · sandbox suicida: aislamiento automático, informe honesto, purga
// ─────────────────────────────────────────────────────────────────────────

/// Cota anti‑bloqueo del ciclo completo de aislamiento (trampa → informe →
/// purga). No mide rendimiento: delata un cuelgue real.
const COTA_ISOLAMIENTO: Duration = Duration::from_secs(30);

#[test]
fn el_sandbox_suicida_se_aisla_y_no_toca_el_nucleo() {
    let kernel = nucleo();
    let huella = kernel.digest();
    let revision = kernel.revision();
    let adn = kernel.dna().root;
    let raices: Vec<String> = kernel.nodes().iter().map(|n| n.root.clone()).collect();

    // La célula copia el núcleo pero no lo toca: tipos compartidos, estado no.
    let mut mutador = AutopoieticMutator::new(SEED);
    let celda = mutador.open_cell(kernel.read());
    assert_eq!(celda, 1);
    assert_eq!(mutador.counters().cells, 1);
    assert!(mutador.cell(celda).map(|c| c.is_open()).unwrap_or(false));
    assert_eq!(
        mutador.cell(celda).map(|c| c.node_count()).unwrap_or(0),
        raices.len()
    );

    // Operación conforme: la célula arranca sana y su rama crece sobre la base.
    let desenlace = mutador.apply(celda, &conforme_de_la_rama());
    assert!(matches!(&desenlace, Ok(forma) if forma.is_applied()));
    assert_eq!(mutador.cell(celda).map(|c| c.op_count()).unwrap_or(0), 1);
    assert_eq!(
        mutador.cell(celda).map(|c| c.node_count()).unwrap_or(0),
        raices.len() + 1
    );

    // Corrupción deliberada: raíz vacía, aridad fuera de cota y nodo inexistente.
    let inicio = Instant::now();
    let corruptas = [
        Mutation::Add {
            root: String::new(),
            original: "legacy_sin_raiz".to_string(),
            arity: MAX_ARITY + 4,
            ret: BaraType::Number,
            hazard: RIESGO_ALTO,
            truth: 0.90,
            falsity: 0.10,
        },
        Mutation::Rewire {
            index: 0,
            arity: MAX_ARITY + 8,
        },
        Mutation::Retarget {
            index: 4096,
            ret: BaraType::Unknown,
        },
    ];
    let mut atrapados = 0_usize;
    for corrupta in &corruptas {
        let intento = mutador.apply(celda, corrupta);
        assert!(
            intento.is_ok(),
            "el contenedor propagó un fallo de la célula"
        );
        if let Ok(forma) = intento {
            assert!(
                forma.is_trapped(),
                "la corrupción no fue atrapada: {}",
                forma.label()
            );
            assert!(forma
                .fault()
                .map(|fallo| !fallo.error.is_empty())
                .unwrap_or(false));
            atrapados += 1;
        }
    }
    let costo = inicio.elapsed();
    assert_eq!(
        atrapados,
        corruptas.len(),
        "la célula no atrapó la corrupción"
    );
    assert!(costo < COTA_ISOLAMIENTO, "el aislamiento tardó {costo:?}");

    // El fallo no salió del sandbox: la célula se aisló sola.
    assert!(matches!(
        mutador.cell(celda).map(|c| c.state()),
        Some(CellState::Quarantined)
    ));
    assert!(mutador
        .cell(celda)
        .map(|c| c.is_poisoned())
        .unwrap_or(false));
    assert_eq!(
        mutador.cell(celda).map(|c| c.faults().len()).unwrap_or(0),
        atrapados
    );
    assert_eq!(mutador.counters().traps, atrapados);

    // Informe honesto: dice cuánto trabajo bueno se descarta y cuántos fallos
    // acumuló; no se declara limpio ni maquilla el recuento.
    let informe = mutador.isolate(celda);
    assert!(
        informe.is_ok(),
        "el aislamiento explícito falló: {:?}",
        informe.as_ref().err()
    );
    if let Ok(informe) = &informe {
        assert_eq!(informe.cell, celda);
        assert_eq!(informe.faults, atrapados);
        assert!(
            !informe.is_clean(),
            "un aislamiento con fallos no es limpio"
        );
        assert_eq!(informe.ops_discarded, 1, "el informe ocultó trabajo bueno");
        assert!(informe.label.contains("aislada"), "{}", informe.label);
    }

    // Una célula aislada no propone: el veto es explícito y tipado.
    let propuesta = mutador.propose(kernel.read(), celda, &evidencia_verde());
    assert!(
        matches!(&propuesta, Err(MutatorError::CellPoisoned { id }) if *id == celda),
        "la célula en cuarentena propuso algo"
    );
    assert_eq!(mutador.counters().proposals, 0);

    // Purga: la rama se descarta y el núcleo queda byte a byte idéntico. No hay
    // nada que deshacer en el núcleo porque la célula nunca tocó su estado: la
    // purga es una retirada, no un *rollback*.
    assert!(mutador.release(celda), "la purga no retiró la célula");
    assert!(!mutador.release(celda), "la célula resucitó tras la purga");
    assert!(mutador.cell(celda).is_none());
    assert_eq!(mutador.cells().count(), 0, "quedaron células vivas");
    assert!(misma_huella(&kernel.digest(), &huella), "el núcleo cambió");
    assert_eq!(kernel.revision(), revision, "el núcleo cambió de revisión");
    assert!(misma_huella(&kernel.dna().root, &adn), "el ADN cambió");
    assert_eq!(
        kernel.nodes().len(),
        raices.len(),
        "el núcleo cambió de tamaño"
    );
    assert_eq!(
        kernel
            .nodes()
            .iter()
            .map(|n| n.root.clone())
            .collect::<Vec<String>>(),
        raices,
        "las raíces del núcleo cambiaron"
    );
    assert!(kernel.verify(), "el núcleo dejó de verificar");
    assert_eq!(mutador.counters().fusions, 0, "hubo fusión sin juicio");
    assert_eq!(mutador.counters().rejections, 0);
    assert!(mutador.counters().isolations >= 1);

    // Repetible: el mismo guion produce el mismo informe y el mismo núcleo.
    let primero = guion_suicida();
    let segundo = guion_suicida();
    assert!(
        misma_huella(&primero.0, &segundo.0),
        "núcleo no determinista"
    );
    assert_eq!(primero.1, segundo.1, "el informe no fue determinista");
    assert!(misma_huella(&primero.0, &huella));
}

/// Ejecuta el guion del sandbox suicida y devuelve `(huella del núcleo,
/// informe de aislamiento)`: dos ejecuciones deben coincidir.
fn guion_suicida() -> ([u8; 32], IsolationReport) {
    let kernel = nucleo();
    let mut mutador = AutopoieticMutator::new(SEED);
    let celda = mutador.open_cell(kernel.read());
    let _ = mutador.apply(celda, &conforme_de_la_rama());
    let _ = mutador.apply(
        celda,
        &Mutation::Rewire {
            index: 0,
            arity: MAX_ARITY + 8,
        },
    );
    let informe = mutador.isolate(celda).unwrap_or(IsolationReport {
        cell: 0,
        ops_discarded: 0,
        faults: 0,
        label: String::new(),
    });
    (kernel.digest(), informe)
}

/// Operación conforme del guion: injerta `חכמ` con valencia `⊤`.
fn conforme_de_la_rama() -> Mutation {
    Mutation::Add {
        root: "חכמ".to_string(),
        original: "legacy_חכמ".to_string(),
        arity: 2,
        ret: BaraType::Number,
        hazard: 0.05,
        truth: 0.95,
        falsity: 0.05,
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Frente 2 (bis) · presupuesto y diario: nada crece sin cota
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn el_presupuesto_y_el_diario_estan_acotados() {
    let kernel = nucleo();
    let mut mutador = AutopoieticMutator::new(SEED);
    let inicio = Instant::now();

    // Una célula no puede trabajar sin fin: el tope de operaciones es real.
    let celda = mutador.open_cell(kernel.read());
    for _ in 0..MAX_CELL_OPS {
        let outcome = mutador.apply(
            celda,
            &Mutation::Retarget {
                index: 0,
                ret: BaraType::Text,
            },
        );
        assert!(matches!(&outcome, Ok(forma) if forma.is_applied()));
    }
    assert_eq!(
        mutador.cell(celda).map(|c| c.op_count()).unwrap_or(0),
        MAX_CELL_OPS
    );
    assert_eq!(mutador.counters().traps, 0, "se agotó antes de tiempo");

    // La operación de más no se «cuela»: se atrapa y la célula se aísla.
    let exhausta = mutador.apply(celda, &Mutation::Seal { index: 0 });
    assert!(matches!(&exhausta, Ok(forma) if forma.is_trapped()));
    if let Ok(forma) = &exhausta {
        assert!(forma
            .fault()
            .map(|fallo| fallo.error.contains("presupuesto agotado"))
            .unwrap_or(false));
    }
    assert!(mutador
        .cell(celda)
        .map(|c| c.is_poisoned())
        .unwrap_or(false));
    assert_eq!(mutador.counters().traps, 1);

    // Y el diario tampoco crece sin cota: se conserva lo último, no todo.
    let total = JOURNAL_LIMIT + 8;
    for _ in 0..total {
        mutador.open_cell(kernel.read());
    }
    let diario = mutador.journal_lines();
    assert_eq!(diario.len(), JOURNAL_LIMIT, "el diario creció sin cota");
    assert!(diario.iter().all(|linea| !linea.is_empty()));
    assert_eq!(mutador.counters().cells, total + 1);
    assert!(inicio.elapsed() < COTA_ISOLAMIENTO, "el guion tardó de más");

    // Ni una célula, ni una operación, ni una línea tocaron el núcleo.
    assert!(kernel.verify(), "el núcleo dejó de verificar");
    assert_eq!(kernel.revision(), 0, "el núcleo cambió de revisión");
    assert_eq!(mutador.counters().fusions, 0);
}

// ─────────────────────────────────────────────────────────────────────────
// Frente 3 · desacuerdo extremo: Belnap congela y veta el parche
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn el_desacuerdo_extremo_congela_belnap_y_veta_el_parche() {
    let kernel = nucleo();
    let huella = kernel.digest();
    let revision = kernel.revision();

    // Desacuerdo extremo entre sub‑motores: `⊤` frente a `⊥` no se promedia, se
    // une informativamente y el resultado es la contradicción tolerada.
    let desacuerdo = BelnapValue::True.union(BelnapValue::False);
    assert_eq!(desacuerdo, BelnapValue::Both, "unir ⊤ y ⊥ no contradijo");
    assert!(desacuerdo.is_contradiction());
    assert!(desacuerdo.is_designated(), "⊤∧⊥ sigue siendo designado");
    assert!(!desacuerdo.is_determined(), "⊤∧⊥ no es una determinación");
    assert_eq!(
        BelnapValue::True.consensus(BelnapValue::False),
        BelnapValue::Neither,
        "dos determinaciones opuestas no pueden consensuar"
    );
    assert_eq!(
        BelnapMatrix::agreement(BelnapValue::Both, BelnapValue::True),
        BelnapValue::True,
        "el tope informativo aporta lo que afirme el otro testigo"
    );
    assert_eq!(
        BelnapMatrix::agreement(BelnapValue::True, BelnapValue::False),
        BelnapValue::Neither,
        "el consenso de dos testigos que discrepan es el vacío, no un promedio"
    );

    // Con contradicción declarada la periferia deja de ser `⊤`: el juicio se
    // congela aunque el testigo independiente del núcleo siga siendo `⊤`.
    let contradictorio = ShoreshAst {
        nodes: vec![nodo_sano("אמת"), nodo_contradictorio("דעת")],
    };
    let juicio = BelnapMatrix::evaluate(kernel.read(), &contradictorio, &evidencia_verde(), true);
    assert_eq!(juicio.periferia, BelnapValue::Both, "{}", juicio.label());
    assert_eq!(juicio.nucleo, BelnapValue::True, "{}", juicio.label());
    assert_eq!(juicio.union, BelnapValue::Both, "{}", juicio.label());
    assert_eq!(juicio.contradictions, 1);
    assert_eq!(
        juicio.violations, 0,
        "contradecirse no es violar la estructura"
    );
    assert!(!juicio.admits_fusion(), "Belnap admitió la contradicción");
    assert!(juicio.is_bounded(), "{}", juicio.label());
    assert!(!juicio.reason().is_empty());

    // El juicio es determinista bit a bit: ni las masas ni la clase titubean.
    let repetido = BelnapMatrix::evaluate(kernel.read(), &contradictorio, &evidencia_verde(), true);
    assert_eq!(juicio, repetido, "el juicio no fue determinista");
    assert_eq!(juicio.truth.to_bits(), repetido.truth.to_bits());
    assert_eq!(juicio.falsity.to_bits(), repetido.falsity.to_bits());

    // Belnap no detiene todo: el parche sano con evidencia verde pasa, mientras
    // la evidencia roja y la ausencia de firma lo detienen.
    let sano = ShoreshAst {
        nodes: vec![nodo_sano("אמת"), nodo_sano("דעת")],
    };
    let verde = BelnapMatrix::evaluate(kernel.read(), &sano, &evidencia_verde(), true);
    let rojo = BelnapMatrix::evaluate(kernel.read(), &sano, &evidencia_roja(), true);
    let sin_firma = BelnapMatrix::evaluate(kernel.read(), &sano, &evidencia_verde(), false);
    assert!(verde.admits_fusion(), "Belnap detuvo un parche sano");
    assert_eq!(verde.union, BelnapValue::True);
    assert!(!rojo.admits_fusion(), "la evidencia roja no vetó");
    assert!(rojo.tests_failed > 0 && rojo.union != BelnapValue::True);
    assert!(!sin_firma.admits_fusion(), "sin firma no hay fusión");
    assert_eq!(sin_firma.periferia, BelnapValue::False);
    assert!(!sin_firma.signature_ok);

    // El veto llega hasta el `commit`: la propuesta se emite, se audita en
    // estático y se rechaza con el tipo explícito del juicio — nunca con un
    // promedio ni con una fusión «de consenso».
    let mut mutador = AutopoieticMutator::new(SEED);
    let celda = mutador.open_cell(kernel.read());
    let aplicado = mutador.apply(celda, &parche_contradictorio());
    assert!(matches!(&aplicado, Ok(forma) if forma.is_applied()));
    let emitida = mutador.propose(kernel.read(), celda, &evidencia_verde());
    assert!(
        emitida.is_ok(),
        "la propuesta ni se emitió: {:?}",
        emitida.as_ref().err()
    );
    let id = emitida.unwrap_or(0);
    if let Some(propuesta) = mutador.proposal(id) {
        assert!(
            propuesta.audit.passed(),
            "la auditoría estática pasó por alto el parche"
        );
        assert_eq!(propuesta.verdict.periferia, BelnapValue::Both);
        assert_eq!(propuesta.verdict.union, BelnapValue::Both);
        assert!(
            !propuesta.admits_fusion(),
            "la propuesta se admitió a sí misma"
        );
        assert_eq!(propuesta.base_revision, revision);
        assert!(misma_huella(&propuesta.base_digest, &huella));
        assert!(propuesta.fingerprint().iter().any(|byte| *byte != 0));
    }
    let veto = mutador.commit(&kernel, id);
    let veto_esperado = matches!(
        &veto,
        Err(MutatorError::VerdictRejected { periferia, union })
            if *periferia == BelnapValue::Both && *union == BelnapValue::Both
    );
    assert!(veto_esperado, "el veto no fue el esperado: {:?}", veto);
    assert!(
        mutador.commit(&kernel, id).is_err(),
        "el parche vetado se fusionó al reintentar"
    );

    // Estado publicado: el núcleo vetado sigue siendo el mismo núcleo, bit a bit.
    assert!(misma_huella(&kernel.digest(), &huella), "el núcleo cambió");
    assert_eq!(kernel.revision(), revision);
    assert!(kernel.verify());
    assert_eq!(
        mutador.counters().fusions,
        0,
        "hubo fusión sin juicio favorable"
    );
    assert_eq!(mutador.counters().rejections, 2);

    // Determinismo extremo a extremo: dos guiones independientes publican el
    // mismo estado, el mismo parche y el mismo veto.
    let un_run = guion_del_veto();
    let otro_run = guion_del_veto();
    assert!(
        misma_huella(&un_run.0, &otro_run.0),
        "el estado publicado cambió entre repeticiones"
    );
    assert!(
        misma_huella(&un_run.1, &otro_run.1),
        "el parche cambió de huella entre repeticiones"
    );
    assert_eq!(un_run.2, otro_run.2, "el veto no fue determinista");
    assert!(
        misma_huella(&un_run.0, &huella),
        "el génesis no se reprodujo"
    );
    assert!(
        matches!(
            &un_run.2,
            Some(MutatorError::VerdictRejected { periferia, union })
                if *periferia == BelnapValue::Both && *union == BelnapValue::Both
        ),
        "el guion no acabó en veto: {:?}",
        un_run.2
    );
}

/// Ejecuta el guion del veto y devuelve `(huella del núcleo publicado, huella
/// del parche candidato, fallo del `commit`)`.
fn guion_del_veto() -> ([u8; 32], [u8; 32], Option<MutatorError>) {
    let kernel = nucleo();
    let mut mutador = AutopoieticMutator::new(SEED);
    let celda = mutador.open_cell(kernel.read());
    let _ = mutador.apply(celda, &parche_contradictorio());
    let id = mutador
        .propose(kernel.read(), celda, &evidencia_verde())
        .unwrap_or(0);
    let parche = mutador
        .proposal(id)
        .map(|p| p.fingerprint())
        .unwrap_or([0_u8; 32]);
    let fallo = mutador.commit(&kernel, id).err();
    (kernel.digest(), parche, fallo)
}

/// Parche contradictorio: un nodo con valencia `⊤∧⊥` y estructura admisible.
fn parche_contradictorio() -> Mutation {
    Mutation::Add {
        root: "חכמ".to_string(),
        original: "legacy_contradictorio".to_string(),
        arity: 2,
        ret: BaraType::Number,
        hazard: 0.10,
        truth: 1.0,
        falsity: 1.0,
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Frente 1 (bis) · la periferia cognitiva no compra autoridad
// ─────────────────────────────────────────────────────────────────────────

/// Cota anti‑bloqueo del asedio cognitivo (lenguaje → filtro → sandbox).
const COTA_COGNITIVA: Duration = Duration::from_secs(30);

/// Enunciado hostil compuesto sólo con agujas de ataque conocidas: el lenguaje
/// lo lee (es texto legible) pero leerlo no le da autoridad sobre el núcleo.
fn enunciado_hostil() -> String {
    let mut out = String::new();
    for (etiqueta, aguja, _peso) in ATTACK_NEEDLES {
        out.push_str(etiqueta);
        out.push(' ');
        out.push_str(aguja);
        out.push(' ');
    }
    out
}

#[test]
fn el_lenguaje_no_compra_autoridad_ni_toca_el_nucleo() {
    let kernel = nucleo();
    let huella = kernel.digest();
    let revision = kernel.revision();
    let motor = NlpToShoresh::new();
    let filtro = HallucinationFilter::new();
    let inicio = Instant::now();

    // El motor de lenguaje es total: lo ilegible se rechaza con un error tipado,
    // nunca con un pánico. El recorte del enunciado cae en frontera de carácter,
    // así que un texto multibyte partido por `from_utf8_lossy` no lo revienta.
    assert_eq!(motor.synthesize("   "), Err(SynthError::EmptyUtterance));
    let multibyte = "☃".repeat(200);
    assert!(
        motor.tokens(&multibyte).is_empty(),
        "el texto ilegible produjo tokens"
    );
    assert_eq!(
        motor.synthesize(&multibyte),
        Err(SynthError::EmptyUtterance)
    );

    // Asedio de ruido: lo que el lenguaje lea debe ser una propuesta conforme
    // (raíz no vacía, riesgo y masas en rango, valencia designada); lo demás se
    // rechaza con `EmptyUtterance`. Ni un pánico en 256 rondas de caos.
    let mut rng = SplitMix64::new(0xCA05_0004);
    let mut candidatas = 0_usize;
    for _ in 0..256 {
        let carga = carga_de_caos(&mut rng);
        let texto = String::from_utf8_lossy(&carga);
        match motor.synthesize(&texto) {
            Ok(lote) => {
                for propuesta in &lote {
                    let conforme = matches!(
                        propuesta,
                        Mutation::Add { root, hazard, truth, falsity, .. }
                            if !root.is_empty()
                                && (0.0..=1.0).contains(hazard)
                                && *truth == 1.0
                                && *falsity == 0.0
                    );
                    assert!(
                        conforme,
                        "propuesta no conforme del lenguaje: {propuesta:?}"
                    );
                    candidatas += 1;
                }
            }
            Err(fallo) => assert_eq!(fallo, SynthError::EmptyUtterance),
        }
    }
    assert!(candidatas > 0, "el motor no propuso nada en todo el asedio");

    // El azar del propio arnés también entra por la periferia: frases legibles
    // generadas con el PRNG (`unit`) se leen, se juzgan y no pasan al núcleo sin
    // revisión humana. La periferia no atraviesa el filtro ni con la suerte de
    // cara, y el núcleo sigue sin enterarse de nada.
    let mut azar = SplitMix64::new(0xCA05_0005);
    for _ in 0..64 {
        let mut frase = String::new();
        for _ in 0..(1 + azar.below(6)) {
            frase.push_str(if azar.unit() < 0.5 {
                "parche "
            } else {
                "sombra "
            });
        }
        let lote = motor.synthesize(&frase).unwrap_or_default();
        let rama_azar = motor.synthesize_ast(&frase).unwrap_or_default();
        assert!(
            !lote.is_empty() && lote.len() == rama_azar.nodes.len(),
            "lote y rama no cuadran para «{frase}»"
        );
        let sin_firma = filtro.judge(kernel.read(), &rama_azar, &evidencia_verde(), false);
        assert!(
            sin_firma.blocked,
            "un parche de lenguaje pasó sin revisión humana: {}",
            sin_firma.reason
        );
        assert!(sin_firma.verdict.is_bounded(), "{}", sin_firma.reason);
    }

    // Determinismo del motor: mismo enunciado, mismas propuestas y misma rama.
    let hostil = enunciado_hostil();
    let mutaciones = motor.synthesize(&hostil).unwrap_or_default();
    assert!(
        !mutaciones.is_empty(),
        "el enunciado hostil no produjo nada"
    );
    assert_eq!(
        motor.synthesize(&hostil),
        Ok(mutaciones.clone()),
        "el motor no fue determinista"
    );
    let rama = motor.synthesize_ast(&hostil).unwrap_or_default();
    assert_eq!(rama.nodes.len(), mutaciones.len(), "rama y lote no cuadran");
    let juicio = filtro.judge(kernel.read(), &rama, &evidencia_verde(), true);
    assert!(juicio.verdict.is_bounded(), "{}", juicio.reason);
    assert!(!juicio.reason.is_empty());
    assert_eq!(
        juicio,
        filtro.judge(kernel.read(), &rama, &evidencia_verde(), true),
        "el filtro no fue determinista"
    );

    // El filtro no veta por vicio: un parche sano, con firma y pruebas, pasa.
    let sano = ast_genesis();
    let permiso = filtro.judge(kernel.read(), &sano, &evidencia_verde(), true);
    assert!(!permiso.blocked, "{}", permiso.reason);
    assert!(permiso.admits(), "{}", permiso.reason);
    assert_eq!(permiso.value(), BelnapValue::True, "{}", permiso.reason);
    assert!(permiso.reason.contains("admisible"), "{}", permiso.reason);

    // Invariantes del veto cognitivo: sin firma, con evidencia en rojo, con
    // estructura inadmisible, con contradicción o con indeterminación, nada de
    // lo que proponga el lenguaje atraviesa el filtro.
    let sin_firma = filtro.judge(kernel.read(), &sano, &evidencia_verde(), false);
    assert!(sin_firma.blocked, "{}", sin_firma.reason);
    assert!(sin_firma.reason.contains("firma"), "{}", sin_firma.reason);

    let en_rojo = filtro.judge(kernel.read(), &sano, &evidencia_roja(), true);
    assert!(en_rojo.blocked, "{}", en_rojo.reason);
    assert!(en_rojo.reason.contains("rojo"), "{}", en_rojo.reason);

    let corrupto = ShoreshAst {
        nodes: vec![nodo_sano("אמת"), nodo_corrupto()],
    };
    let estructura = filtro.judge(kernel.read(), &corrupto, &evidencia_verde(), true);
    assert!(estructura.blocked, "{}", estructura.reason);
    assert!(estructura.verdict.violations > 0, "{}", estructura.reason);
    assert!(
        estructura.reason.contains("inadmisible"),
        "{}",
        estructura.reason
    );

    let contradictorio = ShoreshAst {
        nodes: vec![nodo_sano("אמת"), nodo_contradictorio("דעת")],
    };
    let alucinacion = filtro.judge(kernel.read(), &contradictorio, &evidencia_verde(), true);
    assert!(alucinacion.blocked, "{}", alucinacion.reason);
    assert!(
        alucinacion.verdict.contradictions > 0,
        "{}",
        alucinacion.reason
    );
    assert!(
        alucinacion.reason.contains("alucin"),
        "{}",
        alucinacion.reason
    );

    let indeterminado = ShoreshAst {
        nodes: vec![nodo_sano("אמת"), nodo_indeterminado("דעת")],
    };
    let sin_dato = filtro.judge(kernel.read(), &indeterminado, &evidencia_verde(), true);
    assert!(sin_dato.blocked, "{}", sin_dato.reason);
    assert!(sin_dato.verdict.unknowns > 0, "{}", sin_dato.reason);
    assert!(
        sin_dato.reason.contains("indeterminado"),
        "{}",
        sin_dato.reason
    );
    assert!(
        misma_huella(&kernel.digest(), &huella),
        "el filtro tocó el núcleo"
    );

    // La rama hostil entra en una célula *sandbox*: cada operación se aplica o
    // se atrapa, y ninguna se pierde. La célula no propone nada que el filtro no
    // haya autorizado, y su purga deja el núcleo byte a byte idéntico.
    let mut mutador = AutopoieticMutator::new(SEED);
    let celda = mutador.open_cell(kernel.read());
    assert_eq!(
        mutador.cell(celda).map(|estado| estado.node_count()),
        Some(kernel.nodes().len()),
        "la célula no copió el núcleo"
    );
    let mut aplicadas = 0_usize;
    let mut atrapadas = 0_usize;
    for mutacion in &mutaciones {
        match mutador.apply(celda, mutacion) {
            Ok(forma) => {
                if forma.is_applied() {
                    aplicadas += 1;
                } else if forma.is_trapped() {
                    atrapadas += 1;
                }
            }
            Err(_) => atrapadas += 1,
        }
    }
    assert_eq!(
        aplicadas + atrapadas,
        mutaciones.len(),
        "alguna operación se perdió en la célula"
    );
    assert_eq!(
        mutador.counters().traps,
        atrapadas,
        "el censo de trampas no cuadra"
    );

    // Si algo se atrapó, la célula se aisló sola: queda en cuarentena y ya no
    // gasta cupo. El aislamiento es interno: el núcleo no lo nota.
    if atrapadas > 0 {
        assert!(
            mutador
                .cell(celda)
                .map(|estado| estado.is_poisoned())
                .unwrap_or(false),
            "la célula atrapó un fallo y siguió abierta"
        );
        let envenenada = mutador.propose(kernel.read(), celda, &evidencia_verde());
        assert!(
            matches!(
                &envenenada,
                Err(MutatorError::CellPoisoned { id }) if *id == celda
            ),
            "una célula en cuarentena propuso algo: {envenenada:?}"
        );
    }
    assert!(mutador.release(celda), "la célula no se pudo purgar");
    assert_eq!(mutador.counters().cells, 0, "quedó una célula viva");
    assert_eq!(
        mutador.counters().fusions,
        0,
        "el lenguaje fusionó sin pasar por el filtro"
    );
    assert_eq!(mutador.counters().proposals, 0, "hubo propuesta sin filtro");
    assert!(
        mutador.cell(celda).is_none(),
        "la célula purgada sigue viva"
    );
    assert!(
        misma_huella(&kernel.digest(), &huella),
        "el lenguaje tocó el núcleo"
    );
    assert_eq!(kernel.revision(), revision);
    assert!(kernel.verify());
    assert!(
        inicio.elapsed() < COTA_COGNITIVA,
        "el asedio cognitivo tardó {:?}",
        inicio.elapsed()
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Frente 1 · desbordamiento de aridad: la puerta es abierta, el juicio no
// ─────────────────────────────────────────────────────────────────────────

/// La pasarela **no** decide aridad (su contrato es no descartar nada), pero el
/// juicio tetravalente sí: un nodo con aridad fuera de cota es una violación
/// estructural y veta la fusión. El núcleo soberano queda intacto y la ronda
/// es reproducible bit a bit.
#[test]
fn la_aridad_desbordada_se_juzga_y_nunca_se_fusiona() {
    const BOMBAS: usize = 128;
    const PARAMS: usize = MAX_ARITY * 8;

    let kernel = nucleo();
    let huella = kernel.digest();
    let revision = kernel.revision();

    // Periferia estática: mitad sana, mitad con aridad fuera de cota.
    let mut rama = Vec::with_capacity(BOMBAS);
    for indice in 0..BOMBAS {
        if indice % 2 == 0 {
            rama.push(nodo_sano(&raiz(indice)));
        } else {
            rama.push(nodo_corrupto());
        }
    }
    let juicio = BelnapMatrix::evaluate(
        kernel.read(),
        &ShoreshAst { nodes: rama },
        &evidencia_verde(),
        true,
    );
    assert_eq!(juicio.violations, BOMBAS / 2, "{}", juicio.label());
    assert_eq!(juicio.periferia, BelnapValue::False, "{}", juicio.label());
    assert_eq!(juicio.nucleo, BelnapValue::True, "{}", juicio.label());
    assert_eq!(juicio.union, BelnapValue::Both, "{}", juicio.label());
    assert!(!juicio.admits_fusion(), "{}", juicio.label());

    // Saturación de la puerta: declaraciones C legibles con aridad 64.
    let params: String = (0..PARAMS)
        .map(|indice| format!("int a{indice}"))
        .collect::<Vec<String>>()
        .join(", ");
    let mut ingreso = LoopbackIngress::new("caos:aridad");
    for indice in 0..BOMBAS {
        ingreso.push_text(&format!("int f{indice}({params});"));
    }

    let mut runtime = BaraRuntime::new();
    runtime.push(QuantumState::classical(true));
    runtime.certify();
    let pila_base = runtime.stack.len();

    let mut puerta = Gateway::new();
    let informe = puerta.run(&mut ingreso, BOMBAS, &mut runtime);
    assert_eq!(informe.received, BOMBAS);
    assert_eq!(informe.dropped(), 0, "la puerta descartó bombas de aridad");
    assert!(informe.is_airtight(), "{}", informe.label());
    assert!(ingreso.is_empty(), "quedaron paquetes sin atender");
    assert!(
        runtime.stack.len() > pila_base,
        "la puerta abierta no entregó ningún axioma"
    );

    // Cada bomba trae un nodo con aridad > MAX_ARITY; el juicio las detiene.
    let mut juzgadas = 0_usize;
    for burbuja in &puerta.bubbles {
        let excedidas = burbuja
            .ast
            .nodes
            .iter()
            .filter(|nodo| nodo.arity > MAX_ARITY)
            .count();
        if excedidas == 0 {
            continue;
        }
        juzgadas += 1;
        let juicio = BelnapMatrix::evaluate(kernel.read(), &burbuja.ast, &evidencia_verde(), true);
        assert_eq!(juicio.violations, excedidas, "{}", juicio.label());
        assert!(
            !juicio.admits_fusion(),
            "una aridad desbordada pasó el juicio: {}",
            juicio.label()
        );
    }
    assert_eq!(juzgadas, BOMBAS, "la pasarela no transportó las bombas");

    // El núcleo no se movió: el asedio quedó en la periferia.
    assert!(misma_huella(&kernel.digest(), &huella), "el núcleo cambió");
    assert_eq!(kernel.revision(), revision);
    assert!(kernel.verify());

    // Reproducible: la misma andanada produce el mismo acta y el mismo holograma.
    let mut ingreso2 = LoopbackIngress::new("caos:aridad");
    for indice in 0..BOMBAS {
        ingreso2.push_text(&format!("int f{indice}({params});"));
    }
    let mut runtime2 = BaraRuntime::new();
    let mut puerta2 = Gateway::new();
    let informe2 = puerta2.run(&mut ingreso2, BOMBAS, &mut runtime2);
    assert_eq!(informe, informe2, "la ronda de aridad no fue determinista");
}
