//! # Caja negra de vuelo — pruebas de integración
//!
//! El registro de vuelo sólo sirve si anota **lo que de verdad ocurrió** en las
//! puertas del organismo. Este arnés somete a las dos puertas reales —la
//! pasarela de inmunidad (`immunity_gateway::Gateway`) y la puerta sináptica del
//! autómata (`autopoietic::SynapseGateway`)— y al juicio de Belnap a rechazos
//! declarados, y exige que cada uno deje su traza con el código correcto.
//!
//! ## Invariantes comprobadas
//! 1. **Coherencia**: todo rechazo queda con su `EventKind` y su
//!    `ViolationCode`; una carga inocua no deja rastro.
//! 2. **Sólo huellas**: el registro nunca copia la carga, sólo su resumen de
//!    64 bits (jamás la cadena original).
//! 3. **Acotación**: ni la ocupación ni la vista de inspección superan la
//!    capacidad estática; los contadores son monótonos.
//! 4. **Diagnóstico estructural**: la raíz vacía, la aridad desbordada, el
//!    riesgo sin sellar y la paradoja de Belnap llegan con su código propio.
//!
//! ## Reglas del arnés
//! * **Cero `unsafe`** (`#![forbid(unsafe_code)]`).
//! * **Cero pánicos por `unwrap`/`expect`**: todo se decide con `assert!`,
//!   `matches!` o `if let`.
//! * **Sin recuentos absolutos**: el registro es global y esta suite corre en
//!   paralelo, así que cada prueba abre su propia marca
//!   ([`flight_recorder::mark`]) y filtra por código y huella exacta.
//!
//! [`flight_recorder::mark`]: bara::flight_recorder::mark

#![forbid(unsafe_code)]
#![deny(clippy::all)]

use bara::ast_dna::golden_key;
use bara::autopoietic::{
    BelnapMatrix, Evidence, FrameKind, KernelCore, SynapseGateway, MAX_ARITY, MAX_FRAME,
};
use bara::crypto_native::sha256;
use bara::ffi_ingest::{BaraType, ShoreshAst, ShoreshNode};
use bara::flight_recorder::{self, EventKind, LogEntry, ViolationCode, CAPACITY};
use bara::immunity_gateway::Gateway;
use bara::runtime::QuantumState;

// ─────────────────────────────────────────────────────────────────────────
// Material declarado
// ─────────────────────────────────────────────────────────────────────────

/// Semilla de los núcleos de prueba (determinista).
const SEED: &[u8] = b"bara:caja:negra:v1";

/// Carga hostil declarada: agota el techo de peligro (`1000 ‰`).
const HOSTIL: &str = "../$(rm -rf / && drop table usuarios) <script>";

/// Carga **paradójica**: suma exactamente `500 ‰` con texto legible (`⊤∧⊥`).
const PARADOJA: &str = "../$( ademas un ` guion";

/// Bytes de control sin designación: ilegible (`∅`).
const ILEGIBLE: &[u8] = &[0x00, 0x01, 0x02];

/// Riesgo declarado por encima del umbral de sellado (guarda exigida).
const RIESGO_ALTO: f64 = 0.90;

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

/// Nodo con valencia contradictoria `⊤∧⊥` (estructura admisible).
fn nodo_contradictorio(root: &str) -> ShoreshNode {
    nodo(root, 2, 0.10, 1.0, 1.0)
}

/// Nodo sin información: valencia `∅` (estructura admisible).
fn nodo_indeterminado(root: &str) -> ShoreshNode {
    nodo(root, 2, 0.10, 0.0, 0.0)
}

/// Nodo estructuralmente inadmisible: raíz vacía y aridad fuera de cota.
fn nodo_corrupto() -> ShoreshNode {
    nodo("", MAX_ARITY + 4, 0.10, 0.9, 0.1)
}

/// Nodo admisible en forma pero con riesgo por encima del umbral de sellado.
fn nodo_sin_sellar(root: &str) -> ShoreshNode {
    nodo(root, 2, RIESGO_ALTO, 0.9, 0.1)
}

/// AST génesis del arnés (`אמת` y `דעת`).
fn ast_genesis() -> ShoreshAst {
    ShoreshAst {
        nodes: vec![nodo_sano("אמת"), nodo_sano("דעת")],
    }
}

/// Núcleo génesis del arnés.
fn nucleo() -> KernelCore {
    KernelCore::genesis("caja.negra.kernel", ast_genesis(), SEED)
}

/// Evidencia en verde (la periferia aporta pruebas superadas).
fn evidencia_verde() -> Evidence {
    Evidence::green("bara.caja.negra.suite", 5)
}

// ─────────────────────────────────────────────────────────────────────────
// Utilidades de consulta
// ─────────────────────────────────────────────────────────────────────────

/// Busca, dentro de la ventana abierta por `marca`, la entrada con ese código
/// y esa huella. Filtrar por huella exacta evita depender del estado global.
fn traza(marca: u64, code: ViolationCode, hash: u64) -> Option<LogEntry> {
    flight_recorder::entries_since(marca)
        .into_iter()
        .find(|entry| entry.violation == code && entry.payload_hash == hash)
}

/// Exige que un rechazo concreto quedó registrado con su evento y su huella.
fn exigir_traza(marca: u64, code: ViolationCode, hash: u64, esperado: EventKind) {
    let hallada = traza(marca, code, hash);
    assert!(hallada.is_some(), "sin traza para {code:?}");
    if let Some(entry) = hallada {
        assert_eq!(entry.event, esperado, "evento incoherente para {code:?}");
        assert_eq!(
            entry.hex().len(),
            16,
            "la huella debe ser de 64 bits en hexadecimal"
        );
    }
}

/// Huella con la que la pasarela de inmunidad identifica una carga: imita a
/// `Gateway::compose`, que resume el SHA‑256 de la carga.
fn huella_de_carga(payload: &[u8]) -> u64 {
    flight_recorder::digest_fingerprint(&sha256(payload))
}

// ─────────────────────────────────────────────────────────────────────────
// Pasarela de inmunidad
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn la_pasarela_de_inmunidad_deja_traza_de_lo_que_confina() {
    let mut puerta = Gateway::new();
    let marca = flight_recorder::mark();

    // Hostil → absorción con alerta de perímetro.
    puerta.admit("caja:borde", 0, HOSTIL.as_bytes());
    exigir_traza(
        marca,
        ViolationCode::PerimeterThreat,
        huella_de_carga(HOSTIL.as_bytes()),
        EventKind::PerimeterAlert,
    );

    // Paradójica → contradicción retenida (`⊤∧⊥`), no promediada.
    puerta.admit("caja:borde", 1, PARADOJA.as_bytes());
    exigir_traza(
        marca,
        ViolationCode::ContradictionRetained,
        huella_de_carga(PARADOJA.as_bytes()),
        EventKind::BelnapConflictBoth,
    );

    // Ilegible → cuarentena con veredicto rechazado.
    puerta.admit("caja:borde", 2, ILEGIBLE);
    exigir_traza(
        marca,
        ViolationCode::IllegiblePayload,
        huella_de_carga(ILEGIBLE),
        EventKind::VerdictRejected,
    );
}

#[test]
fn la_carga_inocua_no_ensucia_el_registro() {
    const LIMPIO: &str = r#"{"evento":"saludo","valor":1}"#;

    let mut puerta = Gateway::new();
    let marca = flight_recorder::mark();
    puerta.admit("caja:borde", 0, LIMPIO.as_bytes());

    let digest = huella_de_carga(LIMPIO.as_bytes());
    let propias = flight_recorder::entries_since(marca)
        .into_iter()
        .filter(|entry| entry.payload_hash == digest)
        .count();
    assert_eq!(propias, 0, "una carga inocua no debe dejar rastro");
}

// ─────────────────────────────────────────────────────────────────────────
// Puerta sináptica del autómata
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn la_puerta_synapse_traza_sus_cuatro_rechazos() {
    let clave = golden_key(b"bara:caja:negra:canal");
    let mut puerta = SynapseGateway::new(clave);
    let marca = flight_recorder::mark();

    // 1. Bomba de tamaño: se mide antes de interpretar.
    let bomba = vec![b'A'; MAX_FRAME + 1];
    assert!(puerta.translate(&bomba).is_err(), "la bomba pasó la puerta");
    exigir_traza(
        marca,
        ViolationCode::FrameTooLarge,
        flight_recorder::fingerprint(&bomba),
        EventKind::VerdictRejected,
    );

    // 2. Forma imposible: ni siquiera llega a verificar la firma.
    let forma = b"no-es-un-marco-de-bara";
    assert!(puerta.translate(forma).is_err(), "un marco ilegible pasó");
    exigir_traza(
        marca,
        ViolationCode::MalformedFrame,
        flight_recorder::fingerprint(forma),
        EventKind::VerdictRejected,
    );

    // 3. Firma manipulada: cambia un dígito hexadecimal del sello.
    let mut manipulada = puerta.seal(0, FrameKind::KernelQuery, b"consulta");
    if let Some(ultimo) = manipulada.last_mut() {
        *ultimo = if *ultimo == b'a' { b'b' } else { b'a' };
    }
    assert!(
        puerta.translate(&manipulada).is_err(),
        "la firma falsa pasó la puerta"
    );
    exigir_traza(
        marca,
        ViolationCode::SignatureMismatch,
        flight_recorder::fingerprint(&manipulada),
        EventKind::VerdictRejected,
    );

    // 4. Repetición: firma válida, pero la secuencia ya avanzó.
    let legitimo = puerta.seal(0, FrameKind::MutationRequest, b"alta");
    assert!(
        puerta.translate(&legitimo).is_ok(),
        "el marco legítimo cayó"
    );
    assert!(puerta.translate(&legitimo).is_err(), "la repetición pasó");
    exigir_traza(
        marca,
        ViolationCode::SequenceRegression,
        flight_recorder::fingerprint(&legitimo),
        EventKind::VerdictRejected,
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Juicio de Belnap
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn el_juicio_belnap_traza_la_paradoja_y_la_indeterminacion() {
    let nucleo = nucleo();
    let marca = flight_recorder::mark();

    // Contradicción retenida: la rama entera se resume en su raíz de Merkle.
    let paradoja = ShoreshAst {
        nodes: vec![nodo_sano("אמת"), nodo_contradictorio("דעת")],
    };
    let juicio = BelnapMatrix::evaluate(nucleo.read(), &paradoja, &evidencia_verde(), true);
    assert!(
        juicio.periferia.is_contradiction(),
        "la periferia no quedó contradictoria: {}",
        juicio.label()
    );
    let conflictos = flight_recorder::entries_since(marca)
        .into_iter()
        .filter(|entry| entry.event == EventKind::BelnapConflictBoth)
        .filter(|entry| entry.violation == ViolationCode::ContradictionRetained)
        .count();
    assert!(
        conflictos >= 1,
        "la paradoja no dejó traza en la caja negra"
    );

    // Indeterminación (`∅`): se anota con su propio evento, no como conflicto.
    let marca_duda = flight_recorder::mark();
    let vacio = ShoreshAst {
        nodes: vec![nodo_indeterminado("אמת")],
    };
    let juicio = BelnapMatrix::evaluate(nucleo.read(), &vacio, &evidencia_verde(), true);
    assert!(
        juicio.periferia.is_unknown(),
        "la periferia no quedó indeterminada: {}",
        juicio.label()
    );
    let dudas = flight_recorder::entries_since(marca_duda)
        .into_iter()
        .filter(|entry| entry.event == EventKind::BelnapConflictNeither)
        .filter(|entry| entry.violation == ViolationCode::IndeterminateVerdict)
        .count();
    assert!(dudas >= 1, "la indeterminación no dejó traza");
}

#[test]
fn el_juicio_belnap_clasifica_la_violacion_estructural() {
    let nucleo = nucleo();

    // Raíz vacía: el nodo corrupto no puede venderse como *Shoresh*.
    let marca_raiz = flight_recorder::mark();
    let rota = ShoreshAst {
        nodes: vec![nodo_corrupto()],
    };
    let juicio = BelnapMatrix::evaluate(nucleo.read(), &rota, &evidencia_verde(), true);
    assert_eq!(juicio.violations, 1, "{}", juicio.label());
    exigir_traza(
        marca_raiz,
        ViolationCode::EmptyRoot,
        flight_recorder::fingerprint(b""),
        EventKind::VerdictRejected,
    );

    // Riesgo sin sellar: la forma es admisible, la guarda no está.
    let marca_riesgo = flight_recorder::mark();
    let riesgo = ShoreshAst {
        nodes: vec![nodo_sin_sellar("חטא")],
    };
    let juicio = BelnapMatrix::evaluate(nucleo.read(), &riesgo, &evidencia_verde(), true);
    assert_eq!(juicio.violations, 1, "{}", juicio.label());
    exigir_traza(
        marca_riesgo,
        ViolationCode::HazardUnsealed,
        flight_recorder::fingerprint("חטא".as_bytes()),
        EventKind::VerdictRejected,
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Acotación y opacidad
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn la_caja_negra_es_acotada_y_no_copia_la_carga() {
    let mut puerta = Gateway::new();
    let marca = flight_recorder::mark();
    puerta.admit("caja:borde", 0, HOSTIL.as_bytes());
    assert!(
        traza(
            marca,
            ViolationCode::PerimeterThreat,
            huella_de_carga(HOSTIL.as_bytes())
        )
        .is_some(),
        "la alerta de perímetro no quedó registrada"
    );

    let contadores = flight_recorder::counters();
    assert_eq!(contadores.capacity, CAPACITY);
    assert!(
        contadores.occupied() <= CAPACITY,
        "el anillo se salió de su capacidad"
    );
    assert!(
        contadores.reserved >= contadores.published,
        "se publicó más de lo reservado"
    );
    assert!(
        contadores.published >= contadores.overwritten,
        "se pisó más de lo publicado"
    );

    let inspeccion = flight_recorder::inspect();
    assert!(inspeccion.entries.len() <= CAPACITY, "volcado desbordado");
    assert_eq!(inspeccion.counters.capacity, CAPACITY);

    // Opacidad: el volcado nunca contiene la carga, sólo su huella.
    let volcado = flight_recorder::render();
    assert!(
        !volcado.contains("rm -rf"),
        "el registro copió el comando hostil"
    );
    assert!(
        !volcado.contains("drop table"),
        "el registro copió la inyección"
    );
    assert!(
        !volcado.contains("usuarios"),
        "el registro copió la carga hostil"
    );
    assert!(
        !volcado.contains("script"),
        "el registro copió la etiqueta hostil"
    );
    assert!(
        volcado.contains("caja negra"),
        "el volcado no se identifica"
    );
}
