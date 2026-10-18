//! # Frontera FFI: pruebas de integración del ABI móvil
//!
//! El estado de la frontera es global (una sesión por proceso), así que todas
//! las pruebas se serializan con un `Mutex` propio. Ninguna usa `unsafe`,
//! `unwrap` ni `expect`.

#![forbid(unsafe_code)]

use std::sync::{Mutex, MutexGuard};

use bara::ffi::{
    bara_ffi_abi_version, bara_ffi_admit, bara_ffi_black_box, bara_ffi_incident,
    bara_ffi_incident_count, bara_ffi_init, bara_ffi_kernel, bara_ffi_render_chunk, bara_ffi_reset,
    bara_ffi_set_origin, FfiPayload, FfiSeed, FfiText, ABI_VERSION, ORIGINS, PAYLOAD_MAX,
    STATUS_INVALID_LENGTH, STATUS_INVALID_TAG, STATUS_NOT_INITIALIZED, STATUS_NO_INCIDENT,
    STATUS_OK, TEXT_CHUNK, VERDICT_INNOCUOUS, VERDICT_NEUTRALIZED,
};
use bara::flight_recorder;

/// Cerrojo de la suite: la sesión FFI es única por proceso.
static LOCK: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    match LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Copia acotada de una carga al arreglo del ABI.
fn payload_of(text: &str) -> FfiPayload {
    let mut payload = FfiPayload::empty();
    for (slot, byte) in payload.bytes.iter_mut().zip(text.as_bytes().iter()) {
        *slot = *byte;
    }
    payload
}

/// Trozo como texto, sin `unwrap`.
fn text_of(chunk: &FfiText) -> String {
    let len = chunk.len.min(TEXT_CHUNK as u32) as usize;
    match chunk
        .bytes
        .get(..len)
        .and_then(|raw| std::str::from_utf8(raw).ok())
    {
        Some(text) => text.to_string(),
        None => String::new(),
    }
}

#[test]
fn la_frontera_movil_admite_y_conserva_la_soberania() {
    let _guard = serial();
    assert_eq!(bara_ffi_abi_version(), ABI_VERSION);
    assert_eq!(bara_ffi_reset(), STATUS_OK);

    // Sin sesión, todo falla con un número: nunca con un pánico.
    assert_eq!(
        bara_ffi_kernel().status,
        STATUS_NOT_INITIALIZED,
        "el núcleo no debe existir antes de init"
    );
    let cold = bara_ffi_admit(0, 4, payload_of("hola"));
    assert_eq!(cold.status, STATUS_NOT_INITIALIZED);

    assert_eq!(bara_ffi_init(FfiSeed::new([7u8; 32])), STATUS_OK);
    let kernel = bara_ffi_kernel();
    assert_eq!(kernel.status, STATUS_OK);
    assert_eq!(kernel.verified, 1, "el génesis debe verificar su ADN");
    assert_eq!(kernel.revision, 0);
    assert!(kernel.roots >= 1);
    assert!(kernel.digest.iter().any(|byte| *byte != 0));

    // Origen: sólo índices de la tabla; nunca texto del llamante.
    assert_eq!(
        bara_ffi_set_origin(ORIGINS.len() as u32),
        STATUS_INVALID_TAG
    );
    assert_eq!(bara_ffi_set_origin(3), STATUS_OK);

    // Carga inocua: atraviesa como axioma y su huella es la del digest.
    let clean = payload_of("hola mundo");
    let benign = bara_ffi_admit(0, 10, clean);
    assert_eq!(benign.status, STATUS_OK);
    assert_eq!(benign.verdict, VERDICT_INNOCUOUS);
    assert_eq!(benign.sequence, 0);
    assert_eq!(benign.danger_permille, 0);
    assert_eq!(
        benign.payload_hash,
        flight_recorder::fingerprint(b"hola mundo")
    );

    // Carga hostil: neutralizada, con huella y sin copiar el texto.
    let hostile_text = "rm -rf / && drop table usuarios";
    let hostile = payload_of(hostile_text);
    let blocked = bara_ffi_admit(1, hostile_text.len() as u32, hostile);
    assert_eq!(blocked.status, STATUS_OK);
    assert_eq!(blocked.verdict, VERDICT_NEUTRALIZED);
    assert!(blocked.danger_permille > 0);
    assert_eq!(blocked.bubble_id, benign.bubble_id + 1);
    assert_ne!(blocked.payload_hash, benign.payload_hash);

    // La caja negra registró el incidente con huella, no con carga.
    let counters = bara_ffi_black_box();
    assert_eq!(counters.status, STATUS_OK);
    assert_eq!(counters.capacity, flight_recorder::CAPACITY as u64);
    assert!(counters.reserved >= 1);
    assert_eq!(counters.reserved, counters.published);
    let count = bara_ffi_incident_count();
    assert!(count >= 1);
    let mut saw_hostile_hash = false;
    for index in 0..count {
        let incident = bara_ffi_incident(index);
        assert_eq!(incident.status, STATUS_OK);
        assert!((1..=4).contains(&incident.event));
        if incident.payload_hash == blocked.payload_hash {
            saw_hostile_hash = true;
        }
    }
    assert!(
        saw_hostile_hash,
        "el incidente hostil debe estar en el anillo"
    );
    assert_eq!(
        bara_ffi_incident(count).status,
        STATUS_NO_INCIDENT,
        "un índice fuera del anillo no inventa un incidente"
    );

    // El volcado se trocea respetando UTF-8 y reconstruye el texto exacto.
    let rendered = flight_recorder::render();
    let mut rebuilt = String::new();
    let mut offset = 0u32;
    loop {
        let chunk = bara_ffi_render_chunk(offset);
        assert_eq!(chunk.status, STATUS_OK);
        assert!(chunk.len <= TEXT_CHUNK as u32);
        assert_eq!(chunk.total as usize, rendered.len());
        if chunk.len == 0 {
            break;
        }
        rebuilt.push_str(&text_of(&chunk));
        offset = offset.saturating_add(chunk.len);
        assert!(offset as usize <= rendered.len());
    }
    assert_eq!(rebuilt, rendered);

    // Reinicio: la sesión vuelve a estar fría.
    assert_eq!(bara_ffi_reset(), STATUS_OK);
    assert_eq!(bara_ffi_kernel().status, STATUS_NOT_INITIALIZED);
}

#[test]
fn la_frontera_rechaza_longitudes_y_sesiones_imposibles() {
    let _guard = serial();
    assert_eq!(bara_ffi_reset(), STATUS_OK);
    assert_eq!(bara_ffi_init(FfiSeed::new([0u8; 32])), STATUS_OK);

    // `len` fuera del arreglo: código plano, ni lectura ni pánico.
    let oversized = bara_ffi_admit(0, PAYLOAD_MAX as u32 + 1, payload_of("x"));
    assert_eq!(oversized.status, STATUS_INVALID_LENGTH);
    assert_eq!(oversized.verdict, 0);

    // Carga vacía: ilegible, cuarentena (∅) y sin texto que interpretar.
    let empty = bara_ffi_admit(0, 0, payload_of(""));
    assert_eq!(empty.status, STATUS_OK);
    assert_eq!(empty.verdict, 3);
    assert_eq!(empty.danger_permille, 0);

    // Origen fuera de la tabla antes y después de inicializar.
    assert_eq!(bara_ffi_set_origin(u32::MAX), STATUS_INVALID_TAG);
    assert_eq!(bara_ffi_set_origin(0), STATUS_OK);

    // El desplazamiento más allá del volcado devuelve un trozo vacío, no basura.
    let tail = bara_ffi_render_chunk(u32::MAX);
    assert_eq!(tail.status, STATUS_OK);
    assert_eq!(tail.len, 0);

    assert_eq!(bara_ffi_reset(), STATUS_OK);
}
