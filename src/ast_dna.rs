//! # ADN sintáctico firmado — `ast_dna.rs`
//!
//! Da a cada nodo del AST *Shoresh* una **identidad matemática** y a cada
//! módulo una **firma criptográfica intrínseca**: la estructura nace ya
//! firmada, sin que nadie tenga que acordarse de firmarla después.
//!
//! ## Cómo se construye la identidad
//! 1. **Serialización canónica** ([`canonical_node_bytes`]) — los campos del
//!    nodo se escriben con longitud prefijada y en *little‑endian*; los dos
//!    `f64` (riesgo y masas de Belnap) entran por sus bits (`f64::to_bits`),
//!    de modo que la huella es **estable** bit a bit y no depende de la
//!    plataforma. No hay relojes ni campos no deterministas en el nodo.
//! 2. **Polinomio del nodo** ([`node_identity`]) — los campos se tratan como
//!    coeficientes de un polinomio sobre el mismo cuerpo `𝔽ₚ` (`p = 2⁶¹ − 1`)
//!    que usa el pipeline ZK del núcleo, evaluado en el punto `φ^(1+aridad)`
//!    (una potencia de la razón áurea): el nodo pasa a ser un valor del campo,
//!    no un texto. Es el equivalente a comprometer el nodo con una evaluación
//!    tipo Reed‑Solomon.
//! 3. **Merkle del módulo** ([`merkle_root`]) — los digests de los nodos se
//!    combinan por pares con SHA‑256 hasta una raíz única; cambiar *cualquier*
//!    nodo cambia la raíz, y el orden importa (no hay conmutatividad fingida).
//! 4. **Firma** ([`ast_dna`]) — la raíz se autentica con `HMAC-SHA-256` bajo la
//!    clave soberana derivada de la geometría áurea ([`golden_key`]).
//!
//! ## Qué garantiza, y qué no
//! * **Sí** garantiza **integridad**: [`verify`] falla si se toca un solo bit
//!   del AST, si se reordena, si se añade o se quita un nodo.
//! * **Sí** garantiza **autenticidad bajo clave compartida**: sólo quien tenga
//!   la clave soberana puede producir una firma que verifique.
//! * **No** es una firma de clave pública (no hay par público/privado): es un
//!   MAC. Firmar hacia terceros que no compartan clave exigiría un esquema
//!   asimétrico, que este núcleo no implementa (y que se declara aquí para no
//!   prometer de más).
//! * **No** hay entropía externa: dos ejecuciones con el mismo AST producen el
//!   mismo ADN. Eso es intencionado (reproducibilidad), y significa que el
//!   secreto es la **clave**, no el ruido.

use crate::crypto_native::{digest_eq, hkdf_32, hmac_sha256, sha256};
use crate::ffi_ingest::{BaraType, ShoreshAst, ShoreshNode};
use crate::fractal_geometry::golden_angle;
use crate::runtime::Observation;
use crate::zk_proof::Fp;

/// Fracción áurea en punto fijo de 64 bits: `⌊2⁶⁴/φ⌋ = 0x9E3779B97F4A7C15`.
///
/// Se usa como semilla armónica del ADN: es el mismo `φ` que reparte la memoria
/// holográfica, aquí convertido en sal criptográfica.
pub const GOLDEN_FRACTION: u64 = 0x9E37_79B9_7F4A_7C15;

/// Etiqueta de dominio de la derivación de claves (evita reutilizar claves
/// entre usos distintos).
pub const DNA_KEY_INFO: &[u8] = b"bara:aether-omega:adn:v1";

/// Código estable de un tipo del sistema Bara (para serializar sin ambigüedad).
pub fn type_code(kind: BaraType) -> u8 {
    match kind {
        BaraType::Number => 1,
        BaraType::Text => 2,
        BaraType::Void => 3,
        BaraType::Truth => 4,
        BaraType::List => 5,
        BaraType::Record => 6,
        BaraType::Unknown => 7,
    }
}

/// Pliegue armónico de una raíz: huella de 64 bits mezclada con `φ`.
///
/// Es determinista y total: cualquier texto (incluido el vacío) produce un
/// valor, sin depender de ninguna tabla externa.
pub fn root_fold(root: &str) -> u64 {
    let mut acc = GOLDEN_FRACTION;
    for byte in root.as_bytes() {
        acc = acc.rotate_left(7) ^ u64::from(*byte).wrapping_mul(GOLDEN_FRACTION);
    }
    acc
}

/// Serializa un nodo de forma **canónica** (misma entrada ⇒ mismos bytes).
pub fn canonical_node_bytes(node: &ShoreshNode) -> Vec<u8> {
    let root = node.root.as_bytes();
    let original = node.original.as_bytes();
    let (truth, falsity) = node.valence.belnap();

    let mut out = Vec::with_capacity(64 + root.len() + original.len());
    out.extend_from_slice(&(root.len() as u32).to_le_bytes());
    out.extend_from_slice(root);
    out.extend_from_slice(&(original.len() as u32).to_le_bytes());
    out.extend_from_slice(original);
    out.extend_from_slice(&(node.arity as u32).to_le_bytes());
    out.push(type_code(node.ret));
    out.push(u8::from(node.sanitized));
    out.extend_from_slice(&node.hazard.to_bits().to_le_bytes());
    out.extend_from_slice(&truth.to_bits().to_le_bytes());
    out.extend_from_slice(&falsity.to_bits().to_le_bytes());
    out
}

/// Identidad matemática del nodo: un valor de `𝔽ₚ` (evaluación polinómica).
///
/// Los campos del nodo son los coeficientes y el punto de evaluación es
/// `φ^(1+aridad)` sobre el cuerpo del pipeline ZK: dos nodos con la misma
/// estructura colisionan en la identidad sólo por azar de campo.
pub fn node_identity(node: &ShoreshNode) -> Fp {
    let (truth, falsity) = node.valence.belnap();
    let coefficients = [
        node.arity as u64,
        u64::from(type_code(node.ret)),
        node.hazard.to_bits(),
        truth.to_bits(),
        falsity.to_bits(),
        u64::from(node.sanitized),
    ];
    let fold = root_fold(&node.root);
    let point = Fp::new(GOLDEN_FRACTION ^ fold).pow(1 + node.arity as u64);

    let mut acc = Fp::ZERO;
    for coefficient in coefficients.iter().rev() {
        acc = acc * point + Fp::new(*coefficient);
    }
    acc + Fp::new(fold)
}

/// Clave soberana derivada de la geometría áurea (sin entropía del sistema).
///
/// La sal es el ángulo áureo del núcleo en bits y la información de contexto es
/// [`DNA_KEY_INFO`]: cambiar cualquiera de las dos cambia la clave por completo.
pub fn golden_key(seed: &[u8]) -> [u8; 32] {
    let salt = golden_angle().to_bits().to_le_bytes();
    hkdf_32(&salt, seed, DNA_KEY_INFO)
}

/// ADN de un nodo: digest canónico, identidad polinómica y valencia.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeDna {
    /// Raíz triconsonántica del nodo.
    pub root: String,
    /// Digest SHA‑256 de la serialización canónica.
    pub digest: [u8; 32],
    /// Identidad en `𝔽ₚ` (evaluación polinómica de los campos).
    pub identity: Fp,
    /// Proyección discreta de Belnap (`⊤`, `⊥`, `⊤∧⊥`, `∅`).
    pub observation: Observation,
    /// `true` si el nodo quedó sellado bajo guarda (`שמר`).
    pub sealed: bool,
}

/// Digest del nodo: SHA‑256 de su forma canónica.
pub fn node_dna(node: &ShoreshNode) -> NodeDna {
    NodeDna {
        root: node.root.clone(),
        digest: sha256(&canonical_node_bytes(node)),
        identity: node_identity(node),
        observation: node.valence.observe(),
        sealed: node.sanitized,
    }
}

/// Raíz de Merkle de una lista de digests.
///
/// Los pares se combinan con SHA‑256 y, si un nivel tiene un número impar de
/// nodos, el último se empareja consigo mismo (repetición explícita, nunca
/// ambigua). Un árbol vacío tiene raíz propia: el digest de una constante de
/// dominio, no el de la cadena vacía.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return sha256(b"bara:aether-omega:merkle:vacio");
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let mut buffer = Vec::with_capacity(64);
            buffer.extend_from_slice(&pair[0]);
            buffer.extend_from_slice(pair.get(1).unwrap_or(&pair[0]));
            next.push(sha256(&buffer));
        }
        level = next;
    }
    level.first().copied().unwrap_or_else(|| sha256(b""))
}

/// Identificador público de una clave soberana (primeros 8 bytes del digest).
pub fn key_id(key: &[u8; 32]) -> u64 {
    let digest = sha256(key);
    let mut out = [0u8; 8];
    for (slot, value) in out.iter_mut().zip(digest.iter()) {
        *slot = *value;
    }
    u64::from_le_bytes(out)
}

/// ADN completo de un módulo del AST.
#[derive(Debug, Clone)]
pub struct AstDna {
    /// Etiqueta del módulo (nombre del artefacto o del programa).
    pub label: String,
    /// ADN de cada nodo, en el orden del AST.
    pub nodes: Vec<NodeDna>,
    /// Raíz de Merkle de los nodos.
    pub root: [u8; 32],
    /// Firma `HMAC-SHA-256` de `(etiqueta ‖ raíz)`.
    pub signature: [u8; 32],
    /// Identificador público de la clave que firmó.
    pub key_id: u64,
    /// Suma en `𝔽ₚ` de las identidades de los nodos (identidad del módulo).
    pub identity: Fp,
}

/// Enunciado firmado: la etiqueta del módulo y la raíz de Merkle.
fn signed_statement(label: &str, root: &[u8; 32]) -> Vec<u8> {
    let mut statement = Vec::with_capacity(4 + label.len() + 32);
    statement.extend_from_slice(&(label.len() as u32).to_le_bytes());
    statement.extend_from_slice(label.as_bytes());
    statement.extend_from_slice(root);
    statement
}

/// Construye el ADN firmado de un AST: **nace firmado, no se firma después**.
pub fn ast_dna(label: &str, ast: &ShoreshAst, key: &[u8; 32]) -> AstDna {
    let nodes: Vec<NodeDna> = ast.nodes.iter().map(node_dna).collect();
    let digests: Vec<[u8; 32]> = nodes.iter().map(|dna| dna.digest).collect();
    let root = merkle_root(&digests);
    let signature = hmac_sha256(key, &signed_statement(label, &root));
    let identity = nodes.iter().fold(Fp::ZERO, |acc, dna| acc + dna.identity);

    AstDna {
        label: label.to_string(),
        nodes,
        root,
        signature,
        key_id: key_id(key),
        identity,
    }
}

/// ¿La firma del ADN es válida bajo esta clave?
///
/// Recompone el enunciado desde el propio ADN (etiqueta + raíz) y lo contrasta
/// con `HMAC-SHA-256`: no confía en nada más que en el par (clave, firma).
pub fn signature_is_valid(dna: &AstDna, key: &[u8; 32]) -> bool {
    let expected = hmac_sha256(key, &signed_statement(&dna.label, &dna.root));
    digest_eq(&expected, &dna.signature) && dna.key_id == key_id(key)
}

/// Comprueba el AST **entero** contra su ADN: raíz, firma e identidad.
///
/// Devuelve `false` (nunca un pánico) si se ha tocado un bit, si se ha
/// reordenado, si se ha añadido o quitado un nodo, o si la clave no es la misma
/// que firmó.
pub fn verify(label: &str, ast: &ShoreshAst, dna: &AstDna, key: &[u8; 32]) -> bool {
    let fresh = ast_dna(label, ast, key);
    digest_eq(&fresh.root, &dna.root)
        && digest_eq(&fresh.signature, &dna.signature)
        && fresh.identity == dna.identity
        && fresh.nodes.len() == dna.nodes.len()
        && signature_is_valid(dna, key)
}

/// Representación hexadecimal de una huella (informes, sellos y log).
pub fn short_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

impl AstDna {
    /// Resumen textual del ADN, listo para el log ontológico.
    pub fn summary(&self) -> String {
        format!(
            "ADN «{}» · nodos={} · raíz={} · firma={} · clave=0x{:016X} · identidad=0x{:016X}",
            self.label,
            self.nodes.len(),
            short_hex(&self.root[..8]),
            short_hex(&self.signature[..8]),
            self.key_id,
            self.identity.0
        )
    }

    /// ¿Cuántos nodos quedaron sellados bajo guarda?
    pub fn sealed_nodes(&self) -> usize {
        self.nodes.iter().filter(|dna| dna.sealed).count()
    }

    /// Distribución de las cuatro valencias de Belnap en el módulo.
    pub fn valence_census(&self) -> (usize, usize, usize, usize) {
        let mut truth = 0;
        let mut falsehood = 0;
        let mut both = 0;
        let mut neither = 0;
        for dna in &self.nodes {
            match dna.observation {
                Observation::True => truth += 1,
                Observation::False => falsehood += 1,
                Observation::Both => both += 1,
                Observation::Neither => neither += 1,
            }
        }
        (truth, falsehood, both, neither)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::QuantumState;
    use crate::zk_proof::{Fp, P};

    /// Nodo sintético: los campos del AST son públicos, así que la prueba no
    /// depende de la detección de dialectos de la ingesta.
    #[allow(clippy::too_many_arguments)]
    fn node(
        root: &str,
        original: &str,
        arity: usize,
        ret: BaraType,
        hazard: f64,
        truth: f64,
        falsity: f64,
        sealed: bool,
    ) -> ShoreshNode {
        ShoreshNode {
            root: root.to_string(),
            original: original.to_string(),
            arity,
            ret,
            hazard,
            valence: QuantumState::paraconsistent(truth, falsity),
            sanitized: sealed,
        }
    }

    /// AST de trabajo con las cuatro valencias representadas.
    fn fixture() -> ShoreshAst {
        ShoreshAst {
            nodes: vec![
                node("ברא", "create", 2, BaraType::Number, 0.05, 1.0, 0.0, false),
                node("אמר", "emit", 0, BaraType::Text, 0.35, 0.5, 0.5, true),
                node("נצח", "loop", 1, BaraType::Void, 0.90, 0.0, 1.0, true),
            ],
        }
    }

    /// Clave soberana del enjambre de pruebas.
    fn swarm() -> [u8; 32] {
        golden_key(b"nucleo-soberano")
    }

    #[test]
    fn el_adn_es_determinista_y_la_firma_depende_de_clave_y_etiqueta() {
        let ast = fixture();
        let key = swarm();
        let first = ast_dna("modulo-genesis", &ast, &key);
        let second = ast_dna("modulo-genesis", &ast, &key);
        assert_eq!(first.root, second.root);
        assert_eq!(first.signature, second.signature);
        assert!(verify("modulo-genesis", &ast, &first, &key));
        assert!(signature_is_valid(&first, &key));
        assert_eq!(first.nodes.len(), 3);

        // Otra etiqueta u otra clave producen firmas distintas y no verifican.
        assert_ne!(
            ast_dna("otro-modulo", &ast, &key).signature,
            first.signature
        );
        let neighbour = golden_key(b"clave-vecina");
        assert_ne!(
            ast_dna("modulo-genesis", &ast, &neighbour).signature,
            first.signature
        );
        assert!(!verify("modulo-genesis", &ast, &first, &neighbour));
        assert!(!signature_is_valid(&first, &neighbour));
        assert!(first.summary().contains("ADN"));
    }

    #[test]
    fn tocar_reordenar_o_vaciar_el_ast_invalida_el_adn() {
        let ast = fixture();
        let key = swarm();
        let dna = ast_dna("modulo-genesis", &ast, &key);

        // (a) Un pelo de riesgo distinto en el primer nodo.
        let mut tampered = ast.clone();
        if let Some(first) = tampered.nodes.first_mut() {
            first.hazard += 0.001;
        }
        assert!(!verify("modulo-genesis", &tampered, &dna, &key));

        // (b) Reordenar: la raíz de Merkle no es conmutativa.
        let mut reordered = ast.clone();
        reordered.nodes.reverse();
        assert!(!verify("modulo-genesis", &reordered, &dna, &key));
        assert_ne!(ast_dna("modulo-genesis", &reordered, &key).root, dna.root);

        // (c) Quitar y añadir nodos.
        let mut shrunk = ast.clone();
        shrunk.nodes.pop();
        assert!(!verify("modulo-genesis", &shrunk, &dna, &key));
        let mut grown = ast.clone();
        grown.nodes.push(node(
            "חכם",
            "synth",
            1,
            BaraType::List,
            0.2,
            1.0,
            0.0,
            false,
        ));
        assert!(!verify("modulo-genesis", &grown, &dna, &key));

        // (d) Levantar el sello de un nodo.
        let mut unsealed = ast.clone();
        if let Some(second) = unsealed.nodes.get_mut(1) {
            second.sanitized = false;
        }
        assert!(!verify("modulo-genesis", &unsealed, &dna, &key));
    }

    #[test]
    fn la_raiz_de_merkle_cubre_contenido_y_orden() {
        let a = sha256(b"a");
        let b = sha256(b"b");
        let c = sha256(b"c");
        let root = merkle_root(&[a, b, c]);

        assert_eq!(root, merkle_root(&[a, b, c]));
        assert_ne!(root, merkle_root(&[b, a, c]));
        assert_ne!(root, merkle_root(&[a, b]));
        assert_ne!(root, merkle_root(&[c]));
        // Un solo nodo: la raíz es el propio nodo (no se vuelve a hashear).
        assert_eq!(merkle_root(&[a]), a);
        assert_eq!(merkle_root(&[]), sha256(b"bara:aether-omega:merkle:vacio"));
    }

    #[test]
    fn la_identidad_del_nodo_vive_en_el_cuerpo_primo() {
        let ast = fixture();
        let dna = ast_dna("modulo-genesis", &ast, &swarm());

        assert!(dna.identity.0 < P);
        assert!(dna.nodes.iter().all(|item| item.identity.0 < P));
        assert_ne!(dna.nodes[0].identity, dna.nodes[1].identity);

        let sum = dna
            .nodes
            .iter()
            .fold(Fp::ZERO, |acc, item| acc + item.identity);
        assert_eq!(sum, dna.identity);

        // La forma canónica es estable y sensible al contenido.
        let bytes = canonical_node_bytes(&ast.nodes[0]);
        assert_eq!(bytes, canonical_node_bytes(&ast.nodes[0]));
        assert_ne!(bytes, canonical_node_bytes(&ast.nodes[1]));
        assert_eq!(dna.nodes[0].digest, sha256(&bytes));

        assert_eq!(GOLDEN_FRACTION, 0x9E37_79B9_7F4A_7C15);
        assert_ne!(root_fold("ברא"), root_fold("אמר"));
        assert_eq!(root_fold(""), GOLDEN_FRACTION);
    }

    #[test]
    fn la_clave_aurea_es_estable_y_el_adn_describe_el_modulo() {
        let key = golden_key(b"semilla");
        assert_eq!(key, golden_key(b"semilla"));
        assert_ne!(key, golden_key(b"semilla2"));
        assert_ne!(key, sha256(b"semilla"));
        assert_ne!(key, [0u8; 32]);
        assert_ne!(key_id(&key), key_id(&golden_key(b"otra")));

        let dna = ast_dna("modulo-genesis", &fixture(), &key);
        assert_eq!(dna.sealed_nodes(), 2);
        let (truth, falsehood, both, neither) = dna.valence_census();
        assert_eq!(truth, 1);
        assert_eq!(falsehood, 1);
        assert_eq!(both, 1);
        assert_eq!(neither, 0);
        assert_eq!(short_hex(&dna.root[..2]).len(), 4);
    }
}
