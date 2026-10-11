//! # Zero-Knowledge Proof Verification Pipeline — `zk_proof.rs`
//!
//! Etapa de **compilación** que certifica matemáticamente la integridad de
//! los invariantes del AST antes de la ejecución, sin revelar el *testigo*
//! (`witness`).
//!
//! ## Modelo matemático
//! * Campo primo de Mersenne `P = 2⁶¹ − 1` con aritmética en `u128`.
//! * Polinomios sobre `𝔽ₚ` ([`Poly`]).
//! * Sistema de restricciones tipo R1CS-lite: cada invariante induce la
//!   identidad `A(x)·B(x) − C(x) = H(x)·Z(x)`, donde
//!   `Z(x) = ∏(x − i)` es el polinomio de anulación de las `n` restricciones.
//! * **Prueba** — el probador publica compromisos (hash) de `A, B, C, H` y
//!   las evaluaciones en un punto `r` derivado por **Fiat–Shamir**.
//! * **Verificación** — el verificador *reconstruye* `Z` desde datos
//!   públicos, recomputa el desafío y comprueba la identidad en `r`
//!   (chequeo Schwartz–Zippel): no necesita ver `A, B, C, H`.
//!
//! ## Aviso
//! Esta es una **simulación didáctica** del pipeline ZK-SNARK. NO es
//! criptográficamente segura: usa un campo *toy*, compromisos por hash no
//! *binding* formalmente y un único punto de evaluación. Modela el *flujo*
//! de una verificación en etapa de compilación, que es el objetivo del
//! stub del AETHER-Ω.

/// Módulo primo de Mersenne: `2⁶¹ − 1`.
pub const P: u64 = 2_305_843_009_213_693_951;

// ─────────────────────────────────────────────────────────────────────────
// Campo finito
// ─────────────────────────────────────────────────────────────────────────

/// Elemento del campo finito `𝔽ₚ`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fp(pub u64);

impl Fp {
    /// Cero aditivo.
    pub const ZERO: Fp = Fp(0);
    /// Uno multiplicativo.
    pub const ONE: Fp = Fp(1);

    /// Reduce un entero al campo.
    pub fn new(value: u64) -> Self {
        Fp(value % P)
    }

    /// Suma en el campo.
    pub fn add(self, other: Fp) -> Fp {
        Fp(((self.0 as u128 + other.0 as u128) % P as u128) as u64)
    }

    /// Resta en el campo.
    pub fn sub(self, other: Fp) -> Fp {
        Fp(((self.0 as u128 + P as u128 - other.0 as u128) % P as u128) as u64)
    }

    /// Producto en el campo.
    pub fn mul(self, other: Fp) -> Fp {
        Fp(((self.0 as u128 * other.0 as u128) % P as u128) as u64)
    }

    /// Exponenciación por cuadrado-y-multiplica.
    pub fn pow(self, mut exp: u64) -> Fp {
        let mut base = self;
        let mut acc = Fp::ONE;
        while exp > 0 {
            if exp & 1 == 1 {
                acc = acc.mul(base);
            }
            base = base.mul(base);
            exp >>= 1;
        }
        acc
    }

    /// Inverso multiplicativo (pequeño teorema de Fermat).
    pub fn inv(self) -> Fp {
        self.pow(P - 2)
    }

    /// ¿Es el cero aditivo?
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Polinomios sobre 𝔽ₚ
// ─────────────────────────────────────────────────────────────────────────

/// Polinomio denso sobre `𝔽ₚ` (coeficientes de grado ascendente).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Poly(pub Vec<Fp>);

impl Poly {
    /// Polinomio cero.
    pub fn zero() -> Self {
        Poly(vec![Fp::ZERO])
    }

    /// Polinomio constante.
    pub fn constant(c: Fp) -> Self {
        Poly(vec![c])
    }

    /// ¿Es el polinomio cero?
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|c| c.is_zero())
    }

    /// Grado del polinomio (0 para el cero).
    pub fn degree(&self) -> usize {
        if self.is_zero() {
            0
        } else {
            self.0.len() - 1
        }
    }

    /// Evalúa el polinomio en `x` (esquema de Horner).
    pub fn eval(&self, x: Fp) -> Fp {
        let mut acc = Fp::ZERO;
        for coeff in self.0.iter().rev() {
            acc = acc.mul(x).add(*coeff);
        }
        acc
    }

    /// Suma de polinomios.
    pub fn add(&self, other: &Poly) -> Poly {
        let n = self.0.len().max(other.0.len());
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let a = self.0.get(i).copied().unwrap_or(Fp::ZERO);
            let b = other.0.get(i).copied().unwrap_or(Fp::ZERO);
            out.push(a.add(b));
        }
        Poly(trim(out))
    }

    /// Resta de polinomios.
    pub fn sub(&self, other: &Poly) -> Poly {
        let n = self.0.len().max(other.0.len());
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let a = self.0.get(i).copied().unwrap_or(Fp::ZERO);
            let b = other.0.get(i).copied().unwrap_or(Fp::ZERO);
            out.push(a.sub(b));
        }
        Poly(trim(out))
    }

    /// Producto de polinomios (convolución densa).
    pub fn mul(&self, other: &Poly) -> Poly {
        if self.is_zero() || other.is_zero() {
            return Poly::zero();
        }
        let mut out = vec![Fp::ZERO; self.0.len() + other.0.len() - 1];
        for (i, &ai) in self.0.iter().enumerate() {
            if ai.is_zero() {
                continue;
            }
            for (j, &bj) in other.0.iter().enumerate() {
                out[i + j] = out[i + j].add(ai.mul(bj));
            }
        }
        Poly(trim(out))
    }

    /// Polinomio de anulación `Z(x) = ∏_{i=0}^{n-1} (x − i)`.
    pub fn vanishing(n: usize) -> Poly {
        let mut z = Poly::constant(Fp::ONE);
        for i in 0..n {
            let xi = Fp::new(i as u64);
            // Factor `(x − i)`.
            let factor = Poly(vec![Fp::ZERO.sub(xi), Fp::ONE]);
            z = z.mul(&factor);
        }
        z
    }

    /// Compromiso *binding* por hash sobre los coeficientes (toy).
    pub fn commit(&self) -> u64 {
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for coeff in &self.0 {
            for byte in coeff.0.to_le_bytes() {
                h ^= byte as u64;
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        h
    }
}

/// Recorta ceros de mayor grado, garantizando longitud mínima 1.
fn trim(mut coeffs: Vec<Fp>) -> Vec<Fp> {
    while coeffs.len() > 1 && coeffs.last().map(|c| c.is_zero()).unwrap_or(false) {
        coeffs.pop();
    }
    if coeffs.is_empty() {
        coeffs.push(Fp::ZERO);
    }
    coeffs
}

/// Generador congruencial lineal determinista de coeficientes en `𝔽ₚ`.
fn deterministic_coeffs(mut state: u64, len: usize) -> Vec<Fp> {
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        out.push(Fp::new(state >> 11));
    }
    trim(out)
}

/// Hash FNV-1a de 64 bits (self-contenido, sin dependencias).
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

// ─────────────────────────────────────────────────────────────────────────
// Sistema de restricciones del AST
// ─────────────────────────────────────────────────────────────────────────

/// Enunciado **público** que el certificado compromete.
///
/// El verificador conoce `label`, `n_constraints` y `public_inputs`; nunca el
/// testigo.
#[derive(Debug, Clone)]
pub struct Statement {
    /// Etiqueta del artefacto certificado.
    pub label: String,
    /// Número de invariantes (grado del polinomio de anulación).
    pub n_constraints: usize,
    /// Entradas públicas (huellas de los invariantes).
    pub public_inputs: Vec<Fp>,
}

/// Sistema de restricciones: identidad `A·B − C = H·Z` sobre `𝔽ₚ`.
#[derive(Debug, Clone)]
pub struct ConstraintSystem {
    /// Número de restricciones.
    pub n_constraints: usize,
    /// Polinomio izquierdo `A`.
    pub a: Poly,
    /// Polinomio derecho `B`.
    pub b: Poly,
    /// Polinomio de salida `C`.
    pub c: Poly,
    /// Cociente `H` (testigo).
    pub h: Poly,
    /// Polinomio de anulación `Z`.
    pub z: Poly,
}

impl ConstraintSystem {
    /// Construye el sistema a partir de los invariantes del AST.
    ///
    /// El testigo `A, B, H` se deriva deterministamente de las huellas de los
    /// invariantes; `C` se calcula para satisfacer exactamente `A·B − H·Z`.
    pub fn from_invariants(invariants: &[String]) -> Self {
        let n_constraints = invariants.len().max(1);
        let z = Poly::vanishing(n_constraints);

        let seed = if invariants.is_empty() {
            0x9E37_79B9_7F4A_7C15
        } else {
            invariants.iter().fold(0xcbf2_9ce4_8422_2325u64, |acc, inv| {
                acc ^ fnv1a(inv.as_bytes())
            })
        };

        let len = n_constraints + 1;
        let a = Poly(deterministic_coeffs(seed ^ 0xA5A5_A5A5_A5A5_A5A5, len));
        let b = Poly(deterministic_coeffs(seed ^ 0x5A5A_5A5A_5A5A_5A5A, len));
        let h = Poly(deterministic_coeffs(seed ^ 0x1234_5678_9ABC_DEF0, len));
        let c = a.mul(&b).sub(&h.mul(&z));

        ConstraintSystem {
            n_constraints,
            a,
            b,
            c,
            h,
            z,
        }
    }

    /// Deriva el enunciado público asociado a un conjunto de invariantes.
    pub fn statement(&self, label: &str, invariants: &[String]) -> Statement {
        let mut public_inputs: Vec<Fp> = invariants.iter().map(|inv| Fp::new(fnv1a(inv.as_bytes()))).collect();
        if public_inputs.is_empty() {
            public_inputs.push(Fp::new(fnv1a(label.as_bytes())));
        }
        Statement {
            label: label.to_string(),
            n_constraints: self.n_constraints,
            public_inputs,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Prueba y verificación (Fiat–Shamir + Schwartz–Zippel)
// ─────────────────────────────────────────────────────────────────────────

/// Evaluaciones de la prueba en el punto-desafío `r`.
#[derive(Debug, Clone, Copy)]
pub struct ZkEvals {
    /// `A(r)`.
    pub a: Fp,
    /// `B(r)`.
    pub b: Fp,
    /// `C(r)`.
    pub c: Fp,
    /// `H(r)`.
    pub h: Fp,
}

/// Prueba ZK-SNARK *stub*: compromisos + evaluaciones + desafío.
#[derive(Debug, Clone)]
pub struct Proof {
    /// Compromisos `(nombre, hash)` de `A, B, C, H`.
    pub commitments: Vec<(String, u64)>,
    /// Punto-desafío derivado por Fiat–Shamir.
    pub challenge: Fp,
    /// Evaluaciones en `r`.
    pub evals: ZkEvals,
}

/// Resultado de la verificación, con el detalle de cada comprobación.
#[derive(Debug, Clone)]
pub struct VerifyResult {
    /// Veredicto global.
    pub verified: bool,
    /// Desafío recomputado por el verificador.
    pub challenge: Fp,
    /// Comprobaciones `(nombre, superada)`.
    pub checks: Vec<(String, bool)>,
}

/// Transcrito Fiat–Shamir: enlaza enunciado público y compromisos.
fn transcript_hash(statement: &Statement, commitments: &[(String, u64)]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mix = |h: &mut u64, value: u64| {
        *h ^= value;
        *h = h.wrapping_mul(0x0000_0100_0000_01b3);
    };
    for byte in statement.label.as_bytes() {
        mix(&mut h, *byte as u64);
    }
    mix(&mut h, statement.n_constraints as u64);
    for input in &statement.public_inputs {
        mix(&mut h, input.0);
    }
    for (name, commitment) in commitments {
        for byte in name.as_bytes() {
            mix(&mut h, *byte as u64);
        }
        mix(&mut h, *commitment);
    }
    h
}

/// **Probador**: construye la prueba sin revelar `A, B, C, H`.
pub fn prove(system: &ConstraintSystem, statement: &Statement) -> Proof {
    let commitments = vec![
        ("A".to_string(), system.a.commit()),
        ("B".to_string(), system.b.commit()),
        ("C".to_string(), system.c.commit()),
        ("H".to_string(), system.h.commit()),
    ];
    let challenge = Fp::new(transcript_hash(statement, &commitments));
    let evals = ZkEvals {
        a: system.a.eval(challenge),
        b: system.b.eval(challenge),
        c: system.c.eval(challenge),
        h: system.h.eval(challenge),
    };
    Proof {
        commitments,
        challenge,
        evals,
    }
}

/// **Verificador**: sólo usa el enunciado público y la prueba.
///
/// Reconstruye `Z` desde `statement.n_constraints`, recomputa el desafío por
/// Fiat–Shamir y comprueba `A·B − C = H·Z` en `r`.
pub fn verify(statement: &Statement, proof: &Proof) -> VerifyResult {
    // 1 — Fiat–Shamir: el desafío debe derivarse del transcrito público.
    let expected = Fp::new(transcript_hash(statement, &proof.commitments));
    let fiat_shamir_ok = expected == proof.challenge;

    // 2 — Identidad polinómica en el punto-desafío (Schwartz–Zippel).
    let z = Poly::vanishing(statement.n_constraints);
    let lhs = proof.evals.a.mul(proof.evals.b).sub(proof.evals.c);
    let rhs = proof.evals.h.mul(z.eval(proof.challenge));
    let identity_ok = lhs == rhs;

    // 3 — Compromisos presentes y bien formados.
    let commitments_ok = proof.commitments.len() == 4
        && proof
            .commitments
            .iter()
            .all(|(name, _)| !name.is_empty());

    let checks = vec![
        ("Fiat–Shamir: desafío reconstruido".to_string(), fiat_shamir_ok),
        ("Identidad A·B − C = H·Z en r".to_string(), identity_ok),
        ("Compromisos no degenerados".to_string(), commitments_ok),
    ];

    VerifyResult {
        verified: checks.iter().all(|(_, ok)| *ok),
        challenge: proof.challenge,
        checks,
    }
}

/// Certificado emitido por la etapa de compilación.
#[derive(Debug, Clone)]
pub struct ZkCertificate {
    /// Enunciado público certificado.
    pub statement: Statement,
    /// Prueba emitida.
    pub proof: Proof,
    /// Resultado de la verificación independiente.
    pub result: VerifyResult,
    /// Resumen textual para el log ontológico.
    pub summary: String,
}

impl ZkCertificate {
    /// Prueba y verifica el sistema, devolviendo el certificado completo.
    pub fn certify(system: &ConstraintSystem, statement: Statement) -> Self {
        let proof = prove(system, &statement);
        let result = verify(&statement, &proof);
        let summary = format!(
            "AST «{}» · {} invariantes · desafío=0x{:016X} · verificado={}",
            statement.label, statement.n_constraints, result.challenge.0, result.verified
        );
        ZkCertificate {
            statement,
            proof,
            result,
            summary,
        }
    }
}
