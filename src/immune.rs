//! # Sistema inmunitario adaptativo — Bara / AETHER‑Ω (FASE 2)
//!
//! La [`crate::immunity_gateway`] decide **paquete a paquete**: abre una burbuja
//! holográfica, juzga la carga y libera o inactiva. Ese juicio es completo pero
//! **amnésico**: dos ataques idénticos reciben exactamente la misma respuesta y
//! ninguno deja rastro. Este módulo añade la capa que faltaba — la **memoria**:
//! el organismo reconoce lo que ya vio, madura su respuesta y olvida lo que no
//! vuelve.
//!
//! Nada de aquí toca al núcleo: el sistema inmunitario **lee** paquetes
//! ([`Packet`]), burbujas ya compuestas ([`Bubble`]) y sus modelos de amenaza
//! ([`Threat`]), y devuelve actas. No existe ninguna ruta que reciba un
//! `&mut KernelCore` ni un `&mut BaraRuntime`.
//!
//! ## FASE 2.1 — Antígeno
//! * [`Antigen`] es la lectura inmune de una carga: digest, tamaño, veredicto de
//!   burbuja ([`BubbleVerdict`]), valencia paraconsistente y sus **epítopos**
//!   ([`Epitope`]), extraídos del modelo de amenaza del organismo
//!   ([`crate::immunity_gateway::threat_of`]) y ordenados por peso — el mismo
//!   orden siempre, sin depender de la iteración de una tabla.
//! * [`Antigen::from_payload`] reproduce **la misma regla** que la pasarela
//!   (verdad = lectura, falsedad = amenaza, colapso `observe()`), de modo que un
//!   antígeno derivado de bytes y otro derivado de la burbuja de esos bytes
//!   coinciden. [`Antigen::from_bubble`] toma el veredicto **autoritativo** de la
//!   pasarela cuando ya existe una burbuja.
//!
//! ## FASE 2.2 — Anticuerpos y maduración clonal
//! * [`Antibody`] se une a un epítopo por su **huella** (`sha256` del nombre de
//!   la marca), no por comparación textual: dos marcas distintas nunca se
//!   confunden y la misma marca es siempre la misma diana.
//! * [`AntibodyClass`] distingue la respuesta innata (`IgM`), mucosa (`IgA`), de
//!   memoria (`IgG`) y reguladora (`Treg`). La exposición repetida **madura** la
//!   estirpe: sube la afinidad ([`MATURATION_STEP`]) y, al alcanzar el umbral de
//!   designación ([`AFFINITY_THRESHOLD`]), la clase innata se promueve a memoria.
//!
//! ## FASE 2.3 — Repertorio acotado y olvido
//! * El repertorio ([`Repertoire`]) está acotado por [`MAX_ANTIBODIES`]: cuando
//!   se llena **no crece ni degrada nada**, rechaza con
//!   [`ImmuneError::RepertoireFull`]. La válvula es [`Repertoire::decay`], que
//!   rebaja la afinidad de lo que no se repite y retira lo que cae por debajo del
//!   suelo ([`AFFINITY_FLOOR`]).
//! * La huella del repertorio es **contenido-adictiva**: depende de los
//!   anticuerpos y de su orden de creación, nunca del reloj.
//!
//! ## FASE 2.4 — Respuesta determinista
//! * [`ImmuneSystem::screen`] devuelve siempre un [`ImmuneResponse`]: tolerar,
//!   absorber, cuarentenar, neutralizar o **inmunizar** (neutralizar y recordar).
//!   La disposición nunca se inventa: sale del veredicto de Belnap del antígeno
//!   unido al reconocimiento del repertorio.
//! * [`ImmuneSystem::neutralize`] reutiliza
//!   [`crate::immunity_gateway::neutralized`] con la **firma del anticuerpo**
//!   como semilla: el mismo patógeno produce siempre el mismo ruido inerte, y
//!   ningún byte ASCII reconocible sobrevive.
//!
//! ## Invariantes del módulo
//! 1. **Cero `unsafe`** (`#![forbid(unsafe_code)]`).
//! 2. **Totalidad (axioma A1)** — sin `unwrap`, sin `expect`, sin `panic`: toda
//!    entrada hostil (vacía, enorme, binaria, con `NaN`) produce un acta, no un
//!    aborto.
//! 3. **Determinismo** — el repertorio, sus huellas y sus respuestas derivan sólo
//!    de `sha256` y de aritmética de punto fijo; el reloj no decide nada.
//! 4. **Sin escritura al núcleo** — la inmunidad lee; jamás muta la soberanía.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

use std::fmt;

use crate::ast_dna::short_hex;
use crate::autopoietic::BelnapValue;
use crate::crypto_native::sha256;
use crate::immunity_gateway::{
    is_legible, neutralized, threat_of, Bubble, BubbleVerdict, Packet, Threat, ATTACK_NEEDLES,
    DANGER_CEILING, MARK_CONTROL_PADDING, MARK_DEEP_NESTING, MARK_NUL, MARK_SIZE_BOMB,
    MARK_UNREADABLE,
};
use crate::runtime::{Observation, QuantumState};

// ─────────────────────────────────────────────────────────────────────────
// Límites del sistema inmunitario
// ─────────────────────────────────────────────────────────────────────────

/// Dominio de hash del sistema inmunitario.
pub const IMMUNE_DOMAIN: &[u8] = b"bara:aether-omega:inmune:v1";

/// Anticuerpos simultáneos del repertorio (memoria acotada).
pub const MAX_ANTIBODIES: usize = 64;

/// Epítopos que se conservan de un antígeno (los de mayor peso).
pub const MAX_EPITOPES: usize = 8;

/// Umbral de designación de Belnap: separa lo innato de lo adaptativo.
pub const AFFINITY_THRESHOLD: f64 = 0.5;

/// Generación máxima de una estirpe clonal (maduración acotada).
pub const MAX_GENERATION: u32 = 8;

/// Paso de maduración por exposición reconocida.
pub const MATURATION_STEP: f64 = 0.125;

/// Paso de decaimiento por ronda de olvido.
pub const DECAY_STEP: f64 = 0.25;

/// Suelo de afinidad: por debajo, el anticuerpo se retira del repertorio.
pub const AFFINITY_FLOOR: f64 = 0.0625;

// ─────────────────────────────────────────────────────────────────────────
// Errores tipados del sistema inmunitario
// ─────────────────────────────────────────────────────────────────────────

/// Error tipado de la inmunidad adaptativa.
///
/// Todo rechazo es explícito y mostrable: el IDE recibe un motivo, nunca un
/// repertorio a medias ni una respuesta inventada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImmuneError {
    /// El anticuerpo no declara origen (no se sabe a quién pertenece).
    EmptyOrigin,
    /// El epítopo no tiene nombre: una diana sin nombre no es una diana.
    EmptyEpitope,
    /// El repertorio está lleno: hay que olvidar antes de aprender.
    RepertoireFull {
        /// Techo de anticuerpos.
        limit: usize,
    },
    /// Se pidió un anticuerpo que no existe en el repertorio.
    UnknownAntibody {
        /// Identificador solicitado.
        id: u64,
    },
    /// Una magnitud no finita (`NaN` o infinito) entró en la inmunidad.
    NotFinite {
        /// Campo afectado.
        field: &'static str,
    },
}

impl fmt::Display for ImmuneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImmuneError::EmptyOrigin => write!(f, "el anticuerpo no declara origen"),
            ImmuneError::EmptyEpitope => write!(f, "el epítopo no tiene nombre"),
            ImmuneError::RepertoireFull { limit } => {
                write!(f, "repertorio lleno ({limit} anticuerpos)")
            }
            ImmuneError::UnknownAntibody { id } => {
                write!(f, "anticuerpo {id} desconocido en el repertorio")
            }
            ImmuneError::NotFinite { field } => write!(f, "magnitud «{field}» no finita"),
        }
    }
}

impl std::error::Error for ImmuneError {}

// ─────────────────────────────────────────────────────────────────────────
// FASE 2.1 — Epítopos
// ─────────────────────────────────────────────────────────────────────────

/// Determinante antigénico: una marca del modelo de amenaza, con su peso.
///
/// El epítopo guarda el **nombre** de la marca (una constante `&'static str` del
/// organismo, nunca un `String` arbitrario) y su peso en milésimas. Su identidad
/// inmune es la huella `sha256` del nombre: el repertorio no compara cadenas, une
/// huellas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Epitope {
    /// Nombre canónico de la marca (tabla del organismo).
    pub label: &'static str,
    /// Peso en milésimas, recortado a [`DANGER_CEILING`].
    pub weight: u32,
}

impl Epitope {
    /// Construye un epítopo con el peso recortado al techo de peligro.
    pub fn new(label: &'static str, weight: u32) -> Self {
        Epitope {
            label,
            weight: weight.min(DANGER_CEILING),
        }
    }

    /// Masa normalizada del epítopo en `[0,1]`.
    pub fn mass(&self) -> f64 {
        f64::from(self.weight.min(DANGER_CEILING)) / f64::from(DANGER_CEILING)
    }

    /// Huella determinista del nombre de la marca.
    pub fn digest(&self) -> [u8; 32] {
        let mut statement = Vec::with_capacity(IMMUNE_DOMAIN.len() + 16 + self.label.len());
        statement.extend_from_slice(IMMUNE_DOMAIN);
        statement.extend_from_slice(b":epitopo:");
        statement.extend_from_slice(self.label.as_bytes());
        sha256(&statement)
    }

    /// ¿El epítopo carece de nombre?
    pub fn is_empty(&self) -> bool {
        self.label.trim().is_empty()
    }

    /// Hex corto de su huella (informes y log).
    pub fn short(&self) -> String {
        let digest = self.digest();
        short_hex(digest.get(..4).unwrap_or(&[]))
    }

    /// Acta legible del epítopo.
    pub fn label_text(&self) -> String {
        format!("{} ({} ‰ · {})", self.label, self.weight, self.short())
    }

    /// Serialización JSON mínima.
    pub fn json(&self) -> String {
        let mut out = String::with_capacity(96);
        out.push_str("{\"label\":\"");
        out.push_str(&json_escape(self.label));
        out.push_str("\",\"weight\":");
        out.push_str(&self.weight.to_string());
        out.push_str(",\"digest\":\"");
        out.push_str(&short_hex(&self.digest()));
        out.push_str("\"}");
        out
    }
}

/// Clase de anticuerpo: quién responde y con qué fuerza innata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntibodyClass {
    /// Respuesta innata (`IgM`): primera línea, sin memoria.
    Innate,
    /// Respuesta mucosa (`IgA`): contención perimetral de lo ilegible.
    Mucosal,
    /// Respuesta de memoria (`IgG`): reconocimiento madurado.
    Memory,
    /// Respuesta reguladora (`Treg`): tolerancia activa de lo propio dudoso.
    Regulatory,
}

impl AntibodyClass {
    /// Todas las clases, en orden canónico de censo.
    pub const ALL: [AntibodyClass; 4] = [
        AntibodyClass::Innate,
        AntibodyClass::Mucosal,
        AntibodyClass::Memory,
        AntibodyClass::Regulatory,
    ];

    /// Nombre canónico (minúsculas, sin acentos en claves).
    pub const fn name(self) -> &'static str {
        match self {
            AntibodyClass::Innate => "innata",
            AntibodyClass::Mucosal => "mucosa",
            AntibodyClass::Memory => "memoria",
            AntibodyClass::Regulatory => "reguladora",
        }
    }

    /// Glifo de inmunoglobulina asociado.
    pub const fn glyph(self) -> &'static str {
        match self {
            AntibodyClass::Innate => "IgM",
            AntibodyClass::Mucosal => "IgA",
            AntibodyClass::Memory => "IgG",
            AntibodyClass::Regulatory => "Treg",
        }
    }

    /// ¿La clase pertenece a la inmunidad adaptativa (con memoria)?
    pub const fn is_adaptive(self) -> bool {
        matches!(self, AntibodyClass::Memory | AntibodyClass::Regulatory)
    }

    /// Afinidad innata de la clase (`[0,1]`), determinista.
    pub const fn innate_affinity(self) -> f64 {
        match self {
            AntibodyClass::Innate => 0.5,
            AntibodyClass::Mucosal => 0.625,
            AntibodyClass::Memory => 0.75,
            AntibodyClass::Regulatory => 0.875,
        }
    }

    /// Clave JSON.
    pub const fn json(self) -> &'static str {
        match self {
            AntibodyClass::Innate => "\"innata\"",
            AntibodyClass::Mucosal => "\"mucosa\"",
            AntibodyClass::Memory => "\"memoria\"",
            AntibodyClass::Regulatory => "\"reguladora\"",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// FASE 2.2 — Anticuerpos
// ─────────────────────────────────────────────────────────────────────────

/// Anticuerpo: una estirpe clonal unida a un epítopo concreto.
///
/// Es un **valor** (no una referencia): su firma [`Antibody::signature`] cambia
/// sólo cuando el anticuerpo madura, nunca por el paso del tiempo.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Antibody {
    /// Identificador secuencial dentro del repertorio.
    pub id: u64,
    /// Clase (innata, mucosa, memoria, reguladora).
    pub class: AntibodyClass,
    /// Diana: el epítopo al que se une.
    pub epitope: Epitope,
    /// Generación de la estirpe (`0` = fundador).
    pub generation: u32,
    /// Afinidad en `[0,1]`.
    pub affinity: f64,
    /// Exposiciones reconocidas (veces que ha visto su diana).
    pub exposures: u64,
    /// Neutralizaciones efectivas ejecutadas.
    pub neutralizations: u64,
    /// Antígeno (`sequence`) que lo fundó.
    pub born_at: u64,
    /// Último antígeno (`sequence`) que lo despertó.
    pub last_seen: u64,
}

impl Antibody {
    /// Funda una estirpe innata para un epítopo.
    fn founder(id: u64, epitope: Epitope, born_at: u64) -> Self {
        Antibody::seeded(
            id,
            epitope,
            born_at,
            AntibodyClass::Innate.innate_affinity(),
        )
    }

    /// Funda una estirpe con afinidad sembrada (vacunación dirigida).
    fn seeded(id: u64, epitope: Epitope, born_at: u64, affinity: f64) -> Self {
        let affinity = clamp01(affinity);
        Antibody {
            id,
            class: classify_class(0, affinity),
            epitope,
            generation: 0,
            affinity,
            exposures: 0,
            neutralizations: 0,
            born_at,
            last_seen: born_at,
        }
    }

    /// Despierta la estirpe: cuenta la exposición y madura.
    ///
    /// Devuelve `true` si la afinidad subió. La maduración es asintótica a `1`
    /// (`a ← a + paso·(1−a)`), de modo que **nunca** desborda `[0,1]`, y la
    /// generación se acota en [`MAX_GENERATION`].
    fn recall(&mut self, sequence: u64) -> bool {
        let before = self.affinity;
        self.exposures = self.exposures.saturating_add(1);
        self.last_seen = sequence;
        self.generation = self.generation.saturating_add(1).min(MAX_GENERATION);
        self.affinity = clamp01(self.affinity + MATURATION_STEP * (1.0 - self.affinity));
        self.class = classify_class(self.generation, self.affinity);
        self.affinity > before
    }

    /// Anota una neutralización efectiva.
    fn count_neutralization(&mut self) {
        self.neutralizations = self.neutralizations.saturating_add(1);
    }

    /// Identificador del anticuerpo.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Clase del anticuerpo.
    pub const fn class(&self) -> AntibodyClass {
        self.class
    }

    /// Epítopo diana.
    pub const fn epitope(&self) -> Epitope {
        self.epitope
    }

    /// Generación de la estirpe.
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    /// Afinidad actual en `[0,1]`.
    pub const fn affinity(&self) -> f64 {
        self.affinity
    }

    /// ¿Es un anticuerpo adaptativo (con memoria)?
    pub const fn is_adaptive(&self) -> bool {
        self.class.is_adaptive()
    }

    /// ¿Ha alcanzado el umbral de designación de Belnap?
    pub fn is_designated(&self) -> bool {
        self.affinity >= AFFINITY_THRESHOLD
    }

    /// ¿Está agotada su maduración clonal?
    pub const fn is_terminal(&self) -> bool {
        self.generation >= MAX_GENERATION
    }

    /// Firma canónica: cambia sólo si el anticuerpo cambia.
    pub fn signature(&self) -> [u8; 32] {
        let mut statement = Vec::with_capacity(IMMUNE_DOMAIN.len() + 128);
        statement.extend_from_slice(IMMUNE_DOMAIN);
        statement.extend_from_slice(b":anticuerpo:");
        statement.extend_from_slice(&self.id.to_le_bytes());
        statement.extend_from_slice(self.class.name().as_bytes());
        statement.push(0x1f);
        statement.extend_from_slice(&self.epitope.digest());
        statement.extend_from_slice(&self.generation.to_le_bytes());
        statement.extend_from_slice(&self.affinity.to_bits().to_le_bytes());
        statement.extend_from_slice(&self.exposures.to_le_bytes());
        statement.extend_from_slice(&self.neutralizations.to_le_bytes());
        statement.extend_from_slice(&self.born_at.to_le_bytes());
        statement.extend_from_slice(&self.last_seen.to_le_bytes());
        sha256(&statement)
    }

    /// Firma en hexadecimal (informes y log).
    pub fn fingerprint(&self) -> String {
        short_hex(&self.signature())
    }

    /// ¿Este anticuerpo se une al epítopo dado? (identidad por huella)
    pub fn matches(&self, epitope: &Epitope) -> bool {
        !epitope.is_empty() && self.epitope.digest() == epitope.digest()
    }

    /// Afinidad efectiva frente a un epítopo: cero si no hay unión.
    ///
    /// Al reconocer, la afinidad se mezcla con la masa del epítopo con peso par
    /// (determinista y simétrica): una marca más peligrosa despierta más respuesta.
    pub fn affinity_to(&self, epitope: &Epitope) -> f64 {
        if !self.matches(epitope) {
            return 0.0;
        }
        clamp01((self.affinity + epitope.mass()) / 2.0)
    }

    /// Acta legible del anticuerpo.
    pub fn label_text(&self) -> String {
        format!(
            "{}#{} {} → {} · afinidad {:.3} · gen {} · {} exposición(es)",
            self.class.glyph(),
            self.id,
            self.class.name(),
            self.epitope.label,
            self.affinity,
            self.generation,
            self.exposures
        )
    }

    /// Serialización JSON mínima.
    pub fn json(&self) -> String {
        let mut out = String::with_capacity(320);
        out.push_str("{\"id\":");
        out.push_str(&self.id.to_string());
        out.push_str(",\"clase\":");
        out.push_str(self.class.json());
        out.push_str(",\"glifo\":\"");
        out.push_str(self.class.glyph());
        out.push_str("\",\"epitopo\":");
        out.push_str(&self.epitope.json());
        out.push_str(",\"generacion\":");
        out.push_str(&self.generation.to_string());
        out.push_str(",\"afinidad\":");
        out.push_str(&json_f64(self.affinity));
        out.push_str(",\"exposiciones\":");
        out.push_str(&self.exposures.to_string());
        out.push_str(",\"neutralizaciones\":");
        out.push_str(&self.neutralizations.to_string());
        out.push_str(",\"designado\":");
        out.push_str(if self.is_designated() {
            "true"
        } else {
            "false"
        });
        out.push_str(",\"firma\":\"");
        out.push_str(&self.fingerprint());
        out.push_str("\"}");
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────
// FASE 2.1 — Antígeno
// ─────────────────────────────────────────────────────────────────────────

/// Lectura inmune de una carga: veredicto, valencia y epítopos.
///
/// Un antígeno es un **valor congelado**: se construye una vez a partir de bytes
/// ([`Antigen::from_payload`]), de un paquete ([`Antigen::from_packet`]) o de una
/// burbuja ya juzgada ([`Antigen::from_bubble`]) y no cambia. Su huella
/// ([`Antigen::fingerprint`]) es la clave del reconocimiento del repertorio.
#[derive(Debug, Clone, PartialEq)]
pub struct Antigen {
    /// Origen declarado por el transporte.
    pub origin: String,
    /// Número de orden de llegada.
    pub sequence: u64,
    /// Digest `sha256` de la carga.
    pub digest: [u8; 32],
    /// Bytes de la carga.
    pub bytes: usize,
    /// Peligro acumulado en ‰ (0–1000).
    pub mille: u32,
    /// Peligro normalizado en `[0,1]`.
    pub danger: f64,
    /// ¿La carga es texto interpretable?
    pub legible: bool,
    /// Veredicto de Belnap (autoritativo si viene de burbuja).
    pub verdict: BubbleVerdict,
    /// Colapso tetravalente de la valencia.
    pub observation: Observation,
    /// Valencia paraconsistente `(⊤, ⊥)`.
    pub valence: QuantumState,
    /// Epítopos reconocidos, ordenados por peso (los de mayor peso primero).
    pub epitopes: Vec<Epitope>,
    /// Peligro efectivo: el mayor de (peligro, peso del epítopo dominante).
    pub hazard: f64,
}

impl Antigen {
    /// Construye el antígeno de una carga, aplicando **la misma regla** que la
    /// pasarela: verdad = lectura, falsedad = amenaza, colapso tetravalente.
    ///
    /// Es total: cualquier carga (vacía, enorme, binaria) produce un antígeno.
    pub fn from_payload(origin: &str, sequence: u64, payload: &[u8]) -> Self {
        let digest = sha256(payload);
        let threat = threat_of(payload);
        let danger = threat.danger();
        let legible = is_legible(payload);
        let truth = if legible {
            (1.0 - danger).max(0.0)
        } else {
            0.0
        };
        let valence = QuantumState::paraconsistent(truth, danger);
        let observation = valence.observe();
        let verdict = match observation {
            Observation::True => BubbleVerdict::Innocuous,
            Observation::Both => BubbleVerdict::Absorbed,
            Observation::False => BubbleVerdict::Neutralized,
            Observation::Neither => BubbleVerdict::Quarantined,
        };
        let epitopes = epitopes_of(&threat);
        let hazard = epitope_ceiling(&epitopes).max(danger);
        Antigen {
            origin: origin.to_string(),
            sequence,
            digest,
            bytes: payload.len(),
            mille: threat.mille,
            danger,
            legible,
            verdict,
            observation,
            valence,
            epitopes,
            hazard,
        }
    }

    /// Construye el antígeno de un paquete recibido.
    pub fn from_packet(packet: &Packet) -> Self {
        Antigen::from_payload(&packet.origin, packet.sequence, &packet.payload)
    }

    /// Construye el antígeno de una burbuja **ya juzgada** por la pasarela.
    ///
    /// Cuando la pasarela ya emitió veredicto, éste es autoritativo: la inmunidad
    /// adaptativa no re-juzga, sólo interpreta. La legibilidad se deduce del
    /// veredicto (`∅` ⇔ ilegible), porque la burbuja ya no conserva la carga.
    pub fn from_bubble(bubble: &Bubble) -> Self {
        let mille = bubble.danger.min(DANGER_CEILING);
        let epitopes = epitopes_of_labels(&bubble.markers);
        let danger = f64::from(mille) / f64::from(DANGER_CEILING);
        Antigen {
            origin: bubble.origin.clone(),
            sequence: bubble.sequence,
            digest: bubble.payload_digest,
            bytes: bubble.bytes,
            mille,
            danger,
            legible: bubble.verdict != BubbleVerdict::Quarantined,
            verdict: bubble.verdict,
            observation: bubble.observation,
            valence: bubble.valence.clone(),
            hazard: epitope_ceiling(&epitopes).max(danger),
            epitopes,
        }
    }

    /// Valor de Belnap del antígeno.
    pub fn belnap(&self) -> BelnapValue {
        BelnapValue::from_observation(self.observation)
    }

    /// Glifo de Belnap (`⊤` `⊥` `⊤∧⊥` `∅`).
    pub fn glyph(&self) -> &'static str {
        self.verdict.glyph()
    }

    /// ¿Es contenido propio (inocuo)?
    pub fn is_self(&self) -> bool {
        self.verdict == BubbleVerdict::Innocuous
    }

    /// ¿Es una contradicción tolerada (`⊤∧⊥`)?
    pub fn is_paradoxical(&self) -> bool {
        self.verdict == BubbleVerdict::Absorbed
    }

    /// ¿Es hostil (`⊥`)?
    pub fn is_hostile(&self) -> bool {
        self.verdict == BubbleVerdict::Neutralized
    }

    /// ¿Es ilegible (`∅`)?
    pub fn is_unreadable(&self) -> bool {
        self.verdict == BubbleVerdict::Quarantined
    }

    /// ¿Trae alguna marca de ataque?
    pub fn is_tainted(&self) -> bool {
        !self.epitopes.is_empty()
    }

    /// Epítopo dominante (el de mayor peso), si lo hay.
    pub fn dominant(&self) -> Option<&Epitope> {
        self.epitopes.first()
    }

    /// Gravedad efectiva en `[0,1]`: mezcla del peligro y del peso dominante.
    pub fn severity(&self) -> f64 {
        clamp01((self.danger + self.hazard) / 2.0)
    }

    /// Huella canónica del antígeno.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut statement = Vec::with_capacity(IMMUNE_DOMAIN.len() + 128 + self.origin.len());
        statement.extend_from_slice(IMMUNE_DOMAIN);
        statement.extend_from_slice(b":antigeno:");
        statement.extend_from_slice(&self.digest);
        statement.extend_from_slice(&(self.origin.len() as u64).to_le_bytes());
        statement.extend_from_slice(self.origin.as_bytes());
        statement.extend_from_slice(&self.sequence.to_le_bytes());
        statement.extend_from_slice(&self.mille.to_le_bytes());
        statement.extend_from_slice(self.verdict.label().as_bytes());
        sha256(&statement)
    }

    /// Huella en hexadecimal (informes y log).
    pub fn fingerprint_hex(&self) -> String {
        short_hex(&self.fingerprint())
    }
    /// Acta legible del antígeno.
    pub fn label_text(&self) -> String {
        format!(
            "{} {} · antígeno#{} ⟨{}⟩ {} B · {} ‰ · {} epítopo(s) · {}",
            self.glyph(),
            self.verdict.label(),
            self.sequence,
            self.fingerprint_hex(),
            self.bytes,
            self.mille,
            self.epitopes.len(),
            self.origin
        )
    }

    /// Serialización JSON mínima (inspección desde el IDE).
    pub fn json(&self) -> String {
        let mut out = String::with_capacity(512);
        out.push_str("{\"huella\":\"");
        out.push_str(&self.fingerprint_hex());
        out.push_str("\",\"origen\":\"");
        out.push_str(&json_escape(&self.origin));
        out.push_str("\",\"secuencia\":");
        out.push_str(&self.sequence.to_string());
        out.push_str(",\"bytes\":");
        out.push_str(&self.bytes.to_string());
        out.push_str(",\"mille\":");
        out.push_str(&self.mille.to_string());
        out.push_str(",\"veredicto\":\"");
        out.push_str(self.verdict.label());
        out.push_str("\",\"glifo\":\"");
        out.push_str(self.glyph());
        out.push_str("\",\"belnap\":\"");
        out.push_str(self.belnap().glyph());
        out.push_str("\",\"legible\":");
        out.push_str(if self.legible { "true" } else { "false" });
        out.push_str(",\"epitopos\":[");
        for (index, epitope) in self.epitopes.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str(&epitope.json());
        }
        out.push_str("]}");
        out
    }
}

/// Modelo de epítopos de un modelo de amenaza.
///
/// El orden es **canónico**: peso descendente y, a igual peso, etiqueta
/// ascendente. Así el repertorio no depende del orden de la tabla de agujas.
fn epitopes_of(threat: &Threat) -> Vec<Epitope> {
    epitopes_of_labels(&threat.markers)
}

/// Construye y ordena los epítopos de una lista de etiquetas de marca.
fn epitopes_of_labels(labels: &[&'static str]) -> Vec<Epitope> {
    let mut epitopes: Vec<Epitope> = labels
        .iter()
        .map(|label| Epitope::new(label, marker_weight(label)))
        .collect();
    epitopes.sort_by(|left, right| {
        right
            .weight
            .cmp(&left.weight)
            .then_with(|| left.label.cmp(right.label))
    });
    epitopes.truncate(MAX_EPITOPES);
    epitopes
}

/// Peso en ‰ de una marca del modelo de amenaza.
///
/// Sólo se consultan las tablas del organismo; una etiqueta desconocida pesa
/// cero (no se concede peligro por lo que no está en la tabla).
fn marker_weight(label: &str) -> u32 {
    if let Some((_, _, weight)) = ATTACK_NEEDLES.iter().find(|(name, _, _)| *name == label) {
        return *weight;
    }
    for (name, weight) in [
        MARK_SIZE_BOMB,
        MARK_CONTROL_PADDING,
        MARK_DEEP_NESTING,
        MARK_NUL,
        MARK_UNREADABLE,
    ] {
        if name == label {
            return weight;
        }
    }
    0
}

/// Peso del epítopo dominante en `[0,1]`.
fn epitope_ceiling(epitopes: &[Epitope]) -> f64 {
    epitopes.first().map_or(0.0, Epitope::mass)
}

// ─────────────────────────────────────────────────────────────────────────
// FASE 2.4 — Disposición y acta de respuesta
// ─────────────────────────────────────────────────────────────────────────

/// Disposición inmune: qué se hace con el antígeno.
///
/// Es la traducción exacta del veredicto de Belnap a una acción: **nunca** se
/// inventa una disposición que el veredicto no autorice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// `⊤` · contenido propio: atraviesa (tolerancia).
    Tolerate,
    /// `⊤∧⊥` · contradicción: se absorbe sin explosión.
    Absorb,
    /// `∅` · ilegible: se sella (cuarentena).
    Quarantine,
    /// `⊥` · hostil neutralizado sin memoria previa.
    Neutralize,
    /// `⊥` + anticuerpo designado: neutralizar **y recordar**.
    Immunize,
}

impl Disposition {
    /// Todas las disposiciones, en orden canónico.
    pub const ALL: [Disposition; 5] = [
        Disposition::Tolerate,
        Disposition::Absorb,
        Disposition::Quarantine,
        Disposition::Neutralize,
        Disposition::Immunize,
    ];

    /// Verbo canónico.
    pub const fn name(self) -> &'static str {
        match self {
            Disposition::Tolerate => "tolerar",
            Disposition::Absorb => "absorber",
            Disposition::Quarantine => "cuarentenar",
            Disposition::Neutralize => "neutralizar",
            Disposition::Immunize => "inmunizar",
        }
    }

    /// Glifo de Belnap asociado.
    pub const fn glyph(self) -> &'static str {
        match self {
            Disposition::Tolerate => "⊤",
            Disposition::Absorb => "⊤∧⊥",
            Disposition::Quarantine => "∅",
            Disposition::Neutralize => "⊥",
            Disposition::Immunize => "⊥·IgG",
        }
    }

    /// ¿El contenido puede alcanzar el núcleo?
    pub const fn reaches_core(self) -> bool {
        matches!(self, Disposition::Tolerate | Disposition::Absorb)
    }

    /// ¿La disposición exige neutralizar la carga?
    pub const fn neutralizes(self) -> bool {
        matches!(self, Disposition::Neutralize | Disposition::Immunize)
    }

    /// Clave JSON.
    pub const fn json(self) -> &'static str {
        match self {
            Disposition::Tolerate => "\"tolerar\"",
            Disposition::Absorb => "\"absorber\"",
            Disposition::Quarantine => "\"cuarentenar\"",
            Disposition::Neutralize => "\"neutralizar\"",
            Disposition::Immunize => "\"inmunizar\"",
        }
    }
}

/// Acta de la exposición de un antígeno al repertorio.
#[derive(Debug, Clone, PartialEq)]
pub struct Exposure {
    /// Etiqueta del epítopo reconocido o aprendido, si lo hay.
    pub epitope: Option<&'static str>,
    /// Anticuerpo despertado (recuerdo) o creado (expansión).
    pub antibody: Option<u64>,
    /// Clase del anticuerpo tras la exposición.
    pub class: Option<AntibodyClass>,
    /// Afinidad tras la exposición.
    pub affinity: f64,
    /// ¿Se creó una estirpe nueva?
    pub expanded: bool,
    /// ¿Se despertó una estirpe existente?
    pub recalled: bool,
    /// ¿Subió la afinidad?
    pub matured: bool,
    /// ¿Se quería expandir y el repertorio estaba lleno?
    pub full: bool,
}

impl Exposure {
    /// Exposición sin epítopos: nada que reconocer ni que aprender.
    fn barren() -> Self {
        Exposure {
            epitope: None,
            antibody: None,
            class: None,
            affinity: 0.0,
            expanded: false,
            recalled: false,
            matured: false,
            full: false,
        }
    }

    /// Exposición rechazada por repertorio lleno.
    fn saturated() -> Self {
        Exposure {
            full: true,
            ..Exposure::barren()
        }
    }

    /// ¿Hubo reconocimiento (recuerdo o expansión)?
    pub fn is_familiar(&self) -> bool {
        self.recalled || self.expanded
    }
}

/// Acta completa de la respuesta inmune a un antígeno.
#[derive(Debug, Clone, PartialEq)]
pub struct ImmuneResponse {
    /// Huella del antígeno juzgado.
    pub antigen: [u8; 32],
    /// Número de orden del antígeno.
    pub sequence: u64,
    /// Disposición adoptada.
    pub disposition: Disposition,
    /// Clase del anticuerpo implicado.
    pub class: Option<AntibodyClass>,
    /// Identificador del anticuerpo implicado.
    pub antibody: Option<u64>,
    /// Epítopo que motivó la respuesta.
    pub epitope: Option<&'static str>,
    /// Afinidad efectiva en `[0,1]`.
    pub affinity: f64,
    /// ¿Se expandió el repertorio?
    pub expanded: bool,
    /// ¿Se maduró una estirpe?
    pub matured: bool,
    /// ¿Se despertó memoria?
    pub recalled: bool,
    /// ¿El repertorio estaba lleno al intentar aprender?
    pub repertoire_full: bool,
    /// Ciclo del sistema inmunitario.
    pub tick: u64,
}

impl ImmuneResponse {
    /// ¿El contenido puede alcanzar el núcleo?
    pub fn reaches_core(&self) -> bool {
        self.disposition.reaches_core()
    }

    /// ¿La carga debe convertirse en ruido inerte?
    pub fn neutralizes(&self) -> bool {
        self.disposition.neutralizes()
    }

    /// ¿Hubo reconocimiento?
    pub fn is_familiar(&self) -> bool {
        self.recalled || self.expanded
    }

    /// ¿El reconocimiento es adaptativo (memoria o regulación)?
    pub fn is_adaptive(&self) -> bool {
        match self.class {
            Some(class) => class.is_adaptive(),
            None => false,
        }
    }

    /// Acta legible de la respuesta.
    pub fn label_text(&self) -> String {
        let antibody = match (self.class, self.antibody) {
            (Some(class), Some(id)) => format!("{}#{}", class.glyph(), id),
            _ => "sin anticuerpo".to_string(),
        };
        format!(
            "{} {} · antígeno#{} ⟨{}⟩ · {} · afinidad {:.3} · ciclo {}",
            self.disposition.glyph(),
            self.disposition.name(),
            self.sequence,
            short_hex(self.antigen.get(..4).unwrap_or(&[])),
            antibody,
            self.affinity,
            self.tick
        )
    }

    /// Serialización JSON mínima.
    pub fn json(&self) -> String {
        let mut out = String::with_capacity(384);
        out.push_str("{\"antigeno\":\"");
        out.push_str(&short_hex(&self.antigen));
        out.push_str("\",\"secuencia\":");
        out.push_str(&self.sequence.to_string());
        out.push_str(",\"disposicion\":");
        out.push_str(self.disposition.json());
        out.push_str(",\"glifo\":\"");
        out.push_str(self.disposition.glyph());
        out.push_str("\",\"clase\":");
        out.push_str(self.class.map_or("null", AntibodyClass::json));
        out.push_str(",\"anticuerpo\":");
        out.push_str(&json_opt_u64(self.antibody));
        out.push_str(",\"epitopo\":");
        out.push_str(&json_opt_str(self.epitope));
        out.push_str(",\"afinidad\":");
        out.push_str(&json_f64(self.affinity));
        out.push_str(",\"expandido\":");
        out.push_str(if self.expanded { "true" } else { "false" });
        out.push_str(",\"madurado\":");
        out.push_str(if self.matured { "true" } else { "false" });
        out.push_str(",\"recordado\":");
        out.push_str(if self.recalled { "true" } else { "false" });
        out.push_str(",\"repertorio_lleno\":");
        out.push_str(if self.repertoire_full {
            "true"
        } else {
            "false"
        });
        out.push_str(",\"ciclo\":");
        out.push_str(&self.tick.to_string());
        out.push('}');
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────
// FASE 2.3 — Repertorio acotado
// ─────────────────────────────────────────────────────────────────────────

/// Censo del repertorio por clase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Census {
    /// Estirpes innatas.
    pub innate: usize,
    /// Estirpes mucosas.
    pub mucosal: usize,
    /// Estirpes de memoria.
    pub memory: usize,
    /// Estirpes reguladoras.
    pub regulatory: usize,
    /// Estirpes que han alcanzado la designación de Belnap.
    pub designated: usize,
}

impl Census {
    /// Total de estirpes.
    pub const fn total(&self) -> usize {
        self.innate + self.mucosal + self.memory + self.regulatory
    }

    /// Estirpes adaptativas (memoria + reguladoras).
    pub const fn adaptive(&self) -> usize {
        self.memory + self.regulatory
    }

    /// Estirpes de la clase indicada.
    pub const fn of(&self, class: AntibodyClass) -> usize {
        match class {
            AntibodyClass::Innate => self.innate,
            AntibodyClass::Mucosal => self.mucosal,
            AntibodyClass::Memory => self.memory,
            AntibodyClass::Regulatory => self.regulatory,
        }
    }

    /// JSON del censo.
    pub fn json(&self) -> String {
        let mut out = String::with_capacity(160);
        out.push_str("{\"innata\":");
        out.push_str(&self.innate.to_string());
        out.push_str(",\"mucosa\":");
        out.push_str(&self.mucosal.to_string());
        out.push_str(",\"memoria\":");
        out.push_str(&self.memory.to_string());
        out.push_str(",\"reguladora\":");
        out.push_str(&self.regulatory.to_string());
        out.push_str(",\"designada\":");
        out.push_str(&self.designated.to_string());
        out.push_str(",\"total\":");
        out.push_str(&self.total().to_string());
        out.push('}');
        out
    }
}

/// Acta de una vacunación: estirpe creada o reforzada por orden explícita.
#[derive(Debug, Clone, PartialEq)]
pub struct Vaccination {
    /// Origen que ordena la vacunación (procedencia declarada del patógeno).
    pub origin: String,
    /// Identificador de la estirpe vacunada.
    pub antibody: u64,
    /// Epítopo diana.
    pub epitope: Epitope,
    /// Clase de la estirpe tras la vacunación.
    pub class: AntibodyClass,
    /// Afinidad de la estirpe tras la vacunación.
    pub affinity: f64,
    /// ¿Refuerzo de una estirpe preexistente?
    pub booster: bool,
    /// ¿Subió la afinidad en el refuerzo?
    pub matured: bool,
}

impl Vaccination {
    /// Acta legible de la vacunación.
    pub fn label_text(&self) -> String {
        format!(
            "vacuna {} · {}#{} → {} · afinidad {:.3}",
            if self.booster {
                "de refuerzo"
            } else {
                "primaria"
            },
            self.class.glyph(),
            self.antibody,
            self.epitope.label,
            self.affinity
        )
    }

    /// Serialización JSON mínima.
    pub fn json(&self) -> String {
        let mut out = String::with_capacity(256);
        out.push_str("{\"origen\":\"");
        out.push_str(&json_escape(&self.origin));
        out.push_str("\",\"anticuerpo\":");
        out.push_str(&self.antibody.to_string());
        out.push_str(",\"epitopo\":");
        out.push_str(&self.epitope.json());
        out.push_str(",\"refuerzo\":");
        out.push_str(if self.booster { "true" } else { "false" });
        out.push_str(",\"madurado\":");
        out.push_str(if self.matured { "true" } else { "false" });
        out.push('}');
        out
    }
}

/// Repertorio de anticuerpos: **memoria acotada** del organismo.
///
/// Nunca crece por encima de [`MAX_ANTIBODIES`]: cuando está lleno, la exposición
/// devuelve [`Exposure::full`] y el sistema lo declara
/// ([`ImmuneResponse::repertoire_full`]). La única válvula es
/// [`Repertoire::decay`] (olvido), que libera las estirpes más débiles.
#[derive(Debug, Clone, PartialEq)]
pub struct Repertoire {
    antibodies: Vec<Antibody>,
    next_id: u64,
    exposures: u64,
    decays: u64,
}

impl Repertoire {
    /// Repertorio vacío.
    pub fn new() -> Self {
        Repertoire {
            antibodies: Vec::new(),
            next_id: 0,
            exposures: 0,
            decays: 0,
        }
    }

    /// Estirpes actuales.
    pub fn len(&self) -> usize {
        self.antibodies.len()
    }

    /// ¿Está vacío?
    pub fn is_empty(&self) -> bool {
        self.antibodies.is_empty()
    }

    /// Techo de estirpes ([`MAX_ANTIBODIES`]).
    pub const fn capacity(&self) -> usize {
        MAX_ANTIBODIES
    }

    /// ¿Está lleno?
    pub fn is_full(&self) -> bool {
        self.antibodies.len() >= MAX_ANTIBODIES
    }

    /// Exposiciones acumuladas (antígenos presentados).
    pub const fn exposures(&self) -> u64 {
        self.exposures
    }

    /// Rondas de olvido ejecutadas.
    pub const fn decays(&self) -> u64 {
        self.decays
    }

    /// Estirpes, en orden de creación.
    pub fn antibodies(&self) -> &[Antibody] {
        &self.antibodies
    }

    /// Estirpe por identificador (error tipado si no existe).
    pub fn antibody(&self, id: u64) -> Result<&Antibody, ImmuneError> {
        self.antibodies
            .iter()
            .find(|antibody| antibody.id == id)
            .ok_or(ImmuneError::UnknownAntibody { id })
    }

    /// Afinidad media del repertorio en `[0,1]` (`0` si está vacío).
    pub fn mean_affinity(&self) -> f64 {
        if self.antibodies.is_empty() {
            return 0.0;
        }
        let total: f64 = self
            .antibodies
            .iter()
            .map(|antibody| antibody.affinity)
            .sum();
        clamp01(total / self.antibodies.len() as f64)
    }

    /// Presenta un antígeno al repertorio: recuerda si lo reconoce, aprende si no.
    pub fn expose(&mut self, antigen: &Antigen) -> Exposure {
        self.exposures = self.exposures.saturating_add(1);
        if let Some((index, epitope)) = self.best_match(antigen) {
            let matured = match self.antibodies.get_mut(index) {
                Some(antibody) => antibody.recall(antigen.sequence),
                None => false,
            };
            if let Some(antibody) = self.antibodies.get(index) {
                return Exposure {
                    epitope: Some(epitope.label),
                    antibody: Some(antibody.id),
                    class: Some(antibody.class),
                    affinity: antibody.affinity_to(&epitope),
                    expanded: false,
                    recalled: true,
                    matured,
                    full: false,
                };
            }
        }
        let epitope = match antigen.dominant() {
            Some(epitope) => *epitope,
            None => return Exposure::barren(),
        };
        if self.is_full() {
            return Exposure::saturated();
        }
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let antibody = Antibody::founder(id, epitope, antigen.sequence);
        let exposure = Exposure {
            epitope: Some(epitope.label),
            antibody: Some(antibody.id),
            class: Some(antibody.class),
            affinity: antibody.affinity_to(&epitope),
            expanded: true,
            recalled: false,
            matured: false,
            full: false,
        };
        self.antibodies.push(antibody);
        exposure
    }

    /// Mejor unión del repertorio con los epítopos del antígeno.
    ///
    /// Empate ⇒ gana la estirpe más antigua (orden de creación). Determinista.
    fn best_match(&self, antigen: &Antigen) -> Option<(usize, Epitope)> {
        let mut best: Option<(usize, Epitope, f64)> = None;
        for (index, antibody) in self.antibodies.iter().enumerate() {
            for epitope in &antigen.epitopes {
                let affinity = antibody.affinity_to(epitope);
                let wins = match &best {
                    Some((_, _, current)) => affinity > *current,
                    None => affinity > 0.0,
                };
                if wins {
                    best = Some((index, *epitope, affinity));
                }
            }
        }
        best.map(|(index, epitope, _)| (index, epitope))
    }

    /// Índice de la estirpe que ya une este epítopo, si existe.
    fn strain_of(&self, epitope: &Epitope) -> Option<usize> {
        self.antibodies
            .iter()
            .position(|antibody| antibody.matches(epitope))
    }

    /// Censo por clase.
    pub fn census(&self) -> Census {
        let mut census = Census::default();
        for antibody in &self.antibodies {
            match antibody.class {
                AntibodyClass::Innate => census.innate += 1,
                AntibodyClass::Mucosal => census.mucosal += 1,
                AntibodyClass::Memory => census.memory += 1,
                AntibodyClass::Regulatory => census.regulatory += 1,
            }
            if antibody.is_designated() {
                census.designated += 1;
            }
        }
        census
    }

    /// Vacuna dirigida: crea una estirpe contra un epítopo (o la refuerza).
    ///
    /// A diferencia de la exposición, que exige un antígeno completo, la vacuna
    /// actúa sobre un epítopo **explícito**: es la puerta por la que el operador
    /// declara inmunidad conocida. Nunca duplica estirpes: si ya existe una unión
    /// para ese epítopo, la refuerza.
    pub fn vaccinate(
        &mut self,
        origin: &str,
        epitope: Epitope,
        born_at: u64,
    ) -> Result<Vaccination, ImmuneError> {
        if origin.trim().is_empty() {
            return Err(ImmuneError::EmptyOrigin);
        }
        if epitope.is_empty() {
            return Err(ImmuneError::EmptyEpitope);
        }
        if let Some(index) = self.strain_of(&epitope) {
            let matured = match self.antibodies.get_mut(index) {
                Some(antibody) => antibody.recall(born_at),
                None => false,
            };
            if let Some(antibody) = self.antibodies.get(index) {
                return Ok(Vaccination {
                    origin: origin.to_string(),
                    antibody: antibody.id,
                    epitope,
                    class: antibody.class,
                    affinity: antibody.affinity,
                    booster: true,
                    matured,
                });
            }
        }
        if self.is_full() {
            return Err(ImmuneError::RepertoireFull {
                limit: MAX_ANTIBODIES,
            });
        }
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let seed = clamp01(epitope.mass().max(AntibodyClass::Innate.innate_affinity()));
        let antibody = Antibody::seeded(id, epitope, born_at, seed);
        let vaccination = Vaccination {
            origin: origin.to_string(),
            antibody: antibody.id,
            epitope,
            class: antibody.class,
            affinity: antibody.affinity,
            booster: false,
            matured: false,
        };
        self.antibodies.push(antibody);
        Ok(vaccination)
    }

    /// Olvido: una ronda de decaimiento. Devuelve las estirpes retiradas.
    ///
    /// La pérdida es de [`DECAY_STEP`] para lo que nunca se usó y de la mitad para
    /// lo que sí se usó (lo visto se olvida más despacio). Por debajo de
    /// [`AFFINITY_FLOOR`], la estirpe sale del repertorio.
    pub fn decay(&mut self) -> usize {
        let mut survivors: Vec<Antibody> = Vec::with_capacity(self.antibodies.len());
        let mut evicted = 0_usize;
        for mut antibody in std::mem::take(&mut self.antibodies) {
            let loss = if antibody.exposures == 0 {
                DECAY_STEP
            } else {
                DECAY_STEP / 2.0
            };
            antibody.affinity = clamp01(antibody.affinity - loss);
            if antibody.affinity < AFFINITY_FLOOR {
                evicted += 1;
            } else {
                survivors.push(antibody);
            }
        }
        self.antibodies = survivors;
        self.decays = self.decays.saturating_add(1);
        evicted
    }

    /// Anota una neutralización efectiva en la estirpe indicada.
    fn note_neutralization(&mut self, id: Option<u64>) -> bool {
        let id = match id {
            Some(id) => id,
            None => return false,
        };
        match self
            .antibodies
            .iter_mut()
            .find(|antibody| antibody.id == id)
        {
            Some(antibody) => {
                antibody.count_neutralization();
                true
            }
            None => false,
        }
    }

    /// Huella del repertorio: contenido-adictiva (estirpes + orden de creación).
    pub fn digest(&self) -> [u8; 32] {
        let mut statement =
            Vec::with_capacity(IMMUNE_DOMAIN.len() + 64 + 96 * self.antibodies.len());
        statement.extend_from_slice(IMMUNE_DOMAIN);
        statement.extend_from_slice(b":repertorio:");
        statement.extend_from_slice(&(self.antibodies.len() as u64).to_le_bytes());
        for antibody in &self.antibodies {
            statement.extend_from_slice(&antibody.signature());
        }
        statement.extend_from_slice(&self.exposures.to_le_bytes());
        statement.extend_from_slice(&self.decays.to_le_bytes());
        sha256(&statement)
    }

    /// Huella del repertorio en hexadecimal.
    pub fn fingerprint(&self) -> String {
        short_hex(&self.digest())
    }

    /// Acta legible del repertorio.
    pub fn label_text(&self) -> String {
        let census = self.census();
        format!(
            "repertorio ⟨{}⟩ · {}/{} estirpes · IgM {} · IgA {} · IgG {} · Treg {} · afinidad media {:.3} · {} exposición(es) · {} olvido(s)",
            self.fingerprint(),
            census.total(),
            MAX_ANTIBODIES,
            census.innate,
            census.mucosal,
            census.memory,
            census.regulatory,
            self.mean_affinity(),
            self.exposures,
            self.decays
        )
    }

    /// Serialización JSON mínima (inspección desde el IDE).
    pub fn json(&self) -> String {
        let mut out = String::with_capacity(512 + 256 * self.antibodies.len());
        out.push_str("{\"huella\":\"");
        out.push_str(&self.fingerprint());
        out.push_str("\",\"capacidad\":");
        out.push_str(&MAX_ANTIBODIES.to_string());
        out.push_str(",\"estirpes\":");
        out.push_str(&self.antibodies.len().to_string());
        out.push_str(",\"exposiciones\":");
        out.push_str(&self.exposures.to_string());
        out.push_str(",\"olvidos\":");
        out.push_str(&self.decays.to_string());
        out.push_str(",\"afinidad_media\":");
        out.push_str(&json_f64(self.mean_affinity()));
        out.push_str(",\"censo\":");
        out.push_str(&self.census().json());
        out.push_str(",\"anticuerpos\":[");
        for (index, antibody) in self.antibodies.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str(&antibody.json());
        }
        out.push_str("]}");
        out
    }
}

impl Default for Repertoire {
    fn default() -> Self {
        Repertoire::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────
// FASE 2.4 — Sistema inmunitario adaptativo
// ─────────────────────────────────────────────────────────────────────────

/// Contadores acumulados del sistema inmunitario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ImmuneCounters {
    /// Antígenos tolerados.
    pub tolerated: u64,
    /// Contradicciones absorbidas.
    pub absorbed: u64,
    /// Cargas cuarentenadas.
    pub quarantined: u64,
    /// Neutralizaciones sin memoria previa.
    pub neutralized: u64,
    /// Inmunizaciones (neutralizar + recordar).
    pub immunized: u64,
    /// Estirpes expandidas por primera exposición.
    pub expansions: u64,
    /// Recuerdos despertados.
    pub recalls: u64,
    /// Estirpes retiradas por olvido.
    pub forgotten: u64,
}

impl ImmuneCounters {
    /// Total de respuestas emitidas.
    pub const fn total(&self) -> u64 {
        self.tolerated + self.absorbed + self.quarantined + self.neutralized + self.immunized
    }

    /// JSON de los contadores.
    pub fn json(&self) -> String {
        let mut out = String::with_capacity(256);
        out.push_str("{\"tolerados\":");
        out.push_str(&self.tolerated.to_string());
        out.push_str(",\"absorbidos\":");
        out.push_str(&self.absorbed.to_string());
        out.push_str(",\"cuarentenados\":");
        out.push_str(&self.quarantined.to_string());
        out.push_str(",\"neutralizados\":");
        out.push_str(&self.neutralized.to_string());
        out.push_str(",\"inmunizados\":");
        out.push_str(&self.immunized.to_string());
        out.push_str(",\"expansiones\":");
        out.push_str(&self.expansions.to_string());
        out.push_str(",\"recuerdos\":");
        out.push_str(&self.recalls.to_string());
        out.push_str(",\"olvidados\":");
        out.push_str(&self.forgotten.to_string());
        out.push_str(",\"total\":");
        out.push_str(&self.total().to_string());
        out.push('}');
        out
    }
}

/// Sistema inmunitario adaptativo: repertorio + política + memoria de respuestas.
///
/// Envuelve la pasarela sin sustituirla: la pasarela juzga (¿qué es esto?), la
/// inmunidad adaptativa recuerda (¿lo he visto antes?). El sistema **no** escribe
/// en el núcleo: sólo produce actas ([`ImmuneResponse`]) y ruido inerte.
#[derive(Debug, Clone, PartialEq)]
pub struct ImmuneSystem {
    repertoire: Repertoire,
    tolerance: f64,
    tick: u64,
    counters: ImmuneCounters,
}

impl ImmuneSystem {
    /// Sistema con tolerancia por defecto (umbral de designación de Belnap).
    pub fn new() -> Self {
        ImmuneSystem::with_tolerance(AFFINITY_THRESHOLD)
    }

    /// Sistema con una tolerancia explícita (recortada a `[0,1]`; `NaN` ⇒ umbral).
    pub fn with_tolerance(tolerance: f64) -> Self {
        let tolerance = if tolerance.is_finite() {
            clamp01(tolerance)
        } else {
            AFFINITY_THRESHOLD
        };
        ImmuneSystem {
            repertoire: Repertoire::new(),
            tolerance,
            tick: 0,
            counters: ImmuneCounters::default(),
        }
    }

    /// Umbral de afinidad a partir del cual se inmuniza (no sólo se neutraliza).
    pub const fn tolerance(&self) -> f64 {
        self.tolerance
    }

    /// Ciclos de inmunidad ejecutados.
    pub const fn tick(&self) -> u64 {
        self.tick
    }

    /// Repertorio (memoria acotada) del sistema.
    pub fn repertoire(&self) -> &Repertoire {
        &self.repertoire
    }

    /// Contadores acumulados.
    pub const fn counters(&self) -> &ImmuneCounters {
        &self.counters
    }

    /// Estirpe por identificador (error tipado si no existe).
    pub fn antibody(&self, id: u64) -> Result<&Antibody, ImmuneError> {
        self.repertoire.antibody(id)
    }

    /// Estirpe que atendió una respuesta, si la hubo.
    pub fn recall(&self, response: &ImmuneResponse) -> Option<&Antibody> {
        response
            .antibody
            .and_then(|id| self.repertoire.antibody(id).ok())
    }

    /// Censo del repertorio por clase.
    pub fn census(&self) -> Census {
        self.repertoire.census()
    }

    /// Ciclo de inmunidad sobre un antígeno ya congelado.
    ///
    /// Único punto de decisión: expone el antígeno al repertorio (aprender o
    /// recordar) y traduce el veredicto de Belnap a una [`Disposition`].
    pub fn screen(&mut self, antigen: &Antigen) -> ImmuneResponse {
        self.tick = self.tick.saturating_add(1);
        let exposure = self.repertoire.expose(antigen);
        let disposition = self.disposition(antigen, &exposure);
        if exposure.expanded {
            self.counters.expansions = self.counters.expansions.saturating_add(1);
        }
        if exposure.recalled {
            self.counters.recalls = self.counters.recalls.saturating_add(1);
        }
        match disposition {
            Disposition::Tolerate => self.counters.tolerated += 1,
            Disposition::Absorb => self.counters.absorbed += 1,
            Disposition::Quarantine => self.counters.quarantined += 1,
            Disposition::Neutralize => self.counters.neutralized += 1,
            Disposition::Immunize => self.counters.immunized += 1,
        }
        if disposition.neutralizes() {
            self.repertoire.note_neutralization(exposure.antibody);
        }
        ImmuneResponse {
            antigen: antigen.fingerprint(),
            sequence: antigen.sequence,
            disposition,
            class: exposure.class,
            antibody: exposure.antibody,
            epitope: exposure.epitope,
            affinity: exposure.affinity,
            expanded: exposure.expanded,
            matured: exposure.matured,
            recalled: exposure.recalled,
            repertoire_full: exposure.full,
            tick: self.tick,
        }
    }

    /// Política inmune: del veredicto de Belnap a la disposición.
    ///
    /// * `⊤` contenido propio ⇒ **tolerar** (atraviesa).
    /// * `⊤∧⊥` contradicción ⇒ **absorber** (atraviesa sin explosión).
    /// * `∅` ilegible ⇒ **cuarentenar** (se sella).
    /// * `⊥` hostil ⇒ **neutralizar**; con memoria o afinidad suficiente ⇒ **inmunizar**.
    fn disposition(&self, antigen: &Antigen, exposure: &Exposure) -> Disposition {
        match antigen.verdict {
            BubbleVerdict::Innocuous => Disposition::Tolerate,
            BubbleVerdict::Absorbed => Disposition::Absorb,
            BubbleVerdict::Quarantined => Disposition::Quarantine,
            BubbleVerdict::Neutralized => {
                if exposure.recalled || exposure.affinity >= self.tolerance {
                    Disposition::Immunize
                } else {
                    Disposition::Neutralize
                }
            }
        }
    }

    /// Congela un paquete de la pasarela y lo presenta al sistema.
    pub fn inspect(&mut self, packet: &Packet) -> ImmuneResponse {
        let antigen = Antigen::from_packet(packet);
        self.screen(&antigen)
    }

    /// Congela una burbuja de la pasarela y la presenta al sistema.
    pub fn scan(&mut self, bubble: &Bubble) -> ImmuneResponse {
        let antigen = Antigen::from_bubble(bubble);
        self.screen(&antigen)
    }

    /// Presenta una carga cruda (sin transporte): útil para el puente del IDE.
    pub fn screen_bytes(&mut self, origin: &str, sequence: u64, payload: &[u8]) -> ImmuneResponse {
        let antigen = Antigen::from_payload(origin, sequence, payload);
        self.screen(&antigen)
    }

    /// Vacuna dirigida: inmunidad declarada sobre un epítopo explícito.
    ///
    /// Puerta por la que el operador declara inmunidad conocida sin exponer un
    /// antígeno completo. Nunca duplica estirpes: refuerza la ya existente.
    pub fn vaccinate(
        &mut self,
        origin: &str,
        epitope: Epitope,
        born_at: u64,
    ) -> Result<Vaccination, ImmuneError> {
        self.repertoire.vaccinate(origin, epitope, born_at)
    }

    /// Olvido: una ronda de decaimiento del repertorio. Devuelve las retiradas.
    pub fn forget(&mut self) -> usize {
        let evicted = self.repertoire.decay();
        self.counters.forgotten = self.counters.forgotten.saturating_add(evicted as u64);
        evicted
    }

    /// Inmunidad pasiva: convierte una carga en su análogo inerte.
    ///
    /// La semilla es la **firma de la estirpe** que atendió la respuesta; si no
    /// hubo estirpe, la huella del antígeno. El mismo patógeno produce siempre el
    /// mismo ruido inerte; dos patógenos distintos no colisionan.
    pub fn neutralize(&self, response: &ImmuneResponse, payload: &[u8]) -> Vec<u8> {
        let seed = match self.recall(response) {
            Some(antibody) => antibody.signature(),
            None => response.antigen,
        };
        neutralized(payload, &seed)
    }

    /// Huella del sistema: repertorio + política + contadores.
    pub fn digest(&self) -> [u8; 32] {
        let mut statement = Vec::with_capacity(IMMUNE_DOMAIN.len() + 128);
        statement.extend_from_slice(IMMUNE_DOMAIN);
        statement.extend_from_slice(b":sistema:");
        statement.extend_from_slice(&self.repertoire.digest());
        statement.extend_from_slice(&self.tolerance.to_bits().to_le_bytes());
        statement.extend_from_slice(&self.tick.to_le_bytes());
        statement.extend_from_slice(&self.counters.total().to_le_bytes());
        sha256(&statement)
    }

    /// Huella del sistema en hexadecimal.
    pub fn fingerprint(&self) -> String {
        short_hex(&self.digest())
    }

    /// Acta legible del sistema.
    pub fn label_text(&self) -> String {
        let counters = &self.counters;
        format!(
            "inmunidad ⟨{}⟩ · tolerancia {:.3} · {} respuesta(s) (⊤{} ⊤∧⊥{} ∅{} ⊥{} ⊥·IgG{}) · ciclo {} · {}",
            self.fingerprint(),
            self.tolerance,
            counters.total(),
            counters.tolerated,
            counters.absorbed,
            counters.quarantined,
            counters.neutralized,
            counters.immunized,
            self.tick,
            self.repertoire.label_text()
        )
    }

    /// Instantánea JSON completa (puente de sólo lectura hacia el IDE).
    pub fn json(&self) -> String {
        let mut out = String::with_capacity(768 + 256 * self.repertoire.len());
        out.push_str("{\"huella\":\"");
        out.push_str(&self.fingerprint());
        out.push_str("\",\"tolerancia\":");
        out.push_str(&json_f64(self.tolerance));
        out.push_str(",\"ciclo\":");
        out.push_str(&self.tick.to_string());
        out.push_str(",\"censo\":");
        out.push_str(&self.census().json());
        out.push_str(",\"contadores\":");
        out.push_str(&self.counters.json());
        out.push_str(",\"repertorio\":");
        out.push_str(&self.repertoire.json());
        out.push('}');
        out
    }
}

impl Default for ImmuneSystem {
    fn default() -> Self {
        ImmuneSystem::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Utilidades internas
// ─────────────────────────────────────────────────────────────────────────

/// Recorta a `[0,1]`; lo no finito se trata como `0` (nunca propaga `NaN`).
fn clamp01(value: f64) -> f64 {
    if value.is_finite() {
        value.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

/// Clase de una estirpe según su generación y su afinidad.
///
/// La clase es una función del estado, no un estado aparte: la misma estirpe
/// escala de innata (`IgM`) a mucosa (`IgA`), de memoria (`IgG`) y a reguladora
/// (`Treg`) conforme madura.
fn classify_class(generation: u32, affinity: f64) -> AntibodyClass {
    if affinity >= AFFINITY_THRESHOLD + 3.0 * MATURATION_STEP {
        AntibodyClass::Regulatory
    } else if generation >= 2 && affinity >= AFFINITY_THRESHOLD + MATURATION_STEP {
        AntibodyClass::Memory
    } else if generation >= 1 {
        AntibodyClass::Mucosal
    } else {
        AntibodyClass::Innate
    }
}

/// Escapa una cadena para JSON (comillas, barra inversa y controles).
fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ if (character as u32) < 0x20 => out.push('?'),
            _ => out.push(character),
        }
    }
    out
}

/// Número en coma flotante con formato JSON estable (seis decimales fijos).
fn json_f64(value: f64) -> String {
    if !value.is_finite() {
        return "0.000000".to_string();
    }
    format!("{value:.6}")
}

/// `u64` opcional → JSON (`null` si ausente).
fn json_opt_u64(value: Option<u64>) -> String {
    match value {
        Some(value) => value.to_string(),
        None => "null".to_string(),
    }
}

/// Etiqueta opcional → JSON (`null` si ausente).
fn json_opt_str(value: Option<&str>) -> String {
    match value {
        Some(text) => format!("\"{}\"", json_escape(text)),
        None => "null".to_string(),
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    use crate::immunity_gateway::Gateway;

    /// Carga limpia: JSON inocente, texto alfanumérico sin marcas.
    const LIMPIA: &str = "{\"evento\":\"saludo\",\"valor\":1}";
    /// Carga **paradójica**: suma exactamente `500 ‰` con texto legible (`⊤∧⊥`).
    const PARADOJA: &str = "../$( ademas un ` guion";
    /// Carga hostil declarada: agota el techo de peligro (`1000 ‰`).
    const HOSTIL: &str = "../$(rm -rf / && drop table usuarios) <script>";
    /// Carga ilegible y serena (`300 ‰`): bytes de control sin designación.
    const ILEGIBLE: &[u8] = &[0x00, 0x01, 0x02];
    /// Marca dominante de la carga hostil (el epítopo que despierta el repertorio).
    const DIANA_HOSTIL: &str = "borrado recursivo";

    /// Etiquetas sintéticas para saturar el repertorio (más que su techo).
    const MARCAS: [&str; 68] = [
        "m00", "m01", "m02", "m03", "m04", "m05", "m06", "m07", "m08", "m09", "m10", "m11", "m12",
        "m13", "m14", "m15", "m16", "m17", "m18", "m19", "m20", "m21", "m22", "m23", "m24", "m25",
        "m26", "m27", "m28", "m29", "m30", "m31", "m32", "m33", "m34", "m35", "m36", "m37", "m38",
        "m39", "m40", "m41", "m42", "m43", "m44", "m45", "m46", "m47", "m48", "m49", "m50", "m51",
        "m52", "m53", "m54", "m55", "m56", "m57", "m58", "m59", "m60", "m61", "m62", "m63", "m64",
        "m65", "m66", "m67",
    ];

    #[test]
    fn el_antigeno_congela_la_lectura_de_la_pasarela() {
        let limpio = Antigen::from_payload("repl", 1, LIMPIA.as_bytes());
        assert_eq!(limpio.verdict, BubbleVerdict::Innocuous);
        assert_eq!(limpio.observation, Observation::True);
        assert_eq!(limpio.belnap(), BelnapValue::True);
        assert!(limpio.epitopes.is_empty());
        assert_eq!(limpio.mille, 0);
        assert!(limpio.is_self());
        assert!(!limpio.is_hostile());

        let paradoja = Antigen::from_payload("web", 2, PARADOJA.as_bytes());
        assert_eq!(paradoja.verdict, BubbleVerdict::Absorbed);
        assert_eq!(paradoja.belnap(), BelnapValue::Both);
        assert!(paradoja.is_paradoxical());
        assert_eq!(
            paradoja.dominant().map(|epitopo| epitopo.label),
            Some("travesía de directorios")
        );

        let ilegible = Antigen::from_payload("sensor", 3, ILEGIBLE);
        assert_eq!(ilegible.verdict, BubbleVerdict::Quarantined);
        assert_eq!(ilegible.belnap(), BelnapValue::Neither);
        assert!(ilegible.is_unreadable());

        let hostil = Antigen::from_payload("sensor", 4, HOSTIL.as_bytes());
        assert_eq!(hostil.verdict, BubbleVerdict::Neutralized);
        assert_eq!(hostil.belnap(), BelnapValue::False);
        assert_eq!(hostil.mille, 1000);
        assert_eq!(hostil.danger, 1.0);
        assert!(hostil.is_hostile());
        assert!(hostil.is_tainted());
        assert_eq!(
            hostil.dominant().map(|epitopo| epitopo.label),
            Some(DIANA_HOSTIL)
        );
        assert!(hostil.epitopes.len() <= MAX_EPITOPES);
        assert_ne!(hostil.fingerprint(), limpio.fingerprint());
        assert_eq!(hostil.fingerprint_hex().len(), 64);
    }

    #[test]
    fn la_carga_limpia_se_tolera_y_no_deja_estirpe() {
        let mut sistema = ImmuneSystem::new();
        let respuesta = sistema.screen_bytes("repl", 1, LIMPIA.as_bytes());

        assert_eq!(respuesta.disposition, Disposition::Tolerate);
        assert!(respuesta.reaches_core());
        assert!(!respuesta.neutralizes());
        assert!(!respuesta.is_familiar());
        assert!(!respuesta.is_adaptive());
        assert!(respuesta.antibody.is_none());
        assert!(respuesta.epitope.is_none());
        assert_eq!(respuesta.class, None);
        assert_eq!(respuesta.tick, 1);
        assert!(sistema.repertoire().is_empty());
        assert_eq!(sistema.counters().tolerated, 1);
        assert_eq!(sistema.counters().total(), 1);
        assert!(respuesta.label_text().starts_with("⊤ tolerar"));
    }

    #[test]
    fn la_paradoja_se_absorbe_sin_explosion_y_deja_memoria() {
        let mut sistema = ImmuneSystem::new();
        let respuesta = sistema.screen_bytes("web", 2, PARADOJA.as_bytes());

        assert_eq!(respuesta.disposition, Disposition::Absorb);
        assert!(respuesta.reaches_core());
        assert!(!respuesta.neutralizes());
        assert!(respuesta.expanded);
        assert!(respuesta.is_familiar());
        assert!(!respuesta.is_adaptive());
        assert_eq!(respuesta.epitope, Some("travesía de directorios"));
        assert_eq!(respuesta.class, Some(AntibodyClass::Innate));
        assert_eq!(sistema.repertoire().len(), 1);
        assert_eq!(sistema.counters().absorbed, 1);
        assert_eq!(sistema.census().innate, 1);
        assert!(respuesta.label_text().contains("absorber"));
    }

    #[test]
    fn lo_ilegible_se_cuarentena_sin_escalar_por_memoria() {
        let mut sistema = ImmuneSystem::new();
        let primera = sistema.screen_bytes("sensor", 3, ILEGIBLE);
        let segunda = sistema.screen_bytes("sensor", 4, ILEGIBLE);

        assert_eq!(primera.disposition, Disposition::Quarantine);
        assert!(!primera.reaches_core());
        assert!(!primera.neutralizes());
        assert_eq!(primera.epitope, Some("relleno de control"));
        assert!(primera.expanded);

        // El recuerdo no endurece la cuarentena: manda el veredicto.
        assert_eq!(segunda.disposition, Disposition::Quarantine);
        assert!(segunda.recalled);
        assert_eq!(segunda.antibody, primera.antibody);
        assert_eq!(sistema.repertoire().len(), 1);
        assert_eq!(sistema.counters().quarantined, 2);
    }

    #[test]
    fn lo_hostil_se_neutraliza_y_al_repetirse_se_inmuniza() {
        let mut sistema = ImmuneSystem::new();
        let primera = sistema.screen_bytes("sensor", 5, HOSTIL.as_bytes());

        assert_eq!(primera.disposition, Disposition::Neutralize);
        assert!(primera.neutralizes());
        assert!(!primera.reaches_core());
        assert!(primera.expanded);
        assert!(!primera.recalled);
        assert_eq!(primera.class, Some(AntibodyClass::Innate));
        assert_eq!(primera.epitope, Some(DIANA_HOSTIL));

        let segunda = sistema.screen_bytes("sensor", 6, HOSTIL.as_bytes());
        assert_eq!(segunda.disposition, Disposition::Immunize);
        assert!(segunda.recalled);
        assert!(segunda.matured);
        assert!(segunda.is_familiar());
        assert_eq!(segunda.antibody, primera.antibody);
        assert!(segunda.affinity > primera.affinity);

        assert_eq!(sistema.repertoire().len(), 1);
        assert_eq!(sistema.counters().neutralized, 1);
        assert_eq!(sistema.counters().immunized, 1);
        assert_eq!(sistema.counters().expansions, 1);
        assert_eq!(sistema.counters().recalls, 1);
        for estirpe in sistema.repertoire().antibodies() {
            assert_eq!(estirpe.exposures, 1);
            assert_eq!(estirpe.neutralizations, 2);
            assert_eq!(estirpe.generation, 1);
            assert_eq!(estirpe.born_at, 5);
            assert_eq!(estirpe.last_seen, 6);
            assert_eq!(estirpe.epitope.label, DIANA_HOSTIL);
        }
    }

    #[test]
    fn la_maduracion_crece_sin_desbordar_y_esta_acotada() {
        let mut sistema = ImmuneSystem::new();
        let mut anterior = 0.0_f64;
        for ciclo in 0..48 {
            let respuesta = sistema.screen_bytes("sensor", ciclo, HOSTIL.as_bytes());
            assert!(respuesta.affinity >= anterior);
            assert!(respuesta.affinity <= 1.0);
            anterior = respuesta.affinity;
        }
        assert_eq!(sistema.repertoire().len(), 1);
        assert_eq!(sistema.counters().immunized, 47);
        for estirpe in sistema.repertoire().antibodies() {
            assert!(estirpe.affinity < 1.0);
            assert!(estirpe.is_designated());
            assert!(estirpe.is_adaptive());
            assert!(estirpe.is_terminal());
            assert_eq!(estirpe.generation, MAX_GENERATION);
            assert_eq!(estirpe.class, AntibodyClass::Regulatory);
            assert_eq!(estirpe.neutralizations, 48);
        }
    }

    #[test]
    fn la_vacuna_refuerza_estirpes_y_rechaza_dianas_vacias() {
        let mut sistema = ImmuneSystem::new();
        assert_eq!(
            sistema.vaccinate("", Epitope::new("marca", 100), 1),
            Err(ImmuneError::EmptyOrigin)
        );
        assert_eq!(
            sistema.vaccinate("operador", Epitope::new("", 100), 1),
            Err(ImmuneError::EmptyEpitope)
        );
        assert!(sistema.repertoire().is_empty());
        assert_eq!(sistema.counters().total(), 0);

        let primaria = match sistema.vaccinate("hospital", Epitope::new("cuarentena", 400), 2) {
            Ok(acta) => acta,
            Err(error) => {
                assert!(
                    error.to_string().is_empty(),
                    "vacunación primaria rechazada"
                );
                return;
            }
        };
        let refuerzo = match sistema.vaccinate("hospital", Epitope::new("cuarentena", 400), 3) {
            Ok(acta) => acta,
            Err(error) => {
                assert!(error.to_string().is_empty(), "refuerzo de vacuna rechazado");
                return;
            }
        };
        assert!(!primaria.booster);
        assert!(!primaria.matured);
        assert_eq!(primaria.affinity, AFFINITY_THRESHOLD);
        assert_eq!(primaria.epitope.label, "cuarentena");
        assert!(refuerzo.booster);
        assert!(refuerzo.matured);
        assert_eq!(refuerzo.antibody, primaria.antibody);
        assert!(refuerzo.affinity > primaria.affinity);
        assert!(primaria.label_text().starts_with("vacuna primaria"));
        assert!(refuerzo.label_text().starts_with("vacuna de refuerzo"));
        assert!(refuerzo.json().contains("\"refuerzo\":true"));
        assert!(refuerzo.json().contains("\"madurado\":true"));

        assert_eq!(sistema.repertoire().len(), 1);
        assert_eq!(sistema.census().designated, 1);
        assert_eq!(sistema.repertoire().exposures(), 0);
    }

    #[test]
    fn la_tolerancia_se_recorta_y_gobierna_el_umbral() {
        assert_eq!(ImmuneSystem::new().tolerance(), AFFINITY_THRESHOLD);
        assert_eq!(ImmuneSystem::default().tolerance(), AFFINITY_THRESHOLD);
        assert_eq!(ImmuneSystem::with_tolerance(0.25).tolerance(), 0.25);
        assert_eq!(ImmuneSystem::with_tolerance(-1.0).tolerance(), 0.0);
        assert_eq!(ImmuneSystem::with_tolerance(9.0).tolerance(), 1.0);
        assert_eq!(
            ImmuneSystem::with_tolerance(f64::NAN).tolerance(),
            AFFINITY_THRESHOLD
        );

        // Con tolerancia nula, la primera neutralización ya inmuniza.
        let mut intolerante = ImmuneSystem::with_tolerance(0.0);
        let respuesta = intolerante.screen_bytes("sensor", 1, HOSTIL.as_bytes());
        assert_eq!(respuesta.disposition, Disposition::Immunize);
        assert!(respuesta.expanded);
        assert!(!respuesta.matured);
    }

    #[test]
    fn el_repertorio_se_satura_y_avisa_por_tipos() {
        let mut sistema = ImmuneSystem::new();
        for (indice, marca) in MARCAS.iter().copied().enumerate() {
            let acta = sistema.vaccinate("operador", Epitope::new(marca, 100), indice as u64);
            if indice < MAX_ANTIBODIES {
                assert!(acta.is_ok());
            } else {
                assert_eq!(
                    acta,
                    Err(ImmuneError::RepertoireFull {
                        limit: MAX_ANTIBODIES
                    })
                );
            }
        }
        assert_eq!(sistema.repertoire().len(), MAX_ANTIBODIES);
        assert!(sistema.repertoire().is_full());
        assert_eq!(sistema.repertoire().capacity(), MAX_ANTIBODIES);
        assert!(sistema.repertoire().exposures() == 0);

        // Con el repertorio lleno un patógeno nuevo no se aprende: se declara.
        let respuesta = sistema.screen_bytes("sensor", 99, HOSTIL.as_bytes());
        assert!(respuesta.repertoire_full);
        assert!(!respuesta.expanded);
        assert!(!respuesta.recalled);
        assert_eq!(respuesta.disposition, Disposition::Neutralize);
        assert_eq!(sistema.repertoire().len(), MAX_ANTIBODIES);

        // Una ronda de olvido no basta (lo innato cae a 0.25, sobre el suelo).
        assert_eq!(sistema.forget(), 0);
        assert_eq!(sistema.repertoire().len(), MAX_ANTIBODIES);
        // La segunda sí: abre hueco y entonces el repertorio aprende.
        assert_eq!(sistema.forget(), MAX_ANTIBODIES);
        assert!(sistema.repertoire().is_empty());
        assert_eq!(sistema.repertoire().decays(), 2);
        assert_eq!(sistema.counters().forgotten, MAX_ANTIBODIES as u64);

        let posterior = sistema.screen_bytes("sensor", 100, HOSTIL.as_bytes());
        assert!(posterior.expanded);
        assert!(!posterior.repertoire_full);
        assert_eq!(sistema.repertoire().len(), 1);
    }

    #[test]
    fn el_olvido_decae_por_rondas_y_retira_la_estirpe() {
        let mut sistema = ImmuneSystem::new();
        let acta = sistema.vaccinate("operador", Epitope::new("efímera", 500), 5);
        let identificador = match acta {
            Ok(acta) => acta.antibody,
            Err(_) => 0,
        };
        assert_eq!(sistema.repertoire().len(), 1);
        assert!(sistema.antibody(identificador).is_ok());

        assert_eq!(sistema.forget(), 0);
        assert_eq!(sistema.repertoire().len(), 1);
        assert_eq!(sistema.forget(), 1);
        assert!(sistema.repertoire().is_empty());
        assert_eq!(sistema.repertoire().decays(), 2);
        assert_eq!(sistema.counters().forgotten, 1);
        assert_eq!(
            sistema.antibody(identificador),
            Err(ImmuneError::UnknownAntibody { id: identificador })
        );
        assert_eq!(sistema.repertoire().mean_affinity(), 0.0);
    }

    #[test]
    fn la_inmunidad_pasiva_es_inerte_y_determinista() {
        let mut sistema = ImmuneSystem::new();
        let respuesta = sistema.screen_bytes("sensor", 1, HOSTIL.as_bytes());
        let carga = HOSTIL.as_bytes();
        let inerte = sistema.neutralize(&respuesta, carga);

        assert_eq!(inerte.len(), carga.len());
        assert_ne!(inerte, carga);
        assert!(inerte.iter().all(|byte| byte & 0x80 != 0));
        assert_eq!(sistema.neutralize(&respuesta, carga), inerte);
        assert_eq!(sistema.clone().neutralize(&respuesta, carga), inerte);

        // Sin estirpe la semilla es la huella del antígeno: la misma carga
        // produce ruido distinto según la semilla.
        let limpia = sistema.screen_bytes("repl", 2, LIMPIA.as_bytes());
        let inerte_limpio = sistema.neutralize(&limpia, LIMPIA.as_bytes());
        assert_eq!(inerte_limpio.len(), LIMPIA.len());
        assert_ne!(inerte_limpio, LIMPIA.as_bytes().to_vec());
        assert_ne!(
            inerte_limpio,
            sistema.neutralize(&respuesta, LIMPIA.as_bytes())
        );
        assert!(inerte_limpio.iter().all(|byte| byte & 0x80 != 0));
    }

    #[test]
    fn las_huellas_son_estables_y_sensibles_al_contenido() {
        let mut sistema = ImmuneSystem::new();
        let vacio = ImmuneSystem::new();

        assert_eq!(sistema.fingerprint().len(), 64);
        assert_eq!(sistema.fingerprint(), vacio.fingerprint());
        assert_eq!(
            sistema.repertoire().fingerprint(),
            vacio.repertoire().fingerprint()
        );
        // Dominios distintos: el sistema y su repertorio no comparten huella.
        assert_ne!(sistema.fingerprint(), sistema.repertoire().fingerprint());

        sistema.screen_bytes("sensor", 1, HOSTIL.as_bytes());
        let mut gemelo = ImmuneSystem::new();
        gemelo.screen_bytes("sensor", 1, HOSTIL.as_bytes());
        assert_eq!(sistema.fingerprint(), gemelo.fingerprint());
        assert_eq!(
            sistema.repertoire().fingerprint(),
            gemelo.repertoire().fingerprint()
        );
        assert_ne!(sistema.fingerprint(), vacio.fingerprint());

        // El olvido se refleja aunque no retire ninguna estirpe.
        let mut olvidadizo = sistema.clone();
        olvidadizo.forget();
        assert_ne!(olvidadizo.fingerprint(), sistema.fingerprint());
        assert_ne!(
            olvidadizo.repertoire().fingerprint(),
            sistema.repertoire().fingerprint()
        );

        // Un clon es indistinguible en huella y en acta.
        assert_eq!(sistema.clone().fingerprint(), sistema.fingerprint());
        assert_eq!(sistema.clone().json(), sistema.json());
    }

    #[test]
    fn las_actas_json_son_coherentes_y_estables() {
        let mut sistema = ImmuneSystem::new();
        sistema.screen_bytes("sensor", 1, HOSTIL.as_bytes());
        sistema.screen_bytes("web", 2, PARADOJA.as_bytes());
        let acta = sistema.json();

        for clave in [
            "huella",
            "tolerancia",
            "ciclo",
            "censo",
            "contadores",
            "repertorio",
            "capacidad",
            "estirpes",
            "afinidad_media",
            "anticuerpos",
            "inmunizados",
        ] {
            assert!(acta.contains(clave), "clave ausente en el acta: {clave}");
        }
        assert!(acta.starts_with('{'));
        assert!(acta.ends_with('}'));
        assert_eq!(acta.matches('{').count(), acta.matches('}').count());
        assert_eq!(acta.matches('[').count(), acta.matches(']').count());
        assert_eq!(sistema.clone().json(), acta);
        assert!(sistema.label_text().contains("inmunidad ⟨"));
        assert!(sistema.repertoire().label_text().contains("repertorio ⟨"));
        assert!(acta.contains(&sistema.fingerprint()));
    }

    #[test]
    fn la_burbuja_juzgada_se_lee_igual_que_la_carga_cruda() {
        let mut pasarela = Gateway::new();
        let burbuja = pasarela.admit("sensor", 7, HOSTIL.as_bytes());
        assert_eq!(burbuja.payload_digest, sha256(HOSTIL.as_bytes()));

        let mut por_burbuja = ImmuneSystem::new();
        let mut por_carga = ImmuneSystem::new();
        let lectura = por_burbuja.scan(burbuja);
        let crudo = por_carga.screen_bytes("sensor", 7, HOSTIL.as_bytes());

        assert_eq!(lectura.antigen, crudo.antigen);
        assert_eq!(lectura.disposition, crudo.disposition);
        assert_eq!(lectura.affinity, crudo.affinity);
        assert_eq!(lectura.class, crudo.class);
        assert_eq!(lectura.epitope, crudo.epitope);
        assert_eq!(por_burbuja.fingerprint(), por_carga.fingerprint());

        // El paquete de la pasarela produce la misma lectura.
        let paquete = Packet::new("sensor", 7, HOSTIL.as_bytes());
        let mut por_paquete = ImmuneSystem::new();
        let empaquetado = por_paquete.inspect(&paquete);
        assert_eq!(empaquetado.antigen, crudo.antigen);
        assert_eq!(empaquetado.disposition, crudo.disposition);
        assert_eq!(por_paquete.fingerprint(), por_carga.fingerprint());
    }

    #[test]
    fn todo_error_tiene_acta_legible() {
        for error in [
            ImmuneError::EmptyOrigin,
            ImmuneError::EmptyEpitope,
            ImmuneError::RepertoireFull {
                limit: MAX_ANTIBODIES,
            },
            ImmuneError::UnknownAntibody { id: 7 },
            ImmuneError::NotFinite { field: "afinidad" },
        ] {
            assert!(!error.to_string().trim().is_empty());
            let dinamico: &dyn std::error::Error = &error;
            assert!(!dinamico.to_string().trim().is_empty());
            assert_eq!(error, error.clone());
        }
    }

    #[test]
    fn las_utilidades_de_formato_son_totales() {
        assert_eq!(clamp01(-3.0), 0.0);
        assert_eq!(clamp01(0.25), 0.25);
        assert_eq!(clamp01(7.0), 1.0);
        assert_eq!(clamp01(f64::NAN), 0.0);
        assert_eq!(clamp01(f64::INFINITY), 0.0);

        assert_eq!(json_f64(0.125), "0.125000");
        assert_eq!(json_f64(-0.0), "-0.000000");
        assert_eq!(json_f64(f64::NAN), "0.000000");
        assert_eq!(json_f64(f64::NEG_INFINITY), "0.000000");
        assert_eq!(json_opt_u64(Some(7)), "7");
        assert_eq!(json_opt_u64(None), "null");
        assert_eq!(json_opt_str(Some("diana")), "\"diana\"");
        assert_eq!(json_opt_str(None), "null");
        assert_eq!(json_escape("a\"b\\c\nd\te"), "a\\\"b\\\\c\\nd\\te");
        assert_eq!(json_escape("carga\u{1}normal"), "carga?normal");
        assert_eq!(json_escape("sin controles"), "sin controles");

        assert_eq!(classify_class(0, 0.1), AntibodyClass::Innate);
        assert_eq!(classify_class(1, 0.5), AntibodyClass::Mucosal);
        assert_eq!(classify_class(2, 0.7), AntibodyClass::Memory);
        assert_eq!(classify_class(0, 1.0), AntibodyClass::Regulatory);
        assert_eq!(classify_class(0, 0.5), AntibodyClass::Innate);
    }
}
