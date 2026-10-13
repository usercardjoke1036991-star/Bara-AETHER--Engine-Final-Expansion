//! # Region Inference Memory Model — `memory_region.rs`
//!
//! Modelo de memoria determinista de Bara. Sustituye el *garbage collector*
//! y el *borrow checker* por un **analizador de regiones en tiempo de
//! compilación**: la vida útil de cada dato se infiere a partir de sus
//! rangos de acceso y se materializa como una región léxica anidada.
//!
//! Propiedades del modelo:
//! * **Determinista** — sin GC. La liberación es estática: al cerrar una
//!   región, todos sus descendientes se disuelven en cascada.
//! * **Jerárquico** — las regiones forman un bosque padre/hijo (`depth`),
//!   lo que permite anidar ámbitos sin ambigüedad de propiedad.
//! * **Zero-Copy** — una región puede exponerse simultáneamente a CPU y GPU
//!   mediante [`ZeroCopyHandle`], sin copia de datos (base de la memoria
//!   compartida CPU/GPU).
//! * **Armónica** — el reparto espacial de las regiones vivas sigue una
//!   retícula áurea (pasos de Fibonacci, orden `i·φ`): véase
//!   [`RegionTable::fractal_layout`].
//!
//! La inferencia (`RegionAnalyzer::infer`) agrupa accesos cuyos rangos de
//! vida `[birth, death)` se solapan: si dos datos coexisten, comparten
//! región; si no, se separan en regiones disjuntas.

use crate::fractal_geometry::FractalLayout;
use std::collections::BTreeMap;

/// Identificador opaco de una región de memoria.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RegionId(pub usize);

/// Clase de región: dónde vive y cómo se comparte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    /// Pila (marco léxico de corta vida).
    Stack,
    /// Montículo (datos de vida extendida).
    Heap,
    /// Compartida CPU/GPU (base *zero-copy*).
    Shared,
    /// Génesis: región inmortal creada ex nihilo.
    Genesis,
}

impl RegionKind {
    /// Nombre legible de la clase de región.
    pub fn label(&self) -> &'static str {
        match self {
            RegionKind::Stack => "STACK",
            RegionKind::Heap => "HEAP",
            RegionKind::Shared => "SHARED",
            RegionKind::Genesis => "GENESIS",
        }
    }

    /// Glifo asociado.
    pub fn glyph(&self) -> &'static str {
        match self {
            RegionKind::Stack => "⇱",
            RegionKind::Heap => "⌂",
            RegionKind::Shared => "⇄",
            RegionKind::Genesis => "✦",
        }
    }
}

/// Dispositivo consumidor de una vista de memoria.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Device {
    /// Unidad central de proceso.
    Cpu,
    /// Unidad de procesamiento gráfico.
    Gpu,
}

impl Device {
    /// Nombre legible del dispositivo.
    pub fn label(&self) -> &'static str {
        match self {
            Device::Cpu => "CPU",
            Device::Gpu => "GPU",
        }
    }
}

/// Una región de memoria con su extensión y jerarquía.
#[derive(Debug, Clone)]
pub struct Region {
    /// Identificador de la región.
    pub id: RegionId,
    /// Nombre simbólico.
    pub name: String,
    /// Clase de región.
    pub kind: RegionKind,
    /// Extensión en bytes.
    pub bytes: usize,
    /// Región padre, si la hay.
    pub parent: Option<RegionId>,
    /// Profundidad en el bosque de regiones (raíz = 0).
    pub depth: usize,
}

/// Vista de copia cero sobre una región de memoria.
#[derive(Debug, Clone)]
pub struct ZeroCopyHandle {
    /// Etiqueta de la vista.
    pub label: String,
    /// Región subyacente.
    pub region: RegionId,
    /// Desplazamiento dentro de la región.
    pub offset: usize,
    /// Longitud de la vista.
    pub len: usize,
    /// Dispositivo que la consume.
    pub device: Device,
}

/// Acceso con rango de vida (en *ticks*) usado por la inferencia de regiones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Access {
    /// Etiqueta del dato accedido.
    pub label: String,
    /// Extensión en bytes.
    pub bytes: usize,
    /// Clase de región deseada.
    pub kind: RegionKind,
    /// Tick de nacimiento (inclusive).
    pub birth: u64,
    /// Tick de muerte (exclusive).
    pub death: u64,
}

/// Resultado de la inferencia de regiones.
#[derive(Debug, Clone, Default)]
pub struct RegionPlan {
    /// Tabla de regiones materializadas.
    pub table: RegionTable,
    /// Asignación dato → región inferida.
    pub assignment: BTreeMap<String, RegionId>,
}

/// Tabla (léxico) de regiones vivas de un programa.
#[derive(Debug, Clone, Default)]
pub struct RegionTable {
    regions: Vec<Region>,
    next: usize,
}

impl RegionTable {
    /// Crea una tabla de regiones vacía.
    pub fn new() -> Self {
        Self::default()
    }

    /// Introduce una región y devuelve su identificador.
    pub fn introduce(
        &mut self,
        name: impl Into<String>,
        kind: RegionKind,
        bytes: usize,
        parent: Option<RegionId>,
    ) -> RegionId {
        let id = RegionId(self.next);
        self.next += 1;
        let depth = parent
            .and_then(|p| self.get(p))
            .map(|r| r.depth + 1)
            .unwrap_or(0);
        self.regions.push(Region {
            id,
            name: name.into(),
            kind,
            bytes,
            parent,
            depth,
        });
        id
    }

    /// Recupera una región por identificador.
    pub fn get(&self, id: RegionId) -> Option<&Region> {
        self.regions.iter().find(|r| r.id == id)
    }

    /// Todas las regiones de la tabla.
    pub fn regions(&self) -> &[Region] {
        &self.regions
    }

    /// Número de regiones vivas.
    pub fn len(&self) -> usize {
        self.regions.len()
    }

    /// ¿Tabla vacía?
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Suma de bytes direccionados por todas las regiones.
    pub fn total_bytes(&self) -> usize {
        self.regions.iter().map(|r| r.bytes).sum()
    }

    /// Profundidad máxima del bosque de regiones.
    pub fn max_depth(&self) -> usize {
        self.regions.iter().map(|r| r.depth).max().unwrap_or(0)
    }

    /// Profundidad de una región concreta.
    pub fn depth_of(&self, id: RegionId) -> usize {
        self.get(id).map(|r| r.depth).unwrap_or(0)
    }

    /// Reparto espacial (**retícula áurea**) de las regiones vivas.
    ///
    /// Cada región recibe una ranura lógica cuyo paso es el Fibonacci
    /// inmediatamente mayor que su extensión en bytes, en el orden de la
    /// secuencia de *phyllotaxis* `i·φ` (véase [`crate::fractal_geometry`]).
    /// El relleno interno queda acotado por `1 − 1/φ ≈ 38.2 %`, frente al
    /// `50 %` del reparto por potencias de dos.
    pub fn fractal_layout(&self) -> FractalLayout {
        let widths: Vec<usize> = self.regions.iter().map(|region| region.bytes).collect();
        FractalLayout::plan_from(&widths)
    }

    /// Fragmentación medida de la retícula de regiones, en `[0,1)`.
    pub fn fragmentation(&self) -> f64 {
        self.fractal_layout().fragmentation
    }

    /// Ranura áurea de una región concreta, si existe.
    pub fn slot_of(&self, id: RegionId) -> Option<u64> {
        let position = self.regions.iter().position(|region| region.id == id)?;
        self.fractal_layout().slot_of(position)
    }

    /// Comprueba que `[offset, offset + len)` cabe dentro de la región.
    pub fn contains(&self, id: RegionId, offset: usize, len: usize) -> bool {
        self.get(id)
            .map(|r| offset.saturating_add(len) <= r.bytes)
            .unwrap_or(false)
    }

    /// Crea una vista de copia cero si el rango cabe en la región.
    pub fn share(
        &self,
        label: impl Into<String>,
        region: RegionId,
        offset: usize,
        len: usize,
        device: Device,
    ) -> Option<ZeroCopyHandle> {
        if self.contains(region, offset, len) {
            Some(ZeroCopyHandle {
                label: label.into(),
                region,
                offset,
                len,
                device,
            })
        } else {
            None
        }
    }
}

/// Analizador de inferencia de regiones por rangos de vida.
///
/// No hay dependencias ni estado: la inferencia es una función pura y
/// determinista sobre la lista de accesos.
pub struct RegionAnalyzer;

impl RegionAnalyzer {
    /// Agrupa accesos cuyos rangos de vida `[birth, death)` se solapan en
    /// regiones comunes y devuelve el plan de asignación.
    ///
    /// Algoritmo: se ordenan los accesos por `birth` y se agrupan mientras el
    /// siguiente acceso nazca antes de que muera el grupo (`birth <= max_death`).
    /// Cada grupo se materializa como una región cuyo tamaño es la suma de
    /// tamaños y cuya clase es la del primer acceso del grupo.
    pub fn infer(accesses: &[Access]) -> RegionPlan {
        let mut plan = RegionPlan::default();
        if accesses.is_empty() {
            return plan;
        }

        // Índices ordenados por nacimiento, con desempate estable por posición.
        let mut order: Vec<usize> = (0..accesses.len()).collect();
        order.sort_by_key(|&i| (accesses[i].birth, i));

        // Clústeres: (muerte máxima, índices de acceso).
        let mut clusters: Vec<(u64, Vec<usize>)> = Vec::new();
        for &i in &order {
            let access = &accesses[i];
            match clusters.last_mut() {
                Some((max_death, members)) if access.birth <= *max_death => {
                    *max_death = (*max_death).max(access.death);
                    members.push(i);
                }
                _ => clusters.push((access.death, vec![i])),
            }
        }

        for (idx, (_, members)) in clusters.iter().enumerate() {
            let kind = accesses[members[0]].kind;
            let bytes: usize = members.iter().map(|&i| accesses[i].bytes).sum();
            let id = plan
                .table
                .introduce(format!("region-{}", idx + 1), kind, bytes, None);
            for &i in members {
                plan.assignment.insert(accesses[i].label.clone(), id);
            }
        }

        plan
    }
}
