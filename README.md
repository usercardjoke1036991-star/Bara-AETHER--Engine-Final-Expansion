# בָּרָא · Bara — Motor AETHER‑Ω (Final Expansion)

**Bara** (hebreo: *«creó»*) es un lenguaje de programación **trascendental** y un
*kernel* escrito en **Rust puro (`std` únicamente, cero dependencias)**, donde
cada programa se escribe con **raíces triconsonánticas** (*shoresh*) y se evalúa
con una **lógica paraconsistente de Belnap** que tolera la contradicción en lugar
de explotar.

> *El lenguaje respira: `בָּרָא`.*

---

## Estado del proyecto — Fase 4 completada

| Verificación | Resultado |
|---|---|
| `cargo build` (debug) | EXIT 0 · **0 advertencias** |
| `cargo build --release` | EXIT 0 · `opt-level=3`, `lto=true`, `codegen-units=1`, `panic="abort"` |
| `cargo test` | **40 / 40 pruebas en verde** · 0 advertencias |
| `cargo test --release` | **40 / 40** · arnés de estrés en 0.66 s |
| Dependencias externas | **0** (`Cargo.lock` contiene sólo `bara`) |
| `unsafe` | **0** (`#![forbid(unsafe_code)]` en `src/lib.rs`) |

---

## Arquitectura

El *kernel* vive en `src/lib.rs` (crate `bara`) para que el binario y la suite de
integración de `tests/` compartan **exactamente los mismos tipos** — cero
duplicación del núcleo. `src/main.rs` es un consumidor delgado que orquesta las
trece fases del génesis, y `src/bin/bara_oracle.rs` es el **binario dedicado a la
manifestación interactiva**: arranca el pipeline nativo y entrega el control al
oráculo sin volcar antes todo el log del génesis.

| Módulo | Líneas | Responsabilidad |
|---|---:|---|
| `src/lexer.rs` | 391 | Análisis léxico **triconsonántico** total: raíces, *nikud* plegado, `!!` (fusión), invariante ante entradas hostiles |
| `src/runtime.rs` | 1143 | Evaluador **Belnap** (`⊤ ⊥ f t`), **autopoiesis** (axiogénesis de raíces desconocidas), **memoria holográfica de entropía 0**, log ontológico, rollback integrado |
| `src/memory_region.rs` | 290 | Inferencia de **regiones por rangos de vida** (*lifetimes*) y vistas **zero‑copy** CPU/GPU |
| `src/zk_proof.rs` | 459 | Pipeline **ZK‑SNARK** didáctico sobre `𝔽ₚ` (`P = 2⁶¹ − 1`), Fiat–Shamir |
| `src/ffi_ingest.rs` | 376 | **Ingesta omnívora** C/Python → AST *Shoresh* (saneamiento, valencia, riesgo) |
| `src/temporal_rollback.rs` | 264 | Navegación temporal y **rollback atómico `Δ⁻¹`** (`push`/`pop`/`replace`) |
| `src/quantum_native.rs` | 940 | **Qubits nativos** `Qubit<\|ψ⟩>`, amplitudes complejas, pares de Bell, colapso determinista |
| `src/mesh_sync.rs` | 1057 | **Malla global holográfica**: relojes vectoriales, bus en proceso e hilos `std` |
| `src/metal_ir.rs` | 949 | **Metal‑IR**: *layout* abstracto de registros, ISA de 32 bits y **bypass del driver** |
| `src/repl.rs` | 828 | **Oráculo REPL**: lengua natural → programa *Shoresh*, meta‑comandos, carga de manifiestos |
| `src/bin/bara_oracle.rs` | 331 | **Oráculo en vivo**: binario dedicado (pipeline nativo + manifiestos + bucle interactivo) |
| `src/lib.rs` | 53 | *Crate root*: mapa de módulos, reexportaciones, invariantes |
| `src/main.rs` | 756 | Génesis de 13 fases + bucle del oráculo |

## Las 13 fases del génesis

`FASE 1` léxico triconsonántico · `FASE 2` ejecución ontológica · `FASE 3` autopsia
autopoiética · `FASE 4` memoria holográfica de entropía cero · `FASE 5` tensión
paraconsistente (no‑explosión) · `FASE 6` inferencia de regiones · `FASE 7`
verificación ZK‑SNARK del AST · `FASE 8` ingesta FFI omnívora · `FASE 9`
navegación temporal y rollback `Δ⁻¹` · `FASE 10` tipos cuánticos nativos · `FASE 11`
malla global de memoria holográfica · `FASE 12` Metal‑IR (bypass del driver) ·
`FASE 13` oráculo REPL interactivo.

## Invariantes globales

1. **Sólo `std`** — cero dependencias externas.
2. **Totalidad** — ninguna entrada provoca un pánico: lo incomprensible se degrada
   a un valor **tolerado**.
3. **Determinismo** — no hay aleatoriedad real: todo colapso o huella deriva de
   hashes **FNV‑1a** estables (reproducible *bit a bit*).
4. **Sin `unsafe`** — el *kernel* entero es Rust seguro.

---

## Compilar, ejecutar y probar

```bash
# Compilación limpia (debug y release optimizado)
cargo build
cargo build --release

# Ejecuta el génesis completo (13 fases) y, si hay terminal, entra en el oráculo
cargo run --release

# Fuerza el bucle interactivo aunque la entrada esté redirigida (CI / guiones)
cargo run --release -- --oracle

# ORÁCULO EN VIVO: arranca el pipeline nativo y conversa directamente
cargo run --release --bin bara_oracle

# Conversa un manifiesto de raíces/lengua natural (sesión scriptada)
cargo run --release --bin bara_oracle -- manifests/shoresh_manifest.bara

# Un turno suelto, sin pipeline y sin bucle interactivo (humo de integración)
cargo run --release --bin bara_oracle -- --bare --no-live -s "ברא שמר עבד"

# El manifiesto también puede llegar por stdin (`-`)
type manifests\shoresh_manifest.bara | cargo run --release --bin bara_oracle -- --no-live -

# Suite completa: 30 pruebas de integración + 10 de estrés
cargo test
cargo test --release -- --nocapture
```

El binario `bara` admite un guion por `stdin`: cada línea se interpreta como
lengua natural o como meta‑comando del oráculo (`:estado`, `:memoria`, `:zk`,
`:cuántica`, `:deshacer`, `:salir`, …).

### Oráculo en vivo (`bara_oracle`)

`bara_oracle` es el punto de entrada interactivo: enciende el pipeline nativo
(ψ · malla · Metal‑IR · ZK) y cede el control al oráculo sin imprimir antes las
trece fases del génesis.

```bash
cargo run --release --bin bara_oracle [OPCIONES] [MANIFIESTO...]

#   MANIFIESTO...        rutas a conversar en orden; `-` lee de stdin
#   -m, --manifest RUTA  añade un manifiesto (repetible)
#   -s, --say TEXTO      conversa un turno suelto (repetible)
#   --bare               no enciende ψ · malla · Metal-IR · ZK
#   --no-live            no entra en el bucle interactivo
#   -f, --force-live     entra en el bucle aunque stdin esté redirigido
#   -h, --help / -V, --version
```

Un **manifiesto** (`manifests/*.bara`) es texto con un turno por línea: raíces
triconsonánticas, lengua natural o meta‑comandos. Las líneas vacías y los
comentarios `#` (de línea completa o de cola) se descartan, así que el documento
puede documentarse en prosa sin contaminar el programa compilado. Si el guion
cierra con `:salir`, la sesión termina ahí (`-f` fuerza el bucle interactivo).

```text
$ cargo run --release --bin bara_oracle -- manifests/shoresh_manifest.bara
── PIPELINE NATIVO · ψ · MALLA · METAL-IR · ZK ───────────────
   superposición ψ       : alef=SUPERPOSITION(|α|²=0.750, |β|²=0.250) · bet=SUPERPOSITION(|α|²=0.360, |β|²=0.640)
   entrelazado «Φ⁺»      : PARACONSISTENT(⊤=0.500, ⊥=0.500)
   colapso no local      : alef ⇒ CLASSICAL(true)
   certificado ZK        : «AST-Bara-génesis» · 3 invariante(s) · verificado=true
   Metal-IR «manifiesto.metal»: 68 instrucción(es) · anillo×128 · 68 syscalls evitadas
   ── manifiesto: 31 turno(s) ──
   ⋯ ברא› !!
      ⟶ 2 evento(s) · 0 Δ reversibles · Δ⁻¹ interceptó 1 paradoja(s) · cima=PARACONSISTENT(⊤=1.000, ⊥=0.000)
      ⇢ shoresh compilado: !!
   ⋯ ברא› crea un mundo con luz y ordena el caos
      ⟶ 10 evento(s) · 4 Δ reversibles · axiomas+3 · cima=PARACONSISTENT(⊤=0.530, ⊥=0.500)
      ⇢ shoresh compilado: ברא תחא בהמ ליב

   informe de la sesión: 31 turno(s) · 69 evento(s) · 2 rollback(s) · 11 axioma(s) nuevo(s) · raíces: !! ברא חכם עבד שמר שפט …
```

## Suite de pruebas

| Archivo | Líneas | Pruebas | Cobertura |
|---|---:|---:|---|
| `tests/integration_suite.rs` | 1336 | **30** | léxico, runtime/Belnap, memoria holográfica, autopoiesis, regiones, ZK‑SNARK, FFI, `Δ⁻¹`, cuántica/Bell, malla (bus vs hilos), códec *wire*, Metal‑IR, oráculo REPL, manifiestos, pipeline nativo |
| `tests/stress_test.rs` | 569 | **10** | PRNG SplitMix64 propio: inundación de paradojas, rollback profundo, mutación masiva del AST, tormenta de memoria, fuente adversarial, tormenta de conflictos en la malla, tormenta cuántica, presión de Metal‑IR, tormenta FFI, conversación hostil del oráculo |

Los *tests* enlazan el mismo *kernel* (`use bara::…`), por lo que no hay copias
divergentes de los tipos: lo que pasa en las pruebas es lo que ejecuta el binario.

## Salida de ejemplo

```
── FASE 2 · EJECUCIÓN ONTOLÓGICA (LOG DEL GÉNESIS) ────────────
  [ 1] ⟐ léxico     raíz ברא reconocida ⇒ manifestar (creación ex nihilo)
  [ 2] ⟐ léxico     raíz חכם reconocida ⇒ superponer (coherencia adaptativa)
  ...
  [80] ⊗ pliegue    conjunción/disyunción ⇒ PARACONSISTENT(⊤=0.530, ⊥=1.000)
  [87] ⊙ colapso    PARACONSISTENT(⊤=0.710, ⊥=1.000) ⊳ observación ⊤∧⊥ (contradicción tolerada)
  [95] ⧗ Δ⁻¹ rollback «oráculo: Δ⁻¹ manual al marcador #11» ⊳ 2 deltas revertidos en 0 µs

✦ Génesis completado. El lenguaje respira: בָּרָא.
```

El resumen de la sesión reporta, entre otros: `32 evento(s) · 2 rollback(s) ·
7 axioma(s) nuevo(s)` y el inventario completo de raíces conocidas y
sintetizadas.

## Límites declarados

* La malla es **en proceso** (bus e hilos `std`); el códec *wire* es el punto de
  extensión para transporte de red real.
* **Metal‑IR es un modelo abstracto simulado**: no hay hardware ni *driver*
  real, sólo el *layout* de registros y el *bypass* modelados.
* El pipeline **ZK es didáctico** (campo *toy* de 61 bits, compromisos por hash,
  un punto de evaluación): demuestra el flujo, no es criptografía de producción.
* El colapso cuántico es **determinista** (semilla FNV‑1a), no aleatoriedad
  física: la intención es reproducibilidad total.
* El códec *wire* es bit‑exacto para estados clásicos y paraconsistentes; las
  superposiciones se **renormalizan** al decodificar.

## Flujo de desarrollo

```
main ──●─────────────────────────────●──▶  rama estable (sólo fusiones verificadas)
        \                           /
   dev   ●──●──●──●──●──●──●──●──●──●      desarrollo activo (trabajo diario)
```

* **`main`** — rama estable y **protegida**: sólo recibe cambios por *pull request*
  que pasa el CI (4 checks obligatorios) e historial lineal; sin push directo ni
  *force push*.
* **`dev`** — rama de integración: aquí vive el trabajo diario; cada *commit*
  mantiene el kernel compilando sin advertencias y con la suite completa en verde.
* El remoto `origin` sirve `dev` como rama por defecto de trabajo; `main` es la
  cara publicada / de referencia.

Ciclo típico:

```bash
git switch dev                  # rama activa de desarrollo
cargo test && cargo test --release
git commit -am "…"              # o commits temáticos por módulo
git push                        # upstream ya configurado (origin/dev)

# Cuando dev está verde, se promueve a estable mediante PR
# (`main` protegida: sin push directo, CI obligatorio, historial lineal):
gh pr create --base main --head dev --title "promoción dev → main"   # o desde la web
gh pr merge --squash            # squash ⇒ historial lineal; exige los 4 checks verdes
git switch dev
```

### Integración continua (GitHub Actions)

`.github/workflows/ci.yml` se dispara con `push` y `pull_request` sobre `dev` y
`main` y ejecuta:

| Job | Matriz | Comando | ¿Bloquea la fusión? |
|---|---|---|---|
| `CI (…, debug)` · `CI (…, release)` | `ubuntu-latest` y `windows-latest` × `debug` y `release` (4 jobs) | `cargo test --all-targets --workspace [--release] --locked` | **Sí** |
| `Lints (clippy + rustfmt)` | `ubuntu-latest` | `cargo clippy … -- -D warnings` (**bloqueante**) · `cargo fmt --all --check` (informativo) | **Sí** (clippy) |

Política de **cero advertencias**: el *workflow* exporta `RUSTFLAGS=-D warnings`,
así que cualquier aviso de `rustc` (en la biblioteca, en el binario o en las
pruebas) hace fallar el job. `--locked` garantiza que se compila exactamente el
`Cargo.lock` publicado.

**Estado de la puerta de calidad.** Clippy está **limpio**: los 10 lints que
quedaban —`map_entry` e `iter_cloned_collect` (`src/mesh_sync.rs`),
`manual_div_ceil` (`src/metal_ir.rs`), `approx_constant` ×2 y `manual_clamp`
(`src/runtime.rs`), `should_implement_trait` ×3 (`src/zk_proof.rs`) y `len_zero`
(`tests/integration_suite.rs`)— están resueltos (`Fp` implementa ahora
`Add`/`Sub`/`Mul` de `std::ops`), así que el job **bloquea** la fusión.

Queda una única deuda **estilística**: `cargo fmt --all --check` sigue marcando
diferencias porque el kernel usa alineación manual deliberada (cadenas y firmas
más anchas que los valores por defecto de `rustfmt`); por eso ese paso se ejecuta
como informativo (`continue-on-error` a nivel de paso). Para cerrarlo:
`cargo fmt --all`, commit del reflujo y quitar el flag del paso.

### Protección de la rama `main`

Objetivo: **prohibir los push directos** a `main` y admitir sólo PR que pasen el
CI (idealmente promociones `dev → main`).

> **Aviso verificado**: la API de protección de ramas —y también la de
> *rulesets*— responde `403 Upgrade to GitHub Pro or make this repository public
> to enable this feature.` porque el repositorio es **privado** y la cuenta está
> en plan **Free**. Así que `.github/main-protection.json` **no se puede aplicar
> todavía**: hay que hacer el repositorio **público** o pasar a **GitHub Pro**.
> Los pasos de abajo (o el comando `gh api` de la sección 5) quedan listos para
> ese día.

1. Espera a que el CI se ejecute **al menos una vez**: los nombres de los
   *status checks* sólo aparecen en la lista después de la primera ejecución.
2. Entra en `Settings → Rules → Rulesets` (o `Settings → Branches → Add branch
   protection rule`).
3. *Branch name pattern*: `main`.
4. Marca:
   * ✅ **Require a pull request before merging** — *Required approvals*: `0`
     (podrás fusionar tu propio PR, pero **no** hacer push directo).
   * ✅ **Require status checks to pass before merging** + **Require branches to be
     up to date before merging**, y selecciona los cuatro checks obligatorios:
     `CI (ubuntu-latest, debug)`, `CI (ubuntu-latest, release)`,
     `CI (windows-latest, debug)`, `CI (windows-latest, release)`.
   * ✅ **Require linear history** · ✅ **Require conversation resolution**.
   * ✅ **Do not allow bypassing the above settings** — aplica también a los
     administradores y es lo que **realmente bloquea el push directo**.
   * ❌ *Allow force pushes* · ❌ *Allow deletions*.
5. Alternativa automatizada (el cuerpo JSON ya está versionado en el repo):

   ```bash
   gh auth login            # sólo la primera vez
   gh api -X PUT \
     repos/usercardjoke1036991-star/Bara-AETHER--Engine-Final-Expansion/branches/main/protection \
     -H "Accept: application/vnd.github+json" \
     --input .github/main-protection.json
   ```

   (Equivalente con `curl` y un PAT: el cuerpo es exactamente
   `.github/main-protection.json`.)

Con esto el ciclo queda blindado: `dev` como rama de trabajo con CI verde → PR
`dev → main` con 4 checks obligatorios → fusión con historial lineal, sin push
directo ni *force push*.

## Licencia

MIT © 2026 usercardjoke1036991-star — véase el archivo [`LICENSE`](LICENSE).


