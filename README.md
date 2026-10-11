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
| `cargo test` | **39 / 39 pruebas en verde** · 0 advertencias |
| `cargo test --release` | **39 / 39** · arnés de estrés en 0.66 s |
| Dependencias externas | **0** (`Cargo.lock` contiene sólo `bara`) |
| `unsafe` | **0** (`#![forbid(unsafe_code)]` en `src/lib.rs`) |

---

## Arquitectura

El *kernel* vive en `src/lib.rs` (crate `bara`) para que el binario y la suite de
integración de `tests/` compartan **exactamente los mismos tipos** — cero
duplicación del núcleo. `src/main.rs` es un consumidor delgado que orquesta las
trece fases del génesis.

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
| `src/repl.rs` | 790 | **Oráculo REPL**: lengua natural → programa *Shoresh*, meta‑comandos |
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

# Suite completa: 29 pruebas de integración + 10 de estrés
cargo test
cargo test --release -- --nocapture
```

El binario admite un guion por `stdin`: cada línea se interpreta como lengua
natural o como meta‑comando del oráculo (`:estado`, `:memoria`, `:zk`,
`:cuántica`, `:deshacer`, `:salir`, …).

## Suite de pruebas

| Archivo | Líneas | Pruebas | Cobertura |
|---|---:|---:|---|
| `tests/integration_suite.rs` | 1309 | **29** | léxico, runtime/Belnap, memoria holográfica, autopoiesis, regiones, ZK‑SNARK, FFI, `Δ⁻¹`, cuántica/Bell, malla (bus vs hilos), códec *wire*, Metal‑IR, oráculo REPL, pipeline nativo |
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

## Licencia

MIT — véase `Cargo.toml`.

