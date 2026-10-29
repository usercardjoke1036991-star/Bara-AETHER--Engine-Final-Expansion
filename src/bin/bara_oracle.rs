#![forbid(unsafe_code)]
//! # Bara — Oráculo en vivo (`bara_oracle`)
//!
//! Binario dedicado a la **manifestación interactiva**. A diferencia de `bara`
//! (el génesis de trece fases, que vuelca todo el log ontológico antes de
//! ceder el control), este ejecutable arranca un [`BaraRuntime`] virgen,
//! enciende opcionalmente el pipeline nativo (ψ · malla · Metal‑IR · ZK) y
//! entrega el control al [`Oracle`]: la conversación empieza en el primer turno.
//!
//! ## Uso
//! ```text
//! bara_oracle [OPCIONES] [MANIFIESTO...]
//! ```
//!
//! * `MANIFIESTO...` — rutas de manifiestos a conversar en orden. Una ruta `-`
//!   lee el manifiesto de la entrada estándar.
//! * `-m, --manifest <RUTA>` — añade un manifiesto (repetible).
//! * `-s, --say <TEXTO>` — conversa un turno suelto (repetible).
//! * `--bare` — no enciende el pipeline nativo.
//! * `--no-live` — no entra en el bucle interactivo aunque haya terminal.
//! * `-f, --force-live` — entra en el bucle aunque la entrada esté redirigida
//!   (útil en integración continua y guiones).
//! * `-h, --help` · `-V, --version`.
//!
//! ## Ejemplo
//! ```text
//! cargo run --release --bin bara_oracle -- --manifest manifests/shoresh_manifest.bara
//! ```
//!
//! El binario **nunca falla**: una ruta ilegible o una opción desconocida se
//! toleran con un aviso y la sesión continúa (el kernel es total, y su interfaz
//! también).

use bara::lexer::Lexer;
use bara::memory_region::Device;
use bara::quantum_native::{Amplitude, BellPhase};
use bara::repl::{self, Oracle, OracleTurn};
use bara::runtime::BaraRuntime;
use std::io::{self, Read};

/// Muestra canónica traducida a Metal‑IR cuando no hay manifiesto que bajar.
const GENESIS_SAMPLE: &str = "ברא שמר עבד חכם !!";

/// Texto de ayuda de la interfaz.
const USAGE: &str = "\
bara_oracle — oráculo en vivo de Bara (בָּרָא)

USO:
      bara_oracle [OPCIONES] [MANIFIESTO...]

MANIFIESTOS (cada línea no vacía y sin `#` es un turno):
      RUTA                conversa el manifiesto en raíces y/o lengua natural
      -                   lee el manifiesto de la entrada estándar
      -m, --manifest RUTA añade un manifiesto (puede repetirse)
      -s, --say TEXTO     conversa un turno suelto (puede repetirse)

PIPELINE Y SESIÓN:
      --bare              no enciende ψ · malla · Metal-IR · ZK
      --no-live           no entra en el bucle interactivo
      -f, --force-live    entra en el bucle aunque la entrada esté redirigida

GENERAL:
      -h, --help          esta ayuda
      -V, --version       versión del kernel

DENTRO DEL ORÁCULO:
      :ayuda :estado :memoria :tiempo :cuántica :malla :metal :zk :deshacer :salir
      y en lengua natural o en raíces: «crea un mundo con luz», ברא שמר עבד";

// ─────────────────────────────────────────────────────────────────────────
// Línea de órdenes
// ─────────────────────────────────────────────────────────────────────────

/// Petición resuelta a partir de los argumentos.
enum Request {
    /// Mostrar la ayuda.
    Help,
    /// Mostrar la versión del kernel.
    Version,
    /// Arrancar una sesión con esta configuración.
    Run(Cli),
}

/// Configuración de una sesión del oráculo.
#[derive(Debug, Default)]
struct Cli {
    /// Rutas de manifiestos, en orden de conversación (`-` = stdin).
    manifests: Vec<String>,
    /// Turnos sueltos, conversados antes de los manifiestos.
    says: Vec<String>,
    /// No encender el pipeline nativo.
    bare: bool,
    /// No entrar en el bucle interactivo.
    no_live: bool,
    /// Entrar en el bucle interactivo aunque la entrada esté redirigida.
    force_live: bool,
}

/// Interpreta los argumentos. Un error es un aviso tolerado, nunca un fallo.
fn parse_args(args: &[String]) -> Result<Request, String> {
    let mut cli = Cli::default();
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        match arg {
            "-h" | "--help" => return Ok(Request::Help),
            "-V" | "--version" => return Ok(Request::Version),
            "--bare" => cli.bare = true,
            "--no-live" => cli.no_live = true,
            "-f" | "--force-live" => cli.force_live = true,
            "-m" | "--manifest" => match args.get(index + 1) {
                Some(path) => {
                    cli.manifests.push(path.clone());
                    index += 1;
                }
                None => return Err("«--manifest» exige una ruta".to_string()),
            },
            "-s" | "--say" => match args.get(index + 1) {
                Some(text) => {
                    cli.says.push(text.clone());
                    index += 1;
                }
                None => return Err("«--say» exige un texto".to_string()),
            },
            other if other.starts_with('-') && other != "-" => {
                return Err(format!("opción desconocida «{}»", other));
            }
            other => cli.manifests.push(other.to_string()),
        }
        index += 1;
    }
    Ok(Request::Run(cli))
}

// ─────────────────────────────────────────────────────────────────────────
// Arranque
// ─────────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cli = match parse_args(&args) {
        Ok(Request::Help) => {
            println!("{}", USAGE);
            return;
        }
        Ok(Request::Version) => {
            println!("bara_oracle {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Ok(Request::Run(cli)) => cli,
        Err(message) => {
            println!(
                "   ⚠ {} · se arranca con la configuración por defecto (tolerado)",
                message
            );
            Cli::default()
        }
    };

    banner();

    let mut runtime = BaraRuntime::new();

    // Los manifiestos se leen una sola vez: alimentan tanto al pipeline nativo
    // como al oráculo, y una ruta ilegible se tolera sin abortar la sesión.
    let manifests: Vec<String> = cli
        .manifests
        .iter()
        .filter_map(|path| read_manifest(path))
        .collect();

    if !cli.bare {
        boot_pipeline(&mut runtime, manifests.first().map(String::as_str));
    }

    let report = {
        let mut oracle = Oracle::new(&mut runtime);
        for text in &cli.says {
            // El turno siempre queda registrado (véase [`Oracle::converse`]);
            // si no lo estuviera, la sesión tolera el silencio y continúa.
            match oracle.converse(text) {
                Some(turn) => print_turn(turn),
                None => println!("   ⟅ silencio fértil: turno no registrado ⟆ (tolerado)"),
            }
        }
        for source in &manifests {
            oracle.run_manifest(source);
        }
        // Un guion que cierra con `:salir` es una sesión scriptada: el bucle
        // interactivo no se reabre (salvo con `-f/--force-live`).
        let scripted = !cli.force_live && closes_session(&manifests);
        if scripted {
            println!(
                "   (sesión scriptada: el manifiesto cierra con `:salir` · usa `-f` para conversar en vivo)"
            );
            oracle.report()
        } else if live_allowed(&cli) {
            println!("   ── terminal interactivo: el oráculo toma el control ──");
            oracle.run()
        } else if cli.no_live {
            println!("   (bucle interactivo desactivado con `--no-live`)");
            oracle.report()
        } else {
            println!(
                "   (entrada no interactiva: usa `-f` o un terminal real para conversar en vivo)"
            );
            oracle.report()
        }
    };

    println!("\n   informe de la sesión: {}", report.label());
}

/// Estandarte de apertura.
fn banner() {
    println!("══════════════════════════════════════════════════════════════");
    println!("  BARA ORACLE · בָּרָא · oráculo en vivo (AETHER-Ω)");
    println!(
        "  kernel {} · ברא estructura · שמר aislamiento · עבד ejecución",
        env!("CARGO_PKG_VERSION")
    );
    println!("══════════════════════════════════════════════════════════════");
}

/// ¿Procede entrar en el bucle interactivo real?
fn live_allowed(cli: &Cli) -> bool {
    cli.force_live || (!cli.no_live && repl::interactive_available())
}

/// ¿Algún turno de los manifiestos cierra la sesión (`:salir`)?
///
/// Un guion que termina con `:salir` es una sesión **scriptada**: reabrir el
/// bucle interactivo después sería una contradicción. `-f/--force-live` manda.
fn closes_session(manifests: &[String]) -> bool {
    manifests.iter().any(|source| {
        repl::manifest_lines(source)
            .iter()
            .any(|line| matches!(repl::MetaCommand::parse(line), repl::MetaCommand::Quit))
    })
}

/// Lee un manifiesto de disco (o de la entrada estándar cuando la ruta es `-`).
///
/// Una ruta ilegible no es un fallo: se avisa y se devuelve `None` para que la
/// sesión continúe con los manifiestos restantes.
fn read_manifest(path: &str) -> Option<String> {
    if path == "-" {
        let mut buffer = String::new();
        return match io::stdin().read_to_string(&mut buffer) {
            Ok(_) => Some(buffer),
            Err(error) => {
                println!("   ⚠ entrada estándar ilegible ({}): tolerado", error);
                None
            }
        };
    }
    match std::fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(error) => {
            println!("   ⚠ manifiesto «{}» ilegible ({}): tolerado", path, error);
            None
        }
    }
}

/// Imprime un turno conversado fuera del bucle interactivo.
fn print_turn(turn: &OracleTurn) {
    println!("   ⋯ ברא› {}", turn.input);
    println!("      ⟶ {}", turn.reply);
    if !turn.roots.is_empty() {
        println!("      ⇢ shoresh compilado: {}", turn.roots);
    }
    println!(
        "      · intención={} · {} evento(s) · {} µs · axiomas+{} · Δ⁻¹: {}",
        turn.intent, turn.events, turn.micros, turn.axioms, turn.monitor
    );
}

/// Enciende el pipeline nativo: qubits, malla, Metal‑IR y certificado ZK.
///
/// Son exactamente las mismas llamadas que ejecuta el génesis de `bara`, de
/// modo que los meta‑comandos del oráculo (`:cuántica`, `:malla`, `:metal`,
/// `:zk`) describen máquina real y no un runtime virgen.
fn boot_pipeline(runtime: &mut BaraRuntime, manifest: Option<&str>) {
    println!("\n── PIPELINE NATIVO · ψ · MALLA · METAL-IR · ZK ───────────────");

    // 1 · Superposición nativa (regla de Born): amplitudes complejas.
    let alef = runtime.superpose_native(
        "qubit-alef",
        Amplitude::real(3.0_f64.sqrt() / 2.0),
        Amplitude::from_polar(0.5, std::f64::consts::FRAC_PI_2),
    );
    let bet = runtime.superpose_native("qubit-bet", Amplitude::real(0.6), Amplitude::real(0.8));
    println!(
        "   superposición ψ       : alef={} · bet={}",
        alef.label(),
        bet.label()
    );

    // 2 · Entrelazamiento Φ⁺: la traza parcial es ⊤∧⊥ (tolerada, no explota).
    if let Some(pair) = runtime.entangle_native("qubit-alef", "qubit-bet", BellPhase::PhiPlus) {
        println!("   entrelazado «Φ⁺»      : {}", pair.label());
    }

    // 3 · Colapso de Born con propagación no local a la otra mitad.
    if let Some(measured) = runtime.collapse_native("qubit-alef") {
        println!("   colapso no local      : alef ⇒ {}", measured.label());
    }

    // 4 · Malla global de memoria: bus en proceso y después hilos `std`.
    let bus = runtime.mesh_sync(4, 2, false);
    let threaded = runtime.mesh_sync(4, 3, true);
    println!("   malla (bus en proceso): {}", bus.label());
    println!("   malla (hilos std)     : {}", threaded.label());

    // 5 · Certificado ZK de los invariantes paraconsistentes del AST.
    let certificate = runtime.certify();
    println!(
        "   certificado ZK        : «{}» · {} invariante(s) · verificado={}",
        certificate.statement.label,
        certificate.statement.n_constraints,
        certificate.result.verified
    );

    // 6 · Metal-IR del manifiesto (o de la muestra canónica) con su bypass.
    let source = manifest.unwrap_or(GENESIS_SAMPLE);
    let tokens = Lexer::new(source).tokenize();
    let program = runtime.lower_metal("manifiesto.metal", Device::Cpu, &tokens);
    println!(
        "   Metal-IR «{}»: {} instrucción(es) · {} palabra(s) · {}",
        program.label,
        program.len(),
        program.words().len(),
        program.bypass.label()
    );
}
