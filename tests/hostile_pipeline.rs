//! # Entradas hostiles sobre lexer · parser · analyze
//!
//! Fuzzing *in-tree* sin `cargo-fuzz` ni `proptest` (el núcleo no admite
//! dependencias externas): un SplitMix64 determinista genera bytes aleatorios,
//! UTF-8 roto, anidamiento profundo y blobs grandes. Cada entrada debe
//! atravesar lexer, `syntax::parse` y `bara_ide`-equivalente `analyze` del
//! runtime **sin pánico**.
//!
//! Si algún día aparece un pánico, se añade aquí como caso fijo y se corrige
//! el módulo culpable.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

use bara::lexer::Lexer;
use bara::runtime::BaraRuntime;
use bara::syntax;
use bara::transmuter::SourceLanguage;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Generador SplitMix64: misma semilla ⇒ misma avalancha.
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

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next_u64() as usize) % bound
        }
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let n = self.next_u64().to_le_bytes();
            for (dst, src) in chunk.iter_mut().zip(n.iter()) {
                *dst = *src;
            }
        }
    }
}

fn lossy_utf8(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn pipeline(label: &str, source: &str) {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _tokens = Lexer::new(source).tokenize();
        let _tree = syntax::parse(SourceLanguage::Python, source);
        let _tree_c = syntax::parse(SourceLanguage::C, source);
        let mut runtime = BaraRuntime::new();
        let tokens = Lexer::new(source).tokenize();
        let _ = runtime.execute(&tokens);
    }));
    assert!(
        result.is_ok(),
        "pánico en pipeline hostil «{label}» (len={})",
        source.len()
    );
}

#[test]
fn bytes_aleatorios_no_paran_el_pipeline() {
    let mut rng = SplitMix64::new(0xBA5A_F022_u64);
    for i in 0..64 {
        let len = rng.below(4_096).saturating_add(1);
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf);
        pipeline(&format!("rand-{i}"), &lossy_utf8(&buf));
    }
}

#[test]
fn utf8_roto_no_paran_el_pipeline() {
    let cases: &[&[u8]] = &[
        &[0x80],
        &[0xC3],
        &[0xC3, 0x28],
        &[0xE2, 0x82],
        &[0xF0, 0x9F],
        &[0xF0, 0x9F, 0x92],
        &[0xED, 0xA0, 0x80],
        &[0xFF, 0xFE, 0xFD],
        b"\x80\x81\x82abra\xff",
    ];
    for (i, raw) in cases.iter().enumerate() {
        pipeline(&format!("utf8-{i}"), &lossy_utf8(raw));
    }
}

#[test]
fn anidamiento_profundo_no_paran_el_pipeline() {
    let mut py = String::from("def f0():\n");
    for depth in 1..80 {
        py.push_str(&"    ".repeat(depth));
        py.push_str(&format!("def f{depth}():\n"));
    }
    py.push_str(&"    ".repeat(80));
    py.push_str("return 1\n");
    pipeline("nest-py", &py);

    let mut c = String::from("int main(void){");
    for _ in 0..200 {
        c.push('{');
    }
    c.push('1');
    for _ in 0..200 {
        c.push('}');
    }
    c.push('}');
    pipeline("nest-c", &c);
}

#[test]
fn archivo_grande_no_paran_el_pipeline() {
    let mut rng = SplitMix64::new(0xF11E_B16B_u64);
    // ~256 KiB de ruido: suficiente para ejercer presupuestos sin saturar C:.
    let len = 256 * 1024;
    let mut buf = vec![0u8; len];
    rng.fill(&mut buf);
    // Inserta tramos UTF-8 válidos y hebreo para el lexer triconsonántico.
    for i in (0..len).step_by(1_024) {
        let glyph = "בראשית";
        let end = (i + glyph.len()).min(len);
        buf[i..end].copy_from_slice(&glyph.as_bytes()[..end - i]);
    }
    pipeline("large-256k", &lossy_utf8(&buf));
}

#[test]
fn casos_fijos_regresion_no_paran() {
    let long_alef = "א".repeat(10_000);
    let fixed: &[&str] = &[
        "",
        "\0\0\0",
        "((((((((((((((((((((((((((((((",
        "))))))))))))))))))))))))))))))",
        "עבד עבד עבד עבד עבד",
        "/* /* /* nested */ */ */",
        "\"unterminated string",
        "ברא\u{200B}שמר",
        long_alef.as_str(),
    ];
    for (i, source) in fixed.iter().enumerate() {
        pipeline(&format!("fixed-{i}"), source);
    }
}
