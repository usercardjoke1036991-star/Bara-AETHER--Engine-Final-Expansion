//! Lectura hermética de un contenedor GGUF.
//!
//! Sólo entra la cabecera: magia, metadatos y el censo de tensores. Los pesos
//! no se copian y no hay red ni FFI. Ejecutar un runtime de `llama.cpp` exigiría
//! código inseguro; este módulo se queda en `forbid(unsafe_code)`.

#![forbid(unsafe_code)]

/// Magia little-endian de los cuatro bytes `GGUF`.
const GGUF_MAGIC: u32 = 0x4655_4747;

/// Versiones de contenedor que comparten esta cabecera.
const GGUF_VERSIONS: [u32; 2] = [2, 3];

const MAX_METADATA: u64 = 4_096;
const MAX_TENSORS: u64 = 8_192;
const MAX_DIMS: u32 = 8;
const MAX_STRING: usize = 8 * 1024 * 1024;
const MAX_ARRAY: u64 = 200_000;

/// Tarjeta de un archivo de pesos. No incluye tensores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightCard {
    /// Versión del contenedor.
    pub version: u32,
    /// `general.architecture`, o `desconocida`.
    pub architecture: String,
    /// `general.name`, o la arquitectura.
    pub name: String,
    /// Longitud de contexto declarada. Cero si el archivo no la trae.
    pub context: u32,
    /// Tensores anunciados en la cabecera.
    pub tensors: u64,
    /// Producto de las dimensiones, saturado.
    pub parameters: u64,
}

struct Cur<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Cur<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .at
            .checked_add(len)
            .ok_or_else(|| "cabecera GGUF fuera de rango".to_string())?;
        if end > self.buf.len() {
            return Err("cabecera GGUF truncada".to_string());
        }
        let slice = &self.buf[self.at..end];
        self.at = end;
        Ok(slice)
    }

    fn u32(&mut self) -> Result<u32, String> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64, String> {
        let bytes = self.take(8)?;
        let mut raw = [0u8; 8];
        raw.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(raw))
    }

    fn text(&mut self, keep: usize) -> Result<String, String> {
        let len = self.u64()?;
        let len = usize::try_from(len).map_err(|_| "cadena GGUF fuera de cota".to_string())?;
        if len > MAX_STRING {
            return Err("cadena GGUF fuera de cota".to_string());
        }
        let bytes = self.take(len)?;
        let end = keep.min(bytes.len());
        Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
    }

    fn skip(&mut self, ty: u32, depth: u8) -> Result<(), String> {
        if depth > 4 {
            return Err("metadato GGUF demasiado anidado".to_string());
        }
        match ty {
            0 | 1 | 7 => {
                self.take(1)?;
            }
            2 | 3 => {
                self.take(2)?;
            }
            4..=6 => {
                self.take(4)?;
            }
            10..=12 => {
                self.take(8)?;
            }
            8 => {
                let _ = self.text(0)?;
            }
            9 => {
                let elem = self.u32()?;
                let len = self.u64()?;
                if len > MAX_ARRAY {
                    return Err("arreglo GGUF fuera de cota".to_string());
                }
                for _ in 0..len {
                    self.skip(elem, depth.saturating_add(1))?;
                }
            }
            _ => return Err("tipo GGUF desconocido".to_string()),
        }
        Ok(())
    }
}

/// Lee la tarjeta desde los primeros bytes del archivo. El resto de los pesos
/// puede no estar en `bytes`.
pub fn read_card(bytes: &[u8]) -> Result<WeightCard, String> {
    let mut cur = Cur { buf: bytes, at: 0 };
    let magic = cur.u32()?;
    if magic != GGUF_MAGIC {
        return Err("el archivo no es un contenedor GGUF".to_string());
    }
    let version = cur.u32()?;
    if !GGUF_VERSIONS.contains(&version) {
        return Err("versión GGUF no reconocida".to_string());
    }
    let tensors = cur.u64()?;
    let metadata = cur.u64()?;
    if tensors > MAX_TENSORS || metadata > MAX_METADATA {
        return Err("cabecera GGUF fuera de cota".to_string());
    }
    let mut architecture = String::new();
    let mut name = String::new();
    let mut context = 0u32;
    for _ in 0..metadata {
        let key = cur.text(256)?;
        let ty = cur.u32()?;
        if key == "general.architecture" && ty == 8 {
            architecture = cur.text(64)?;
        } else if key == "general.name" && ty == 8 {
            name = cur.text(128)?;
        } else if key.ends_with(".context_length") && ty == 4 {
            context = cur.u32()?;
        } else if key.ends_with(".context_length") && ty == 10 {
            context = u32::try_from(cur.u64()?).unwrap_or(u32::MAX);
        } else {
            cur.skip(ty, 0)?;
        }
    }
    let mut parameters = 0u64;
    for _ in 0..tensors {
        let _name = cur.text(0)?;
        let dims = cur.u32()?;
        if dims > MAX_DIMS {
            return Err("tensor GGUF con demasiadas dimensiones".to_string());
        }
        let mut product = 1u64;
        for _ in 0..dims {
            product = product.saturating_mul(cur.u64()?);
        }
        let _ty = cur.u32()?;
        let _offset = cur.u64()?;
        parameters = parameters.saturating_add(product);
    }
    if architecture.is_empty() {
        architecture = "desconocida".to_string();
    }
    if name.is_empty() {
        name = architecture.clone();
    }
    Ok(WeightCard {
        version,
        architecture,
        name,
        context,
        tensors,
        parameters,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_str(buf: &mut Vec<u8>, text: &str) {
        buf.extend_from_slice(&(text.len() as u64).to_le_bytes());
        buf.extend_from_slice(text.as_bytes());
    }

    fn sample() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&GGUF_MAGIC.to_le_bytes());
        buf.extend_from_slice(&3u32.to_le_bytes());
        buf.extend_from_slice(&1u64.to_le_bytes());
        buf.extend_from_slice(&3u64.to_le_bytes());
        push_str(&mut buf, "general.architecture");
        buf.extend_from_slice(&8u32.to_le_bytes());
        push_str(&mut buf, "neura");
        push_str(&mut buf, "general.name");
        buf.extend_from_slice(&8u32.to_le_bytes());
        push_str(&mut buf, "bara-local");
        push_str(&mut buf, "neura.context_length");
        buf.extend_from_slice(&4u32.to_le_bytes());
        buf.extend_from_slice(&2048u32.to_le_bytes());
        push_str(&mut buf, "token.embd");
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&4u64.to_le_bytes());
        buf.extend_from_slice(&8u64.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf
    }

    #[test]
    fn la_tarjeta_sale_de_la_cabecera_sin_leer_pesos() {
        let Ok(card) = read_card(&sample()) else {
            panic!("gguf");
        };
        assert_eq!(card.version, 3);
        assert_eq!(card.architecture, "neura");
        assert_eq!(card.name, "bara-local");
        assert_eq!(card.context, 2048);
        assert_eq!(card.tensors, 1);
        assert_eq!(card.parameters, 32);
    }

    #[test]
    fn una_magia_ajena_se_rechaza() {
        let mut bytes = sample();
        bytes[0] = 0;
        assert!(read_card(&bytes).is_err());
        assert!(read_card(&[]).is_err());
    }

    #[test]
    fn el_modulo_no_abre_la_red() {
        let source = include_str!("gguf_local.rs");
        let production = source.split("mod tests").next().unwrap_or(source);
        assert!(!production.contains("TcpStream"));
        assert!(!production.contains("https://"));
        assert!(!production.contains("unsafe {"));
    }
}
