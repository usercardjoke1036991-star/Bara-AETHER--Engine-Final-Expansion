// Vectores externos del puente BSC (`bsc_bridge`).
//
// Las primitivas criptográficas, el RLP y la firma EIP‑155 se contrastan contra
// valores publicados —Keccak‑256, EIP‑55 y el ejemplo normativo de EIP‑155— y
// contra puntos de orden pequeño de secp256k1. La intención es que ningún fallo
// de la aritmética de curva pase inadvertido: si `r` deja de ser una coordenada
// válida, `recover_address` ya no devuelve al firmante y estas pruebas lo dicen.
use bara::bsc_bridge::*;

/// Carga firmable del ejemplo normativo de EIP‑155 (`chain_id = 1`).
const EIP155_SIGNING_PAYLOAD: &str =
    "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080";
/// Digest de esa carga firmable.
const EIP155_SIGNING_HASH: &str =
    "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53";
/// Transacción firmada que publica el EIP (adviértase el `v = 37`).
const EIP155_SIGNED_TX: &str = concat!(
    "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a7640000",
    "8025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276",
    "a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
);
/// Componentes `r` y `s` del mismo ejemplo.
const EIP155_R: &str = "28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276";
const EIP155_S: &str = "67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";

/// `⌊n/2⌋` de secp256k1: el techo que EIP‑2 impone a `s`.
const HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// Transacción del ejemplo EIP‑155.
fn eip155_transaction() -> LegacyTx {
    LegacyTx {
        nonce: U256::from_u64(9),
        gas_price: U256::from_dec("20000000000").expect("precio de gas del ejemplo"),
        gas_limit: U256::from_u64(21000),
        to: Some(
            Address::from_hex("3535353535353535353535353535353535353535").expect("destinatario"),
        ),
        value: U256::from_dec("1000000000000000000").expect("valor del ejemplo"),
        data: Vec::new(),
    }
}

/// Clave privada del ejemplo EIP‑155 (`0x4646…46`).
fn eip155_key() -> SigningKey {
    SigningKey::from_bytes(&[0x46u8; 32]).expect("clave 0x46…46 dentro del rango")
}

#[test]
fn keccak256_matches_published_vectors() {
    assert_eq!(
        hex_encode(&keccak256(b"")),
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );
    assert_eq!(
        hex_encode(&keccak256(b"abc")),
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    );
    // La firma canónica del evento `Transfer` del estándar BEP‑20/ERC‑20.
    assert_eq!(
        hex_encode(&keccak256(b"Transfer(address,address,uint256)")),
        "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    );
    // El selector no es más que el prefijo del hash anterior.
    assert_eq!(
        hex_encode(&selector("Transfer(address,address,uint256)")),
        "ddf252ad"
    );
    assert_eq!(hex_encode(&selector("balanceOf(address)")), "70a08231");
    assert_eq!(
        hex_encode(&selector("transfer(address,uint256)")),
        "a9059cbb"
    );
}

#[test]
fn public_keys_and_addresses_match_known_keys() {
    // Puntos de orden pequeño: ejercitan la suma de puntos afines distintos.
    let mut three = [0u8; 32];
    three[31] = 3;
    assert_eq!(
        hex_encode(
            &SigningKey::from_bytes(&three)
                .expect("k=3")
                .public_key()
                .expect("3·G")
        ),
        concat!(
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
            "388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672"
        )
    );
    let mut four = [0u8; 32];
    four[31] = 4;
    assert_eq!(
        hex_encode(
            &SigningKey::from_bytes(&four)
                .expect("k=4")
                .public_key()
                .expect("4·G")
        ),
        concat!(
            "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
            "51ed993ea0d455b75642e2098ea51448d967ae33bfbdfe40cfe97bdc47739922"
        )
    );

    // Direcciones derivadas del hash de la clave pública, con EIP‑55.
    let mut one = [0u8; 32];
    one[31] = 1;
    assert_eq!(
        SigningKey::from_bytes(&one)
            .expect("k=1")
            .address()
            .to_checksum(),
        "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
    );
    let mut two = [0u8; 32];
    two[31] = 2;
    assert_eq!(
        SigningKey::from_bytes(&two)
            .expect("k=2")
            .address()
            .to_checksum(),
        "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF"
    );
}

#[test]
fn eip55_checksum_matches_the_spec_vector() {
    let address = Address::from_hex("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
        .expect("dirección del ejemplo");
    assert_eq!(
        address.to_checksum(),
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    );
}

#[test]
fn rlp_matches_canonical_examples() {
    assert_eq!(hex_encode(&rlp_encode(&rlp_data(b"dog"))), "83646f67");
    assert_eq!(
        hex_encode(&rlp_encode(&rlp_list(vec![
            rlp_data(b"cat"),
            rlp_data(b"dog")
        ]))),
        "c88363617483646f67"
    );
    // El cero y las cantidades de un solo byte se codifican sin prefijo de longitud.
    assert_eq!(hex_encode(&rlp_encode(&rlp_quantity(&U256::ZERO))), "80");
    assert_eq!(
        hex_encode(&rlp_encode(&rlp_quantity(&U256::from_u64(127)))),
        "7f"
    );
    assert_eq!(
        hex_encode(&rlp_encode(&rlp_quantity(&U256::from_u64(1024)))),
        "820400"
    );
    let decoded = rlp_decode(&hex_decode("c88363617483646f67").expect("hex")).expect("RLP válido");
    assert_eq!(decoded.arity(), Some(2));
}

#[test]
fn eip155_signing_payload_and_digest_match_the_spec_example() {
    let tx = eip155_transaction();
    // Nueve elementos: los seis campos más `[chainId, 0, 0]`.
    assert_eq!(hex_encode(&tx.signing_payload(1)), EIP155_SIGNING_PAYLOAD);
    assert_eq!(hex_encode(&tx.signing_digest(1)), EIP155_SIGNING_HASH);
}

#[test]
fn eip155_signature_matches_the_spec_example() {
    // Este vector ata todo el camino: nonce determinista (RFC 6979), producto
    // escalar, inverso modular, RLP y `v = chainId·2 + 35 + rec`.
    let key = eip155_key();
    let signed = key
        .sign_transaction(&eip155_transaction(), 1)
        .expect("la firma del ejemplo no puede fallar");
    assert_eq!(hex_encode(&signed.signature.r), EIP155_R);
    assert_eq!(hex_encode(&signed.signature.s), EIP155_S);
    assert_eq!(signed.signature.recovery, 0);
    assert_eq!(signed.signature.v(1), 37);
    assert_eq!(hex_encode(&signed.raw), EIP155_SIGNED_TX);
    assert_eq!(signed.raw_hex(), format!("0x{EIP155_SIGNED_TX}"));
    assert_eq!(signed.sender, key.address());
}

#[test]
fn signed_transaction_decodes_back_to_its_signer() {
    // Camino inverso sobre el vector externo: decodificar la transacción
    // publicada y deducir de nuevo quién la firmó.
    let raw = hex_decode(EIP155_SIGNED_TX).expect("hex del ejemplo");
    let decoded = LegacyTx::decode_signed(&raw).expect("el vector debe decodificarse");
    assert_eq!(decoded.chain_id, 1);
    assert_eq!(decoded.sender, eip155_key().address());
    assert_eq!(
        decoded.digest.as_slice(),
        hex_decode(EIP155_SIGNING_HASH).expect("hex").as_slice()
    );
    assert_eq!(
        decoded.signature.r.as_slice(),
        hex_decode(EIP155_R).expect("hex").as_slice()
    );
    assert_eq!(
        decoded.signature.s.as_slice(),
        hex_decode(EIP155_S).expect("hex").as_slice()
    );
    assert_eq!(decoded.raw, raw);
    assert!(verify_digest(
        &decoded.digest,
        &decoded.signature,
        &decoded.sender
    ));

    // Y el ida y vuelta propio del puente (firmar → serializar → decodificar).
    let signed = eip155_key()
        .sign_transaction(&eip155_transaction(), 1)
        .expect("firma propia");
    let again = LegacyTx::decode_signed(&signed.raw).expect("decodificación propia");
    assert_eq!(again.sender, signed.sender);
    assert_eq!(again.chain_id, signed.chain_id);
    assert_eq!(again.hash, signed.hash);
}

#[test]
fn signature_is_low_s_per_eip2() {
    // EIP‑2 exige `s ≤ ⌊n/2⌋`: la normalización depende del desplazamiento a la
    // derecha del orden de la curva. Sin ella la firma sigue recuperando al
    // firmante, pero la EVM la rechaza.
    let eip155 = eip155_key()
        .sign_transaction(&eip155_transaction(), 1)
        .expect("firma del ejemplo");
    assert!(eip155.signature.s <= HALF_ORDER);

    // La misma comprobación en la cadena 56, con la clave 1 y una llamada BEP‑20.
    let mut secret = [0u8; 32];
    secret[31] = 1;
    let key = SigningKey::from_bytes(&secret).expect("k=1");
    let tx = LegacyTx {
        nonce: U256::from_u64(3),
        gas_price: U256::from_dec("5000000000").expect("precio de gas"),
        gas_limit: U256::from_u64(60000),
        to: Some(
            Address::from_hex("3535353535353535353535353535353535353535").expect("destinatario"),
        ),
        value: U256::from_u64(12345),
        data: transfer_call(
            &Address::from_hex("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").expect("token"),
            &U256::from_u64(99),
        ),
    };
    let signed = key
        .sign_transaction(&tx, BSC_CHAIN_ID)
        .expect("firma en BSC");
    assert!(signed.signature.s <= HALF_ORDER);
    let v = signed.signature.v(BSC_CHAIN_ID);
    assert!((2 * BSC_CHAIN_ID + 35..=2 * BSC_CHAIN_ID + 36).contains(&v));

    // La firma es reproducible: el mismo par (clave, mensaje) da los mismos bytes.
    let repeated = key
        .sign_transaction(&tx, BSC_CHAIN_ID)
        .expect("segunda firma");
    assert_eq!(signed.raw, repeated.raw);
    assert_eq!(signed.signature, repeated.signature);
    assert_eq!(
        recover_address(&signed.digest, &signed.signature).expect("recuperación"),
        key.address()
    );

    // El camino que rompía la aritmética de curva: `decode_signed` resuelve
    // `y² = x³ + 7` a partir de `r` y reconstruye el punto para recuperar `Q`.
    let decoded = LegacyTx::decode_signed(&signed.raw).expect("decodificación en BSC");
    assert_eq!(decoded.chain_id, BSC_CHAIN_ID);
    assert_eq!(decoded.sender, key.address());
    assert_eq!(decoded.signature, signed.signature);
}

#[test]
fn legacy_v_falls_back_to_27_and_28_for_chain_zero() {
    // Pre‑EIP‑155: seis campos firmables y `v ∈ {27, 28}`. El puente debe poder
    // emitirlo y volver a leerlo como cadena 0.
    let signature = LegacySignature {
        r: [1u8; 32],
        s: [1u8; 32],
        recovery: 1,
    };
    assert_eq!(signature.v(0), 28);
    assert_eq!(
        LegacySignature {
            recovery: 0,
            ..signature
        }
        .v(0),
        27
    );
    assert_eq!(signature.v(BSC_CHAIN_ID), 2 * BSC_CHAIN_ID + 36);

    let tx = eip155_transaction();
    let six_fields = rlp_encode(&rlp_list(vec![
        rlp_quantity(&tx.nonce),
        rlp_quantity(&tx.gas_price),
        rlp_quantity(&tx.gas_limit),
        rlp_data(
            tx.to
                .as_ref()
                .expect("el ejemplo tiene destinatario")
                .as_bytes(),
        ),
        rlp_quantity(&tx.value),
        rlp_data(&tx.data),
    ]));
    assert_eq!(tx.signing_payload(0), six_fields);

    let signed = eip155_key()
        .sign_transaction(&tx, 0)
        .expect("firma previa al EIP");
    let v = signed.signature.v(0);
    assert!(v == 27 || v == 28, "v pre-EIP fuera de rango: {v}");
    let decoded = LegacyTx::decode_signed(&signed.raw).expect("decodificación previa al EIP");
    assert_eq!(decoded.chain_id, 0);
    assert_eq!(decoded.sender, eip155_key().address());
}

#[test]
fn abi_helpers_build_bep20_payloads() {
    let holder = Address::from_hex("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").expect("titular");

    // `balanceOf(address)`: selector + la dirección rellenada a 32 bytes.
    let balance = balance_of_call(&holder);
    assert_eq!(balance.len(), 36);
    assert_eq!(
        hex_encode(&balance[..4]),
        hex_encode(&selector("balanceOf(address)"))
    );
    assert_eq!(
        hex_encode(&balance[4..]),
        format!("{}{}", "0".repeat(24), hex_encode(holder.as_bytes()))
    );
    assert_eq!(
        decode_word(&balance[4..]).expect("palabra ABI"),
        U256::from_be_bytes(holder.to_abi_word())
    );

    // `transfer(address,uint256)`: selector + dirección + importe.
    let amount = U256::from_u64(1234);
    let transfer = transfer_call(&holder, &amount);
    assert_eq!(transfer.len(), 68);
    assert_eq!(
        hex_encode(&transfer[..4]),
        hex_encode(&selector("transfer(address,uint256)"))
    );
    assert_eq!(transfer[4..36], holder.to_abi_word());
    assert_eq!(hex_encode(&transfer[36..]), hex_encode(&amount.to_bytes()));
    assert_eq!(decode_word(&transfer[36..]).expect("importe"), amount);

    // Menos de 32 bytes no es una palabra: se rechaza por longitud, no se rellena.
    assert!(decode_word(&transfer[..31]).is_err());
}
