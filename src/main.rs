use hex;
use std::str;

fn hex_to_bytes(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).expect("Invalid hex string")
}

fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

fn guess_key_segment(ciphertext: &[u8], known_plaintext: &[u8]) -> Vec<u8> {
    xor_bytes(ciphertext, known_plaintext)
}

fn main() {
    let ciphertexts_hex = vec![
        "160111433b00035f536110435a380402561240555c526e1c0e431300091e4f04451d1d490d1c49010d000a0a4510111100000d434202081f0755034f13031600030d0204040e050602061d07035f4e3553501400004c1e4f1f01451359540c5804110c1c47560a1415491b06454f0e45040816431b144f0f4900450d1501094c1b16550f0b4e151e03031b450b4e020c1a124f020a0a4d09071f16003a0e5011114501494e16551049021011114c291236520108541801174b03411e1d124554284e141a0a1804045241190d543c00075453020a044e134f540a174f1d080444084e01491a090b0a1b4103570740",
        // Add all other ciphertexts here...
    ];

    // Convert all ciphertexts to bytes
    let ciphertexts: Vec<Vec<u8>> = ciphertexts_hex.iter().map(|hex| hex_to_bytes(hex)).collect();

    // Placeholder for guessed plaintext (modify as necessary)
    let known_plaintext = b"hello"; // Example known plaintext

    // Placeholder: We'll use the first ciphertext for demonstration
    let ciphertext = &ciphertexts[0];

    // Get the key segment from the first few bytes of the ciphertext and known plaintext
    let key_segment = guess_key_segment(&ciphertext[..known_plaintext.len()], known_plaintext);

    // Assuming we know the position of this known plaintext in the message
    let key_length = ciphertext.len();
    let mut key = vec![0u8; key_length];
    key[..key_segment.len()].copy_from_slice(&key_segment);

    // Decrypt all ciphertexts with the derived key
    for (i, ciphertext) in ciphertexts.iter().enumerate() {
        let plaintext = xor_bytes(ciphertext, &key);
        println!("Decrypted message {}: {:?}", i + 1, str::from_utf8(&plaintext));
    }
}
