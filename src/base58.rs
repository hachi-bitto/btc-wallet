// Implementation is described here: https://tools.ietf.org/id/draft-msporny-base58-01.html
// Part of the implementation below took inspiration from
// https://github.com/dotcypress/base58check and
// https://github.com/debris/base58
// https://github.com/bitcoin/bitcoin/blob/master/src/base58.cpp
// However, I tried not to look at the code so much, and instead tried to derive
// some things myself.

use crypto::{digest::Digest, sha2};

const ALPHABET: &'static [u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// This is used to translate bytes in a string to their index in `ALPHABET`.
// For example, `b"aO"` is equal to `[97, 79]`.
// See that `CHAR_ALPHABET_INDEX_MAP[97] = 33`, which is the index of 'a' in `ALPHABET`.
// Also, note that `CHAR_ALPHABET_INDEX_MAP[79] = -1`, since `O` is not in `ALPHABET`.
const CHAR_ALPHABET_INDEX_MAP: &'static [i8; 256] = &[
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, -1, -1, -1, -1, -1, -1, -1, 9, 10, 11, 12, 13, 14, 15, 16, -1,
    17, 18, 19, 20, 21, -1, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1, -1, 33,
    34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56,
    57, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
];

fn double_sha256(payload: &[u8]) -> [u8; 32] {
    let mut final_hash: [u8; 32] = [0; 32];
    let mut hasher = sha2::Sha256::new();
    hasher.input(payload);
    hasher.result(&mut final_hash);
    hasher.reset();
    hasher.input(&final_hash);
    hasher.result(&mut final_hash);

    final_hash
}

#[derive(Debug, PartialEq)]
enum FromBase58Error {
    InvalidCharacter,
}

trait ToBase58 {
    fn to_base58(&self) -> String;
}

trait FromBase58 {
    fn from_base58(&self) -> Result<Vec<u8>, FromBase58Error>;
}

impl ToBase58 for [u8] {
    // After all the initial zeros are counted, what follows is just long
    // division.
    fn to_base58(&self) -> String {
        let mut zero_counter: usize = 0;
        let mut encoding_flag = false;

        let mut b58_bytes: Vec<u32> = Vec::new();

        let mut first_b58_byte_iter = true;
        let mut size = 0;
        for &byte in self.iter() {
            if !encoding_flag {
                zero_counter += (byte == 0) as usize;
                if byte == 0 {
                    continue;
                }
                encoding_flag = true;
            }

            let mut carry = byte as u32;
            let mut i = 0;

            while carry != 0 || i < size {
                if first_b58_byte_iter {
                    b58_bytes.push(0);
                    first_b58_byte_iter = false;
                } else {
                    if let Some(b58_byte) = b58_bytes.get(i) {
                        carry += b58_byte * 256;
                    } else {
                        b58_bytes.push(0);
                    }
                }

                b58_bytes[i] = carry % 58;
                carry /= 58;

                i += 1;
            }

            size = i;
        }

        let encoding_length = zero_counter as usize + b58_bytes.len();
        let mut b58_encoding: Vec<u8> = vec![b'1'; encoding_length];

        for (i, &b58_byte) in b58_bytes.iter().rev().enumerate() {
            b58_encoding[zero_counter + i] = ALPHABET[b58_byte as usize];
        }

        String::from_utf8(b58_encoding).unwrap()
    }
}

impl FromBase58 for str {
    fn from_base58(&self) -> Result<Vec<u8>, FromBase58Error> {
        let mut raw_bytes: Vec<u8> = Vec::new();
        let mut final_bytes: Vec<u8> = Vec::new();

        let mut encoding_flag = false;

        let mut first_byte_iter = true;
        let mut size = 0;
        for &byte in self.as_bytes().iter() {
            let b58_value = CHAR_ALPHABET_INDEX_MAP[byte as usize];
            if b58_value == -1 {
                return Err(FromBase58Error::InvalidCharacter);
            }

            if !encoding_flag {
                if b58_value == 0 {
                    final_bytes.push(0);
                    continue;
                }
                encoding_flag = true;
            }

            let mut carry = b58_value as u32;
            let mut i = 0;

            while carry != 0 || i < size {
                if first_byte_iter {
                    raw_bytes.push(0);
                    first_byte_iter = false;
                } else {
                    if let Some(raw_byte) = raw_bytes.get(i) {
                        carry += *raw_byte as u32 * 58;
                    } else {
                        raw_bytes.push(0);
                    }
                }

                raw_bytes[i] = (carry % 256) as u8;
                carry /= 256;

                i += 1
            }

            size = i;
        }

        raw_bytes.reverse();
        final_bytes.extend_from_slice(&raw_bytes);
        Ok(final_bytes)
    }
}

#[derive(Debug, PartialEq)]
enum FromBase58CheckError {
    Base58Error(FromBase58Error),
    InvalidCheckSum,
}

#[derive(Debug, PartialEq)]
enum Base58CheckVersion {
    PKH,
    SH,
    SKWIF,
    SKBIP38,
    PKBIP32,
}

impl Base58CheckVersion {
    fn to_vec(&self) -> Vec<u8> {
        match self {
            Base58CheckVersion::PKH => vec![0x00],
            Base58CheckVersion::SH => vec![0x05],
            Base58CheckVersion::SKWIF => vec![0x80],
            Base58CheckVersion::SKBIP38 => vec![0x01, 0x42],
            Base58CheckVersion::PKBIP32 => vec![0x04, 0x88, 0xB2, 0x1E],
        }
    }

    fn get_version(payload_with_version: &[u8]) -> Option<Self> {
        match payload_with_version {
            [0x00, ..] => Some(Base58CheckVersion::PKH),
            [0x05, ..] => Some(Base58CheckVersion::SH),
            [0x80, ..] => Some(Base58CheckVersion::SKWIF),
            [0x01, 0x42, ..] => Some(Base58CheckVersion::SKBIP38),
            [0x04, 0x88, 0xB2, 0x1E, ..] => Some(Base58CheckVersion::PKBIP32),
            _ => None,
        }
    }
}

trait ToBase58Check {
    fn to_base58check(&self, version: Option<Base58CheckVersion>) -> String;
}

trait FromBase58Check {
    fn from_base58check(
        &self,
    ) -> Result<(Vec<u8>, Option<Base58CheckVersion>), FromBase58CheckError>;
}

impl ToBase58Check for [u8] {
    fn to_base58check(&self, version: Option<Base58CheckVersion>) -> String {
        let mut final_vec = match version {
            None => vec![],
            Some(v) => v.to_vec(),
        };

        final_vec.extend_from_slice(self);

        let final_hash = double_sha256(&final_vec);
        final_vec.extend_from_slice(&final_hash[0..4]);

        let base58_encoded = final_vec.as_slice().to_base58();
        base58_encoded
    }
}

impl FromBase58Check for str {
    fn from_base58check(
        &self,
    ) -> Result<(Vec<u8>, Option<Base58CheckVersion>), FromBase58CheckError> {
        let decoded = self
            .from_base58()
            .map_err(FromBase58CheckError::Base58Error)?;

        let decoded_size = decoded.len();

        let payload_with_version = &decoded[..decoded_size - 4];
        let checksum = &decoded[decoded_size - 4..];

        let final_hash = double_sha256(payload_with_version);

        if checksum != &final_hash[0..4] {
            return Err(FromBase58CheckError::InvalidCheckSum);
        }

        let version = Base58CheckVersion::get_version(payload_with_version);

        let payload_without_version = match version {
            None => payload_with_version,
            Some(Base58CheckVersion::PKH)
            | Some(Base58CheckVersion::SH)
            | Some(Base58CheckVersion::SKWIF) => &payload_with_version[1..],
            Some(Base58CheckVersion::SKBIP38) => &payload_with_version[2..],
            Some(Base58CheckVersion::PKBIP32) => &payload_with_version[4..],
        };

        Ok((payload_without_version.to_vec(), version))
    }
}

#[cfg(test)]
mod tests {
    // Tests cases come from the following sources:
    // - https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04.asciidoc
    // - https://github.com/bitcoin/bitcoin/blob/master/src/test/data/base58_encode_decode.json
    // - https://github.com/keis/base58/blob/master/test_base58.py

    use super::*;
    use hex_literal::hex;

    #[test]
    fn to_base58() {
        assert_eq!(hex!("6263").to_base58(), "8VG");
        assert_eq!(b"".to_base58(), "");
        assert_eq!(hex!("").to_base58(), "");
        assert_eq!(hex!("61").to_base58(), "2g");
        assert_eq!(hex!("626262").to_base58(), "a3gV");
        assert_eq!(hex!("636363").to_base58(), "aPEr");
        assert_eq!(
            hex!("73696d706c792061206c6f6e6720737472696e67").to_base58(),
            "2cFupjhnEsSn59qHXstmK2ffpLv2"
        );
        assert_eq!(hex!("572e4794").to_base58(), "3EFU7m");
        assert_eq!(hex!("ecac89cad93923c02321").to_base58(), "EJDM8drfXA6uyA");
        assert_eq!(hex!("10c8511e").to_base58(), "Rt5zm");
        assert_eq!(hex!("00000000000000000000").to_base58(), "1111111111");

        assert_eq!(b"hello world".to_base58(), "StV1DL6CwTryKyV");
        assert_eq!(b"\0\0hello world".to_base58(), "11StV1DL6CwTryKyV");
        assert_eq!(hex!("bf4f89001e670274dd").to_base58(), "3SEo3LWLoPntC");
        assert_eq!(
            hex!("00eb15231dfceb60925886b67d065299925915aeb172c06647").to_base58(),
            "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"
        );
        assert_eq!(hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").to_base58(), "1cWB5HCBdLjAuqGGReWE3R3CguuwSjw6RHn39s2yuDRTS5NsBgNiFpWgAnEx6VQi8csexkgYw3mdYrMHr8x9i7aEwP8kZ7vccXWqKDvGv3u1GxFKPuAkn8JCPPGDMf3vMMnbzm6Nh9zh1gcNsMvH3ZNLmP5fSG6DGbbi2tuwMWPthr4boWwCxf7ewSgNQeacyozhKDDQQ1qL5fQFUW52QKUZDZ5fw3KXNQJMcNTcaB723LchjeKun7MuGW5qyCBZYzA1KjofN1gYBV3NqyhQJ3Ns746GNuf9N2pQPmHz4xpnSrrfCvy6TVVz5d4PdrjeshsWQwpZsZGzvbdAdN8MKV5QsBDY");
        assert_eq!(hex!("000111d38e5fc9071ffcd20b4a763cc9ae4f252bb4e48fd66a835e252ada93ff480d6dd43dc62a641155a5").to_base58(), "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");
    }

    #[test]
    fn from_base58_correct() {
        assert_eq!(
            "11StV1DL6CwTryKyV".from_base58().unwrap(),
            b"\0\0hello world".to_vec()
        );
        assert_eq!("1".from_base58().unwrap(), b"\0".to_vec());
        assert_eq!("".from_base58().unwrap(), b"".to_vec());
        assert_eq!(
            "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z"
                .from_base58()
                .unwrap(),
            b"The quick brown fox jumps over the lazy dog.".to_vec()
        );
        assert_eq!(
            "2NEpo7TZRRrLZSi2U".from_base58().unwrap(),
            b"Hello World!".to_vec()
        );
        assert_eq!(
            "StV1DL6CwTryKyV".from_base58().unwrap(),
            b"hello world".to_vec()
        );
    }

    #[test]
    fn from_base58_error() {
        assert_eq!(
            "xyz0"
                .from_base58()
                .expect_err("Wrong character should return an error"),
            FromBase58Error::InvalidCharacter
        );
        assert_eq!(
            "2yGEbw0RKGAsJ2HmJv"
                .from_base58()
                .expect_err("Wrong character should return an error"),
            FromBase58Error::InvalidCharacter
        );
        assert_eq!(
            "2yGEbwRKGOAsJ2HmJv"
                .from_base58()
                .expect_err("Wrong character should return an error"),
            FromBase58Error::InvalidCharacter
        );
        assert_eq!(
            "2yGEbwRKGAsJ2HImJv"
                .from_base58()
                .expect_err("Wrong character should return an error"),
            FromBase58Error::InvalidCharacter
        );
        assert_eq!(
            "2yGEbwRKGAsJ2HlmJv"
                .from_base58()
                .expect_err("Wrong character should return an error"),
            FromBase58Error::InvalidCharacter
        );
    }

    #[test]
    fn to_base58check() {
        assert_eq!(
            hex!("1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd")
                .to_base58check(Some(Base58CheckVersion::SKWIF)),
            "5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn"
        );
        assert_eq!(
            hex!("3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6")
                .to_base58check(Some(Base58CheckVersion::SKWIF)),
            "5JG9hT3beGTJuUAmCQEmNaxAuMacCTfXuw1R3FCXig23RQHMr4K"
        );
        assert_eq!(b"hello world".to_base58check(None), "3vQB7B6MrGQZaxCuFg4oh");
        assert_eq!(
            hex!("3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa601")
                .to_base58check(Some(Base58CheckVersion::SKWIF)),
            "KyBsPXxTuVD82av65KZkrGrWi5qLMah5SdNq6uftawDbgKa2wv6S"
        );
        assert_eq!(
            hex!("27b5891b01da2db74cde1689a97a2acbe23d5fb1")
                .to_base58check(Some(Base58CheckVersion::PKH)),
            "14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3"
        );
        assert_eq!(
            hex!("09c6e71118d8f12bec6b5c61884b35677c0a0ae3")
                .to_base58check(Some(Base58CheckVersion::PKH)),
            "1thMirt546nngXqyPEz532S8fLwbozud8"
        );
        assert_eq!(
            hex!("f5f2d624cfb5c3f66d06123d0829d1c9cebf770e")
                .to_base58check(Some(Base58CheckVersion::PKH)),
            "1PRTTaJesdNovgne6Ehcdu1fpEdX7913CK"
        );
        assert_eq!(
            hex!("1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd01")
                .to_base58check(Some(Base58CheckVersion::SKWIF)),
            "KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ"
        );
    }

    #[test]
    fn from_base58check_correct() {
        assert_eq!(
            "14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3"
                .from_base58check()
                .unwrap(),
            (
                hex!("27b5891b01da2db74cde1689a97a2acbe23d5fb1").to_vec(),
                Some(Base58CheckVersion::PKH)
            )
        );
        assert_eq!(
            "3vQB7B6MrGQZaxCuFg4oh".from_base58check().unwrap(),
            (b"hello world".to_vec(), None),
        );
        assert_eq!(
            "5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn"
                .from_base58check()
                .unwrap(),
            (
                hex!("1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd").to_vec(),
                Some(Base58CheckVersion::SKWIF)
            ),
        );
        assert_eq!(
            "KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ"
                .from_base58check()
                .unwrap(),
            (
                hex!("1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd01").to_vec(),
                Some(Base58CheckVersion::SKWIF)
            ),
        );
    }

    #[test]
    fn from_base58check_error() {
        assert_eq!(
            "3vQB7B6MrGQZaxCuFg4oH".from_base58check().unwrap_err(),
            FromBase58CheckError::InvalidCheckSum
        );
        assert_eq!(
            "3vOB7B6MrGQZaxCuFg4oh".from_base58check().unwrap_err(),
            FromBase58CheckError::Base58Error(FromBase58Error::InvalidCharacter)
        );
    }
}
