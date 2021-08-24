use derive_tag::{FromTag, ToTag};
use std::convert::TryInto;
use strum_macros::EnumString;
use tag::{FromTag, ToTag};

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, ToTag, FromTag, EnumString)]
#[repr(u8)]
pub enum Script {
    // holds bytes pushed to the stack and the value of the amount of bytes that
    // were supposed to be pushed (in little-endian)
    OP_FALSE = 0x00, // equivalent to OP_0
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_TRUE = 0x51, // equivalent to OP_1
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5a,
    OP_11 = 0x5b,
    OP_12 = 0x5c,
    OP_13 = 0x5d,
    OP_14 = 0x5e,
    OP_15 = 0x5f,
    OP_16 = 0x60,

    OP_NOP = 0x61,
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,

    OP_TOALTSTACK = 0x6b,
    OP_FROMALTSTACK = 0x6c,
    OP_2DROP = 0x6d,
    OP_2DUP = 0x6e,
    OP_3DUP = 0x6f,
    OP_2OVER = 0x70,
    OP_2ROT = 0x71,
    OP_2SWAP = 0x72,
    OP_IFDUP = 0x73,
    OP_DEPTH = 0x74,
    OP_DROP = 0x75,
    OP_DUP = 0x76,
    OP_NIP = 0x77,
    OP_OVER = 0x78,
    OP_PICK = 0x79,
    OP_ROLL = 0x7a,
    OP_ROT = 0x7b,
    OP_SWAP = 0x7c,
    OP_TUCK = 0x7d,

    OP_SIZE = 0x82,

    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,

    OP_1ADD = 0x8b,
    OP_1SUB = 0x8c,

    OP_NEGATE = 0x8f,
    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,
    OP_ADD = 0x93,
    OP_SUB = 0x94,

    OP_BOOLAND = 0x9a,
    OP_BOOLOR = 0x9b,
    OP_NUMEQUAL = 0x9c,
    OP_NUMEQUALVERIFY = 0x9d,
    OP_NUMNOTEQUAL = 0x9e,
    OP_LESSTHAN = 0x9f,
    OP_GREATERTHAN = 0xa0,
    OP_LESSTHANOREQUAL = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN = 0xa3,
    OP_MAX = 0xa4,
    OP_WITHIN = 0xa5,

    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,
    OP_CODESEPARATOR = 0xab,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,

    OP_CHECKLOCKTIMEVERIFY = 0xb1,
    OP_CHECKSEQUENCEVERIFY = 0xb2,

    OP_PUBKEYHASH = 0xfd,
    OP_PUBKEY = 0xfe,
    OP_INVALIDOPCODE = 0xff,

    OP_RESERVED = 0x50,
    OP_VER = 0x62,
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8a,

    OP_NOP1 = 0xb0,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,

    // this has an arbitrary (unused) u8 value, but such value will never be used
    Data(Vec<u8>, Vec<u8>),
}

impl Script {
    fn is_data(&self) -> bool {
        match &self {
            Self::Data(_, _) => true,
            _ => false,
        }
    }

    fn get_data_info(&self) -> (Vec<u8>, Vec<u8>) {
        match &self {
            Self::Data(size, data) => (size.to_vec(), data.to_vec()),
            _ => panic!("Method should be called on Script::Data only."),
        }
    }

    fn is_pushdata_op(&self) -> bool {
        match &self {
            Self::OP_PUSHDATA1 | Self::OP_PUSHDATA2 | Self::OP_PUSHDATA4 => true,
            _ => false,
        }
    }

    fn get_data_for_pushdata(&self, hex_script: &[u8]) -> (usize, Self) {
        match &self {
            Self::OP_PUSHDATA1 => {
                let data_size = hex_script[0];

                let total_to_skip = 1 + data_size as usize;
                let size_bytes = vec![data_size];

                (
                    total_to_skip,
                    Self::Data(size_bytes, hex_script[1..=data_size as usize].to_vec()),
                )
            }
            Self::OP_PUSHDATA2 => {
                let data_size_bytes = &hex_script[..2];
                let data_size = u16::from_le_bytes(data_size_bytes.try_into().unwrap());

                let total_to_skip = 2 + data_size as usize;
                let size_bytes = data_size_bytes.to_vec();

                (
                    total_to_skip,
                    Self::Data(
                        size_bytes,
                        hex_script[2..=(1 + data_size) as usize].to_vec(),
                    ),
                )
            }
            Self::OP_PUSHDATA4 => {
                let data_size_bytes = &hex_script[..4];
                let data_size = u32::from_le_bytes(data_size_bytes.try_into().unwrap());

                let total_to_skip = 4 + data_size as usize;
                let size_bytes = data_size_bytes.to_vec();

                (
                    total_to_skip,
                    Self::Data(
                        size_bytes,
                        hex_script[4..=(3 + data_size) as usize].to_vec(),
                    ),
                )
            }
            _ => panic!("Not a OP_PUSHDATAx op."),
        }
    }

    fn to_opcode(&self) -> u8 {
        match &self {
            Script::Data(_, _) => panic!("This does not have a specific opcode."),
            _ => self.to_tag(),
        }
    }

    fn opcode_to_script(opcode: u8, hex_script: &[u8]) -> Self {
        match opcode {
            0x01..=0x4b => Self::Data(vec![opcode], hex_script[..opcode as usize].to_vec()),
            _ => Script::from_tag(opcode),
        }
    }
}

trait ToScript {
    fn to_script(&self) -> Vec<Script>;
}

impl ToScript for Vec<u8> {
    fn to_script(&self) -> Vec<Script> {
        let mut script: Vec<Script> = Vec::new();

        let mut skip = false;
        let mut skip_until = 0;

        for (i, &byte) in self.iter().enumerate() {
            if skip && i <= skip_until {
                continue;
            }

            let s = Script::opcode_to_script(byte, &self[(i + 1)..]);

            if s.is_pushdata_op() {
                let (total_to_skip, data) = s.get_data_for_pushdata(&self[(i + 1)..]);

                script.push(s);
                script.push(data);

                skip = true;
                skip_until = i + total_to_skip;
            } else if s.is_data() {
                skip = true;
                let (mut size, _) = s.get_data_info();

                size.extend(vec![0; 8 - size.len()]);
                skip_until = i + usize::from_le_bytes(size.try_into().unwrap());

                script.push(s);
            } else {
                skip = false;
                script.push(s);
            }
        }

        script
    }
}

pub trait FromScript {
    fn from_script(&self) -> Vec<u8>;
}

impl FromScript for Vec<Script> {
    fn from_script(&self) -> Vec<u8> {
        let mut hex_script: Vec<u8> = Vec::new();

        for opcode in self.iter() {
            if opcode.is_data() {
                let (size, data) = opcode.get_data_info();
                hex_script.extend(size);
                hex_script.extend(data);
            } else {
                hex_script.push(opcode.to_opcode());
            }
        }

        hex_script
    }
}

#[cfg(test)]
mod tests {
    // Test cases from the following sources:
    // - https://github.com/bitcoin/bitcoin/blob/7fcf53f7b4524572d1d0c9a5fdc388e87eb02416/src/test/data/script_tests.json
    // - https://en.bitcoin.it/wiki/Script#Script_examples

    use super::*;

    fn get_test_data() -> (Vec<u8>, Vec<Script>) {
        let hex_script: Vec<u8> = vec![
            0x76, 0xA9, 0x14, 0x89, 0xAB, 0xCD, 0xEF, 0xAB, 0xBA, 0xAB, 0xBA, 0xAB, 0xBA, 0xAB,
            0xBA, 0xAB, 0xBA, 0xAB, 0xBA, 0xAB, 0xBA, 0xAB, 0xBA, 0x88, 0xAC,
        ];

        let script = vec![
            Script::OP_DUP,
            Script::OP_HASH160,
            Script::Data(
                vec![0x14],
                vec![
                    0x89, 0xAB, 0xCD, 0xEF, 0xAB, 0xBA, 0xAB, 0xBA, 0xAB, 0xBA, 0xAB, 0xBA, 0xAB,
                    0xBA, 0xAB, 0xBA, 0xAB, 0xBA, 0xAB, 0xBA,
                ],
            ),
            Script::OP_EQUALVERIFY,
            Script::OP_CHECKSIG,
        ];

        (hex_script, script)
    }

    #[test]
    fn to_script() {
        let (hex_script, expected_script) = get_test_data();
        assert_eq!(hex_script.to_script(), expected_script);
    }

    #[test]
    fn from_script() {
        let (expected_hex_script, script) = get_test_data();
        assert_eq!(script.from_script(), expected_hex_script);
    }

    #[test]
    fn op_pushdata1() {
        let script = vec![Script::OP_PUSHDATA1, Script::Data(vec![0x01], vec![0x07])];
        let hex_script: Vec<u8> = vec![0x4c, 0x01, 0x07];

        assert_eq!(script.from_script(), hex_script);
        assert_eq!(hex_script.to_script(), script);
    }

    #[test]
    fn op_pushdata2() {
        let script = vec![
            Script::OP_PUSHDATA2,
            Script::Data(vec![0x01, 0x00], vec![0x08]),
        ];
        let hex_script: Vec<u8> = vec![0x4d, 0x01, 0x00, 0x08];

        assert_eq!(script.from_script(), hex_script);
        assert_eq!(hex_script.to_script(), script);
    }

    #[test]
    fn op_pushdata4() {
        let script = vec![
            Script::OP_PUSHDATA4,
            Script::Data(vec![0x01, 0x00, 0x00, 0x00], vec![0x09]),
        ];
        let hex_script: Vec<u8> = vec![0x4e, 0x01, 0x00, 0x00, 0x00, 0x09];

        assert_eq!(script.from_script(), hex_script);
        assert_eq!(hex_script.to_script(), script);
    }
}
