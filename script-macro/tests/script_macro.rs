use script_macro::script;

#[test]
fn hex_is_correct() {
    let hex_script: Vec<u8> = vec![
        0x76, 0xA9, 0x14, 0xAA, 0xAB, 0xCD, 0xEF, 0xAB, 0xBA, 0xAB, 0xBA, 0xAB, 0xBA, 0xAB, 0xBA,
        0xAB, 0xBA, 0xAB, 0xBA, 0xAB, 0xBA, 0xAB, 0xBA, 0x88, 0xAC,
    ];
    let script = script!(
        OP_DUP OP_HASH160 14 aaabcdefabbaabbaabbaabbaabbaabbaabbaabba OP_EQUALVERIFY OP_CHECKSIG
    );
    assert_eq!(script, hex_script);

    let hex_script: Vec<u8> = vec![
        0x76, 0xA9, 0x14, 0x89, 0xAB, 0xCD, 0xEF, 0xAB, 0xBA, 0xAB, 0xBA, 0xAB, 0xBA, 0xAB, 0xBA,
        0xAB, 0xBA, 0xAB, 0xBA, 0xAB, 0xBA, 0xAB, 0xBA, 0x88, 0xAC,
    ];
    let script = script!(
        OP_DUP OP_HASH160 14 89abcdefabbaabbaabbaabbaabbaabbaabbaabba OP_EQUALVERIFY OP_CHECKSIG
    );
    assert_eq!(script, hex_script);

    let hex_script: Vec<u8> = vec![0x4c, 0x01, 0x07];
    let script = script!(
        OP_PUSHDATA1 01 07
    );
    assert_eq!(script, hex_script);

    let hex_script: Vec<u8> = vec![0x4d, 0x01, 0x00, 0x08];
    let script = script!(
        OP_PUSHDATA2 0100 08
    );
    assert_eq!(script, hex_script);

    let hex_script: Vec<u8> = vec![0x4e, 0x01, 0x00, 0x00, 0x00, 0x09];
    let script = script!(
        OP_PUSHDATA4 01000000 09
    );
    assert_eq!(script, hex_script);
}
