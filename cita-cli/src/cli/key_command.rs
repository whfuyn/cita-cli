use ansi_term::Colour::Yellow;
use clap::{App, Arg, ArgMatches, SubCommand};

use cita_tool::{
    encode, decode, pubkey_to_address, sm4_encrypt, sm4_decrypt, sign,
    remove_0x, Hashable, KeyPair, LowerHex, Message, PubKey, PrivateKey, Signature,
};

use crate::cli::{encryption, is_hex, key_validator};
use crate::interactive::GlobalConfig;
use crate::printer::Printer;
use std::str::FromStr;

/// Key related commands
pub fn key_command() -> App<'static, 'static> {
    App::new("key")
        .about("Some key operations, such as generating address, public key")
        .subcommand(SubCommand::with_name("create"))
        .subcommand(
            SubCommand::with_name("from-private").arg(
                Arg::with_name("private-key")
                    .long("private-key")
                    .takes_value(true)
                    .required(true)
                    .validator(|privkey| key_validator(privkey.as_ref()).map(|_| ()))
                    .help("The private key of transaction"),
            ),
        )
        .subcommand(
            SubCommand::with_name("pub-to-address").arg(
                Arg::with_name("pubkey")
                    .long("pubkey")
                    .takes_value(true)
                    .required(true)
                    .validator(|pubkey| key_validator(&pubkey).map(|_| ()))
                    .help("Pubkey"),
            ),
        )
        .subcommand(
            SubCommand::with_name("hash").arg(
                Arg::with_name("content")
                    .long("content")
                    .takes_value(true)
                    .required(true)
                    .validator(|content| is_hex(content.as_str()))
                    .help(
                        "Hash the content and output,\
                         Secp256k1 means keccak256/Ed25519 means blake2b/Sm2 means Sm3",
                    ),
            ),
        )
        .subcommand(
            SubCommand::with_name("verify")
                .arg(
                    Arg::with_name("pubkey")
                        .long("pubkey")
                        .takes_value(true)
                        .required(true)
                        .validator(|pubkey| key_validator(&pubkey).map(|_| ()))
                        .help("Pubkey"),
                )
                .arg(
                    Arg::with_name("message")
                        .long("message")
                        .takes_value(true)
                        .required(true)
                        .help("message"),
                )
                .arg(
                    Arg::with_name("signature")
                        .long("signature")
                        .takes_value(true)
                        .required(true)
                        .help("signature"),
                ),
        )
        .subcommand(
            SubCommand::with_name("sign")
                .arg(
                    Arg::with_name("privkey")
                        .long("privkey")
                        .takes_value(true)
                        .required(true)
                        .validator(|privkey| key_validator(&privkey).map(|_| ()))
                        .help("private key")
                )
                .arg(
                    Arg::with_name("message")
                        .long("message")
                        .takes_value(true)
                        .required(true)
                        .help("the message(hash) to sign")
                )
        )
        .subcommand(
            SubCommand::with_name("sm4_encrypt")
                .about("encrypt ciphertext using sm4 algorithm")
                .arg(
                    Arg::with_name("plaintext")
                        .long("plaintext")
                        .takes_value(true)
                        .required(true)
                        .validator(|content| is_hex(content.as_str()))
                        .help("hex encoded plaintext")
                )
                .arg(
                    Arg::with_name("password")
                        .long("password")
                        .takes_value(true)
                        .required(true)
                        .help("password")
                )
        )
        .subcommand(
            SubCommand::with_name("sm4_decrypt")
                .about("decrypt ciphertext using sm4 algorithm")
                .arg(
                    Arg::with_name("ciphertext")
                        .long("ciphertext")
                        .takes_value(true)
                        .required(true)
                        .validator(|content| is_hex(content.as_str()))
                        .help("hex encoded ciphertext")
                )
                .arg(
                    Arg::with_name("password")
                        .long("password")
                        .takes_value(true)
                        .required(true)
                        .help("password")
                )
        )
}

/// Key processor
pub fn key_processor(
    sub_matches: &ArgMatches,
    printer: &Printer,
    config: &GlobalConfig,
) -> Result<(), String> {
    match sub_matches.subcommand() {
        ("create", Some(m)) => {
            let encryption = encryption(m, config);
            let key_pair = KeyPair::new(encryption);
            let is_color = !sub_matches.is_present("no-color") && config.color();
            printer.println(&key_pair, is_color);
        }
        ("from-private", Some(m)) => {
            let encryption = encryption(m, config);
            let private_key = m.value_of("private-key").unwrap();
            let key_pair = KeyPair::from_str(remove_0x(private_key), encryption)?;
            let is_color = !sub_matches.is_present("no-color") && config.color();
            printer.println(&key_pair, is_color);
        }
        ("pub-to-address", Some(m)) => {
            let encryption = encryption(m, config);
            let pubkey = m.value_of("pubkey").unwrap();
            let address = pubkey_to_address(&PubKey::from_str(remove_0x(pubkey), encryption)?);
            if printer.color() {
                printer.println(
                    &format!("{} 0x{:#x}", Yellow.paint("[address]:"), address),
                    true,
                );
            } else {
                printer.println(&format!("{} 0x{:#x}", "[address]:", address), false);
            }
        }
        ("hash", Some(m)) => {
            let encryption = encryption(m, config);
            let content =
                decode(remove_0x(m.value_of("content").unwrap())).map_err(|err| err.to_string())?;
            printer.println(&content.crypt_hash(encryption).lower_hex(), printer.color());
        }
        ("verify", Some(m)) => {
            let encryption = encryption(m, config);
            let pubkey = PubKey::from_str(remove_0x(m.value_of("pubkey").unwrap()), encryption)?;

            let message = {
                let msg = m.value_of("message").unwrap().as_bytes();
                let hash = msg.crypt_hash(encryption).lower_hex();
                Message::from_str(&hash).map_err(|err| err.to_string())?
            };
            let sig = Signature::from(
                &decode(remove_0x(m.value_of("signature").unwrap())).map_err(|e| e.to_string())?,
            );
            println!("{}", sig.verify_public(pubkey, &message)?);
        }
        ("sign", Some(m)) => {
            let encryption = encryption(m, config);
            let privkey = PrivateKey::from_str(remove_0x(m.value_of("privkey").unwrap()), encryption)
                .map_err(|err| err.to_string())?;

            let message = {
                let msg = m.value_of("message").unwrap().as_bytes();
                let hash = msg.crypt_hash(encryption).lower_hex();
                Message::from_str(&hash).map_err(|err| err.to_string())?
            };

            let signature = sign(&privkey, &message);
            println!("signature: 0x{}", signature);
        }
        ("sm4_encrypt", Some(m)) => {
            let password = m.value_of("password").unwrap();
            let plaintext = decode(remove_0x(m.value_of("plaintext").unwrap()))
                .map_err(|err| err.to_string())?;
            let ciphertext = sm4_encrypt(&plaintext, password);
            println!("ciphertext: 0x{}", encode(ciphertext));
        }
        ("sm4_decrypt", Some(m)) => {
            let password = m.value_of("password").unwrap();
            let ciphertext = decode(remove_0x(m.value_of("ciphertext").unwrap()))
                .map_err(|err| err.to_string())?;
            let plaintext = sm4_decrypt(&ciphertext, password);
            println!("plaintext: 0x{}", encode(plaintext));
        }
        _ => {
            return Err(sub_matches.usage().to_owned());
        }
    }
    Ok(())
}
