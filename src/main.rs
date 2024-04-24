extern crate elements_miniscript as miniscript;

use std::str::FromStr;

use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let cmd : &str = &args[1];
        match cmd {
            "parse" => {
                // remove white spaces
                let arg: &str = &args[2].replace(" ", "");

                let desc_pub_key = miniscript::Descriptor::<bitcoin::PublicKey>::from_str(arg);
                if desc_pub_key.is_err() {
                    println!("Error: {}", desc_pub_key.err().unwrap());
                } else {
                    let script_pub_key = desc_pub_key.unwrap().script_pubkey();
                    println!("ScriptPubKey: \n\t{}", script_pub_key.to_string());
                }

                let desc = miniscript::Descriptor::<String>::from_str(arg).unwrap();
                if let miniscript::Descriptor::Tr(ref p) = desc {
                    let internal_key = p.internal_key();
                    println!("Internal key: \n\t{}", internal_key.to_string());

                    for (i, (_, script)) in p.iter_scripts().enumerate() {
                        println!("Tapscript #{}: \n\t{}", i, script.as_miniscript().unwrap().to_string());
                        
                    }
                } 
            },
            _ => {
                println!("Unknown command: {}", cmd);
            }
        }
    }
}
