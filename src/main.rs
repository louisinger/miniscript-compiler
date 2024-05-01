extern crate elements_miniscript as miniscript;
extern crate hex;

use miniscript::extensions;
use miniscript::policy;
use miniscript::Descriptor;
use miniscript::MiniscriptKey;
use serde::{Deserialize, Serialize};
use std::env;
use std::str::FromStr;

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct HexBytes(pub Vec<u8>);

impl HexBytes {
    pub fn hex(&self) -> String {
        hex::encode(&self.0)
    }

    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn take_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for HexBytes {
    fn from(vec: Vec<u8>) -> HexBytes {
        HexBytes(vec)
    }
}

impl<'a> From<&'a [u8]> for HexBytes {
    fn from(slice: &'a [u8]) -> HexBytes {
        HexBytes(slice.to_vec())
    }
}

impl ::serde::Serialize for HexBytes {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> ::serde::Deserialize<'de> for HexBytes {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<HexBytes, D::Error> {
        use serde::de::Error;

        let hex_str: String = ::serde::Deserialize::deserialize(d)?;
        Ok(HexBytes(hex::decode(hex_str).map_err(D::Error::custom)?))
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MiniscriptKeyType {
    PublicKey,
    String,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct DescriptorInfo {
    pub descriptor: String,
    pub key_type: MiniscriptKeyType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_pubkey: Option<HexBytes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_satisfaction_weight: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_paths: Option<Vec<String>>
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct PolicyInfo {
    pub is_concrete: bool,
    pub key_type: MiniscriptKeyType,
    pub is_trivial: bool,
    pub is_unsatisfiable: bool,
    pub relative_timelocks: Vec<u32>,
    pub n_keys: usize,
    pub minimum_n_keys: usize,
    pub sorted: String,
    pub normalized: String,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let cmd: &str = &args[1];
        match cmd {
            "descriptor" => parse_descriptor(format_str(args[2].clone())),
            "policy" => {
                if let Ok(info) = parse_policy::<bitcoin::PublicKey>(
                    args[2].as_str(),
                    MiniscriptKeyType::PublicKey,
                ) {
                    println!("{}", serde_json::to_string_pretty(&info).unwrap());
                } else if let Ok(info) =
                    parse_policy::<String>(args[2].as_str(), MiniscriptKeyType::String)
                {
                    println!("{}", serde_json::to_string_pretty(&info).unwrap());
                }
            }
            _ => println!("Unknown command: {}", cmd),
        }
    }
}

fn parse_descriptor(desc_str: String) {
    let info = Descriptor::<bitcoin::PublicKey>::from_str(
        desc_str.as_str(),
    ).map(|desc| DescriptorInfo {        
			descriptor: desc.to_string(),
			key_type: MiniscriptKeyType::PublicKey,
			script_pubkey: Some(desc.script_pubkey().into_bytes().into()),
			max_satisfaction_weight: desc.max_weight_to_satisfy().ok(),
			policy: policy::Liftable::lift(&desc).map(|pol| pol.to_string()).ok(),
            script_paths: if let miniscript::Descriptor::TrExt(ref p) = desc {
                Some(
                    p.iter_scripts().map(
                        |(_ ,script)| script
                            .as_miniscript().unwrap().encode().asm()
                    )
                    .collect()
                )
            } else if let miniscript::Descriptor::Tr(ref p) = desc {
                Some(
                    p.iter_scripts().map(
                        |(_ ,script)| script
                            .as_miniscript().unwrap().encode().asm()
                    )
                    .collect()
                )
            } else {
                None
            }
		})
		.or_else(|e| {
            println!("Error: {}", e);

			// Then try with strings.
			desc_str
            .parse::<Descriptor<String, extensions::CovenantExt<extensions::CovExtArgs>>>()
            .map(|desc| DescriptorInfo {
				descriptor: desc.to_string(),
				key_type: MiniscriptKeyType::String,
				script_pubkey: None,
				max_satisfaction_weight: desc.max_weight_to_satisfy().ok(),
				policy: policy::Liftable::lift(&desc).map(|pol| pol.to_string()).ok(),
                script_paths: None
			})
		});

    if let Ok(info) = info {
        println!("{}", serde_json::to_string_pretty(&info).unwrap());
    }
}

fn parse_policy<Pk: MiniscriptKey>(
    policy_str: &str,
    key_type: MiniscriptKeyType,
) -> Result<PolicyInfo, miniscript::Error>
where
    Pk: std::str::FromStr,
    <Pk as std::str::FromStr>::Err: std::fmt::Display,
    <Pk as MiniscriptKey>::Sha256: std::str::FromStr,
    <Pk as MiniscriptKey>::Hash256: std::str::FromStr,
    <Pk as MiniscriptKey>::Ripemd160: std::str::FromStr,
    <Pk as MiniscriptKey>::Hash160: std::str::FromStr,
    <<Pk as MiniscriptKey>::Sha256 as std::str::FromStr>::Err: std::fmt::Display,
    <<Pk as MiniscriptKey>::Hash256 as std::str::FromStr>::Err: std::fmt::Display,
    <<Pk as MiniscriptKey>::Ripemd160 as std::str::FromStr>::Err: std::fmt::Display,
    <<Pk as MiniscriptKey>::Hash160 as std::str::FromStr>::Err: std::fmt::Display,
{
    let concrete_pol: Option<policy::Concrete<Pk>> = policy_str.parse().ok();
    let policy = (match concrete_pol {
        Some(ref concrete) => policy::Liftable::lift(concrete),
        None => policy_str.parse(),
    })
    .unwrap();

    Ok(PolicyInfo {
        is_concrete: concrete_pol.is_some(),
        key_type: key_type,
        is_trivial: policy.is_trivial(),
        is_unsatisfiable: policy.is_unsatisfiable(),
        relative_timelocks: policy.relative_timelocks(),
        n_keys: policy.n_keys(),
        minimum_n_keys: policy
            .minimum_n_keys()
            .ok_or(miniscript::Error::CouldNotSatisfy)?,
        sorted: policy.clone().sorted().to_string(),
        normalized: policy.clone().normalized().to_string(),
    })
}

fn format_str(str: String) -> String {
    // remove \t, \n, \r and " "
    // remove all unprintable characters
    str
        .replace("\t", "")
        .replace("\n", "")
        .replace("\r", "")
        .replace(" ", "")
        .chars()
        .filter(|c| c.is_ascii() && !c.is_control())
        .collect()
}
