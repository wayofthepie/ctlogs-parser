use anyhow::{anyhow, Result};
use der_parser::oid;
use serde::{Deserialize, Serialize};
use x509_parser::{
    extensions::{GeneralName, ParsedExtension, SubjectAlternativeName, X509Extension},
    prelude::oid_registry,
};

#[derive(Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub struct Logs {
    pub entries: Vec<LogEntry>,
}

#[derive(Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub struct LogEntry {
    /// The `leaf_input` field is a `String` of base64 encoded data. The data is a DER encoded
    /// MerkleTreeHeader, which has the following structure.
    /// ```no_compile
    /// [0] [1] [2..=9] [10..=11] [12..=14] [15..]
    /// |   |     |        |         |      |
    /// |   |     |        |         |      |- rest
    /// |   |     |        |         |
    /// |   |     |        |         |- length
    /// |   |     |        |
    /// |   |     |        | - log entry type
    /// |   |     |
    /// |   |     | - timestamp
    /// |   |
    /// |   | - signature type
    /// |
    /// | - version
    /// ```
    ///
    pub leaf_input: String,
    pub extra_data: String,
}

#[derive(Debug)]
pub struct CertDetails {
    pub subject: String,
    pub not_before: i64,
    pub not_after: i64,
    pub san: Vec<String>,
}

pub fn parse_logs(logs: Logs) -> Vec<(usize, Result<CertDetails>)> {
    let mut details = vec![];
    for (position, entry) in logs.entries.iter().enumerate() {
        match base64::decode(&entry.leaf_input) {
            Ok(bytes) => {
                let entry_type = bytes[10] + bytes[11];
                if entry_type == 0 {
                    let cert_end_index =
                        u32::from_be_bytes([0, bytes[12], bytes[13], bytes[14]]) as usize + 15;
                    details.push((
                        position,
                        parse_x509_bytes(&bytes[15..cert_end_index], position),
                    ));
                } else {
                    println!("precert");
                }
            }
            Err(_) => details.push((
                position,
                Err(anyhow!("Failed to base64 decode certificate")),
            )),
        }
    }
    details
}

fn parse_x509_bytes(bytes: &[u8], position: usize) -> Result<CertDetails> {
    match x509_parser::parse_x509_certificate(bytes) {
        Ok((_, cert)) => {
            let subject = cert.subject().to_string_with_registry(oid_registry())?;
            let validity = cert.validity();
            let not_before = validity.not_before.timestamp();
            let not_after = validity.not_after.timestamp();
            let extensions = cert.extensions();
            // skip formatting this for now, the ".17" gets prefixed with a space, doesnt break
            // but looks weird
            #[rustfmt::skip]
            let san_oid = oid!(2.5.29.17);
            let san = extensions
                .iter()
                .filter(|extension| extension.oid == san_oid)
                .flat_map(decode_san)
                .collect();
            let details = CertDetails {
                subject,
                not_before,
                not_after,
                san,
            };
            Ok(details)
        }
        Err(err) => Err(anyhow!("Error at position {}: {}", position, err)),
    }
}

fn decode_san(san: &X509Extension) -> Vec<String> {
    if let ParsedExtension::SubjectAlternativeName(SubjectAlternativeName { general_names }) =
        san.parsed_extension()
    {
        general_names.iter().fold(Vec::new(), |mut acc, name| {
            match name {
                GeneralName::OtherName(_, _) => {
                    // skip
                }
                GeneralName::RFC822Name(rfc822) => {
                    acc.push(rfc822.to_string());
                }
                GeneralName::DNSName(dns) => {
                    acc.push(dns.to_string());
                }
                GeneralName::DirectoryName(name) => {
                    acc.push(name.to_string());
                }
                GeneralName::URI(uri) => {
                    acc.push(uri.to_string());
                }
                GeneralName::IPAddress(_) => {
                    // skip
                }
                GeneralName::RegisteredID(_) => {
                    // skip
                }
                GeneralName::X400Address(_) => {
                    // skip
                }
                GeneralName::EDIPartyName(_) => {
                    // skip
                }
            }
            acc
        })
    } else {
        vec![]
    }
}

#[cfg(test)]
mod test {
    use super::{parse_logs, LogEntry, Logs};

    #[test]
    fn should_parse_cert_from_leaf_data() {
        let cert = include_str!("../resources/test/leaf_input_with_cert").trim();
        let logs = Logs {
            entries: vec![LogEntry {
                leaf_input: cert.to_string(),
                extra_data: "".to_string(),
            }],
        };
        let mut result = parse_logs(logs);
        assert_eq!(result.len(), 1);
        let details = result.pop().unwrap().1.unwrap();
        assert_eq!(details.subject, "CN=www.libraryav.com.au".to_string());
        assert_eq!(details.not_before, 1501804800);
        assert_eq!(details.not_after, 1596499199);
        assert_eq!(
            details.san,
            vec!["www.libraryav.com.au", "libraryav.com.au"]
        );
    }

    #[test]
    fn should_parse_cert_where_san_has_directory_name() {
        let cert =
            include_str!("../resources/test/leaf_input_cert__san_with_directory_name").trim();
        let logs = Logs {
            entries: vec![LogEntry {
                leaf_input: cert.to_string(),
                extra_data: "".to_string(),
            }],
        };
        let mut result = parse_logs(logs);
        assert_eq!(result.len(), 1);
        let details = result.pop().unwrap().1.unwrap();
        //        assert_eq!(details.subject, "CN=www.libraryav.com.au".to_string());
        //        assert_eq!(details.not_before, 1501804800);
        //        assert_eq!(details.not_after, 1596499199);
        assert_eq!(details.san, vec!["CN=VeriSignMPKI-2-58"]);
    }
}
