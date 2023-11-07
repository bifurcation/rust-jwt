use crate::algorithm::{SigningAlgorithm, VerifyingAlgorithm};
use crate::error::Error;
use crate::header::JoseHeader;
use crate::token::signed::SignWithKey;
use crate::token::verified::VerifyWithKey;
use crate::token::{Signed, Unsigned, Unverified, Verified};
use crate::{FromBase64, ToBase64};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Disclosure;

/// Representation of a structured JWT. Methods vary based on the signature
/// type `S`.
pub struct Token<H, C, S> {
    issuer_jwt: crate::Token<H, C, S>,
    disclosures: Vec<Disclosure>,
    signature: S,
}

impl<H, C, S> Token<H, C, S> {
    pub fn issuer_jwt(&self) -> &crate::Token<H, C, S> {
        &self.issuer_jwt
    }

    pub fn remove_signature(self) -> Token<H, C, Unsigned> {
        Token {
            issuer_jwt: self.issuer_jwt.remove_signature(),
            disclosures: self.disclosures,
            signature: Unsigned,
        }
    }
}

impl<H, C> Token<H, C, Unsigned> {
    /// Create a new unsigned token, with mutable headers and claims.
    pub fn new(header: H, claims: C) -> Self {
        Token {
            issuer_jwt: crate::Token::new(header, claims),
            disclosures: Default::default(),
            signature: Unsigned,
        }
    }

    pub fn issuer_jwt_mut(&mut self) -> &mut crate::Token<H, C, Unsigned> {
        &mut self.issuer_jwt
    }
}

impl<H, C> Default for Token<H, C, Unsigned>
where
    H: Default,
    C: Default,
{
    fn default() -> Self {
        Token::new(H::default(), C::default())
    }
}

impl<'a, H, C> Token<H, C, Signed> {
    /// Get the string representation of the token.
    pub fn as_str(&self) -> &str {
        &self.signature.token_string
    }
}

impl<H, C> From<Token<H, C, Signed>> for String {
    fn from(token: Token<H, C, Signed>) -> Self {
        token.signature.token_string
    }
}

impl<'a, H: FromBase64, C: FromBase64> Token<H, C, Unverified<'a>> {
    /// Not recommended. Parse the header and claims without checking the validity of the signature.
    pub fn parse_unverified(token_str: &str) -> Result<Token<H, C, Unverified>, Error> {
        let mut components = token_str.split(SEPARATOR);
        let issuer_jwt = components.next().ok_or(Error::NoIssuerJwt)?;

        let mut raw_disclosures: Vec<String> = components.map(|s| s.into()).collect();
        let last_entry = raw_disclosures.last();
        if last_entry.is_none() || last_entry.unwrap() != "" {
            // XXX(RLB): It seems like Option should have a more elegant flavor of the above
            return Err(Error::InvalidKeyBinding);
        }
        raw_disclosures.pop();

        let issuer_jwt: crate::Token<H, C, _> = crate::Token::parse_unverified(issuer_jwt)?;
        let disclosures: Vec<Disclosure> = raw_disclosures
            .iter()
            .map(|d| Disclosure::from_base64(d))
            .collect::<Result<Vec<_>, _>>()?;
        // We only need this field for type alignment with issuer_jwt
        let signature = Unverified {
            header_str: &"",
            claims_str: &"",
            signature_str: &"",
        };

        Ok(Token {
            issuer_jwt,
            disclosures,
            signature,
        })
    }
}

const SEPARATOR: &str = "~";

impl<H, C> SignWithKey<Token<H, C, Signed>> for Token<H, C, Unsigned>
where
    H: ToBase64 + JoseHeader,
    C: ToBase64,
{
    fn sign_with_key(self, key: &impl SigningAlgorithm) -> Result<Token<H, C, Signed>, Error> {
        let issuer_jwt = self.issuer_jwt.sign_with_key(key)?;

        let disclosures = self
            .disclosures
            .iter()
            .map(|d| d.to_base64())
            .collect::<Result<Vec<_>, _>>()?;

        let mut parts = disclosures;
        parts.insert(0, issuer_jwt.as_str().into()); // issuer JWT comes first
        parts.push("".into()); // empty key binding comes last

        let token_string = parts.join(SEPARATOR);
        Ok(Token {
            issuer_jwt: issuer_jwt,
            disclosures: self.disclosures,
            signature: Signed { token_string },
        })
    }
}

impl<'a, H: JoseHeader, C> VerifyWithKey<Token<H, C, Verified>> for Token<H, C, Unverified<'a>> {
    fn verify_with_key(
        self,
        key: &impl VerifyingAlgorithm,
    ) -> Result<Token<H, C, Verified>, Error> {
        let issuer_jwt = self.issuer_jwt.verify_with_key(key)?;
        Ok(Token {
            issuer_jwt,
            disclosures: self.disclosures,
            signature: Verified,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::algorithm::AlgorithmType::Hs256;
    use crate::error::Error;
    use crate::header::Header;
    use crate::sd::Token;
    use crate::token::signed::SignWithKey;
    use crate::token::verified::VerifyWithKey;
    use crate::Claims;
    use hmac::Hmac;
    use hmac::Mac;
    use sha2::Sha256;

    #[test]
    pub fn raw_data_no_disclosures() -> Result<(), Error> {
        let raw = "eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ~";
        let token: Token<Header, Claims, _> = Token::parse_unverified(raw)?;

        assert_eq!(token.issuer_jwt().header().algorithm, Hs256);

        let verifier: Hmac<Sha256> = Hmac::new_from_slice(b"secret")?;
        assert!(token.verify_with_key(&verifier).is_ok());

        Ok(())
    }

    #[test]
    pub fn roundtrip_no_disclosures() -> Result<(), Error> {
        let token: Token<Header, Claims, _> = Default::default();
        let key: Hmac<Sha256> = Hmac::new_from_slice(b"secret")?;
        let signed_token = token.sign_with_key(&key)?;
        let signed_token_str = signed_token.as_str();

        let recreated_token: Token<Header, Claims, _> = Token::parse_unverified(signed_token_str)?;

        assert_eq!(
            signed_token.issuer_jwt().header(),
            recreated_token.issuer_jwt().header()
        );
        assert_eq!(
            signed_token.issuer_jwt().claims(),
            recreated_token.issuer_jwt().claims()
        );
        recreated_token.verify_with_key(&key)?;
        Ok(())
    }
}
