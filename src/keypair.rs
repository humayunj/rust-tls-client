use crypto::curve25519;

pub struct KeyPair {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
}

impl From<[u8; 32]> for KeyPair {
    fn from(secret: [u8; 32]) -> Self {
        let public_key = curve25519::curve25519_base(&secret[..]);
        KeyPair {
            private_key: secret,
            public_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let secret: [u8; 32] = hex::decode(
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f".as_bytes(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        let kp = KeyPair::from(secret);

        assert_eq!(
            hex::encode(kp.public_key),
            "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"
        );
    }
}
