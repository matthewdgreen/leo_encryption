program core.aleo {

    // NOTE: TEST CODE, DOES NOT COMPILE YET

    struct ecies_ciphertext {
        C0: group,
        C1: field;
        C2: field;
    }

    // Test function for ECIES
    transition main(a: field, pk: group) -> (group, field) {
        let (c0, c1):(group, field) = crypto_encrypt_ecies(a, 2scalar, pk, 2group);
        let plaintext:field = crypto_decrypt_ecies(sk, c0, c1);

        return (c0, c1, plaintext);
    }
    

    // eciesKeygen()
    // 
    // Given some entropy and a generator, return a public key.
    // This requires that the entropy be passed from an external source,
    // since Leo does not have any sort of internal RNG.
    function crypto_keygen_ecies(entropy: field, generator: group) {
      // pk = hash(entropy) * G
      let sk: scalar = Poseidon8::hash_to_scalar(entropy);
      let pk: group = scalar * generator;

      // return pk
      return pk;
    }


    // eciesEncrypt()
    //
    // Given a public ECIES key (group element), a message (field element) and
    // a random field element (nonce), and a generator of the group (generator),
    // produces a valid CCA-secure ECIES ciphertext.
    function crypto_encrypt_ecies(plaintext: field, random: scalar, pubKey: group, generator: group) -> (group, field) {
        // c0 = r * G
        // epk = r * PK
        // c1 = H(epk) (as field elt) + plaintext (as field elt)
        let c0: group = nonce * generator;
        let epk: group = nonce * pubKey;
        let encKey: field = Poseidon8::hash_to_field(epk);
        let macKey: field = Poseidon8::hash_to_field(epk); // Need to pluralize this!
        let c1: field = encKey + plaintext;
        let c2: field = Poseidon8::hash_to_field(macKey, plaintext);

        // return c0, c1
        return ecies_ciphertext {
          C0: c0,
          C1: c1,
          C2: c2
        }  
    }

    // eciesDecrypt()
    //
    // Given an ECIES ciphertext and a secret key, decrypt and return the plaintext
    // or an error.
    function crypto_decrypt_ecies(sk: scalar, c0: group, c1: field) -> (field) {
        // epk = sk * c0
        // plaintext = c1 - H(epk)
        //
        // This hash should be Poseidon! It's currently using BHP, which is totally bogus
        // and insecure, because Poseidon isn't supported
        //
        let epk: group = sk * c0;
        let plaintext: field = (c1 - BHP256::hash(epk));

        // return c0, c1
        return plaintext;
    }
}