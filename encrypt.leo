program core.aleo {
    // This function takes as input a field `a` and calls several core functions.
    // Core functions are built-in to the Leo language and call handwritten, optimized circuits in the AVM.
    // To call a core function, use the correct capitalized identifier followed by two colons
    // and then the function name. Example: `Pedersen64::hash()`.
    transition main(a: field, pk: group) -> (group, field) {
        let (c0, c1):(group, field) = elgamalEncrypt(a, 1scalar, pk, 2group);
        return (c0, c1);
    }

    // elgamalEncrypt()
    //
    // Given a public Elgamal key (group element), a message (field element) and
    // a random field element (nonce), and a generator of the group (generator),
    // produces a valid CCA-secure Elgamal ciphertext.
    function elgamalEncrypt(plaintext: field, nonce: scalar, pubKey: group, generator: group) -> (group, field) {
        // c0 = r * G
        // epk = r * PK
        // c1 = H(epk) (as field elt) + plaintext (as field elt)
        let c0: group = nonce * generator;
        let epk: group = nonce * pubKey;
        let c1: field = (BHP256::hash(epk) + plaintext);

        // return c0, c1
        return (c0, c1);
    }
}
