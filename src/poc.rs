#![allow(non_snake_case)]

/*
    KMS

    Copyright 2018 by Kzen Networks

    This file is part of KMS library
    (https://github.com/KZen-networks/kms)

    KMS is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/kmd/blob/master/LICENSE>
*/

#[cfg(test)]
mod tests {
    use std::cmp;

    use curv::{BigInt, elliptic::curves::traits::ECScalar, FE, arithmetic::traits::Modulo};
    use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::{party_one, party_two};


    #[test]
    fn test_two_party_blinded_sign() {
        // assume party1 and party2 engaged with KeyGen in the past resulting in
        // party1 owning private share and paillier key-pair
        // party2 owning private share and paillier encryption of party1 share
        let (_party_one_private_share_gen, _comm_witness, ec_key_pair_party1) =
            party_one::KeyGenFirstMsg::create_commitments();
        let (party_two_private_share_gen, ec_key_pair_party2) = party_two::KeyGenFirstMsg::create();
    
        let keypair =
            party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(&ec_key_pair_party1);
    
        // creating the ephemeral private shares:
    
        let (eph_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
            party_two::EphKeyGenFirstMsg::create_commitments();
        let (eph_party_one_first_message, eph_ec_key_pair_party1) =
            party_one::EphKeyGenFirstMsg::create();
        let eph_party_two_second_message = party_two::EphKeyGenSecondMsg::verify_and_decommit(
            eph_comm_witness,
            &eph_party_one_first_message,
        )
        .expect("party1 DLog proof failed");
    
        let _eph_party_one_second_message =
            party_one::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
                &eph_party_two_first_message,
                &eph_party_two_second_message,
            )
            .expect("failed to verify commitments and DLog proof");
        let party2_private = party_two::Party2Private::set_private_key(&ec_key_pair_party2);
        let message = BigInt::from(1234);
    
        let blinding_factor: FE = ECScalar::new_random();
        let inv_blinding_factor = blinding_factor.invert();
    
        let partial_sig = party_two::PartialSig::compute_blinded(
            &keypair.ek,
            &keypair.encrypted_share,
            &party2_private,
            &eph_ec_key_pair_party2,
            &eph_party_one_first_message.public_share,
            &message,
            &blinding_factor.to_big_int(),
        );
    
        let party1_private = party_one::Party1Private::set_private_key(&ec_key_pair_party1, &keypair);
    
        let blinded_signature = party_one::Signature::compute_blinded(
            &party1_private,
            &partial_sig.c4,
            &eph_ec_key_pair_party1,
        );
    
        let q = FE::q();
    
        let unblinded_signature_s1 = BigInt::mod_mul(&blinded_signature.s, &inv_blinding_factor.to_big_int(), &q);
    
        let unblinded_message_s = cmp::min(
            unblinded_signature_s1.clone(),
            FE::q() - unblinded_signature_s1,
        );
    
        let signature = party_one::Signature {
            r: partial_sig.r,
            s: unblinded_message_s,
        };
    
        let pubkey =
            party_one::compute_pubkey(&party1_private, &party_two_private_share_gen.public_share);
        party_one::verify(&signature, &pubkey, &message).expect("Invalid signature");
    
        let party_one_pubkey = party_one::compute_pubkey(&party1_private, &ec_key_pair_party2.public_share);
        party_one::verify(&signature, &party_one_pubkey, &message).expect("Invalid signature");
    
    }
}
