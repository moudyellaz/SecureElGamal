ElGamal is an asymmetric encryption scheme that consists of three algorithms: key generation(η), η being a security parameter, encryption E(m, pk) with m being a plaintext
and pk a public key, and decryption D(c,sk) where c is a ciphertext and sk is a private key. 

The ElGamal encryption scheme is known to be IND-CPA secure under the decisional Diffie-Hellman assumption:

Given two distributions DDH0 = (g^x, g^y, g^xy) and DDH1 = (g^x, g^y, g^z) where x, y,z are randomly distributed in Zq, a cyclic group with generator g. It
is hard to distinguish between DDH0 and DDH1.

An encryption scheme is said to be IND-CPA secure if a polynomial time adversary choosing two plaintexts cannot distinguish between the resulting ciphertexts.
If the adversary can distinguish between the ciphertexts better than guessing blindly, we say that the adversary achieves an advantage. The advantage of any
efficient adversary is expressed as a negligible function of the security parameter in the formal definition
of IND-CPA . For ElGamal, the security parameter is
the key length.
