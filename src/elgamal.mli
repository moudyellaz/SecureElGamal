(* Types for ElGamal *)

(* --------------------------------------------------------------------------- *)
type group = private {
  pbits : int;
  p     : Z.t;
  g     : Z.t;
}

type key = private {
  group : group;
  key   : Z.t;
             }

type pkey = key
type skey = key

type keys = private {
  skey : skey;
  pkey : pkey;
}

type cipher = Z.t * Z.t

(* --------------------------------------------------------------------------- *)
val random_safe_prime : int -> Z.t 

val sample_group : int -> group

(* building a group *)
val mk_group : int -> Z.t -> Z.t -> group

(* Encode *)
val encode : group -> Z.t -> Z.t 

(* Decode *)
val decode : group -> Z.t -> Z.t 

(* Key generation *)
 
val keygen : group -> keys

(* --------------------------------------------------------------------------- *)
(* Encryption and decryption without encoding/decoding                         *)

(* [unsafe_encrypt pk m] return the encryption of [m] under the 
   publick key [pk].
   [m] is assumed to be an element of the group                                *)
val unsafe_encrypt : pkey -> Z.t -> cipher

(* [unsafe_decrypt sk c] return the decryption of [c] under the             
   secret key [sk].
   The resulting message should be a element of the group                      *)
val unsafe_decrypt : skey -> cipher -> Z.t

exception BadElem
(* [encrypt_check pk m] return the encryption of [m] under the 
   publick key [pk].
   Raise BadElem if [m] is not a element of the group                          *)
val encrypt_check : pkey -> Z.t -> cipher

(* [decrypt_check sk c] return the decryption of [c] under the             
   secret key [sk].                                                            *)
val decrypt_check : skey -> cipher -> Z.t

(* [encrypt pk m] return the encryption of [m] under the 
   publick key [pk]. 
   The message [m] is encoded.
   Raise BadElem if [m] cannot be encoded                                      *)
val encrypt : pkey -> Z.t -> cipher

(* [decrypt sk c] return the decryption of [c] under the             
   secret key [sk]. 
   The resulting message is decoded                                            *)
val decrypt : skey -> cipher -> Z.t


