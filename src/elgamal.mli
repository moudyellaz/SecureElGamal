  let g = Z.of_int 4 in
  if not (Z.lt g p) then raise (Invalid_argument "generator");
  g

let sample_group pbits =
  let p = random_safe_prime pbits in
  let g = generator p in
  { pbits; p; g }

exception BadElem
(* Encode *)
let encode gr m  = 
  if not (Z.leq Z.zero m && Z.lt m (Z.sub (q gr.p) (Z.of_int 2))) then
    raise BadElem;
  Z.powm (Z.succ m) (Z.of_int 2) gr.p

(* Decode *)
let decode gr m =
  let p = gr.p in
  let q = q gr.p in
  let r = Z.powm m (Z.shift_right (Z.succ q) 1) p  in
  let m = if Z.leq r q then r else (Z.sub p r) in
  (Z.pred m)

(* Key generation *)
 
let keygen gr =
  let pbits = gr.pbits in
  let p = gr.p in 
  let q = q gr.p in
  let g = gr.g in 
  let x = sample_le (pbits - 1) q in
  { skey = { group = gr; key = x};
    pkey = { group = gr; key = Z.powm g x p }; }


(* --------------------------------------------------------------------------- *)
(* Encryption and decryption without encoding/decoding                         *)

(* [unsafe_encrypt pk m] return the encryption of [m] under the 
   publick key [pk].
   [m] is assumed to be an element of the group                                *)
let unsafe_encrypt pk m = 
  let gr = pk.group in
  let r = sample_le (gr.pbits - 1) (q gr.p) in
  (Z.powm gr.g r gr.p, mulm gr (Z.powm pk.key r gr.p) m)

(* [unsafe_decrypt sk c] return the decryption of [c] under the             
   secret key [sk].
   The resulting message should be a element of the group                      *)
let unsafe_decrypt sk (u,v) = 
  let gr = sk.group in
  let mult =  Z.mul (Z.pred (q gr.p)) sk.key in
  let modulo = Z.powm u mult gr.p in
  mulm gr v modulo 

(* [encrypt_check pk m] return the encryption of [m] under the 
   publick key [pk].
   Raise BadElem if [m] is not a element of the group                          *)
let encrypt_check pk m = 
   let gr = pk.group in
   if not (Z.leq Z.one m && Z.lt m gr.p && quad gr.p m) then
     raise BadElem;
   unsafe_encrypt pk m

(* [decrypt_check sk c] return the decryption of [c] under the             
   secret key [sk].                                                            *)
let decrypt_check = unsafe_decrypt 

(* [encrypt pk m] return the encryption of [m] under the 
   publick key [pk]. 
   The message [m] is encoded.
   Raise BadElem if [m] cannot be encoded                                      *)
let encrypt pk m = 
  unsafe_encrypt pk (encode pk.group m)

(* [decrypt sk c] return the decryption of [c] under the             
   secret key [sk]. 
   The resulting message is decode                                             *)
let decrypt sk c = 
  decode sk.group (unsafe_decrypt sk c)

