(* Plain implementation of ElGamal scheme *)


(* Define the type of group and keys *)

type group = {
  pbits : int;
  p     : Z.t;
  g     : Z.t;
}

type key = {
  group : group;
  key   : Z.t;
             }

type pkey = key
type skey = key

type keys = {
  skey : skey;
  pkey : pkey;
}

type cipher = Z.t * Z.t

(* --------------------------------------------------------------------------- *)

(* [q p] returns [p/2] *)
let q p = Z.shift_right p 1

(* [quad p q x] tests if x is a quadratic residue in p *)
let quad p x = Z.equal ( Z.powm x (q p) p) Z.one 

(* [ mulm gr m n] returns the multiplication modulo p *)
let mulm gr m n = Z.(mod) (Z.mul m n) gr.p


(* --------------------------------------------------------------------------- *)

(* Return a random number of [n] bits *)
let _ = Random.self_init ()

let sample n =
  let rec aux n p = 
    if n = 0 then p
    else
      let b = Random.bool () in
      let q = Z.shift_left p 1 in (* 2p *)
      let q' = if b then Z.succ q  (* 2p + 1 *) else q (* 2p *) in
      aux (n-1) q' in
  if (n <= 0) then raise (Invalid_argument "sample");
  aux (n-1) Z.one


(* Return a random number between 1 and q-1 *)
let rec sample_le nbits q =
  let x = sample nbits in
  if Z.lt Z.zero x && Z.lt x q then x
  else sample_le nbits q


exception Check_safe_prime


(* Ensure that p is a safe prime of nbits *)
let check_safe_prime nbits p = 
  if not (Z.leq Z.zero p && Z.numbits p = nbits && 
          Z.probab_prime (q p) 10 <> 0 && Z.probab_prime p 10 <> 0) then
    raise Check_safe_prime


let rec random_safe_prime nbits =
  let q = sample (nbits - 1) in
  let q = Z.nextprime q in
  let p = Z.succ (Z.shift_left q 1) in
  try check_safe_prime nbits p; p 
  with Check_safe_prime -> random_safe_prime nbits


(* Make the group of order safe prime *)
let mk_group pbits p g = 
  let sp = try check_safe_prime pbits p; true with Check_safe_prime -> false in
  if sp && quad p g then { pbits; p; g }
  else raise (Invalid_argument "mk_group")

(* Generator *)
let generator p = 
  let g = Z.of_int 4 in
  if not (Z.lt g p) then raise (Invalid_argument "generator");
  g

(* Sample the right group and generator *)
let sample_group pbits =
  let p = random_safe_prime pbits in
  let g = generator p in
  { pbits; p; g }

exception BadElem

(* Key generation *)

let keygen gr =
  let pbits = gr.pbits in
  let p = gr.p in                                       (* p prime *)
  let q = q gr.p in                                     (* q prime *)
  let g = gr.g in                                       (* g generator *)
  let x = sample_le (pbits - 1) q in                    (* choose x /in q *)
  { skey = { group = gr; key = x};                      (* x: private key *)
    pkey = { group = gr; key = Z.powm g x p }; }        (* y: public key as y=g^x mod p *)

(* --------------------------------------------------------------------------- *)

(* TO DO with the interviewer *)

(* Encrypt a message [m] with the public key [pk]: c = (u,v) = (g^r mod p, m*g^r mod p)  *)

(* Decrypt a ciphertext [c] with the secret key [sk]: m = v * u^(-x)  *)

(* Add an encoding and decoding technique to make sure that the selected messaged are in the right group *)


