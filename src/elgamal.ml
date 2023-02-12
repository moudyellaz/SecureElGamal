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
