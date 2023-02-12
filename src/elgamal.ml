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
