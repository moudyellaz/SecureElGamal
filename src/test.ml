(* Testing *)
open Elgamal

let group1024 = 
  let pbits = 1024 in
  let p = 
    Z.of_string "125523584999034538210001592548399210296896604498265434746636864649711343642409219587158216217518029583876224875052771050097736562946444503265933852150653651984481512390890800346555452834223348242027110859441109903844595359631804185895073640995154120471519631783558242014298463411521978962333002749989287415283" in
  let g = Z.of_int 4 in
  Elgamal.mk_group pbits p g 

let _ =
  Format.printf "enter a number of bits, less or equal to 0 means default group of 1024 bits otherwise random generation of the group:@.";
  let pbits = read_int () in
  let gr = 
    if pbits <= 0 then group1024 
    else begin
      Format.printf "generate group@.";
      Elgamal.sample_group pbits 
    end in 
      
  while true do 
    Format.printf "generate keys@.";
    let {pkey; skey} = Elgamal.keygen gr in
    Format.printf "keys generated@.";
    Format.printf "skey = %s@." (Z.to_string skey.Elgamal.key);
    Format.printf "pkey = %s@." (Z.to_string pkey.Elgamal.key);
    let rec aux () = 
      Format.printf "enter a number (negative means generate new keys:@.";
      let msg = Z.of_string (read_line ()) in
      if (Z.lt msg Z.zero) then ()
      else 
        begin 
          (try 
            let (u, v) = (Elgamal.encrypt_check pkey msg) in
            Format.printf "msg = %s@.(u, v) = (%s, %s)@."
              (Z.to_string msg) (Z.to_string u) (Z.to_string v);
            let msg' = Elgamal.decrypt_check skey (u,v) in
            Format.printf " msg' = %s@.%s@." 
              (Z.to_string msg')
              (if Z.equal msg msg' then "OK" else "ERROR")
          with BadElem -> 
            Format.printf "cannot encode the message@.");
          aux() 
        end in
    aux ()
  done




