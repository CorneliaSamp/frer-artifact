#!/bin/sh
# analyze_rsd.sh <Delta>
# Runs the RSD config with the given Delta and computes A_loss from the payload-size discriminator.
#   legit_sent = talker packetSent ;  N_acc = #100B at the listener (=1) ;  delivered256 = #256B
#   L_supp = legit_sent - delivered256 (suppressed resuming legit) ;  A_loss = L_supp / N_acc
D="$1"
cd "$(dirname "$0")"
../src/frer_experiments -u Cmdenv -c RSD "--*.attacker.app[0].offsets=\"$D\"" -n .:../src:../../inet-4.7.0/src -l ../../inet-4.7.0/src/INET >/dev/null 2>&1
SCA="results/RSD-#0.sca"; VEC="results/RSD-#0.vec"
LSENT=$(grep -E 'talker\.app\[0\] packetSent:count' "$SCA" | awk '{print $NF}')
VECID=$(grep -E 'vector [0-9]+ FRERTestNetwork\.listener\.app\[0\]\.io packetReceived:vector\(packetBytes\)' "$VEC" | awk '{print $2}')
awk -v id="$VECID" -v d="$D" -v lsent="$LSENT" '
  $1==id && $4==100 {nacc++}
  $1==id && $4==256 {legit++}
  END{
    lsupp=lsent-legit;
    printf "Delta=%-3s | legit_sent=%d N_acc=%d legit_deliv=%d L_supp=%d", d, lsent, nacc, legit, lsupp;
    if(nacc>0) printf " | A_loss=%.1f\n", lsupp/nacc; else printf " | A_loss=n/a\n";
  }' "$VEC"
