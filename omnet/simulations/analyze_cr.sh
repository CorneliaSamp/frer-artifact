#!/bin/sh
# analyze_cr.sh <ConfigName> [key=val ...]
# Runs a CR config (optionally with ini overrides via --<key>=<val>) and computes the CR metrics
# from the payload-size discriminator at the listener: attacker payload=100B, legit=256B.
#   N_acc  = #100B received (accepted+delivered attacker frames)
#   L_supp = 1000 - #256B received (suppressed legit frames)
#   A_loss = L_supp / N_acc ;  PDR = legit_delivered/1000
#   max_burst = largest contiguous legit loss (from time gaps of the 256B deliveries)
CFG="$1"; shift
cd "$(dirname "$0")"
../src/frer_experiments -u Cmdenv -c "$CFG" "$@" -n .:../src:../../inet-4.7.0/src -l ../../inet-4.7.0/src/INET >/dev/null 2>&1
SCA="results/${CFG}-#0.sca"; VEC="results/${CFG}-#0.vec"
IN=$(grep -E 'S4\.bridging\.streamRelay\.merger incomingPackets:count' "$SCA" | awk '{print $NF}')
DROP=$(grep -E 'S4\.bridging\.streamRelay\.merger droppedPackets:count' "$SCA" | awk '{print $NF}')
OUT=$(grep -E 'S4\.bridging\.streamRelay\.merger outgoingPackets:count' "$SCA" | awk '{print $NF}')
SENT=$(grep -E 'attacker\.app\[0\] packetSent:count' "$SCA" | awk '{print $NF}')
VECID=$(grep -E 'vector [0-9]+ FRERTestNetwork\.listener\.app\[0\]\.io packetReceived:vector\(packetBytes\)' "$VEC" | awk '{print $2}')
awk -v id="$VECID" -v cfg="$CFG" -v inc="$IN" -v drop="$DROP" -v out="$OUT" -v sent="$SENT" '
  $1==id && $4==100 {nacc++}
  $1==id && $4==256 {legit++; t=$3; if(prev!=""){gap=t-prev; if(gap>maxgap)maxgap=gap} prev=t}
  END{
    lsupp=1000-legit;
    printf "[%s] merger in/drop/out=%d/%d/%d  attacker_sent=%d\n", cfg, inc, drop, out, sent;
    printf "  N_acc=%d  legit_delivered=%d  L_supp=%d  PDR=%.3f\n", nacc, legit, lsupp, legit/1000.0;
    if(nacc>0) printf "  A_loss = %.3f\n", lsupp/nacc; else printf "  A_loss = n/a\n";
    # max_burst: largest 256B time gap, minus the normal 1ms cadence, in frames
    printf "  max_loss_burst ~ %d frames (max 256B gap=%.1f ms)\n", (maxgap*1000)-1+0.5, maxgap*1000;
  }' "$VEC"
