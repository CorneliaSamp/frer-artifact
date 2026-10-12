#!/bin/sh
# analyze_rsdhw.sh <Delta>   (Delta="-" for D0/N0 without a sweep -> config name as $2)
# HW-faithful RSD evaluation. Burst 100/1.2s/512B, 50 bursts, 16 injections ACTIVE.
# Discriminator: attacker=100B, legit=512B. legit_TX=5000. supp/inj = (5000-legit_RX)/N_acc = A_loss.
D="$1"; CFG="${2:-RSDHW}"
cd "$(dirname "$0")"
if [ "$D" = "-" ]; then
  # baseline/control configs without a Delta override (D0, N0)
  ../src/frer_experiments -u Cmdenv -c "$CFG" -n .:../src:../../inet-4.7.0/src -l ../../inet-4.7.0/src/INET >/dev/null 2>&1
else
  # Delta sweep on any RSDHW* config (e.g. RSDHW, RSDHW_H8)
  ../src/frer_experiments -u Cmdenv -c "$CFG" "--*.attacker.app[0].offsets=\"$D\"" -n .:../src:../../inet-4.7.0/src -l ../../inet-4.7.0/src/INET >/dev/null 2>&1
fi
VEC="results/${CFG}-#0.vec"
VECID=$(grep -E 'vector [0-9]+ FRERTestNetwork\.listener\.app\[0\]\.io packetReceived:vector\(packetBytes\)' "$VEC" | awk '{print $2}')
awk -v id="$VECID" -v d="$D" -v cfg="$CFG" '
  $1==id && $4==100 {nacc++}
  $1==id && $4==512 { legit++; t=$3; if(t>=20 && t<40) act++ }
  END{
    ltx=5000; lost=ltx-legit;
    printf "%-10s Delta=%-5s | N_acc=%d legit_RX=%d total_lost=%d act512=%d", cfg, d, nacc, legit, lost, act;
    if(nacc>0) printf " | supp/inj=A_loss=%.2f\n", lost/nacc; else printf " | supp/inj=n/a\n";
  }' "$VEC"
