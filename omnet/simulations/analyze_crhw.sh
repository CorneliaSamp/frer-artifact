#!/bin/sh
# analyze_crhw.sh <Config> <fps> <legitBytes>
# HW-faithful CR evaluation over 60s with PRE/ACTIVE/POST=0-20/20-40/40-60. Discriminator:
# attacker=100B, legit=<legitBytes>. Metrics like the HW result.json.
CFG="$1"; FPS="$2"; LB="$3"
cd "$(dirname "$0")"
../src/frer_experiments -u Cmdenv -c "$CFG" -n .:../src:../../inet-4.7.0/src -l ../../inet-4.7.0/src/INET >/dev/null 2>&1
SCA="results/${CFG}-#0.sca"; VEC="results/${CFG}-#0.vec"
LTX=$((FPS*60))   # continuous talker: legit_TX = fps * 60s (the stat lives elsewhere, module-internal)
VECID=$(grep -E 'vector [0-9]+ FRERTestNetwork\.listener\.app\[0\]\.io packetReceived:vector\(packetBytes\)' "$VEC" | awk '{print $2}')
awk -v id="$VECID" -v cfg="$CFG" -v fps="$FPS" -v lb="$LB" -v ltx="$LTX" '
  $1==id && $4==100 {nacc++}
  $1==id && $4==lb {
    legit++; t=$3;
    if(t<20) pre++; else if(t<40){ act++; if(pa!=""){g=t-pa; if(g>mg)mg=g} pa=t } else post++;
  }
  END{
    seg=fps*20;
    lrx=legit; L=ltx-lrx; ldirect=(nacc<L?nacc:L); lcoll=L-ldirect; if(lcoll<0)lcoll=0;
    printf "[%s]  legit_TX=%d  N_acc=%d  legit_RX=%d\n", cfg, ltx, nacc, lrx;
    printf "  L=%d  L_direct=%d  L_collateral=%d  A_loss=%.3f\n", L, ldirect, lcoll, (nacc>0?L/nacc:0);
    printf "  PDR_pre=%.4f  PDR_active=%.4f  PDR_post=%.4f\n", pre/seg, act/seg, post/seg;
    printf "  max_loss_run(active)~%d frames (max gap=%.1f ms)\n", (mg*fps)-1+0.5, mg*1000;
  }' "$VEC"
