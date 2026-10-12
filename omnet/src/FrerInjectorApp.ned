package frer_experiments;

import inet.applications.udpapp.UdpBasicApp;

//
// The attacker injector (module B) for CR and RSD. Inherits from INET's UdpBasicApp so that the
// whole send/timing/socket machinery (startTime, sendInterval, stopTime) is already there -
// we change ONLY one thing: instead of letting INET assign the 802.1CB seq number automatically,
// the injector sets a SELF-CHOSEN seq number (SequenceNumberReq). INET's R-TAG chain
// (Ieee8021rTagEpdHeaderInserter) copies this value 1:1 onto the wire. At the attacker the
// streamIdentifier must therefore be set to sequenceNumbering:false (otherwise the identifier
// overwrites our value); the identifier then only sets StreamReq for the VLAN assignment.
//
// The chosen seq is  target = legit_est(t) + offset,  with  legit_est = seqBase + floor(t/productionInterval).
// So the attacker OBSERVES nothing, it estimates the legit progression from time (in the sim
// time is known) - this matches the non-observing / one-shot-calibration threat model.
//
// Mode-agnostic: CR and RSD only differ in timing (sendInterval, start/stop) and the
// offsets, both come from the ini. CR: several in-window forward jumps, e.g. offsets "8 18 28".
// RSD: one frame per idle gap with a single offset delta, e.g. offsets "17".
//
simple FrerInjectorApp extends UdpBasicApp
{
    parameters:
        @class(FrerInjectorApp);
        double productionInterval @unit(s);   // frame interval of the legit talker, to estimate its seq from time
        int seqBase = default(0);              // legit seq reference. CR: phase offset at t=0. RSD: the resume seq of the legit progression.
        bool timeVarying = default(true);      // true=CR (target = seqBase + floor(t/prod) + offset). false=RSD single (target = seqBase + offset, fixed).
        bool blind = default(false);           // true=BLIND open-loop: seq uniform from [0,seqSpace). No time reference/feedback/adaptation. Takes precedence over timeVarying/burstSize/offsets.
        int seqSpace = default(65536);         // seq space for blind guessing (16 bit). Only in blind mode.
        bool attachAuth = default(false);      // true=mitigation evaluation: attaches a guessed identifier value to the frame.
        int idSpace = default(1);              // identifier space 2^b for guessing. idSpace=1 -> value 0 (b=0, no mitigation).
        int burstSize = default(0);            // >0 = RSD burst mode: tracks the bursty legit progression across many bursts.
                                               //   target = seqBase + floor(t/productionInterval)*burstSize + (burstSize-1) + offset  (productionInterval = burst period).
        string offsets = default("0");         // forward offsets, space-separated; cycled through once per sent frame (= one ramp cycle)
        double cycleGap @unit(s) = default(0s); // re-anchor pause AFTER each full ramp cycle: state stays frozen,
                                                // legit catches up (a-priori ~ D_peak/fps, like the HW's T_cu). 0s = no pause (const./B2).
}
