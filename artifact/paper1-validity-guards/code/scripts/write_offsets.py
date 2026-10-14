import io, re

p = "orchestrator.py"
s = io.open(p, encoding="utf-8").read()

new = '''INFECTION_OFFSETS = {
    # Seconds from capture start to infection.
    #
    # DERIVATION
    # ----------
    # Three sources, in decreasing order of trust:
    #
    #   derived  first connection from the README's stated infected host to an
    #            external address, taken as the minimum timestamp over the whole
    #            conn.log (Zeek writes records at connection CLOSE, so the file
    #            is not time-ordered and a head-of-file reading is wrong).
    #            Local, multicast and DNS destinations excluded.
    #   pkt      "Date of last packet in tcpdump before infection" from the
    #            README, given in capture-relative time. Present in four READMEs.
    #   wall     (infected - started) from the README timeline. Hand-written
    #            operator notes.
    #
    # derived exceeds wall by 11-73 s wherever both exist, consistently and in
    # one direction: the operator's execution timestamp precedes the malware's
    # first network activity. derived is used because it is measured from the
    # capture itself and is independent of anything the detector computes.
    #
    # Ground truth is therefore: pre-infection = t < offset, post = t >= offset.

    # --- derived from first external contact (8) ---
    "2017-06-24_win10emotet_271-1":                    459,  # 458.6 -> 82.165.142.107:443
                                                             #   then :8080 beacon rotation
                                                             #   across 10 hosts, cycle
                                                             #   repeats at 1055 s
                                                             #   (pkt n/a, wall 430)
    "2017-06-24_win6trickbot_267-1":                   424,  # 423.6 -> 50.19.97.123:80
                                                             #   then periodic :443
                                                             #   (pkt n/a, wall 351)
    "2017-07-11_capture-win2wannacryfailed_283-1":     297,  # 297.3 -> mass :445 across
                                                             #   dozens of external hosts
                                                             #   (pkt n/a, wall 268)
    "2017-07-11_capture-win2wannacrysuccessful_284-1": 437,  # 437.3 -> mass :445
                                                             #   (pkt n/a, wall 419)
    "2018-04-03_win6_ramnit343-1":                     306,  # 306.1 -> 91.220.62.30:443
                                                             #   (pkt 287, wall 295)
    "2018-04-03_win11cobalt_345-1":                    241,  # 241.2 -> 95.46.8.65:443
                                                             #   (pkt 219, wall 247)
    "2018-04-03_win12_fixed_346-1":                    302,  # 301.5 -> 37.187.54.76:443
                                                             #   (pkt 274, wall 285)
    "2018-04-04_win16bitcoinminer_347-1":              493,  # 492.9 -> 5.187.7.235:3333
                                                             #   (pkt 465, wall 413)

    # --- README wall clock is wrong; derived value used (1) ---
    "2017-11-23_win16sality_319-1":                    376,  # 376.4 -> 81.169.145.74:80.
                                                             # That host appears verbatim
                                                             # in the README's own mitmdump
                                                             # output as the first fetch.
                                                             # README timeline says 58 s,
                                                             # off by ~6x. Treated as a
                                                             # typo in the source.

    # --- wall clock only, not independently verified (1) ---
    "2017-12-18_win2ccleaner_320-1":                    97,  # first external contact is
                                                             # 195.113.232.73:80 at 12.5 s,
                                                             # which is CVUT address space
                                                             # (benign startup), so the
                                                             # derivation does not isolate
                                                             # infection here. wall 97 kept
                                                             # unverified.
}

# Captures excluded: Zeek extraction produced too few records to derive or
# evaluate anything.
#   2017-07-03_capture-win13mitm_281-1   conn.log 27 lines
#   2017-07-13_capture-win2NotPeya_298-1 conn.log 835 lines
UNUSABLE_CAPTURES = {
    "2017-07-03_capture-win13mitm_281-1",
    "2017-07-13_capture-win2NotPeya_298-1",
}'''

m = re.search(r"INFECTION_OFFSETS = \{.*?\n\}", s, re.S)
if not m:
    raise SystemExit("INFECTION_OFFSETS block not found")

io.open(p, "w", encoding="utf-8").write(s[:m.start()] + new + s[m.end():])
print("derived offsets written")
