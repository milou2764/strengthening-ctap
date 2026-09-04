/*
 * CTAP client enrollment over a direct BLE connection with numeric comparison,
 * checked against a GENERATIVE intruder.
 *
 * No attack is scripted. The intruder is given capabilities and knowledge, and
 * SPIN composes the traces. Two authenticators are in Bluetooth range -- the
 * victim's (A_VIC, the one the property is about) and the intruder's own
 * (A_ATT) -- and the shared client's BLE discovery may reach either of them.
 * The intruder is therefore a full participant in TWO pairings at once: it is a
 * client towards A_VIC and an authenticator towards the shared client. Whatever
 * its own pairing lets it choose, it chooses.
 *
 * What is actually checked. The user types, into their authenticator, the code
 * displayed on the client's screen; the authenticator accepts iff it equals the
 * code of its own pairing (the condition `c == client_code` below -- identical
 * for the compare-and-confirm variant, only the party doing the comparison
 * differs). Note what this does NOT check: that the two codes belong to the
 * same pairing. That is the whole question.
 *
 * The code derivation is the parameter under study.
 *
 *   default              code = f(client public key)
 *       The code is a function of the key alone, so anyone holding the key can
 *       compute it. The intruder learns the key -- the client's discovery may
 *       reach ITS authenticator -- and, since only six digits are displayed,
 *       holds a precomputed key pair for every code. It shows the matching one.
 * *
 *   -DCOMMITTED_CODE     code = g(AID, client public key, both nonces), each nonce
 *                        committed before the peer's is revealed
 *       This is the Bluetooth Secure Simple Pairing numeric-comparison
 *       construction. Neither endpoint -- nor an intruder running two pairings
 *       -- can bias the output, so two distinct pairings yield unrelated codes.
 *       Modelled as: each pairing has its own code that no participant can
 *       choose. The residual 10^-6 chance that two unrelated codes collide is
 *       abstracted away, as is standard for numeric comparison.
 *
 * Client key policy.
 *   default                 a distinct key pair per authenticator (KEY_C0/KEY_C1)
 *   -DGLOBAL_CLIENT_KEY     one key reused with every authenticator, whose public
 *                           part the intruder already learned from an earlier
 *                           enrollment of the same shared client
 *
 * Other switch:
 *   -DNO_NUMERIC_COMPARISON the code check is skipped entirely
 *
 * p_binding: whenever the victim's authenticator completes an enrollment, the
 * key it stored is the one the legitimate client uses with it.
 */

#define A_ATT 0                 /* the intruder's own authenticator */
#define A_VIC 1                 /* the victim's authenticator       */

mtype = { KEY_NONE, KEY_C0, KEY_C1, KEY_FAKE, WHO_CLIENT, WHO_INTRUDER };

chan conn[2] = [6] of { mtype, mtype, byte };   /* peer, key written, code shown */

mtype ckey[2];                  /* key the client uses with each authenticator */
mtype stored_key = KEY_NONE;    /* what the victim's authenticator enrolled    */
bool  vic_enrolled = false;

byte client_code = 0;           /* code currently displayed by the client (0: none) */
bool knows_key[4] = false;      /* intruder knowledge, indexed by key id */

/* Key ids: KEY_C0 -> 1, KEY_C1 -> 2, anything the intruder controls -> 3. */
inline key_id(_k, _id) {
    if
    :: _k == KEY_C0 -> _id = 1
    :: _k == KEY_C1 -> _id = 2
    :: else         -> _id = 3
    fi
}

/* The code displayed for a key id: with a key-derived code it is a function
   of the key alone, so anyone holding the key can reproduce it anywhere. */
inline code_of(_kid, _out) {
    _out = _kid;
}

/* The shared client (a kiosk, a library workstation). It enrolls with whichever
   authenticator its BLE discovery reaches, writes the key it uses with that
   authenticator, and displays the corresponding code. */
proctype Client() {
    byte j, c, id;

    if :: j = A_ATT :: j = A_VIC fi;
    key_id(ckey[j], id);
#ifdef COMMITTED_CODE
    c = 11;                             /* this pairing's own code; nobody can bias it */
#else
    code_of(id, c);
#endif
    client_code = c;                    /* the client shows its code */
end_write:
    conn[j] ! WHO_CLIENT, ckey[j], c;
    if
    :: j == A_ATT ->                    /* it just handed its key to the intruder */
        knows_key[id] = true
    :: else -> skip
    fi
}

/* The victim's authenticator: accepts connections, displays the code of the
   pairing it is in, and enrolls the key if the user confirms. */
proctype AuthVictim() {
    mtype who, k;
    byte c, handled = 0;

end_vic:
    do
    :: (handled < 2 && !vic_enrolled) ->
end_wait:
        conn[A_VIC] ? who, k, c;
        handled++;
#ifdef NO_NUMERIC_COMPARISON
        stored_key = k;
        vic_enrolled = true
#else
        if
        :: (client_code != 0 && c == client_code) ->   /* typed code matches this pairing's */
            stored_key = k;
            vic_enrolled = true
        :: else -> skip                                /* the user declines */
        fi
#endif
    :: else -> break
    od
}

/* The intruder's own authenticator: whatever is written to it is knowledge. */
proctype AuthAttacker() {
    mtype who, k;
    byte c, id;

end_att:
    conn[A_ATT] ? who, k, c;
    key_id(k, id);
    knows_key[id] = true
}

/* Generative intruder. On its connection to the victim's authenticator it
   writes a key it controls and displays any code it can produce there. */
proctype Intruder() {
    byte c, t, acts = 0;

end_intruder:
    do
    :: (acts < 2) ->                      /* bounded number of attempts (finiteness) */
       atomic {
           acts++;
#ifdef COMMITTED_CODE
           c = 22;                        /* only its own pairing's code, which it cannot bias */
#else
           if                             /* a key whose code it can compute */
           :: knows_key[1] -> t = 1
           :: knows_key[2] -> t = 2
           :: t = 3                       /* its own key, honestly */
           fi;
           code_of(t, c);                 /* reproducible on ITS connection */
#endif
           conn[A_VIC] ! WHO_INTRUDER, KEY_FAKE, c
       }
    :: break
    od
}

init {
    atomic {
#ifdef GLOBAL_CLIENT_KEY
        ckey[A_ATT] = KEY_C1;             /* one key for every authenticator */
        ckey[A_VIC] = KEY_C1;
        knows_key[2] = true;              /* learned from an earlier enrollment */
#else
        ckey[A_ATT] = KEY_C0;             /* a distinct key pair per authenticator */
        ckey[A_VIC] = KEY_C1;
#endif
        run AuthVictim();
        run AuthAttacker();
        run Client();
        run Intruder()
    }
}

/* Enrollment integrity: a completed enrollment stored the legitimate client's
   key for this authenticator. */
ltl p_binding { [] (vic_enrolled -> (stored_key == ckey[A_VIC])) }

/* Non-vacuity witness: a legitimate enrollment CAN complete. EXPECTED TO FAIL;
   the counterexample is a successful legitimate enrollment. */
ltl e_reachable { [] (!vic_enrolled) }
