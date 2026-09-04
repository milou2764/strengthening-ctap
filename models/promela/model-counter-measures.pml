/*
 * CTAP hybrid authentication with the proposed client-authentication
 * countermeasure, checked against a GENERATIVE intruder.
 *
 * The point of this model is that no attack trace is written down. The intruder
 * is described by what it KNOWS and what it can BUILD from that knowledge, and
 * it may act at any interleaving; SPIN composes the attacks itself. Two
 * authenticator sessions run concurrently, so cross-session behaviour (relaying
 * or replaying material from one session into another) is inside the state
 * space rather than being a scenario we selected. The assertion binds the
 * session identifier used by the implementation: the Noise handshake-transcript
 * hash.
 *
 * Session identifier. Each session is identified by its Noise
 * handshake-transcript hash (SID0/SID1) -- the value the implementation binds:
 * a digest of the whole handshake, fresh and unpredictable per session because
 * both parties contribute fresh ephemeral keys. Unlike a BLE advertisement it
 * is not broadcast: only the two parties to a handshake hold it.
 *
 * Intruder model.
 *   Knowledge:  knows_sid[i]  - the transcript hash of session i; acquired by
 *                               BEING a party to that session's handshake, or
 *                               from a captured assertion (whose payload
 *                               carries the hash);
 *               knows_sig[i]  - a COSE_Sign1 produced by the enrolled client
 *                               over hash i, if the client ever made one (we
 *                               grant this even though the real assertion
 *                               travels inside the Noise tunnel: a strictly
 *                               stronger intruder).
 *   Construction: it can sign with its own, unenrolled key (SIG_NONE) over any
 *               hash it knows; it can present (SIG_LEGIT, sid i) only if
 *               knows_sig[i] -- a captured assertion is a bound pair and cannot
 *               be re-targeted (perfect cryptography).
 *   Actions:    connect to either session, and inject any message it can build
 *               into any session it owns, any number of times, in any order.
 *
 * Assumption made explicit. A session belongs to the peer that completed the
 * Noise handshake with the authenticator: once established, the channel cannot
 * be hijacked by a third party. Both the legitimate client and the intruder may
 * race for a session, and SPIN explores both outcomes. What Noise does NOT give
 * is any evidence of WHO the peer is -- exactly the gap the countermeasure
 * closes.
 *
 * Countermeasure. The authenticator serves a request only if it is signed with
 * the enrolled key (client authentication) AND the signed hash is this
 * session's own transcript hash (so the assertion is not replayable).
 *
 * Compile-time switches:
 *   -DNO_COUNTERMEASURE  neither check (baseline CTAP)
 *   -DNO_FRESHNESS       both sessions end up with the SAME transcript hash --
 *                        the identifier recurs (e.g. reused ephemeral keys),
 *                        which must re-enable replay
 */

mtype = { SIG_NONE, SIG_LEGIT, SID0, SID1,
          CRED, ABORT, CONSENT, CONSENT_OK,
          WHO_NONE, WHO_LEGIT, WHO_INTRUDER };

chan conn_ch[2] = [4] of { mtype };               /* peer -> session: handshake      */
chan req_ch[2]  = [6] of { mtype, mtype, mtype };  /* peer -> session: who,signer,adv */
chan res_ch[2]  = [4] of { mtype, mtype };         /* session -> peer: who,result     */
chan a2u        = [1] of { mtype };                /* authenticator -> user           */
chan u2a        = [1] of { mtype };                /* user -> authenticator           */

mtype sid_of[2];                    /* transcript hash of each session's handshake */
mtype owner_of[2] = WHO_NONE;       /* peer that completed the handshake       */
bool  sid_ready[2] = false;

/* Intruder knowledge, indexed by session identifier (0 -> SID0, 1 -> SID1). */
bool knows_sid[2] = false;
bool knows_sig[2] = false;

/* Observable state for the LTL claims. */
bool legitimate_client_requested = false;
bool verifier_granted_access     = false;
bool attacker_has_credential     = false;

inline sid_index(a, i) {
    if
    :: a == SID0 -> i = 0
    :: else      -> i = 1
    fi
}

proctype Authenticator(byte s) {
    mtype who, sg, a, cons;
    byte i, served = 0;

#ifdef NO_FRESHNESS
    sid_of[s] = SID0;               /* the transcript hash recurs across sessions */
#else
    if
    :: s == 0 -> sid_of[s] = SID0   /* fresh ephemerals: unique per session */
    :: else   -> sid_of[s] = SID1
    fi;
#endif
    sid_ready[s] = true;

end_hs:
    conn_ch[s] ? who;               /* Noise handshake with whoever connects first */
    owner_of[s] = who;
    /* The transcript hash is known to the parties of the handshake -- and to
       nobody else. If the intruder is the peer, it now holds this session's. */
    sid_index(sid_of[s], i);
    if
    :: who == WHO_INTRUDER -> knows_sid[i] = true
    :: else -> skip
    fi;

end_serve:
    do
    :: (served < 2) ->
end_req:
        req_ch[s] ? who, sg, a;
        served++;
#ifdef NO_COUNTERMEASURE
        a2u ! CONSENT; u2a ? cons;
        verifier_granted_access = true;
        if
        :: who == WHO_INTRUDER -> attacker_has_credential = true
        :: else -> skip
        fi;
        res_ch[s] ! who, CRED;
        break
#else
        if
        :: (sg == SIG_LEGIT && a == sid_of[s]) ->
            a2u ! CONSENT; u2a ? cons;
            verifier_granted_access = true;
            if
            :: who == WHO_INTRUDER -> attacker_has_credential = true
            :: else -> skip
            fi;
            res_ch[s] ! who, CRED;
            break
        :: else ->
            res_ch[s] ! who, ABORT
        fi
#endif
    :: (served >= 2) -> break
    od
}

proctype User() {
    mtype m;
end_user:
    do
    :: a2u ? m -> u2a ! CONSENT_OK
    od
}

/* The user's own enrolled client. It drives one session, and signs only the
   transcript hash of the session it established itself. */
proctype LegitClient() {
    mtype r;
    byte i;

    (sid_ready[0]);
end_conn:
    conn_ch[0] ! WHO_LEGIT;
end_own:
    (owner_of[0] != WHO_NONE);
    if
    :: owner_of[0] == WHO_LEGIT ->
        legitimate_client_requested = true;
        sid_index(sid_of[0], i);
        knows_sig[i] = true;           /* grant the intruder the assertion... */
        knows_sid[i] = true;           /* ...whose payload reveals the hash   */
end_send:
        req_ch[0] ! WHO_LEGIT, SIG_LEGIT, sid_of[0];
end_resp:
        res_ch[0] ? WHO_LEGIT, r
    :: else -> skip                    /* it lost the race for the session */
    fi
}

/* Generative intruder: connects where it likes and emits anything it can build
   from its knowledge, in any order, into any session it owns. */
proctype Intruder() {
    mtype sg, a, r;
    byte s, i, conns = 0, acts = 0;

end_intruder:
    do
    :: (conns < 2 && (sid_ready[0] || sid_ready[1])) ->
       atomic {                           /* bounded number of connections */
           conns++;
           if
           :: sid_ready[0] -> s = 0
           :: sid_ready[1] -> s = 1
           fi;
           conn_ch[s] ! WHO_INTRUDER
       }
    :: (acts < 3 && (owner_of[0] == WHO_INTRUDER || owner_of[1] == WHO_INTRUDER)
                 && (knows_sid[0] || knows_sid[1])) ->
       atomic {                           /* bounded number of injections */
           acts++;
           if                             /* into any session it owns */
           :: owner_of[0] == WHO_INTRUDER -> s = 0
           :: owner_of[1] == WHO_INTRUDER -> s = 1
           fi;
           if                             /* over any transcript hash it knows */
           :: knows_sid[0] -> a = SID0; i = 0
           :: knows_sid[1] -> a = SID1; i = 1
           fi;
           if
           :: sg = SIG_NONE                    /* its own, unenrolled key */
           :: knows_sig[i] -> sg = SIG_LEGIT   /* a captured enrolled assertion */
           fi;
           req_ch[s] ! WHO_INTRUDER, sg, a
       };
end_wait:
       res_ch[s] ? WHO_INTRUDER, r
    :: break
    od
}

init {
    atomic {
        run Authenticator(0);
        run Authenticator(1);
        run User();
        run LegitClient();
        run Intruder();
    }
}

/* CA - Client authentication: no unenrolled client is ever served. */
ltl p_auth { [] (!attacker_has_credential) }

/* Non-vacuity witness: the enrolled client CAN still be served. EXPECTED TO
   FAIL; the counterexample is a successful legitimate authentication. */
ltl p_reachable { [] (!verifier_granted_access) }
