/* Legitimate CTAP Hybrid Authentication Flow */

mtype = { 
    VISIT_WEBSITE, 
    CREDENTIAL_REQ, 
    SHOW_QR, 
    SCAN_QR, 
    BLE_SECRET, 
    CTAP_REQ, 
    USER_CONSENT, 
    CONSENT_OK, 
    CREDENTIAL 
};

// Channels representing network and physical interactions
chan c_v = [1] of {mtype}; // Client to Verifier
chan v_c = [1] of {mtype}; // Verifier to Client
chan c_u = [1] of {mtype}; // Client to User (Screen)
chan u_a = [1] of {mtype}; // User to Authenticator (Camera, Button)
chan a_u = [1] of {mtype}; // Authenticator to User (Screen)
chan a_c = [1] of {mtype}; // Authenticator to Client (BLE, CTAP)
chan c_a = [1] of {mtype}; // Client to Authenticator (CTAP)

// Global state for properties
bool verifier_granted_access = false;
bool legitimate_client_requested = false;

active proctype Verifier() {
    c_v ? VISIT_WEBSITE;
    v_c ! CREDENTIAL_REQ;
    c_v ? CREDENTIAL;
    verifier_granted_access = true;
}

active proctype Client() {
    c_v ! VISIT_WEBSITE;
    legitimate_client_requested = true;
    v_c ? CREDENTIAL_REQ;
    c_u ! SHOW_QR;
    a_c ? BLE_SECRET;
    // CTAP channel established
    c_a ! CTAP_REQ;
    a_c ? CREDENTIAL;
    c_v ! CREDENTIAL;
}

active proctype User() {
    c_u ? SHOW_QR;
    u_a ! SCAN_QR;
    a_u ? USER_CONSENT;
    u_a ! CONSENT_OK;
}

active proctype Authenticator() {
    u_a ? SCAN_QR;
    a_c ! BLE_SECRET;
    c_a ? CTAP_REQ;
    a_u ! USER_CONSENT;
    u_a ? CONSENT_OK;
    a_c ! CREDENTIAL;
}

// LTL Property: If access is granted, the legitimate client must have initiated the request.
ltl p_auth { [] (verifier_granted_access -> legitimate_client_requested) }
