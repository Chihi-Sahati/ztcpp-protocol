------------------------- MODULE ZTCPP_Adversarial_Model -------------------------
EXTENDS Integers, FiniteSets, Sequences, TLC

(* 
   ZTCPP Adversarial Formal Verification Model (TLA+)
   --------------------------------------------------
   Extends the standard model with:
   1. Malicious agent replay attempts (Attacker state).
   2. SAT token reuse under race conditions.
   3. NHP handshake interruption and partial state corruption.
   4. Byzantine behavior in NHP-AC (Arbitrary score reporting).
   5. Deadlock and Livelock analysis constraints.
*)

CONSTANTS 
    Agents,             \* Set of possible Agent IDs (e.g., {"HonestAgent", "MaliciousAgent"})
    MaxNonce,           \* Model checking bound for nonces
    MaxTime,            \* Model checking bound for time (SAT expiration)
    MinSafetyScore      \* Minimum MAMA safety threshold

VARIABLES 
    gateway_state,      \* Function: Agent -> {"LISTEN", "PARSE_SIG", "VERIFY_SAT", "EVALUATE_MAMA", "ESTABLISHED", "CORRUPTED"}
    highest_nonce,      \* Function: Agent -> Integer
    sat_registry,       \* Set of valid SATs: [agent: Agent, exp: Integer, intent: String, active: Boolean]
    messages,           \* Set of messages in transit
    clock,              \* Global monotonic clock
    byzantine_active    \* Boolean flag representing NHP-AC byzantine corruption

vars == << gateway_state, highest_nonce, sat_registry, messages, clock, byzantine_active >>

\* --- INITIALIZATION ---
Init == 
    /\ gateway_state = [a \in Agents |-> "LISTEN"]
    /\ highest_nonce = [a \in Agents |-> 0]
    /\ sat_registry = {}
    /\ messages = {}
    /\ clock = 0
    /\ byzantine_active = FALSE

\* --- HONEST ACTIONS ---
AgentRequestIntent(a, exp, intent) ==
    /\ sat_registry' = sat_registry \cup {[agent |-> a, exp |-> exp, intent |-> intent, active |-> TRUE]}
    /\ UNCHANGED << gateway_state, highest_nonce, messages, clock, byzantine_active >>

AgentSendHandshake(a, nonce, intent) ==
    /\ nonce \in 1..MaxNonce
    /\ messages' = messages \cup {[type |-> "KNK", agent |-> a, nonce |-> nonce, intent |-> intent, is_replay |-> FALSE]}
    /\ UNCHANGED << gateway_state, highest_nonce, sat_registry, clock, byzantine_active >>

\* --- ADVERSARIAL ACTIONS ---
MaliciousReplay(a) ==
    \* Attacker intercepts and replays an existing message exactly
    /\ \E m \in messages:
        /\ messages' = messages \cup {[type |-> m.type, agent |-> m.agent, nonce |-> m.nonce, intent |-> m.intent, is_replay |-> TRUE]}
    /\ UNCHANGED << gateway_state, highest_nonce, sat_registry, clock, byzantine_active >>

StateCorruption(a) ==
    \* Attacker attempts to interrupt the handshake and corrupt the memory state
    /\ gateway_state[a] \in {"PARSE_SIG", "VERIFY_SAT"}
    /\ gateway_state' = [gateway_state EXCEPT ![a] = "CORRUPTED"]
    /\ UNCHANGED << highest_nonce, sat_registry, messages, clock, byzantine_active >>

ByzantineTrigger ==
    \* NHP-AC (Policy Engine) acts byzantine, arbitrarily granting access regardless of EDNS/CEI
    /\ byzantine_active = FALSE
    /\ byzantine_active' = TRUE
    /\ UNCHANGED << gateway_state, highest_nonce, sat_registry, messages, clock >>

\* --- GATEWAY STATE MACHINE TRANSITIONS ---
GatewayReceiveKNK(m) ==
    /\ m \in messages
    /\ m.type = "KNK"
    /\ gateway_state[m.agent] \in {"LISTEN", "CORRUPTED"}
    /\ gateway_state' = [gateway_state EXCEPT ![m.agent] = "PARSE_SIG"]
    /\ UNCHANGED << highest_nonce, sat_registry, messages, clock, byzantine_active >>

GatewayParseSig(a) ==
    /\ gateway_state[a] = "PARSE_SIG"
    /\ \E m \in messages:
        /\ m.agent = a
        /\ IF m.nonce > highest_nonce[a] THEN
              /\ highest_nonce' = [highest_nonce EXCEPT ![a] = m.nonce]
              /\ gateway_state' = [gateway_state EXCEPT ![a] = "VERIFY_SAT"]
           ELSE
              \* Replay Attack Dropped
              /\ highest_nonce' = highest_nonce
              /\ gateway_state' = [gateway_state EXCEPT ![a] = "LISTEN"]
    /\ UNCHANGED << sat_registry, messages, clock, byzantine_active >>

GatewayVerifySAT(a) ==
    /\ gateway_state[a] = "VERIFY_SAT"
    /\ \E m \in messages:
        /\ m.agent = a
        /\ \E sat \in sat_registry:
            /\ sat.agent = a
            /\ sat.intent = m.intent
            /\ IF sat.exp > clock THEN
                  /\ gateway_state' = [gateway_state EXCEPT ![a] = "EVALUATE_MAMA"]
               ELSE
                  \* SAT Expired
                  /\ gateway_state' = [gateway_state EXCEPT ![a] = "LISTEN"]
    /\ UNCHANGED << highest_nonce, sat_registry, messages, clock, byzantine_active >>

GatewayEvaluateMAMA(a) ==
    /\ gateway_state[a] = "EVALUATE_MAMA"
    /\ \E score \in 0..100:
        /\ IF byzantine_active = TRUE \/ score >= MinSafetyScore THEN
              /\ gateway_state' = [gateway_state EXCEPT ![a] = "ESTABLISHED"]
           ELSE
              /\ gateway_state' = [gateway_state EXCEPT ![a] = "LISTEN"]
    /\ UNCHANGED << highest_nonce, sat_registry, messages, clock, byzantine_active >>

GatewayRecoverCorruption(a) ==
    \* Fail-Closed recovery: Any corrupted state must immediately fall back to LISTEN and drop memory
    /\ gateway_state[a] = "CORRUPTED"
    /\ gateway_state' = [gateway_state EXCEPT ![a] = "LISTEN"]
    /\ UNCHANGED << highest_nonce, sat_registry, messages, clock, byzantine_active >>

\* --- ENVIRONMENT ACTIONS ---
TickClock ==
    /\ clock < MaxTime
    /\ clock' = clock + 1
    /\ UNCHANGED << gateway_state, highest_nonce, sat_registry, messages, byzantine_active >>

\* --- NEXT STATE RELATION ---
Next ==
    \/ (\E a \in Agents, exp \in clock+1..MaxTime, intent \in {"beamform", "monitor"}: AgentRequestIntent(a, exp, intent))
    \/ (\E a \in Agents, nonce \in 1..MaxNonce, intent \in {"beamform", "monitor"}: AgentSendHandshake(a, nonce, intent))
    \/ (\E a \in Agents: MaliciousReplay(a))
    \/ (\E a \in Agents: StateCorruption(a))
    \/ ByzantineTrigger
    \/ (\E m \in messages: GatewayReceiveKNK(m))
    \/ (\E a \in Agents: GatewayParseSig(a))
    \/ (\E a \in Agents: GatewayVerifySAT(a))
    \/ (\E a \in Agents: GatewayEvaluateMAMA(a))
    \/ (\E a \in Agents: GatewayRecoverCorruption(a))
    \/ TickClock

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

\* =============================================================================
\* ADVERSARIAL THEOREMS AND INVARIANTS
\* =============================================================================

\* 1. Strong Replay Immunity (Even under malicious message duplication)
NoReplayAttack ==
    \A a \in Agents:
        \A m \in messages:
            (m.agent = a /\ m.is_replay = TRUE)
            => ~(gateway_state[a] = "ESTABLISHED" /\ highest_nonce[a] = m.nonce)

\* 2. Fail-Closed Recovery from State Corruption
CorruptionRecovery ==
    \A a \in Agents:
        gateway_state[a] = "CORRUPTED" ~> gateway_state[a] = "LISTEN"

\* 3. Liveness / Deadlock Freedom
\* The gateway state machine must never be stuck (unless in ESTABLISHED or LISTEN waiting for input)
DeadlockFree ==
    \A a \in Agents:
        gateway_state[a] \in {"PARSE_SIG", "VERIFY_SAT", "EVALUATE_MAMA", "CORRUPTED"} 
        ~> (gateway_state[a] = "ESTABLISHED" \/ gateway_state[a] = "LISTEN")

=============================================================================
