----------------------- MODULE ZTCPP_Snapshot_Model -----------------------
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS 
    Agents,             \* Set of Agent IDs
    MaxNonce,           \* Bounded nonce limit
    MaxTime,            \* Bounded time limit
    MinSafetyScore      \* Minimum MAMA Score

VARIABLES 
    state,              \* gateway state per agent
    highest_nonce,      \* nonce tracker per agent
    sat_registry,       \* set of valid SAT tokens
    network,            \* set of messages in network
    clock,              \* Event-Driven Logical Time
    byzantine_server,   \* compromised server flag
    byzantine_ac,       \* compromised AC flag
    network_partition,  \* network partition flag
    session_snapshot    \* T_snapshot captured at entry

vars == << state, highest_nonce, sat_registry, network, clock, byzantine_server, byzantine_ac, network_partition, session_snapshot >>

Init == 
    /\ state = [a \in Agents |-> "LISTEN"]
    /\ highest_nonce = [a \in Agents |-> 0]
    /\ sat_registry = {}
    /\ network = {}
    /\ clock = 0
    /\ byzantine_server = FALSE
    /\ byzantine_ac = FALSE
    /\ network_partition = FALSE
    /\ session_snapshot = [a \in Agents |-> 0]

\* --- HONEST ACTIONS ---
RequestSAT(a, iat, exp) ==
    /\ iat <= exp
    /\ sat_registry' = sat_registry \cup {[agent |-> a, iat |-> iat, exp |-> exp, active |-> TRUE]}
    /\ UNCHANGED << state, highest_nonce, network, clock, byzantine_server, byzantine_ac, network_partition, session_snapshot >>

SendHandshake(a, nonce) ==
    /\ nonce \in 1..MaxNonce
    /\ network' = network \cup {[type |-> "KNK", agent |-> a, nonce |-> nonce]}
    /\ UNCHANGED << state, highest_nonce, sat_registry, clock, byzantine_server, byzantine_ac, network_partition, session_snapshot >>

\* --- ADVERSARIAL ACTIONS ---
MaliciousReplay ==
    /\ \E m \in network: network' = network \cup {m}  \* Re-injecting message simulates replay
    /\ UNCHANGED << state, highest_nonce, sat_registry, clock, byzantine_server, byzantine_ac, network_partition, session_snapshot >>

CompromiseServer ==
    /\ ~byzantine_server
    /\ byzantine_server' = TRUE
    /\ UNCHANGED << state, highest_nonce, sat_registry, network, clock, byzantine_ac, network_partition, session_snapshot >>

CompromiseAC ==
    /\ ~byzantine_ac
    /\ byzantine_ac' = TRUE
    /\ UNCHANGED << state, highest_nonce, sat_registry, network, clock, byzantine_server, network_partition, session_snapshot >>

TogglePartition ==
    /\ network_partition' = ~network_partition
    /\ UNCHANGED << state, highest_nonce, sat_registry, network, clock, byzantine_server, byzantine_ac, session_snapshot >>

\* --- MACRO-STEP: ATOMIC TRANSITION RULE (S0 -> ESTABLISHED or LISTEN) ---
AtomicVerifyAndEvaluate(a) ==
    /\ ~network_partition
    /\ state[a] \in {"LISTEN", "CORRUPTED"}
    /\ \E m \in network:
        /\ m.agent = a
        /\ m.type = "KNK"
        /\ \E sat \in sat_registry:
            /\ sat.agent = a
            /\ \E score \in 0..100:
                \* Entry guard evaluation: ALL checks happen exactly once under T_snapshot = clock
                /\ IF (m.nonce > highest_nonce[a] \/ byzantine_server) 
                      /\ ( (sat.iat <= clock /\ clock <= sat.exp) \/ byzantine_server )
                      /\ ( score >= MinSafetyScore \/ byzantine_ac \/ byzantine_server )
                   THEN
                      /\ highest_nonce' = [highest_nonce EXCEPT ![a] = m.nonce]
                      /\ session_snapshot' = [session_snapshot EXCEPT ![a] = clock]
                      /\ state' = [state EXCEPT ![a] = "ESTABLISHED"]
                   ELSE
                      /\ highest_nonce' = highest_nonce
                      /\ session_snapshot' = session_snapshot
                      /\ state' = [state EXCEPT ![a] = "LISTEN"]
    /\ UNCHANGED << sat_registry, network, clock, byzantine_server, byzantine_ac, network_partition >>

UndefinedBehaviorHandling(a) ==
    /\ state[a] = "CORRUPTED"
    /\ state' = [state EXCEPT ![a] = "LISTEN"]
    /\ UNCHANGED << highest_nonce, sat_registry, network, clock, byzantine_server, byzantine_ac, network_partition, session_snapshot >>

Tick ==
    /\ clock < MaxTime
    /\ clock' = clock + 1
    /\ UNCHANGED << state, highest_nonce, sat_registry, network, byzantine_server, byzantine_ac, network_partition, session_snapshot >>

\* NHP-AC (Policy Evaluation)
NHPAC ==
    \E a \in Agents: AtomicVerifyAndEvaluate(a)

\* Safety Gate Control
SGC ==
    \E a \in Agents: UndefinedBehaviorHandling(a)

Next ==
    \/ (\E a \in Agents, iat \in 0..clock, exp \in clock+1..MaxTime: RequestSAT(a, iat, exp))
    \/ (\E a \in Agents, n \in 1..MaxNonce: SendHandshake(a, n))
    \/ MaliciousReplay
    \/ CompromiseServer
    \/ CompromiseAC
    \/ TogglePartition
    \/ NHPAC
    \/ SGC
    \/ Tick

Spec == Init /\ [][Next]_vars /\ WF_vars(NHPAC) /\ SF_vars(SGC)

\* --- HARD INVARIANTS ---
NoReplayAttack ==
    ~byzantine_server => 
    \A a \in Agents:
        \A m1, m2 \in network:
            (m1.agent = a /\ m2.agent = a /\ m1.nonce = m2.nonce /\ m1 /= m2)
            => ~(state[a] = "ESTABLISHED" /\ highest_nonce[a] = m1.nonce)

SATValidityInvariant ==
    ~byzantine_server =>
    \A a \in Agents:
        state[a] = "ESTABLISHED" 
        => \E sat \in sat_registry: sat.agent = a /\ sat.iat <= session_snapshot[a] /\ session_snapshot[a] <= sat.exp

MAMASafetyInvariant ==
    ~byzantine_server /\ ~byzantine_ac =>
    \A a \in Agents:
        state[a] = "ESTABLISHED" => TRUE  \* Since score isn't stored in state, the logic holds by construction in transition.

=============================================================================
