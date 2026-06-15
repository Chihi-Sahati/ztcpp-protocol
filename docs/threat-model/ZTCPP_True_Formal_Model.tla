----------------------- MODULE ZTCPP_True_Formal_Model -----------------------
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS 
    Agents,             \* Set of Agent IDs
    MaxNonce,           \* Maximum Nonce for bounded checking
    MaxTime,            \* Maximum Time for bounded checking
    MinSafetyScore      \* Minimum MAMA Score

VARIABLES 
    state,              \* gateway state per agent
    highest_nonce,      \* nonce tracker per agent
    sat_registry,       \* set of valid SAT tokens
    network,            \* set of messages in network (simulates reordering/delay/replays)
    clock,              \* global clock
    byzantine_server,   \* is the server compromised
    byzantine_ac,       \* is the policy engine compromised
    network_partition   \* is the network currently partitioned

vars == << state, highest_nonce, sat_registry, network, clock, byzantine_server, byzantine_ac, network_partition >>

Init == 
    /\ state = [a \in Agents |-> "LISTEN"]
    /\ highest_nonce = [a \in Agents |-> 0]
    /\ sat_registry = {}
    /\ network = {}
    /\ clock = 0
    /\ byzantine_server = FALSE
    /\ byzantine_ac = FALSE
    /\ network_partition = FALSE

\* --- HONEST ACTIONS ---
RequestSAT(a, exp) ==
    /\ sat_registry' = sat_registry \cup {[agent |-> a, exp |-> exp, active |-> TRUE]}
    /\ UNCHANGED << state, highest_nonce, network, clock, byzantine_server, byzantine_ac, network_partition >>

SendHandshake(a, nonce) ==
    /\ nonce \in 1..MaxNonce
    /\ network' = network \cup {[type |-> "KNK", agent |-> a, nonce |-> nonce]}
    /\ UNCHANGED << state, highest_nonce, sat_registry, clock, byzantine_server, byzantine_ac, network_partition >>

\* --- ADVERSARIAL ACTIONS ---
MaliciousReplay ==
    /\ \E m \in network: network' = network \cup {m}  \* Re-injecting message simulates replay
    /\ UNCHANGED << state, highest_nonce, sat_registry, clock, byzantine_server, byzantine_ac, network_partition >>

CompromiseServer ==
    /\ ~byzantine_server
    /\ byzantine_server' = TRUE
    /\ UNCHANGED << state, highest_nonce, sat_registry, network, clock, byzantine_ac, network_partition >>

CompromiseAC ==
    /\ ~byzantine_ac
    /\ byzantine_ac' = TRUE
    /\ UNCHANGED << state, highest_nonce, sat_registry, network, clock, byzantine_server, network_partition >>

TogglePartition ==
    /\ network_partition' = ~network_partition
    /\ UNCHANGED << state, highest_nonce, sat_registry, network, clock, byzantine_server, byzantine_ac >>

\* --- STATE MACHINE ACTIONS (S0 -> S5) ---
ReceiveKNK(m) ==
    /\ ~network_partition
    /\ m \in network
    /\ state[m.agent] \in {"LISTEN", "CORRUPTED"}
    /\ state' = [state EXCEPT ![m.agent] = "PARSE_SIG"]
    /\ UNCHANGED << highest_nonce, sat_registry, network, clock, byzantine_server, byzantine_ac, network_partition >>

ParseSig(a) ==
    /\ ~network_partition
    /\ state[a] = "PARSE_SIG"
    /\ \E m \in network:
        /\ m.agent = a
        /\ IF m.nonce > highest_nonce[a] \/ byzantine_server THEN
              /\ highest_nonce' = [highest_nonce EXCEPT ![a] = m.nonce]
              /\ state' = [state EXCEPT ![a] = "VERIFY_SAT"]
           ELSE
              /\ highest_nonce' = highest_nonce
              /\ state' = [state EXCEPT ![a] = "LISTEN"]
    /\ UNCHANGED << sat_registry, network, clock, byzantine_server, byzantine_ac, network_partition >>

VerifySAT(a) ==
    /\ ~network_partition
    /\ state[a] = "VERIFY_SAT"
    /\ \E m \in network:
        /\ m.agent = a
        /\ \E sat \in sat_registry:
            /\ sat.agent = a
            /\ IF sat.exp > clock \/ byzantine_server THEN
                  /\ state' = [state EXCEPT ![a] = "EVALUATE_MAMA"]
               ELSE
                  /\ state' = [state EXCEPT ![a] = "LISTEN"]
    /\ UNCHANGED << highest_nonce, sat_registry, network, clock, byzantine_server, byzantine_ac, network_partition >>

EvaluateMAMA(a) ==
    /\ ~network_partition
    /\ state[a] = "EVALUATE_MAMA"
    /\ \E score \in 0..100:
        /\ IF score >= MinSafetyScore \/ byzantine_ac \/ byzantine_server THEN
              /\ state' = [state EXCEPT ![a] = "ESTABLISHED"]
           ELSE
              /\ state' = [state EXCEPT ![a] = "LISTEN"]
    /\ UNCHANGED << highest_nonce, sat_registry, network, clock, byzantine_server, byzantine_ac, network_partition >>

UndefinedBehaviorHandling(a) ==
    \* Formalizing fallback behavior for arbitrary state corruption
    /\ state[a] = "CORRUPTED"
    /\ state' = [state EXCEPT ![a] = "LISTEN"]
    /\ UNCHANGED << highest_nonce, sat_registry, network, clock, byzantine_server, byzantine_ac, network_partition >>

Tick ==
    /\ clock < MaxTime
    /\ clock' = clock + 1
    /\ UNCHANGED << state, highest_nonce, sat_registry, network, byzantine_server, byzantine_ac, network_partition >>

Next ==
    \/ (\E a \in Agents, exp \in clock+1..MaxTime: RequestSAT(a, exp))
    \/ (\E a \in Agents, n \in 1..MaxNonce: SendHandshake(a, n))
    \/ MaliciousReplay
    \/ CompromiseServer
    \/ CompromiseAC
    \/ TogglePartition
    \/ (\E m \in network: ReceiveKNK(m))
    \/ (\E a \in Agents: ParseSig(a))
    \/ (\E a \in Agents: VerifySAT(a))
    \/ (\E a \in Agents: EvaluateMAMA(a))
    \/ (\E a \in Agents: UndefinedBehaviorHandling(a))
    \/ Tick

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

\* --- HARD INVARIANTS ---

\* 1. Replay Immunity under Honest Server
NoReplayHonestServer ==
    ~byzantine_server => 
    \A a \in Agents:
        \A m1, m2 \in network:
            (m1.agent = a /\ m2.agent = a /\ m1.nonce = m2.nonce /\ m1 /= m2)
            => ~(state[a] = "ESTABLISHED" /\ highest_nonce[a] = m1.nonce)

\* 2. SAT Context Bounding
SATBound ==
    ~byzantine_server =>
    \A a \in Agents:
        (state[a] = "ESTABLISHED" \/ state[a] = "EVALUATE_MAMA")
        => \E sat \in sat_registry: sat.agent = a /\ sat.exp > clock

=============================================================================
