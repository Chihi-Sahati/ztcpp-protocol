---- MODULE NHP-SBA_Deterministic_Model_TTrace_1781516796 ----
EXTENDS NHP-SBA_Deterministic_Model_TEConstants, Sequences, TLCExt, Toolbox, Naturals, TLC, NHP-SBA_Deterministic_Model

_expression ==
    LET NHP-SBA_Deterministic_Model_TEExpression == INSTANCE NHP-SBA_Deterministic_Model_TEExpression
    IN NHP-SBA_Deterministic_Model_TEExpression!expression
----

_trace ==
    LET NHP-SBA_Deterministic_Model_TETrace == INSTANCE NHP-SBA_Deterministic_Model_TETrace
    IN NHP-SBA_Deterministic_Model_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        network_partition = (FALSE)
        /\
        byzantine_ac = (FALSE)
        /\
        state = ((a1 :> "ESTABLISHED"))
        /\
        sat_registry = ({[iat |-> 0, exp |-> 1, agent |-> a1, active |-> TRUE]})
        /\
        clock = (2)
        /\
        highest_nonce = ((a1 :> 1))
        /\
        network = ({[agent |-> a1, nonce |-> 1, type |-> "KNK"]})
        /\
        byzantine_server = (FALSE)
    )
----

_init ==
    /\ state = _TETrace[1].state
    /\ byzantine_ac = _TETrace[1].byzantine_ac
    /\ network = _TETrace[1].network
    /\ network_partition = _TETrace[1].network_partition
    /\ byzantine_server = _TETrace[1].byzantine_server
    /\ sat_registry = _TETrace[1].sat_registry
    /\ highest_nonce = _TETrace[1].highest_nonce
    /\ clock = _TETrace[1].clock
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ state  = _TETrace[i].state
        /\ state' = _TETrace[j].state
        /\ byzantine_ac  = _TETrace[i].byzantine_ac
        /\ byzantine_ac' = _TETrace[j].byzantine_ac
        /\ network  = _TETrace[i].network
        /\ network' = _TETrace[j].network
        /\ network_partition  = _TETrace[i].network_partition
        /\ network_partition' = _TETrace[j].network_partition
        /\ byzantine_server  = _TETrace[i].byzantine_server
        /\ byzantine_server' = _TETrace[j].byzantine_server
        /\ sat_registry  = _TETrace[i].sat_registry
        /\ sat_registry' = _TETrace[j].sat_registry
        /\ highest_nonce  = _TETrace[i].highest_nonce
        /\ highest_nonce' = _TETrace[j].highest_nonce
        /\ clock  = _TETrace[i].clock
        /\ clock' = _TETrace[j].clock

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("NHP-SBA_Deterministic_Model_TTrace_1781516796.json", _TETrace)

=============================================================================

 Note that you can extract this module `NHP-SBA_Deterministic_Model_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `NHP-SBA_Deterministic_Model_TEExpression.tla` file takes precedence 
  over the module `NHP-SBA_Deterministic_Model_TEExpression` below).

---- MODULE NHP-SBA_Deterministic_Model_TEExpression ----
EXTENDS NHP-SBA_Deterministic_Model_TEConstants, Sequences, TLCExt, Toolbox, Naturals, TLC, NHP-SBA_Deterministic_Model

expression == 
    [
        \* To hide variables of the `NHP-SBA_Deterministic_Model` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        state |-> state
        ,byzantine_ac |-> byzantine_ac
        ,network |-> network
        ,network_partition |-> network_partition
        ,byzantine_server |-> byzantine_server
        ,sat_registry |-> sat_registry
        ,highest_nonce |-> highest_nonce
        ,clock |-> clock
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_stateUnchanged |-> state = state'
        
        \* Format the `state` variable as Json value.
        \* ,_stateJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(state)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_stateModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].state # _TETrace[s-1].state
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE NHP-SBA_Deterministic_Model_TETrace ----
\*EXTENDS NHP-SBA_Deterministic_Model_TEConstants, IOUtils, TLC, NHP-SBA_Deterministic_Model
\*
\*trace == IODeserialize("NHP-SBA_Deterministic_Model_TTrace_1781516796.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE NHP-SBA_Deterministic_Model_TETrace ----
EXTENDS NHP-SBA_Deterministic_Model_TEConstants, TLC, NHP-SBA_Deterministic_Model

trace == 
    <<
    ([network_partition |-> FALSE,byzantine_ac |-> FALSE,state |-> (a1 :> "LISTEN"),sat_registry |-> {},clock |-> 0,highest_nonce |-> (a1 :> 0),network |-> {},byzantine_server |-> FALSE]),
    ([network_partition |-> FALSE,byzantine_ac |-> FALSE,state |-> (a1 :> "LISTEN"),sat_registry |-> {[iat |-> 0, exp |-> 1, agent |-> a1, active |-> TRUE]},clock |-> 0,highest_nonce |-> (a1 :> 0),network |-> {},byzantine_server |-> FALSE]),
    ([network_partition |-> FALSE,byzantine_ac |-> FALSE,state |-> (a1 :> "LISTEN"),sat_registry |-> {[iat |-> 0, exp |-> 1, agent |-> a1, active |-> TRUE]},clock |-> 0,highest_nonce |-> (a1 :> 0),network |-> {[agent |-> a1, nonce |-> 1, type |-> "KNK"]},byzantine_server |-> FALSE]),
    ([network_partition |-> FALSE,byzantine_ac |-> FALSE,state |-> (a1 :> "ESTABLISHED"),sat_registry |-> {[iat |-> 0, exp |-> 1, agent |-> a1, active |-> TRUE]},clock |-> 0,highest_nonce |-> (a1 :> 1),network |-> {[agent |-> a1, nonce |-> 1, type |-> "KNK"]},byzantine_server |-> FALSE]),
    ([network_partition |-> FALSE,byzantine_ac |-> FALSE,state |-> (a1 :> "ESTABLISHED"),sat_registry |-> {[iat |-> 0, exp |-> 1, agent |-> a1, active |-> TRUE]},clock |-> 1,highest_nonce |-> (a1 :> 1),network |-> {[agent |-> a1, nonce |-> 1, type |-> "KNK"]},byzantine_server |-> FALSE]),
    ([network_partition |-> FALSE,byzantine_ac |-> FALSE,state |-> (a1 :> "ESTABLISHED"),sat_registry |-> {[iat |-> 0, exp |-> 1, agent |-> a1, active |-> TRUE]},clock |-> 2,highest_nonce |-> (a1 :> 1),network |-> {[agent |-> a1, nonce |-> 1, type |-> "KNK"]},byzantine_server |-> FALSE])
    >>
----


=============================================================================

---- MODULE NHP-SBA_Deterministic_Model_TEConstants ----
EXTENDS NHP-SBA_Deterministic_Model

CONSTANTS a1

=============================================================================

---- CONFIG NHP-SBA_Deterministic_Model_TTrace_1781516796 ----
CONSTANTS
    Agents = { a1 }
    MaxNonce = 2
    MaxTime = 3
    MinSafetyScore = 85
    a1 = a1

INVARIANT
    _inv

CHECK_DEADLOCK
    \* CHECK_DEADLOCK off because of PROPERTY or INVARIANT above.
    FALSE

INIT
    _init

NEXT
    _next

CONSTANT
    _TETrace <- _trace

ALIAS
    _expression
=============================================================================
\* Generated on Mon Jun 15 11:46:36 EET 2026