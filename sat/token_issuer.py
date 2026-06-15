import jwt
import logging

logger = logging.getLogger(__name__)

class TokenIssuer:
    def __init__(self, secret_key: str = "ztcpp-super-secret-key-for-dev"):
        self.secret_key = secret_key
        
    def issue_sat(self, agent_uri: str, intent_class: int, t_snapshot: int, max_duration_sec: int, tunnel_id: str) -> str:
        """
        Issues a Session Authorization Token (SAT) as a JWT.
        
        CRITICAL SEMANTICS:
        Adheres to "Event-Driven Logical Time with Atomic Snapshots".
        The token time validity is STRICTLY anchored to t_snapshot.
        No continuous time (e.g. time.time()) is used for iat/exp.
        """
        
        # SAT_valid := (iat <= T_snapshot) AND (T_snapshot <= exp)
        # Therefore, iat = t_snapshot, exp = t_snapshot + max_duration_sec
        
        payload = {
            "iss": "ztcpp-pdp",
            "sub": agent_uri,
            # Standard claims anchored to the snapshot
            "iat": t_snapshot,
            "nbf": t_snapshot,
            "exp": t_snapshot + max_duration_sec,
            
            # ZTCPP Custom Claims
            "ztcpp_intent_class": intent_class,
            "ztcpp_micro_tunnel_id": tunnel_id,
            "ztcpp_temporal_bounds": {
                "t_snapshot": t_snapshot,
                "max_duration": max_duration_sec
            }
        }
        
        logger.info(f"Issuing SAT for {agent_uri} anchored at T_snapshot={t_snapshot}")
        
        # In ZTCPP, EdDSA (Ed25519) should be used. For this PoC, we use HS256 to minimize dependencies,
        # but in a production setup, it would be 'EdDSA' with a private key.
        token = jwt.encode(payload, self.secret_key, algorithm="HS256")
        return token
