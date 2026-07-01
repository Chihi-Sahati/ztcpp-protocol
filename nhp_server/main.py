import sys
import os
import uuid
import logging
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Add the parent directory to the python path to import nhp_sba modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sat.token_issuer import TokenIssuer
from safety_gates.evaluator import SafetyGateEvaluator

# Note: The directory is "safety-gates" but Python modules don't like hyphens.
# We will assume the folder can be accessed via importlib or we handle it here.
# Actually, let's just use importlib to import from a directory with a hyphen.
import importlib.util
spec = importlib.util.spec_from_file_location("evaluator", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "safety-gates", "evaluator.py"))
evaluator_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluator_module)
SafetyGateEvaluator = evaluator_module.SafetyGateEvaluator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nhp_server")

app = FastAPI(title="NHP-SBA NHP-Server (PDP)", version="0.2.0")

issuer = TokenIssuer()
gate_evaluator = SafetyGateEvaluator()

class KnkRequest(BaseModel):
    # In a real implementation, this would be a Base64Url encoded JWS containing FlatBuffers
    # For this PoC endpoint, we will mock the parsed fields of the FlatBuffers payload
    agent_uri: str
    nonce: int
    t_snapshot: int
    intent_class: int
    target_service: str

@app.post("/nhp/knk")
async def process_knk(request: KnkRequest):
    logger.info(f"Received NHP-KNK from {request.agent_uri} with T_snapshot={request.t_snapshot}")
    
    # 1. Evaluate Safety Gates based on the requested intent
    gate_params = gate_evaluator.evaluate_intent(request.intent_class, request.target_service)
    
    # 2. Assign a micro-tunnel ID
    tunnel_id = f"tun-{uuid.uuid4().hex[:8]}"
    
    # 3. Issue SAT Token (Strict Snapshot Semantics)
    sat_jwt = issuer.issue_sat(
        agent_uri=request.agent_uri,
        intent_class=request.intent_class,
        t_snapshot=request.t_snapshot,
        max_duration_sec=gate_params["max_duration_sec"],
        tunnel_id=tunnel_id
    )
    
    # 4. Construct NHP-AOP (Auth-Open-Policy) Payload
    aop_payload = {
        "agent_uri": request.agent_uri,
        "tunnel_id": tunnel_id,
        "sat_jwt": sat_jwt,
        "safety_gates": gate_params
    }
    
    # Normally this AOP is sent to the NHP-AC (PEP). For this PDP, we just return it.
    logger.info(f"Generated NHP-AOP for tunnel {tunnel_id}")
    return {"status": "success", "nhp_aop": aop_payload}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
