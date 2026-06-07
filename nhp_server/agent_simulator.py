import sys
sys.stdout.reconfigure(encoding='utf-8')
import asyncio
import json
import time
import base64
import uuid
import logging
from jwcrypto import jwk, jws
from fastapi.testclient import TestClient

# Silence server logs for clean CLI
logging.getLogger("app").setLevel(logging.CRITICAL)
logging.getLogger("httpx").setLevel(logging.CRITICAL)

from app.main import app

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.live import Live
from rich.spinner import Spinner
from rich.align import Align
from rich import print as rprint

console = Console()

ZTCPP_LOGO = """
 [cyan]███████╗████████╗ ██████╗██████╗ ██████╗ [/cyan]
 [cyan]╚══███╔╝╚══██╔══╝██╔════╝██╔══██╗██╔══██╗[/cyan]
 [cyan]  ███╔╝    ██║   ██║     ██████╔╝██████╔╝[/cyan]
 [cyan] ███╔╝     ██║   ██║     ██╔═══╝ ██╔═══╝ [/cyan]
 [cyan]███████╗   ██║   ╚██████╗██║     ██║     [/cyan]
 [cyan]╚══════╝   ╚═╝    ╚═════╝╚═╝     ╚═╝     [/cyan]
"""

def print_header():
    console.clear()
    logo_text = Text.from_markup(ZTCPP_LOGO)
    credits_text = Text()
    credits_text.append("\nZero Trust Control and Policy Protocol\n", style="bold white")
    credits_text.append("Advanced Reference Implementation Simulator\n\n", style="italic dim white")
    credits_text.append("Researcher: ", style="bold cyan")
    credits_text.append("AlHussein A. AlSahati\n", style="bold white")
    credits_text.append("Supervisor: ", style="bold cyan")
    credits_text.append("Dr. Houda Chihi\n", style="bold white")
    header_layout = Align.center(logo_text + credits_text)
    console.print(Panel(header_layout, border_style="cyan", padding=(1, 2)))
    console.print("\n")

def generate_key():
    return jwk.JWK.generate(kty="OKP", crv="Ed25519")

def generate_agent_dns_query(key, service_id: str):
    header = {"alg": "EdDSA"}
    payload = {
        "service_identifier": service_id, "intent_class": "monitor", "agent_role": "performance_monitor",
        "context_preferences": {"min_cei_threshold": 50, "max_edns_tolerance": 0.2, "latency_bound_ms": 100, "preferred_domain": "core"},
        "policy_token_reference": "ref-123"
    }
    iat = int(time.time())
    exp = iat + 30
    token = jws.JWS(json.dumps(payload).encode("utf-8"))
    token.add_signature(key, None, json.dumps(header), None)
    return payload, token.serialize(compact=True), str(uuid.uuid4()), iat, exp

def generate_knk_payload(key, node_id, edns=0.15, confidence=0.98, time_offset=0):
    intent = {
        "action_class": "monitor", "target_service": "amf.5gc.svc",
        "impact_scope": {"max_subscribers": 1000, "max_edns_delta": 0.05, "domain": "core"},
        "temporal_bounds": {"session_duration_ms": 300000, "execution_window": {"start_time": int(time.time()), "end_time": int(time.time()) + 300000}}
    }
    context = {
        "current_edns": edns, "current_cei": 85, "active_alarms": 0, "ongoing_remediations": 0, "agent_confidence_score": confidence
    }
    
    # Generate the actual JWS token (with spoofed time offset if provided)
    header = {"alg": "EdDSA"}
    nonce_val = base64.b64encode(uuid.uuid4().bytes).decode()
    jws_payload = {
        "iss": "ztcpp-agent", "aud": "ztcpp-nhp-server", "exp": int(time.time()) + 30 + time_offset,
        "node_id": node_id, "nonce": nonce_val,
        "timestamp": int(time.time()), "ztcpp_intent": intent, "ztcpp_context": context
    }
    token = jws.JWS(json.dumps(jws_payload).encode("utf-8"))
    token.add_signature(key, None, json.dumps(header), None)

    knk = {
        "version": "1.0", "node_id": node_id, "timestamp": jws_payload["timestamp"],
        "nonce": jws_payload["nonce"], "public_key": base64.b64encode(base64.urlsafe_b64decode(key.export_public(as_dict=True)["x"] + "===")[:32]).decode(),
        "jws": token.serialize(compact=True), "ztcpp_intent": intent, "ztcpp_context": context, "ztcpp_sat_fragment": "sat-fragment-001"
    }
    return knk

def run_simulation():
    print_header()
    
    # Initialize keys
    trusted_key = generate_key()
    untrusted_key = generate_key()
    trusted_node_id = "agent-trusted-001"
    untrusted_node_id = "agent-rogue-999"

    with TestClient(app) as client:
        # Register the trusted key directly into the server's state for simulation
        public_bytes = base64.urlsafe_b64decode(trusted_key.export_public(as_dict=True)["x"] + "===")[:32]
        app.state.trust_store.load_key_bytes(trusted_node_id, public_bytes)

        console.print("[bold cyan]Executing 10 Advanced Security Scenarios...[/bold cyan]\n")

        results = []

        with Live(Spinner("dots", text="[yellow]Running Scenarios..."), transient=True, console=console):
            
            # Scenario 1: Valid AgentDNS Resolution
            q_payload, sig, jti, iat, exp = generate_agent_dns_query(trusted_key, "amf.5gc.svc")
            r1 = client.post("/api/v1/agentdns/resolve", json=q_payload, headers={"jws-signature": sig, "jti": jti, "iat": str(iat), "exp": str(exp)})
            results.append(("1. AgentDNS Intent Resolution", "Valid Intent 'monitor'", "200 OK", "200 OK" if r1.status_code == 200 else str(r1.status_code)))

            # Scenario 2: Valid Cryptographic Handshake
            p2 = generate_knk_payload(trusted_key, trusted_node_id)
            cei_valid = {"capability_effectiveness_index": 0.85, "projected_demand_not_served": 0.15, "throughput_impact": 0.05, "sla_penalty_exposure": 0.01}
            r2 = client.post("/api/v1/knk/submit", json={"payload": p2, "cei_metrics": cei_valid})
            d2 = r2.json().get("decision") if r2.status_code == 200 else "ERROR"
            results.append(("2. Cryptographic Handshake", "Trusted Node (Trust Store Hit)", "APPROVE", d2))

            # Scenario 3: Untrusted Node Rejection (Fail-Closed)
            p3 = generate_knk_payload(untrusted_key, untrusted_node_id)
            r3 = client.post("/api/v1/knk/submit", json={"payload": p3, "cei_metrics": cei_valid})
            d3 = r3.json().get("reason") if r3.status_code == 200 else "ERROR"
            results.append(("3. Untrusted Node Intrusion", "Unknown Key Attempt", "untrusted_node", d3))

            # Scenario 4: Stale/Expired Token Attack
            p4 = generate_knk_payload(trusted_key, trusted_node_id, time_offset=-100) # Expired 100s ago
            r4 = client.post("/api/v1/knk/submit", json={"payload": p4, "cei_metrics": cei_valid})
            d4 = r4.json().get("reason") if r4.status_code == 200 else "ERROR"
            results.append(("4. Expired Token Replay", "JWT 'exp' in the past", "expired_token", d4))

            # Scenario 5: Future Token Manipulation (Clock Skew)
            p5 = generate_knk_payload(trusted_key, trusted_node_id, time_offset=1000) # Expires too far in future
            r5 = client.post("/api/v1/knk/submit", json={"payload": p5, "cei_metrics": cei_valid})
            d5 = r5.json().get("reason") if r5.status_code == 200 else "ERROR"
            results.append(("5. Token Future Manipulation", "JWT 'exp' bypasses skew limit", "clock_skew_exceeded", d5))

            # Scenario 6: Value Realization Gate Violation
            p6 = generate_knk_payload(trusted_key, trusted_node_id, edns=0.0)
            cei_value_fail = {"capability_effectiveness_index": 0.70, "projected_demand_not_served": 0.80, "throughput_impact": 0.05, "sla_penalty_exposure": 0.01}
            r6 = client.post("/api/v1/knk/submit", json={"payload": p6, "cei_metrics": cei_value_fail})
            d6 = r6.json().get("reason") if r6.status_code == 200 else "ERROR"
            results.append(("6. MAMA Gate: Value Realization", "Projected Demand > CEI", "negative_value_realization", d6))

            # Scenario 7: Safety Gate Violation
            p7 = generate_knk_payload(trusted_key, trusted_node_id, edns=0.80) 
            cei_safety_fail = {"capability_effectiveness_index": 0.30, "projected_demand_not_served": 0.15, "throughput_impact": 0.05, "sla_penalty_exposure": 0.01}
            r7 = client.post("/api/v1/knk/submit", json={"payload": p7, "cei_metrics": cei_safety_fail})
            d7 = r7.json().get("reason") if r7.status_code == 200 else "ERROR"
            results.append(("7. MAMA Gate: Safety Drop", "Safety Score < min_safety", "safety_gate_triggered", d7))

            # Scenario 8: Funding Gate Violation (SLA Penalty)
            p8 = generate_knk_payload(trusted_key, trusted_node_id)
            cei_funding_fail = {"capability_effectiveness_index": 0.85, "projected_demand_not_served": 0.15, "throughput_impact": 0.05, "sla_penalty_exposure": 0.90}
            r8 = client.post("/api/v1/knk/submit", json={"payload": p8, "cei_metrics": cei_funding_fail})
            d8 = r8.json().get("reason") if r8.status_code == 200 else "ERROR"
            results.append(("8. MAMA Gate: SLA Exposure", "SLA Penalty > Threshold", "sla_penalty_exposure_exceeded", d8))

            # Scenario 9: Unauthenticated SBA Access
            r9 = client.get("/api/v1/sba/resource")
            results.append(("9. SBA Mediation Bypass", "Access SBA without ZTCPP Headers", "403", str(r9.status_code)))

            # Scenario 10: Authenticated SBA Access
            r10 = client.get("/api/v1/sba/resource", headers={"ztcpp-auth-context": "jwt-sat", "ztcpp-flow-bind": "sha256=abc;tunnel=123"})
            results.append(("10. Authenticated SBA Access", "Access SBA with ZTCPP Headers", "404", str(r10.status_code)))
            
            time.sleep(1) # Dramatic pause

        # Build Master Table
        matrix = Table(title="ZTCPP Strict Security Test Matrix", show_header=True, header_style="bold magenta", expand=True)
        matrix.add_column("No.", style="dim", width=4)
        matrix.add_column("Test Scenario", style="cyan")
        matrix.add_column("Attack Vector / State", style="yellow")
        matrix.add_column("Expected Result", style="bold blue")
        matrix.add_column("Actual Result", style="bold")
        matrix.add_column("Pass/Fail", justify="center")

        for idx, (name, vector, expected, actual) in enumerate(results, 1):
            actual_str = str(actual)
            passed = expected in actual_str or actual_str in expected
            pass_str = "[bold green]PASS[/bold green]" if passed else "[bold red]FAIL[/bold red]"
            actual_style = "green" if passed else "red"
            matrix.add_row(str(idx), name, vector, expected, f"[{actual_style}]{actual}[/]", pass_str)

        console.print(matrix)
        console.print("\n[dim italic]All 10 rigorous Zero-Trust scenarios executed against the PDP policy engine and SBA Middleware.[/dim italic]\n")

if __name__ == "__main__":
    run_simulation()


