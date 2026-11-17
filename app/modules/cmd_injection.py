"""Module 4 (Member 4): OS Command Injection — In-Band (Command Output Returned)."""

import re
import subprocess
import sys
import time
from typing import Any, Dict, List
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from app.config import BASE_DIR, COURSE_INFO, GROUP_MEMBERS
from app.logger import event_logger
from app.source_inspector import get_module_source_pair

router = APIRouter(prefix="/modules/cmd-injection", tags=["Module 4: OS Command Injection"])
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

MODULE_KEY = "cmd-injection"
MEMBER_INFO = GROUP_MEMBERS[3]

# Strict lab safety guardrail for vulnerable mode so only harmless local academic inspection commands can run
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "ip6-localhost"}
SAFE_DEMO_SUBCOMMANDS = {"id", "whoami", "uname -a", "uname", "date", "pwd", "hostname", "echo iiita-lab-ok"}

EXAMPLE_PAYLOADS = [
    {
        "label": "Logical AND Chaining (&& whoami)",
        "target": "127.0.0.1 && whoami",
        "description": "Works cross-platform (Linux/macOS/Windows): runs 'whoami' immediately after the base command succeeds.",
    },
    {
        "label": "Semicolon Command Chaining (; id)",
        "target": "localhost; id",
        "description": "POSIX shell chaining: terminates the base command with ';' and executes 'id', returning user/group IDs in-band.",
    },
    {
        "label": "Hostname Inspection (&& hostname)",
        "target": "localhost && hostname",
        "description": "Chains 'hostname' to print the local machine name in the diagnostic output.",
    },
    {
        "label": "Benign Localhost Lookup (Control)",
        "target": "localhost",
        "description": "Valid host diagnostic target that succeeds in both vulnerable and secured modes.",
    },
]

ALTERNATIVE_MITIGATIONS = [
    {
        "name": "Avoiding the Shell + Argument Vector Execution",
        "status": "IMPLEMENTED",
        "idea": "Invoke executables directly using an argument list (subprocess.run([sys.executable, '-c', '...', target], shell=False)) instead of passing a concatenated string to the OS shell.",
        "why_effective": "Without a shell interpreter, metacharacters like ';', '&&', '|', and '$()' are passed as literal arguments and are never interpreted as command separators.",
    },
    {
        "name": "Allow-List Input Validation",
        "status": "IMPLEMENTED",
        "idea": "Enforce a strict allow-list of permitted hostnames/IPs (e.g., {'localhost', '127.0.0.1'}) before invoking any subprocess.",
        "why_effective": "Rejects unexpected metacharacters and unauthorized targets at the application boundary.",
    },
    {
        "name": "Least Privilege Execution",
        "status": "THEORETICAL",
        "idea": "Run the web server process under a dedicated unprivileged OS account with minimal filesystem permissions, no sudo access, and seccomp/container isolation.",
        "why_effective": "Contains potential damage even if an unexpected command execution flaw is discovered.",
    },
]

VIVA_QA = [
    {
        "q": "Why does 'localhost && whoami' or 'localhost; id' execute the second command in vulnerable mode?",
        "a": "Because subprocess.run(..., shell=True) passes the concatenated string to the OS shell (/bin/sh -c on POSIX, cmd.exe on Windows). The shell treats '&&' or ';' as a command separator, running both commands and returning their stdout in-band.",
    },
    {
        "q": "What does 'In-Band' OS Command Injection mean?",
        "a": "In-Band means the attacker receives the output of the injected OS command directly in the same HTTP response channel, as opposed to Blind command injection where output must be inferred via time delays or out-of-band channels.",
    },
    {
        "q": "Why is shell=False with an argument vector effective?",
        "a": "With shell=False, the OS launches the target executable directly with an argv list. No shell is spawned, so '&& whoami' is treated as a literal string argument rather than a second command.",
    },
    {
        "q": "Why is allow-list validation preferred over block-list filtering?",
        "a": "Block-lists (trying to strip ';' or '|') often miss alternative shell syntax like newlines, backticks, $(), or IFS tricks. Allow-lists define the exact valid format and reject everything else.",
    },
]


def _check_lab_sandbox_safety(user_input: str) -> Dict[str, Any]:
    """
    Academic safety guardrail: ensures vulnerable mode only executes harmless local test
    operations (id, whoami, uname, date, pwd, hostname, echo) and blocks destructive or
    secret-access commands.
    """
    cleaned = user_input.strip()
    if not cleaned:
        return {"safe": False, "reason": "Empty diagnostic target."}
    if re.fullmatch(r"[a-zA-Z0-9.-]{1,64}", cleaned):
        return {"safe": True, "injected": False}

    parts = re.split(r"\s*(?:;|&&|\|\|)\s*", cleaned)
    if len(parts) >= 2:
        base_host = parts[0].strip()
        extra_cmds = [p.strip() for p in parts[1:] if p.strip()]
        if base_host in ALLOWED_HOSTS and all(cmd in SAFE_DEMO_SUBCOMMANDS for cmd in extra_cmds):
            return {"safe": True, "injected": True, "subcommands": extra_cmds}

    return {
        "safe": False,
        "reason": (
            "Lab Safety Sandbox Guardrail: Vulnerable mode restricts chained commands to harmless "
            "academic inspection commands (id, whoami, uname -a, date, pwd, hostname, echo iiita-lab-ok) "
            "on localhost/127.0.0.1."
        ),
    }


# [SOURCE_INSPECT:VULNERABLE_START]
def run_diagnostic_vulnerable(target: str) -> Dict[str, Any]:
    """VULNERABLE: Concatenates user input into a shell command string with shell=True."""
    safety = _check_lab_sandbox_safety(target)
    if not safety["safe"]:
        return {
            "status": "sandbox_blocked",
            "command": f"echo [DIAG] Checking host: {target}",
            "stdout": "",
            "stderr": safety["reason"],
            "returncode": -1,
            "duration_ms": 0,
            "injected": False,
        }

    # FLAW: String formatting + shell=True passes user input directly to the OS shell
    shell_cmd = f"echo [DIAG] Checking host: {target}"
    t0 = time.perf_counter()
    proc = subprocess.run(
        shell_cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=3,
    )
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
    return {
        "status": "executed",
        "command": shell_cmd,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "returncode": proc.returncode,
        "duration_ms": elapsed_ms,
        "injected": safety.get("injected", False),
    }
# [SOURCE_INSPECT:VULNERABLE_END]


# [SOURCE_INSPECT:SECURED_START]
def run_diagnostic_secured(target: str) -> Dict[str, Any]:
    """SECURED: Strict allow-list validation + argument vector execution (shell=False)."""
    cleaned = target.strip()
    # SAFE 1: Allow-list validation rejects metacharacters and non-local targets
    if cleaned not in ALLOWED_HOSTS:
        return {
            "status": "rejected",
            "command": f"[python, '-c', '...', {cleaned!r}]",
            "stdout": "",
            "stderr": f"ValidationError: Target {cleaned!r} rejected. Allowed targets: {sorted(ALLOWED_HOSTS)}.",
            "returncode": 400,
            "duration_ms": 0,
            "injected": False,
        }

    # SAFE 2: Parameterized argument vector with shell=False (no shell spawned)
    argv: List[str] = [
        sys.executable,
        "-c",
        "import sys, socket; h=sys.argv[1]; print(f'[DIAG] {h} -> {socket.gethostbyname(h)}')",
        cleaned,
    ]
    t0 = time.perf_counter()
    proc = subprocess.run(
        argv,
        shell=False,
        capture_output=True,
        text=True,
        timeout=3,
    )
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
    return {
        "status": "executed",
        "command": repr(argv),
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "returncode": proc.returncode,
        "duration_ms": elapsed_ms,
        "injected": False,
    }
# [SOURCE_INSPECT:SECURED_END]


@router.get("", response_class=HTMLResponse)
async def cmd_page(request: Request, mode: str = "vulnerable"):
    mode = mode if mode in ("vulnerable", "secured") else "vulnerable"
    source_code = get_module_source_pair("cmd_injection.py")
    return templates.TemplateResponse(
        "modules/cmd_injection.html",
        {
            "request": request,
            "course": COURSE_INFO,
            "member": MEMBER_INFO,
            "module_key": MODULE_KEY,
            "mode": mode,
            "example_payloads": EXAMPLE_PAYLOADS,
            "alternatives": ALTERNATIVE_MITIGATIONS,
            "viva_qa": VIVA_QA,
            "source_code": source_code,
            "result": None,
            "submitted_target": "localhost",
        },
    )


@router.post("/run")
async def cmd_run(
    request: Request,
    target: str = Form("localhost"),
    mode: str = Form("vulnerable"),
):
    mode = mode if mode in ("vulnerable", "secured") else "vulnerable"
    is_json = "application/json" in request.headers.get("accept", "") or request.headers.get("x-requested-with") == "fetch"

    event_logger.log(
        MODULE_KEY,
        "HTTP_REQ",
        "Diagnostic Request Received",
        f"POST /modules/cmd-injection/run in {mode.upper()} mode",
        mode=mode,
        method="POST",
        endpoint="/modules/cmd-injection/run",
        params={"target": target, "mode": mode},
        payload=target,
    )

    result = run_diagnostic_vulnerable(target) if mode == "vulnerable" else run_diagnostic_secured(target)

    if result["status"] == "executed" and result["injected"]:
        event_logger.log(
            MODULE_KEY,
            "EXPLOIT_SUCCESS",
            "In-Band OS Command Injection Succeeded",
            f"Shell executed chained command: {result['command']} in {result['duration_ms']} ms.",
            mode=mode,
            payload=target,
            details={"returncode": result["returncode"], "duration_ms": result["duration_ms"]},
        )
    elif result["status"] == "rejected":
        event_logger.log(
            MODULE_KEY,
            "MITIGATION_BLOCKED",
            "Command Injection Blocked by Allow-List",
            result["stderr"],
            mode=mode,
            payload=target,
        )
    elif result["status"] == "sandbox_blocked":
        event_logger.log(
            MODULE_KEY,
            "WARNING",
            "Lab Safety Sandbox Guardrail Triggered",
            result["stderr"],
            mode=mode,
            payload=target,
        )
    else:
        event_logger.log(
            MODULE_KEY,
            "INFO",
            "Diagnostic Command Completed",
            f"Executed {result['command']} cleanly in {result['duration_ms']} ms.",
            mode=mode,
            details={"returncode": result["returncode"], "duration_ms": result["duration_ms"]},
        )

    if is_json:
        return JSONResponse({"ok": True, "mode": mode, "result": result})

    source_code = get_module_source_pair("cmd_injection.py")
    return templates.TemplateResponse(
        "modules/cmd_injection.html",
        {
            "request": request,
            "course": COURSE_INFO,
            "member": MEMBER_INFO,
            "module_key": MODULE_KEY,
            "mode": mode,
            "example_payloads": EXAMPLE_PAYLOADS,
            "alternatives": ALTERNATIVE_MITIGATIONS,
            "viva_qa": VIVA_QA,
            "source_code": source_code,
            "result": result,
            "submitted_target": target,
        },
    )


@router.post("/compare")
async def cmd_compare(target: str = Form("127.0.0.1 && whoami")):
    vuln = run_diagnostic_vulnerable(target)
    sec = run_diagnostic_secured(target)
    event_logger.log(
        MODULE_KEY,
        "INFO",
        "Side-by-Side Comparison Executed",
        "Tested identical diagnostic input in Vulnerable (shell=True) vs Secured (allow-list + shell=False).",
        payload=target,
    )
    return {"payload": target, "vulnerable": vuln, "secured": sec}


@router.post("/reset")
async def cmd_reset():
    event_logger.clear_logs(MODULE_KEY)
    event_logger.log(MODULE_KEY, "INFO", "Module Reset", "Cleared diagnostic output and execution logs.")
    return JSONResponse({"ok": True, "message": "Module 4 reset complete."})
