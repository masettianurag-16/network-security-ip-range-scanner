"""
Network Security IP Range Scanner
=================================
An educational web application demonstrating basic host discovery in authorized environments.
"""

import os
import re
import platform
import subprocess
import ipaddress
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, render_template, request, jsonify, Response, stream_with_context

app = Flask(__name__)

# Security & Safety Configuration
MAX_HOSTS_PER_SCAN = 254
DEFAULT_TIMEOUT_MS = 800  # 800 milliseconds per ping probe
MAX_WORKERS = 15          # Concurrency limit to prevent network congestion


def parse_latency(output: str) -> str | None:
    """Extract round-trip time from ping command output if available."""
    match = re.search(r"time[<=]([0-9]+(?:\.[0-9]+)?)ms", output, re.IGNORECASE)
    if match:
        return f"{match.group(1)} ms"
    if "time<1ms" in output.lower():
        return "< 1 ms"
    return None


def ping_host(ip: str, timeout_ms: int = DEFAULT_TIMEOUT_MS) -> dict:
    """
    Perform a cross-platform ICMP ping host discovery check on an IPv4 address.
    
    Returns a dictionary with:
      - ip: string IP address
      - status: 'ACTIVE' | 'INACTIVE' | 'UNKNOWN/ERROR'
      - latency: response time string or None
      - note: educational note detailing discovery outcome
    """
    system = platform.system().lower()
    
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        # Linux / macOS / BSD
        timeout_sec = max(1, round(timeout_ms / 1000))
        cmd = ["ping", "-c", "1", "-W", str(timeout_sec), ip]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=(timeout_ms / 1000.0) + 1.5,
            check=False
        )
        output = proc.stdout

        if system == "windows":
            lower_out = output.lower()
            # On Windows, ping can return code 0 on ICMP errors from routers.
            # A true active reply must be directly from the target IP with payload bytes/TTL.
            is_active = (
                proc.returncode == 0
                and f"reply from {ip}" in lower_out
                and ("bytes=" in lower_out or "ttl=" in lower_out)
                and "destination host unreachable" not in lower_out
                and "request timed out" not in lower_out
                and "general failure" not in lower_out
                and "transmit failed" not in lower_out
            )
        else:
            is_active = (proc.returncode == 0) and ("1 received" in output.lower() or "1 packets received" in output.lower())

        if is_active:
            latency = parse_latency(output)
            return {
                "ip": ip,
                "status": "ACTIVE",
                "latency": latency or "Received",
                "note": "Host responded to ICMP Echo Request"
            }
        else:
            return {
                "ip": ip,
                "status": "NO RESPONSE",
                "latency": None,
                "note": "No response after timeout (firewall blocking ICMP or host inactive)"
            }

    except subprocess.TimeoutExpired:
        return {
            "ip": ip,
            "status": "NO RESPONSE",
            "latency": None,
            "note": "Probe timed out (no response received)"
        }
    except Exception:
        # Never expose raw python tracebacks in normal user notes
        return {
            "ip": ip,
            "status": "ERROR",
            "latency": None,
            "note": "Probe failed to execute or network error"
        }


def validate_and_generate_ips(input_mode: str, start_ip: str, end_ip: str, cidr: str, max_hosts: int = MAX_HOSTS_PER_SCAN):
    """
    Validate input parameters and generate the list of IPv4 addresses.
    Returns: (list_of_ips, error_message, target_range_string)
    """
    input_mode = (input_mode or "range").strip().lower()

    if input_mode == "cidr":
        cidr = (cidr or "").strip()
        if not cidr:
            return None, "CIDR input cannot be empty. Example: 192.168.1.0/28", None
        try:
            # strict=False allows host bits to be set, e.g. 192.168.1.5/24
            network = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError:
            return None, f"Invalid CIDR notation '{cidr}'. Please enter a valid IPv4 subnet (e.g., 192.168.1.0/28).", None

        num_hosts = network.num_addresses
        if num_hosts > max_hosts:
            return None, f"Network size ({num_hosts} hosts) exceeds maximum limit of {max_hosts} hosts per scan.", None

        # Handle /31 and /32 single host special cases vs standard subnets
        if network.prefixlen in (31, 32):
            ip_list = [str(ip) for ip in network]
        else:
            # Exclude broadcast and network addresses in standard subnets for beginner host scans
            ip_list = [str(ip) for ip in network.hosts()]
            if not ip_list:
                ip_list = [str(network.network_address)]

        target_range = str(network)
        return ip_list, None, target_range

    else:
        # Range mode
        start_ip = (start_ip or "").strip()
        end_ip = (end_ip or "").strip()

        if not start_ip or not end_ip:
            return None, "Both Start IP and End IP addresses are required.", None

        try:
            start_addr = ipaddress.IPv4Address(start_ip)
        except ValueError:
            return None, f"Invalid Start IP address '{start_ip}'. Must be a valid IPv4 address (e.g. 192.168.1.1).", None

        try:
            end_addr = ipaddress.IPv4Address(end_ip)
        except ValueError:
            return None, f"Invalid End IP address '{end_ip}'. Must be a valid IPv4 address (e.g. 192.168.1.10).", None

        start_int = int(start_addr)
        end_int = int(end_addr)

        if start_int > end_int:
            return None, f"Start IP ({start_ip}) cannot be greater than End IP ({end_ip}).", None

        count = end_int - start_int + 1
        if count > max_hosts:
            return None, f"Selected range contains {count} hosts, which exceeds the limit of {max_hosts} hosts per scan.", None

        ip_list = [str(ipaddress.IPv4Address(i)) for i in range(start_int, end_int + 1)]
        target_range = f"{start_ip} - {end_ip}"
        return ip_list, None, target_range


def compute_summary(target_range: str, results: list) -> dict:
    """Compute summary metrics from scan results."""
    total = len(results)
    active = sum(1 for r in results if r["status"] == "ACTIVE")
    no_response = sum(1 for r in results if r["status"] == "NO RESPONSE")
    errors = sum(1 for r in results if r["status"] == "ERROR")

    return {
        "target_range": target_range,
        "total_scanned": total,
        "active": active,
        "no_response": no_response,
        "errors": errors
    }


def execute_scan(ip_list: list) -> list:
    """Run concurrent ping discovery for a list of IPs and maintain ordering."""
    results_map = {}
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(ip_list) or 1)) as executor:
        future_to_ip = {executor.submit(ping_host, ip): ip for ip in ip_list}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                results_map[ip] = future.result()
            except Exception:
                results_map[ip] = {
                    "ip": ip,
                    "status": "ERROR",
                    "latency": None,
                    "note": "Probe execution failed"
                }

    # Return results in the original IP order
    return [results_map[ip] for ip in ip_list]


@app.route("/", methods=["GET"])
def index():
    """Render initial clean scanner interface."""
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan_form():
    """Fallback standard POST handler for non-JavaScript browsers."""
    input_mode = request.form.get("input_mode", "range")
    start_ip = request.form.get("start_ip", "")
    end_ip = request.form.get("end_ip", "")
    cidr = request.form.get("cidr", "")

    ip_list, error, target_range = validate_and_generate_ips(input_mode, start_ip, end_ip, cidr)

    if error:
        return render_template(
            "index.html",
            error=error,
            input_mode=input_mode,
            start_ip=start_ip,
            end_ip=end_ip,
            cidr=cidr
        )

    results = execute_scan(ip_list)
    summary = compute_summary(target_range, results)

    return render_template(
        "index.html",
        results=results,
        summary=summary,
        input_mode=input_mode,
        start_ip=start_ip,
        end_ip=end_ip,
        cidr=cidr,
        status_message="Scan completed."
    )


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """AJAX JSON scan endpoint."""
    data = request.get_json(force=True, silent=True) or {}
    input_mode = data.get("input_mode", "range")
    start_ip = data.get("start_ip", "")
    end_ip = data.get("end_ip", "")
    cidr = data.get("cidr", "")

    ip_list, error, target_range = validate_and_generate_ips(input_mode, start_ip, end_ip, cidr)

    if error:
        return jsonify({"success": False, "error": error}), 400

    results = execute_scan(ip_list)
    summary = compute_summary(target_range, results)

    return jsonify({
        "success": True,
        "target_range": target_range,
        "results": results,
        "summary": summary
    })


@app.route("/api/scan/stream", methods=["GET"])
def api_scan_stream():
    """
    Server-Sent Events (SSE) endpoint providing real-time scanning progress updates.
    Yields events: 'progress' per host and 'complete' with final summary.
    """
    input_mode = request.args.get("input_mode", "range")
    start_ip = request.args.get("start_ip", "")
    end_ip = request.args.get("end_ip", "")
    cidr = request.args.get("cidr", "")

    ip_list, error, target_range = validate_and_generate_ips(input_mode, start_ip, end_ip, cidr)

    if error:
        def error_gen():
            yield f"event: error\ndata: {json.dumps({'error': error})}\n\n"
        return Response(error_gen(), mimetype="text/event-stream")

    def sse_generator():
        total = len(ip_list)
        results = []
        completed_count = 0

        # Run concurrent probes while streaming results as they finish
        with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, total or 1)) as executor:
            future_to_ip = {executor.submit(ping_host, ip): ip for ip in ip_list}
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    res = future.result()
                except Exception:
                    res = {
                        "ip": ip,
                        "status": "ERROR",
                        "latency": None,
                        "note": "Probe execution failed"
                    }
                results.append(res)
                completed_count += 1

                progress_data = {
                    "completed": completed_count,
                    "total": total,
                    "target_range": target_range,
                    "result": res
                }
                yield f"event: progress\ndata: {json.dumps(progress_data)}\n\n"

        summary = compute_summary(target_range, results)
        complete_data = {
            "summary": summary,
            "target_range": target_range
        }
        yield f"event: complete\ndata: {json.dumps(complete_data)}\n\n"

    response = Response(stream_with_context(sse_generator()), mimetype="text/event-stream")
    response.headers["Cache-Control"] = "no-cache"
    response.headers["X-Accel-Buffering"] = "no"
    return response


if __name__ == "__main__":
    # Local educational server
    print("=" * 60)
    print(" Network Security IP Range Scanner")
    print(" Educational and Authorized Testing Only")
    print(" Running at: http://127.0.0.1:5000")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=False)
