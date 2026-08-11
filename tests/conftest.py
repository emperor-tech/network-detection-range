import re
import subprocess
import time
import json
import os

GATEWAY = "clab-soc-a3-d2-gateway"


def run_in(container, cmd, timeout=10):
    """Run a shell command inside a running container via `docker exec`."""
    return subprocess.run(
        ["docker", "exec", container] + cmd,
        capture_output=True, text=True, timeout=timeout,
    )


def get_rule_counter(rule_identifier):
    """
    Read the current packet counter for one nftables rule on the gateway.
    `rule_identifier` is any unique substring that appears on that rule's
    line — either its `comment` (e.g. "finance-to-payroll") or its log
    prefix (e.g. "NF_SEGMENT_DENY").
    """
    result = run_in(GATEWAY, ["nft", "list", "table", "inet", "segmentation"])
    for line in result.stdout.splitlines():
        if rule_identifier in line:
            match = re.search(r"packets (\d+) bytes (\d+)", line)
            if match:
                return int(match.group(1))
    raise ValueError(f"No rule line found containing '{rule_identifier}'")


def assert_traffic_hits_rule(source_container, dest_ip, dest_port, protocol, rule_identifier):
    """
    Send one connection attempt from source_container to dest_ip:dest_port,
    then confirm the gateway's counter for rule_identifier increased.
    This proves which exact rule handled the flow, whether it accepted or
    dropped it -- not just "did the app work."
    """
    before = get_rule_counter(rule_identifier)

    if protocol == "tcp":
        run_in(source_container, ["nc", "-zv", "-w3", dest_ip, str(dest_port)], timeout=6)
    elif protocol == "udp":
        run_in(source_container, ["nc", "-zvu", "-w3", dest_ip, str(dest_port)], timeout=6)
    else:
        raise ValueError(f"Unsupported protocol: {protocol}")

    time.sleep(0.5)  # give nftables a moment to update the counter
    after = get_rule_counter(rule_identifier)

    assert after > before, (
        f"Expected '{rule_identifier}' packet counter to increase "
        f"(before={before}, after={after}) for "
        f"{source_container} -> {dest_ip}:{dest_port}/{protocol}"
    )

def send_spoofed_packet(source_container, spoofed_source_ip, dest_ip, dest_port, protocol="udp"):
    """Craft one packet with a forged source IP using nping (raw sockets) --
    plain `nc` always sends from the container's real address and can't do this."""
    proto_flag = "--udp" if protocol == "udp" else "--tcp"
    result = run_in(source_container, [
        "hping3", proto_flag, "-p", str(dest_port),
        "--spoof", spoofed_source_ip, "-c", "1", dest_ip,
    ], timeout=8)
    assert result.returncode == 0, (
	f"hping3 failed to run inside {source_container} (exit code {result.returncode}). "
	f"stderr: {result.stderr.strip()}"
    )


def count_suricata_alerts(sid, log_path="pcaps/suricata/eve.json"):
    """Count how many times a given Suricata signature ID has fired,
    by reading the mirrored eve.json evidence file directly."""
    if not os.path.exists(log_path):
        return 0
    count = 0
    with open(log_path) as f:
        for line in f:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") == "alert" and event.get("alert", {}).get("signature_id") == sid:
                count += 1
    return count
