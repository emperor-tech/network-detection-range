import time
import pytest
from conftest import (
	assert_traffic_hits_rule,
	get_rule_counter, 
	send_spoofed_packet, 
	count_suricata_alerts, 
	run_in,
)


def test_net03_users_cannot_reach_payroll_db():
    """NET-03: users -> finance, tcp/5432 (payroll db). Expected: deny."""
    assert_traffic_hits_rule(
        source_container="clab-soc-a3-d2-users",
        dest_ip="10.61.20.10",
        dest_port=5432,
        protocol="tcp",
        rule_identifier="NF_SEGMENT_DENY",
    )

def test_net04_finance_can_reach_payroll_app():
    """NET-04: finance -> servers, tcp/443 (payroll app). Expected: allow."""
    assert_traffic_hits_rule(
        source_container="clab-soc-a3-d2-finance",
        dest_ip="10.61.50.10",
        dest_port=443,
        protocol="tcp",
        rule_identifier="finance-to-payroll",
    )

def test_net16_finance_can_reach_payroll_db():
    """NET-16: finance -> servers, tcp/5432 (payroll db). Expected: allow."""
    assert_traffic_hits_rule(
	source_container="clab-soc-a3-d2-finance",
	dest_ip="10.61.50.10",
	dest_port=5432,
	protocol="tcp",
	rule_identifier="finance-to-payroll",
	)


# --- guest / users / engineering / servers -> internet (core) ---

def test_net01_guest_can_reach_internet_dns():
    """NET-01: guest -> internet, udp/53 (DNS). Expected: allow."""
    assert_traffic_hits_rule("clab-soc-a3-d2-guest", "10.61.254.1", 53, "udp", "guest-dns")


def test_net01_guest_can_reach_internet_https():
    """NET-01: guest -> internet, tcp/443 (HTTPS). Expected: allow."""
    assert_traffic_hits_rule("clab-soc-a3-d2-guest", "10.61.254.1", 443, "tcp", "guest-https")


def test_net02_guest_cannot_reach_servers():
    """NET-02: guest -> servers, any. Expected: deny."""
    assert_traffic_hits_rule("clab-soc-a3-d2-guest", "10.61.50.10", 443, "tcp", "NF_SEGMENT_DENY")


def test_net05_engineering_can_reach_codesvc():
    """NET-05: engineering -> servers, tcp/443 (code service). Expected: allow."""
    assert_traffic_hits_rule("clab-soc-a3-d2-engineering", "10.61.50.10", 443, "tcp", "engineering-to-codesvc")


def test_net06_engineering_cannot_reach_payroll_db():
    """NET-06: engineering -> servers, tcp/5432 (payroll db). Expected: deny."""
    assert_traffic_hits_rule("clab-soc-a3-d2-engineering", "10.61.50.10", 5432, "tcp", "NF_SEGMENT_DENY")


def test_net09_internet_can_reach_dmz_web():
    """NET-09: internet -> dmz, tcp/443. Expected: allow."""
    assert_traffic_hits_rule("clab-soc-a3-d2-core", "10.61.60.10", 443, "tcp", "internet-to-dmz-web")


def test_net10_internet_cannot_reach_servers():
    """NET-10: internet -> servers, any. Expected: deny."""
    assert_traffic_hits_rule("clab-soc-a3-d2-core", "10.61.50.10", 443, "tcp", "NF_SEGMENT_DENY")


def test_net11_dmz_can_reach_assigned_db_port():
    """NET-11: dmz -> servers, tcp/5432 (assigned db port). Expected: allow."""
    assert_traffic_hits_rule("clab-soc-a3-d2-dmz", "10.61.50.10", 5432, "tcp", "dmz-to-db")


def test_net12_dmz_cannot_reach_management():
    """NET-12: dmz -> management, any. Expected: deny."""
    assert_traffic_hits_rule("clab-soc-a3-d2-dmz", "10.61.10.10", 22, "tcp", "NF_SEGMENT_DENY")


def test_net13_users_can_reach_internet_dns():
    """NET-13: users -> internet, udp/53. Expected: allow."""
    assert_traffic_hits_rule("clab-soc-a3-d2-users", "10.61.254.1", 53, "udp", "users-dns")


def test_net14_users_cannot_reach_internet_http():
    """NET-14: users -> internet, tcp/80. Expected: deny."""
    assert_traffic_hits_rule("clab-soc-a3-d2-users", "10.61.254.1", 80, "tcp", "NF_SEGMENT_DENY")


def test_net15_users_can_reach_internet_https():
    """NET-15: users -> internet, tcp/443. Expected: allow."""
    assert_traffic_hits_rule("clab-soc-a3-d2-users", "10.61.254.1", 443, "tcp", "users-https")


def test_net17_finance_cannot_reach_engineering():
    """NET-17: finance -> engineering, any. Expected: deny."""
    assert_traffic_hits_rule("clab-soc-a3-d2-finance", "10.61.30.10", 443, "tcp", "NF_SEGMENT_DENY")


def test_net18_engineering_can_reach_pkg_repo():
    """NET-18: engineering -> internet, tcp/443 (package repo). Expected: allow."""
    assert_traffic_hits_rule("clab-soc-a3-d2-engineering", "10.61.254.1", 443, "tcp", "engineering-pkg-repo")


def test_net19_engineering_cannot_reach_internet_ssh():
    """NET-19: engineering -> internet, tcp/22. Expected: deny."""
    assert_traffic_hits_rule("clab-soc-a3-d2-engineering", "10.61.254.1", 22, "tcp", "NF_SEGMENT_DENY")


def test_net20_servers_can_reach_updates():
    """NET-20: servers -> internet, tcp/443 (software updates). Expected: allow."""
    assert_traffic_hits_rule("clab-soc-a3-d2-servers", "10.61.254.1", 443, "tcp", "servers-updates")


def test_net21_servers_cannot_initiate_to_users():
    """NET-21: servers -> users, new session. Expected: deny."""
    assert_traffic_hits_rule("clab-soc-a3-d2-servers", "10.61.40.10", 443, "tcp", "NF_SEGMENT_DENY")


def test_net22_management_can_reach_finance():
    """NET-22: management -> finance, tcp/22 (admin). Expected: allow."""
    assert_traffic_hits_rule("clab-soc-a3-d2-management", "10.61.20.10", 22, "tcp", "mgmt-admin-finance")


def test_net23_management_cannot_reach_guest():
    """NET-23: management -> guest, tcp/22 (admin). Expected: deny."""
    assert_traffic_hits_rule("clab-soc-a3-d2-management", "10.61.70.10", 22, "tcp", "NF_SEGMENT_DENY")


def test_net24_dmz_cannot_reach_nonassigned_db_port():
    """NET-24: dmz -> servers, tcp/3306 (nonassigned port). Expected: deny."""
    assert_traffic_hits_rule("clab-soc-a3-d2-dmz", "10.61.50.10", 3306, "tcp", "NF_SEGMENT_DENY")


def test_net25_dmz_cannot_reach_internet():
    """NET-25: dmz -> internet, any. Expected: deny."""
    assert_traffic_hits_rule("clab-soc-a3-d2-dmz", "10.61.254.1", 443, "tcp", "NF_SEGMENT_DENY")


def test_net26_internet_cannot_reach_dmz_http():
    """NET-26: internet -> dmz, tcp/80. Expected: deny."""
    assert_traffic_hits_rule("clab-soc-a3-d2-core", "10.61.60.10", 80, "tcp", "NF_SEGMENT_DENY")


def test_net27_internet_cannot_reach_dmz_ssh():
    """NET-27: internet -> dmz, tcp/22. Expected: deny."""
    assert_traffic_hits_rule("clab-soc-a3-d2-core", "10.61.60.10", 22, "tcp", "NF_SEGMENT_DENY")


def test_net29_established_return_traffic_allowed():
    """NET-29: users -> servers, established return traffic. Expected: allow.
    Uses the users-to-staff-portal flow (D-001): the SYN hits that accept rule,
    the server's RST reply (nothing is listening yet) travels back and must hit
    the stateful-return rule, not get dropped."""
    assert_traffic_hits_rule("clab-soc-a3-d2-users", "10.61.50.10", 443, "tcp", "stateful-return")


# --- input chain: traffic addressed to the gateway itself, not through it ---

def test_net07_management_can_reach_gateway_ssh():
    """NET-07: management -> network devices (the gateway itself), tcp/22. Expected: allow."""
    assert_traffic_hits_rule("clab-soc-a3-d2-management", "10.61.10.1", 22, "tcp", "mgmt-to-gateway-ssh")


def test_net08_users_cannot_reach_gateway_ssh():
    """NET-08: users -> network devices (the gateway itself), tcp/22. Expected: deny."""
    assert_traffic_hits_rule("clab-soc-a3-d2-users", "10.61.40.1", 22, "tcp", "NF_INPUT_DENY")




def test_net28_guest_spoofed_source_detected():
    """NET-28: guest forges a management-range source IP toward management, DNS/udp 53.
    Expected: both the firewall drop AND a Suricata alert fire."""
    before_fw = get_rule_counter("NF_SPOOF_GUEST")
    before_alert = count_suricata_alerts(1000001)

    send_spoofed_packet("clab-soc-a3-d2-guest", "10.61.10.99", "10.61.10.10", 53, protocol="udp")
    time.sleep(2)  # give Suricata a moment to process and flush eve.json

    after_fw = get_rule_counter("NF_SPOOF_GUEST")
    after_alert = count_suricata_alerts(1000001)

    assert after_fw > before_fw, "Expected NF_SPOOF_GUEST counter to increase"
    assert after_alert > before_alert, "Expected a Suricata alert (sid 1000001) to fire"


def test_net30_sensor_has_no_routable_address():
    """NET-30: sensor must never be able to initiate traffic into protected zones.
    Structural test: the sensor's mirror interface has no IPv4 address assigned at
    all, so it's incapable of sending routed traffic -- stronger than a firewall
    rule, since there's no address for return traffic to even target."""
    result = run_in("clab-soc-a3-d2-sensor", ["ip", "-4", "addr", "show", "eth1"])
    assert "inet " not in result.stdout, (
        "Sensor's eth1 unexpectedly has an IPv4 address assigned - this would "
        "let it participate in routed traffic, breaking the passive-only "
        "guarantee the brief requires."
    )

@pytest.mark.xfail(reason="D1 fault has been repaired; this test's target rule no longer exists by design")
def test_d1_finance_established_return_blocked():
    """FAULT D1 evidence: finance's established/related return traffic should
    now hit the injected drop rule instead of the general stateful-return rule.
    Uses the already-allowed finance-to-payroll path: the SYN gets through and
    the server (nothing listening) replies with a TCP RST -- that RST is the
    'established' reply traffic this fault targets."""
    before = get_rule_counter("FAULT-D1-finance-return-broken")
    run_in("clab-soc-a3-d2-finance", ["nc", "-zv", "-w3", "10.61.50.10", "443"], timeout=6)
    time.sleep(0.5)
    after = get_rule_counter("FAULT-D1-finance-return-broken")
    assert after > before, (
        "Expected finance's return traffic to be caught by the injected fault "
        "rule, but the counter didn't move -- the fault may not be working as intended."
    )

def test_fault2_users_should_not_reach_finance_admin():
    """FAULT 2 evidence: users (untrusted) should NEVER be able to reach
    finance's admin SSH path -- only management is the declared source.
    If this passes while the fault is present, that PROVES the vulnerability:
    an unauthorized zone is matching the broadened admin rule."""
    before = get_rule_counter("FAULT-2-mgmt-ingress-broadened")
    run_in("clab-soc-a3-d2-users", ["nc", "-zv", "-w3", "10.61.20.10", "22"], timeout=6)
    time.sleep(0.5)
    after = get_rule_counter("FAULT-2-mgmt-ingress-broadened")
    assert after > before, (
        "Expected users' traffic to hit the broadened admin rule, proving "
        "the fault is live. If this fails, the fault may not be injected correctly."
    )
