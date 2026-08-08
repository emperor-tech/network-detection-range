from conftest import assert_traffic_hits_rule


def test_net04_finance_can_reach_payroll_app():
    """NET-04: finance -> servers, tcp/443 (payroll app). Expected: allow."""
    assert_traffic_hits_rule(
        source_container="clab-soc-a3-d2-finance",
        dest_ip="10.61.50.10",
        dest_port=443,
        protocol="tcp",
        rule_identifier="finance-to-payroll",
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
