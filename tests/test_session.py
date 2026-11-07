from pcappeek.session import FlowTable, flow_key


def test_flow_key_merges_both_directions():
    forward = flow_key("10.0.0.1", "10.0.0.2", 50000, 80, 6)
    backward = flow_key("10.0.0.2", "10.0.0.1", 80, 50000, 6)

    assert forward == backward


def test_table_accumulates_packets_and_bytes():
    key = flow_key("10.0.0.1", "10.0.0.2", 50000, 80, 6)
    table = FlowTable()

    table.add(key, nbytes=100)
    table.add(key, nbytes=50)

    flows = table.flows()
    assert len(flows) == 1
    assert flows[0].packets == 2
    assert flows[0].total_bytes == 150