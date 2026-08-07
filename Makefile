.PHONY: lab clean test destroy collect baseline

lab:
	containerlab deploy --topo topology.clab.yml

baseline:
	docker exec clab-soc-a3-d2-gateway nft -f /etc/nftables.conf

destroy:
	containerlab destroy --topo topology.clab.yml --cleanup

clean: destroy
	rm -rf pcaps/*.pcap test-results.xml .pytest_cache

collect:
	bash scripts/collect-state.sh

test:
	pytest tests/ --junitxml=test-results.xml
