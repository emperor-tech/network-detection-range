.PHONY: configure lab baseline clean test destroy collect

configure:
	bash scripts/render-config.sh

lab: configure
	containerlab deploy --topo topology.clab.yml

baseline: configure
	docker exec clab-soc-a3-d2-gateway nft -f /etc/nftables.conf

destroy:
	containerlab destroy --topo topology.clab.yml --cleanup

clean: destroy
	rm -rf pcaps/*.pcap test-results.xml .pytest_cache

collect:
	bash scripts/collect-state.sh

test: configure
	pytest tests/ --junitxml=test-results.xml
