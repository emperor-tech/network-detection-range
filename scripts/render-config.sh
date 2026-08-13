#!/usr/bin/env bash
set -euo pipefail
source variant.env

render() {
  sed "s/__OCTET__/${OCTET}/g" "$1.tmpl" > "$1"
}

render topology.clab.yml
render configs/core/frr.conf
render configs/gateway/bootstrap.sh
render configs/gateway/nftables.conf
render detections/rules/suricata.yaml
render tests/conftest.py
render tests/test_segmentation.py

chmod +x configs/gateway/bootstrap.sh
echo "Rendered all files for octet ${OCTET}"
