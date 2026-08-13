#!/bin/sh
# Minimal stub web listener standing in for the public-facing DMZ relay.
nohup sh -c 'while true; do nc -l -p 443; done' >/tmp/svc-443.log 2>&1 &
