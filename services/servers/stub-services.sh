#!/bin/sh
# Minimal stub listeners standing in for payroll app, payroll db, code
# service, and staff portal -- all logically hosted here, differentiated
# by SOURCE zone via firewall policy, not by separate destination ports.
nohup sh -c 'while true; do nc -l -p 443; done' >/tmp/svc-443.log 2>&1 &
nohup sh -c 'while true; do nc -l -p 5432; done' >/tmp/svc-5432.log 2>&1 &
