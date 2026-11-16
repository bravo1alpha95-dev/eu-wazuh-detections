# EmpowerU Wazuh Docker lab

Compose file and helper scripts for a manager + agent lab (Wazuh 4.14.10). Used to confirm file-integrity rules 100020 and 100021 on a real syscheck event. Optional extras:

- `docker-compose.dashboard.yml` + `dashboard/dashboard.sh`: opt-in Wazuh indexer and dashboard with generated TLS certs and random passwords (never printed; stored in `dashboard/.generated/credentials.env`, mode 600), and the starter-dashboard import. Needs about 4 GB of free RAM.
- `simulate/`: dry-run-by-default attack simulation against the lab agent container only. See [../docs/ATTACK-SIMULATION.md](../docs/ATTACK-SIMULATION.md).

Full beginner-friendly instructions, including teardown and a section on a real single-node server: [../docs/SETUP-WAZUH-LAB.md](../docs/SETUP-WAZUH-LAB.md).

```bash
cd lab
docker compose up -d          # add sudo if your user is not in the docker group
# wait until: docker exec wazuh-lab-manager /var/ossec/bin/agent_control -l
# shows wazuh-lab-agent as Active
./fim-test.sh
docker compose down           # stop; keep volumes
docker compose down -v        # also wipe lab data

# optional
./dashboard/dashboard.sh plan && CONFIRM=yes ./dashboard/dashboard.sh up && CONFIRM=yes ./dashboard/dashboard.sh import
./simulate/run-all.sh                 # dry run
CONFIRM=yes ./simulate/run-all.sh     # fire the rules and report
```

This is a lab. Enrollment has no password. Do not publish ports 1514, 1515, or 55000 to the internet.
