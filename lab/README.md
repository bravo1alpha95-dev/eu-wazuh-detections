# EmpowerU Wazuh Docker lab

Compose file and helper script for a manager + agent lab (Wazuh 4.14.10, no indexer or dashboard). Used to confirm file-integrity rules 100020 and 100021 on a real syscheck event.

Full beginner-friendly instructions, including teardown and a section on a real single-node server: [../docs/SETUP-WAZUH-LAB.md](../docs/SETUP-WAZUH-LAB.md).

```bash
cd lab
docker compose up -d          # add sudo if your user is not in the docker group
# wait until: docker exec wazuh-lab-manager /var/ossec/bin/agent_control -l
# shows wazuh-lab-agent as Active
./fim-test.sh
docker compose down           # stop; keep volumes
docker compose down -v        # also wipe lab data
```

This is a lab. Enrollment has no password. Do not publish ports 1514, 1515, or 55000 to the internet.
