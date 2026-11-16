# Wazuh version matrix — wazuh-logtest

GitHub Actions loads the rule pack into several official `wazuh/wazuh-manager` images and runs every synthetic sample in [tests/samples/](../tests/samples/) through `wazuh-logtest`. Each sample must produce the rule IDs listed in [tests/logtest/expected.tsv](../tests/logtest/expected.tsv), and must not produce the IDs in its "must NOT" column. The job is `logtest` in [.github/workflows/ci.yml](../.github/workflows/ci.yml); the runner is [tests/logtest/run-logtest.sh](../tests/logtest/run-logtest.sh).

Run one version locally (needs Docker; starts one throwaway container and removes it):

```bash
EU_WAZUH_VERSION=4.12.0 tests/logtest/run-logtest.sh
```

## Results

Local run on 2026-11-14 (America/New_York). Every tag below exists on Docker Hub and was pulled that day. "14/14" means all 14 checks in `expected.tsv` passed, covering:

- 100002, through all five listener samples
- 100010 and 100011, the PAM burst followed by a success
- 100012
- 100013, which also must not fire for a non-root user
- 100016 and 100017, for both the invalid-user burst and the failed-password burst
- 100018
- the 5503 / 5710 / 5760 parents
- a 5503 PAM failure, which must NOT fire 100012

| Manager image | VERSION.json | Rules enabled | Result |
|---|---|---|---|
| `wazuh/wazuh-manager:4.14.10` | 4.14.10 rc2 `6e7835b` | 8466 | **14/14 pass** |
| `wazuh/wazuh-manager:4.14.0` | 4.14.0 rc2 `3438573` | 7079 | **14/14 pass** |
| `wazuh/wazuh-manager:4.13.1` | 4.13.1 rc1 `829cac5` | 7079 | **14/14 pass** |
| `wazuh/wazuh-manager:4.12.0` | 4.12.0 rc1 `802b10f` | 7026 | **14/14 pass** |
| `wazuh/wazuh-manager:4.10.1` | (no VERSION.json in image) | 7023 | **14/14 pass** |
| `wazuh/wazuh-manager:4.8.2` | (no VERSION.json in image) | 6798 | **14/14 pass** |

No version failed because of rule syntax or parent SIDs. The parents the pack relies on (530, 5501, 5503, 5551, 5710, 5712, 5715, 5760, 5763) behave the same on all six images.

A negative control confirms the job can fail. With 100013's parent changed from 5715 to 5716 in a scratch copy, the 4.14.10 run reported `FAIL 100013-ssh-root-success.log -> 100018 (missing 100013)` and exited 1.

## Not covered by the matrix

- **FIM rules 100020 and 100021.** `wazuh-logtest` does not invoke the FIM plugin decoder, so these load but cannot fire here. They were verified on a live 4.14.10 manager and agent; see [SETUP-WAZUH-LAB.md](SETUP-WAZUH-LAB.md).
- **Wazuh 5.x**, and 4.x releases not listed above.
- **The optional collector JSON decoder.** It is not exercised; the rules do not depend on it.

## Two things the matrix uncovered (images, not rules)

These are about the official Docker images. They matter if you run older managers in containers.

1. **`TZ` does not move `<time>` rules on images before 4.14.10.** wazuh-analysisd runs chrooted in `/var/ossec` and uses `/var/ossec/etc/localtime`, which the images ship as UTC.
   - On 4.12.0, 4.13.1 and 4.14.0, starting the container with `-e TZ=<zone>` left 100012 and 100018 on UTC. The PAM and SSH successes produced only 5501 and 5715.
   - On 4.12.0 this was confirmed live as well as through logtest. With `TZ` set, a live event at 02:30 local time still gave 5501. Without `TZ`, and with the zone file copied to `/var/ossec/etc/localtime`, it gave 100012.
   - 4.14.10 honors `TZ`.
   - If you run an older manager image, set the zone by copying it to `/var/ossec/etc/localtime` (for example through `/wazuh-config-mount/etc/localtime`), not with `TZ`. Then check one off-hours event.
2. **On 4.10.1, bind-mounting a file straight into `/var/ossec/etc/rules/` prevents start-up.** The image's init sees `/var/ossec/etc` as "already mounted" and skips installing it. `ossec.conf` is then missing and analysisd never starts.
   - The runner mounts files under `/wazuh-config-mount/etc/...` instead. That is the images' documented hook, and `/init` copies it over `/var/ossec/`. It works on every version above.
   - The lab's `lab/docker-compose.yml` mounts rules directly. That is fine for the 4.14.10 image it pins.
