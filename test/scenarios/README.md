# Attack scenarios

Five pods that exercise the trigger ruleset end to end, one per detection class
the shipped rules cover.

**These are simulations, not malware.** Every payload here is inert:

- No real malicious binary is downloaded or executed. Miners are `sleep`
  renamed; the "C2" addresses are IETF documentation ranges (192.0.2.0/24,
  198.51.100.0/24, 203.0.113.0/24) and `example` domains that route nowhere.
- Nothing writes outside the pod's own filesystem, and nothing persists.
- The container-escape scenario deliberately runs **unprivileged**, so the
  escape fails. What matters is that the `execve` happens and the capture
  fires - a real escape attempt would produce the identical trigger.

The point is to prove the pipeline works: a rule matches, memory is acquired
before the pod dies, the bundle seals and verifies, and the resulting evidence
contains recoverable indicators.

## Running them

```bash
kubectl apply -f test/scenarios/namespace.yaml
kubectl apply -f test/scenarios/           # or one at a time

# Watch the recorder react
kubectl -n flight-recorder logs -l app.kubernetes.io/name=flight-recorder -f | grep -E "trigger matched|evidence sealed"

# On the node that captured it
sudo flight-recorder verify --all --root /var/lib/flight-recorder/evidence --key /etc/flight-recorder/key.pem
```

Each pod runs `restartPolicy: Never` and exits within a few seconds - that is
the point. The `fileless` and `ephemeral` scenarios exit almost immediately and
are the real test of the capture window.

## Expected outcome

| Scenario | Rule | Recoverable indicator in the dump |
|---|---|---|
| `fileless.yaml` | `curl_pipe_sh` | Stage-2 URL held in the shell's memory |
| `reverse_shell.yaml` | `reverse_shell` | C2 address and port in the shell's heap |
| `cryptominer.yaml` | `crypto_miner` | Pool URL and wallet string in the process image |
| `dns_exfil.yaml` | `dns_exfil` | Encoded hostname in the resolver buffer |
| `container_breakout.yaml` | `container_breakout` | Mount target and `nsenter` argv |

Cleanup:

```bash
kubectl delete -f test/scenarios/ --ignore-not-found
```
