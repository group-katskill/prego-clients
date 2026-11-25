# Upgrade an A2A 0.3 card

`prego a2a upgrade` converts an A2A 0.3 Agent Card to an A2A 1.0 card. It works offline and needs no Prego account.

- [`agent.json`](agent.json) is an A2A 0.3 card.
- [`agent-card.json`](agent-card.json) is the A2A 1.0 card that `prego a2a upgrade` writes from it.

Both files are copies of the shared test vectors (`prego/tests/vectors/a2a/upgrade/full-03/`). The tests of
`prego` check this exact output.

Run it:

```sh
cd artifact-types/a2a/examples/upgrade
prego a2a upgrade agent.json -o /tmp/agent-card.json
diff /tmp/agent-card.json agent-card.json        # no difference
```

With no `-o`, the output goes to `agent-card.json` next to the input. `prego` does not replace a file that exists;
give `--force` to replace it.

`prego` prints each change on stderr, for example:

```text
~ /url -> /supportedInterfaces/0/url
~ /preferredTransport -> /supportedInterfaces/0/protocolBinding
~ /security -> /securityRequirements ...
```

If `prego` cannot map a field with certainty, it stops, writes nothing and names the field as a JSON pointer.

Each interface in the output has `protocolVersion` `"0.3"`: the agent still serves A2A 0.3 at those URLs. Change it
to `"1.0"` when the agent serves A2A 1.0.

**The output is unsigned.** Sign it before you push it to Prego:
`prego a2a push <folder> <ref> --sign <key file> --key <key ref>`.
