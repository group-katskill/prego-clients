# Adapters quickstart

From prego 0.10.0 and registry 1.11.1. **Publisher plan** (and Trial).

AI model adapters are the fine-tuned layers of your AI models: the output of LoRA and the other
parameter-efficient methods of [peft](https://huggingface.co/docs/peft). An adapter is small and loads on top
of a base model. Prego keeps your adapters in your private registry. Your machines and your customers load
them with their own identity. The base model stays on Hugging Face or in your own storage.

This guide uses tenant `acme`, namespace `ml` and the adapter `support-bot`.

## 1. In the console (once)

1. The tenant must be on the Publisher plan (or Trial). On Indie and Org, `prego adapter push` stops with
   `403 DENIED` (`plan_limit`).
2. Give the machine that pushes a grant: ecosystem `oci`, package `support-bot` (or a glob), verbs `read` and
   `publish`. Adapters use the same grants as container images.
3. Give the machines that load the adapter a `read` grant. A customer in another tenant gets a cross-tenant
   `read` grant, as for images. On Trial, the adapter stays in your own tenant until you choose a paid plan.

## 2. Push an adapter

Save the adapter with peft. `save_pretrained` writes `adapter_config.json` and `adapter_model.safetensors`:

```python
model.save_pretrained("./out/support-bot")   # a PeftModel after training
```

Then push the folder:

```sh
prego adapter push ./out/support-bot acme/ml/support-bot:2026-11-14 \
  --license LicenseRef-llama3.1 --base-revision 0e9e39f249a16976918f6564b8830bc894c89659
```

- The version (`2026-11-14`) is a tag. **A version is written one time only.** A second push of other
  content to the same version stops with `409` ("An adapter version is written one time only"). Push it
  with a new version. The same push again (the same files) is accepted and changes nothing, so you can run
  it again after a network error.
- `prego` checks the folder before it sends anything, with the rules of the registry:

  | Part | Rule |
  | --- | --- |
  | `adapter_config.json` | At most 64 KiB, a JSON object with `peft_type` and `base_model_name_or_path`. |
  | Weights | Exactly one `.safetensors` file, with a valid header (at most 8 MiB). No other weight format. |
  | Extra files | At most 8, each at most 10 MiB, UTF-8 text only: `README.md`, tokenizer files. |
  | Whole adapter | At most 2 GiB. |

  Prego does not accept pickle files (`.bin`, `.pt`, `.ckpt`). They can run code when they load. Move
  `training_args.bin` and checkpoint folders out of the adapter folder. Names that start with `.` (for
  example `.gitattributes`) are not pushed.
- **License (required).** An SPDX identifier (`Apache-2.0`, `MIT`), or `LicenseRef-<name>` for a model
  license such as the Llama or Gemma license. Without `--license`, `prego` uses the `license:` line of the
  `README.md` front matter (a Hugging Face model card). `license: other` with `license_name: llama3.1` gives
  `LicenseRef-llama3.1`. If you send the adapter to another company, you redistribute a fine-tune of the base
  model: check that the base model license allows it.
- **Base model revision (recommended).** `--base-revision` records the commit of the base model, so a loader
  gets the same base model. Without it, `prego` shows a warning and the console shows the revision as missing.
- The base model name comes from `base_model_name_or_path` in `adapter_config.json`.

`prego` prints `<host>/<name>:<version>@<digest>` on stdout, and the progress on stderr. ORAS can also push
an adapter with the same media types; the registry checks it with the same rules.

## 3. Load an adapter

```sh
prego adapter get acme/ml/support-bot:2026-11-14 ./adapters/support-bot
```

`prego adapter get` writes `adapter_config.json`, the weights and the extra files to a new or empty folder.
It checks the SHA-256 of each file before it gives the file its name. If one check fails, it writes nothing.

With transformers and peft:

```python
from transformers import AutoModelForCausalLM
from peft import PeftModel
base = AutoModelForCausalLM.from_pretrained("meta-llama/Llama-3.1-8B-Instruct")  # from Hugging Face or a local folder
model = PeftModel.from_pretrained(base, "./adapters/support-bot")
```

With vLLM:

```sh
vllm serve meta-llama/Llama-3.1-8B-Instruct --enable-lora --lora-modules support-bot=./adapters/support-bot
```

`oras pull` works too, with `docker-credential-prego` for sign-in.

## 4. In CI

The commands use the machine identity, as the other `prego` commands: GitLab `id_tokens`, GitHub Actions
OIDC, SPIFFE or a workload token file, or `PREGO_API_KEY`. See the [CI guide](ci.md). A training job pushes
with a `publish` grant; a serving job gets with a `read` grant.

```yaml
# GitLab CI: a serving image that loads the adapter at build time
build:
  id_tokens:
    PREGO_ID_TOKEN:
      aud: prego.k8skill.com
  script:
    - prego adapter get acme/ml/support-bot:2026-11-14 ./adapters/support-bot
```

## Errors

| Message | Cause | What to do |
| --- | --- | --- |
| `HTTP 403 DENIED: Org plan does not include Adapters` | The tenant that owns the repository is not on Publisher or Trial. | Change the plan in the console: Settings, Plan. |
| `HTTP 409 DENIED ... An adapter version is written one time only` | The version has other content. | Push with a new version. |
| `HTTP 400 MANIFEST_INVALID: adapter_invalid: ...` | The registry refused the adapter, with the reason. | Correct the file and push again. |
| `the adapter needs a license` | No `--license` and no `license:` in `README.md`. | Give `--license`. |
| `... is a pickle file` | A `.bin`, `.pt` or `.ckpt` file is in the folder. | Move it out of the folder. |
| `the folder ... is not empty` | `prego adapter get` writes to a new or empty folder only. | Give another folder. |
| `HTTP 404 ... NAME_UNKNOWN` | No grant for this repository, or the name is wrong. | Check the grants in the console. |
