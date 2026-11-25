# Adapters

**Preview.** The `prego adapter` commands and flags can still change in a 1.x minor release.

AI model adapters are the fine-tuned layers (LoRA and the other peft methods) of your AI models. Prego keeps each
adapter as one checked OCI artifact: `adapter_config.json`, one `.safetensors` file and at most 8 text files.
Pickle files are refused. Your machines and your customers load adapters with their own identity.

**Plans:** Trial and Publisher can publish. Indie and Org do not include Adapters. Consumer reads through grants.

## Start

- [Adapters quickstart](quickstart.md): the console setup, push, load with peft or vLLM, CI, and the errors.
- [Adapters](../../README.md#adapters) in the root README.
- Full docs: <https://docs.prego.k8skill.com/adapters> (sign in with your Prego account).

## Examples

The [Adapters quickstart](quickstart.md#4-in-ci) has a CI job.
