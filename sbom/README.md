# sbom/

---

## What this folder is, in plain words

`ml-bom.cdx.json` is the **ingredient list of the AI assistant**.

A food label tells you what is inside the box. This file does the same for
Inno, the banking assistant: which AI models it calls, and which documents it
reads from to answer questions. Each ingredient carries enough identity (exact
model ID, a fingerprint of the documents) that, after an incident, someone can
answer "what exactly was running?" without guessing.

Key facts:

- **Format:** CycloneDX 1.6, an industry standard for these lists. "ML-BOM"
  means Machine Learning Bill of Materials. Using a standard means security
  tools and auditors can read it without knowing anything about this repo.
- **It is generated, never hand-edited.** `make gate` writes it, but only after
  the supply chain checks pass (pinned model IDs, no unpinned models in the
  code, no dangerous pickle files). So a fresh BOM is also proof the gate passed.
- **Why it is a separate README and not comments in the JSON:** JSON does not
  allow comments, and any edit to the file would be overwritten on the next
  `make gate`. This page explains it instead.
- **Why it is committed:** the ingredient entries and the serial number are
  computed only from the inputs, so a change to them in a diff means a real
  change to what the assistant is made of. That makes it easy to review.
  (The timestamp can still move on each run, see below.)

---

## Walk-through of the file

### Header

| Field | Value here | Why it is there |
|---|---|---|
| `bomFormat`, `specVersion` | `CycloneDX`, `1.6` | Tells any reader which standard and version to parse it with. Version 1.6 is the one that supports the `machine-learning-model` type. |
| `serialNumber` | `urn:uuid:...` | Unique ID for this BOM. It is derived from a hash of the components, not random, so it only changes when the ingredients change. |
| `version` | `1` | Revision counter defined by the standard. Kept at 1 because the serial number already changes with the content. |

### `metadata`

| Field | Why it is there |
|---|---|
| `timestamp` | When the BOM was made. If the `SOURCE_DATE_EPOCH` environment variable is set, that fixed date is used instead of the current time, so rebuilding the same content does not create a noisy diff just because the clock moved. Without it, the current time is used. |
| `component` | The thing being described: the `innovabank` application. Its `bom-ref` (`app:innovabank`) is the anchor the dependency graph below points from. |
| `tools` | What produced the BOM (`ib_supplychain`, the repo's own gate in `supplychain/`). Lets a reader trace the file back to the code that wrote it. |

### `components` (the ingredients)

Each entry has a `bom-ref`, a short internal ID used to link entries together.

**1. `model:agent-llm`, Amazon Nova Lite (`amazon.nova-lite-v1:0`)**
The model that does the reasoning and decides which tools to call. This is the
"brain" every attack in the catalog tries to manipulate.
- `supplier` and `licenses`: who made it and under what terms. AWS-hosted
  models fall under the AWS Service Terms.
- `inference_profile` (`us.amazon.nova-lite-v1:0`): the cross-region ID the
  code actually calls. Recorded separately because it is not the same string
  as the model ID, and both are needed to match logs to this entry.
- `hosting: managed`: AWS runs the model. There are no weights in this repo to
  scan, so trust rests on pinning the exact model ID instead.

**2. `model:kb-embeddings`, Amazon Titan Text Embeddings v2 (`amazon.titan-embed-text-v2:0`)**
Turns knowledge base documents and questions into numbers so the assistant can
find relevant passages. Listed because swapping it silently would change what
the assistant retrieves, and so what it says.

**3. `dataset:knowledge-base-corpus`**
The public documents the assistant searches (`corpus/kb/public`, 5 files).
- `hashes` (SHA-256): one fingerprint over every file name and its contents.
  If any document is added, removed, or altered, this value changes. That
  matters because poisoned documents are a real attack path (indirect prompt
  injection), so you want to know exactly which corpus was live.
- `documents`: the file count, a quick sanity check next to the hash.

The `innovabank:*` entries under `properties` are this project's own extra
labels. The standard allows custom properties, and the prefix keeps them from
clashing with anyone else's.

If self-hosted model files (for example Hugging Face weights) were ever added
to `supplychain/model-lock.yaml`, they would show up here too, with a version,
a SHA-256 hash, and the number of scan findings. There are none today.

### `dependencies`

States that `app:innovabank` depends on all three components. This is the
link that lets a scanner answer "which apps are affected?" if one of these
models or the corpus is later found to be compromised.

---

## How to update it

Do not edit the JSON by hand. Change the source instead, then regenerate:

1. Edit `supplychain/model-lock.yaml` (models, artifacts, datasets) or the
   files under `corpus/kb/public`.
2. Run `make gate`. It re-checks everything and rewrites `ml-bom.cdx.json`.
3. Review the diff. CI also runs the gate and uploads the BOM as a build
   artifact named `ml-bom`.
