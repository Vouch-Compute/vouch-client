"""Reference embeddings from the REAL bge-m3 bundle, for the ignored test `real_bge_m3_matches_the_reference`.

Needs the owner's approval before running: it reads the 2.3 GB fp32 weights, which must already be on disk
(downloaded at the pinned commit 5617a9f6, every file checked against the engine catalog's PINNED_FILES). CPU only.

  PYTHONPATH=engine/src python client/crates/pool-runner/tests/fixtures/xlmr-tiny/bge_m3_reference.py <bge-m3 dir> <out.json>

Run it from a checkout that also has the engine sources (engine/src). <bge-m3 dir> holds `onnx/model.onnx`, `onnx/model.onnx_data`, `onnx/tokenizer.json`, ... as in the manifest.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

from make_fixture import TEXTS  # same inputs as the tiny fixture

from engine.registry.catalog import PINNED_FILES
from engine.refworker.gpu import OnnxEmbedder


def main() -> None:
    root, out = Path(sys.argv[1]), Path(sys.argv[2])
    for rel, (sha, size) in PINNED_FILES["bge-m3"].items():
        p = root / rel
        h = hashlib.sha256()
        with p.open("rb") as f:
            for block in iter(lambda: f.read(1 << 24), b""):
                h.update(block)
        if p.stat().st_size != size or h.hexdigest() != sha:
            sys.exit(f"{rel} does not match its pin")
    spec = SimpleNamespace(model_id="bge-m3", repo="BAAI/bge-m3", max_input=8192)
    ref = OnnxEmbedder(spec, str(root), ["CPUExecutionProvider"])
    vecs = ref.embed(TEXTS)
    tokens = ref.tokens(TEXTS)
    out.write_text(json.dumps({"inputs": TEXTS, "tokens": tokens, "embeddings": [[float(x) for x in v] for v in vecs]},
                              ensure_ascii=False), encoding="utf-8")
    print("wrote", out)


if __name__ == "__main__":
    main()
