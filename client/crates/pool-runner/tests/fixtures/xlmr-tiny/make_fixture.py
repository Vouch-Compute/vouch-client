"""Regenerate the tiny XLM-R stand-in used by `tests/onnx_xlmr.rs` and the tokenizer unit tests.

What it writes (next to this script):
  onnx/tokenizer.json         bge-m3's tokenizer pipeline (Precompiled + Replace normalizer, Metaspace, Unigram,
                              <s> ... </s> template) with the vocabulary cut to its first 3,000 pieces plus <mask>
  onnx/tokenizer_config.json  model_max_length 16, so truncation is exercised
  onnx/model.onnx             a tiny opset-11 graph with bge-m3's signature: inputs input_ids + attention_mask,
                              outputs token_embeddings [b, l, 16] then sentence_embedding [b, 16]; every token's
                              output depends on the masked mean of the sequence, so padding errors change the CLS row
  onnx/model.onnx_data        the graph's weights as external data (all initializers), like bge-m3's fp32 export
  expected.json               inputs, token ids and the reference embeddings
  real_tokenizer_ids.json     token ids of the same inputs from the real bge-m3 tokenizer.json (truncation 8192)

The reference embeddings come from the engine reference worker's own `OnnxEmbedder` (engine/src/engine/refworker/
gpu.py: tokenizers + ONNX Runtime, first output, CLS pooling, L2 normalisation) on the CPU provider.

Usage (monorepo root; needs numpy, onnx, onnxruntime, tokenizers and the engine sources; no GPU, no weights):
  PYTHONPATH=engine/src python client/crates/pool-runner/tests/fixtures/xlmr-tiny/make_fixture.py \
      <dir with bge-m3's onnx/tokenizer.json at commit 5617a9f6>
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import onnx
from onnx import TensorProto, helper, numpy_helper

HERE = Path(__file__).resolve().parent
REAL_TOKENIZER_SHA256 = "6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790"
VOCAB = 3000
HIDDEN = 16
MAX_LEN = 16

TEXTS = [
    "",
    "Hello world",
    "The contributor's computer runs this embedding job only after the signed bundle verified.",
    "Merhaba dünya, bugün hava çok güzel. İstanbul'da ışıklar yanıyor.",
    "مرحبا بالعالم، هذا اختبار للتضمين",
    "你好，世界。这是一个测试。",
    "Привет, мир! Это проверка.",
    "spaces   collapse    here",
    "Ｆｕｌｌ-width ｌｅｔｔｅｒｓ and ﬁ ligatures",
    "emoji 🙂🚀 and numbers 12345",
    "naïve café résumé",
    "a",
]


def tiny_tokenizer(real: dict) -> dict:
    tok = json.loads(json.dumps(real))
    vocab = tok["model"]["vocab"][:VOCAB] + [["<mask>", 0.0]]
    tok["model"]["vocab"] = vocab
    for t in tok["added_tokens"]:
        if t["content"] == "<mask>":
            t["id"] = VOCAB
    return tok


def tiny_graph(rng: np.random.Generator) -> onnx.ModelProto:
    vocab = VOCAB + 1
    emb = numpy_helper.from_array(rng.standard_normal((vocab, HIDDEN)).astype(np.float32), "embeddings.weight")
    w = numpy_helper.from_array((rng.standard_normal((HIDDEN, HIDDEN)) / 4).astype(np.float32), "dense.weight")
    b = numpy_helper.from_array(rng.standard_normal((HIDDEN,)).astype(np.float32) / 10, "dense.bias")
    nodes = [
        helper.make_node("Gather", ["embeddings.weight", "input_ids"], ["x"]),
        helper.make_node("Cast", ["attention_mask"], ["mf"], to=TensorProto.FLOAT),
        helper.make_node("Unsqueeze", ["mf"], ["m3"], axes=[2]),
        helper.make_node("Mul", ["x", "m3"], ["xm"]),
        helper.make_node("ReduceSum", ["xm"], ["s"], axes=[1], keepdims=1),
        helper.make_node("ReduceSum", ["m3"], ["c"], axes=[1], keepdims=1),
        helper.make_node("Div", ["s", "c"], ["mean"]),
        helper.make_node("MatMul", ["x", "dense.weight"], ["xw"]),
        helper.make_node("Add", ["xw", "dense.bias"], ["xwb"]),
        helper.make_node("Add", ["xwb", "mean"], ["pre"]),
        helper.make_node("Tanh", ["pre"], ["token_embeddings"]),
        # a second output that is NOT what the reference pools (it takes the first output): the masked mean
        helper.make_node("ReduceSum", ["mean"], ["sentence_embedding"], axes=[1], keepdims=0),
    ]
    graph = helper.make_graph(
        nodes, "xlmr_tiny",
        [helper.make_tensor_value_info("input_ids", TensorProto.INT64, ["batch_size", "sequence_length"]),
         helper.make_tensor_value_info("attention_mask", TensorProto.INT64, ["batch_size", "sequence_length"])],
        [helper.make_tensor_value_info("token_embeddings", TensorProto.FLOAT, ["batch_size", "sequence_length", HIDDEN]),
         helper.make_tensor_value_info("sentence_embedding", TensorProto.FLOAT, ["batch_size", HIDDEN])],
        [emb, w, b],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 11)], producer_name="xlmr-tiny-fixture")
    model.ir_version = 7
    onnx.checker.check_model(model)
    return model


def main() -> None:
    real_dir = Path(sys.argv[1])
    real_path = real_dir / "onnx" / "tokenizer.json" if (real_dir / "onnx").is_dir() else real_dir / "tokenizer.json"
    raw = real_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != REAL_TOKENIZER_SHA256:
        sys.exit("tokenizer.json is not bge-m3's pinned file")
    out = HERE / "onnx"
    out.mkdir(exist_ok=True)

    (out / "tokenizer.json").write_text(json.dumps(tiny_tokenizer(json.loads(raw)), ensure_ascii=False), encoding="utf-8")
    (out / "tokenizer_config.json").write_text(
        json.dumps({"model_max_length": MAX_LEN, "pad_token": "<pad>", "tokenizer_class": "XLMRobertaTokenizer"}),
        encoding="utf-8")
    model = tiny_graph(np.random.default_rng(20261122))
    for f in ("model.onnx", "model.onnx_data"):
        (out / f).unlink(missing_ok=True)
    onnx.save_model(model, str(out / "model.onnx"), save_as_external_data=True, all_tensors_to_one_file=True,
                    location="model.onnx_data", size_threshold=0)

    from engine.refworker.gpu import OnnxEmbedder  # the reference worker's own code path

    spec = SimpleNamespace(model_id="xlmr-tiny", repo="fixture/xlmr-tiny", max_input=MAX_LEN)
    ref = OnnxEmbedder(spec, str(HERE), ["CPUExecutionProvider"])
    vecs = ref.embed(TEXTS)
    ids = [[i for i, m in zip(e.ids, e.attention_mask) if m] for e in ref.tokenizer.encode_batch(TEXTS)]
    expected = {"max_len": MAX_LEN, "inputs": TEXTS, "ids": ids, "tokens": sum(len(i) for i in ids),
                "embeddings": [[float(x) for x in v] for v in vecs]}
    (HERE / "expected.json").write_text(json.dumps(expected, ensure_ascii=False, indent=1), encoding="utf-8")

    from tokenizers import Tokenizer

    real = Tokenizer.from_str(raw.decode("utf-8"))
    real.enable_truncation(8192)
    (HERE / "real_tokenizer_ids.json").write_text(
        json.dumps({"inputs": TEXTS, "ids": [e.ids for e in real.encode_batch(TEXTS)]}, ensure_ascii=False),
        encoding="utf-8")
    print("fixture written to", HERE)


if __name__ == "__main__":
    main()
