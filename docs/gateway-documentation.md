# Custos-Gateway Technical Documentation

> Staging documentation migrated from `Custos-Gateway/README.md` for future integration into `Custos-Web` (`docs.html` / `paper.html`).

---

## Problem Statement & Architectural Rationale

Modern AI inference runtimes—such as **NVIDIA Triton Inference Server**—rely on high-throughput gRPC streams transporting binary Protocol Buffers (Protobuf) tensor payloads (`KServe v2` / `inference.GRPCInferenceService/ModelInfer`). Because model runtimes execute tight compute-bound operations on specialized GPU and CPU hardware, they assume well-formed wire inputs and are acutely vulnerable to resource-exhausting or structurally malformed payloads:

* **Protobuf Nesting Bombs:** Deeply nested `Wire Type 2` length-delimited submessages that exhaust C++ recursive parser call stacks.
* **Tensor Shape Overflows:** Anomalous dimension arrays (negative dimensions, 64-bit integer wraparounds, or multi-gigabyte dimension products) that trigger unhandled out-of-memory (OOM) heap allocations before tensor buffer bounds are checked.
* **Malformed Varints:** Unterminated Base-128 varint sequences (`11+` continuation bytes with `MSB = 1` or 10th-byte 64-bit overflows) that stall wire parsers.

### Why Layer 7 `ext_proc` Instead of Layer 2/3 `AF_XDP` / `eBPF`?

Custos pivoted from a kernel-bypass `AF_XDP` packet filter to an **unprivileged, zero-copy Layer 7 admission control daemon** written in Rust due to three physical systems boundaries verified during early prototyping:

1. **Cryptographic Blindness (TLS 1.3 / mTLS):** Ephemeral per-connection keys render NIC-level packet rings opaque ciphertext; the Linux eBPF verifier prohibits the unbounded loops and dynamic allocations required to terminate TLS in-kernel.
2. **Multi-Frame TCP Segmentation & HTTP/2 Multiplexing:** Inference tensors (`600 KB` to `9.6+ MB`) span hundreds of MTU frames that can arrive out of order and are multiplexed across stateful HTTP/2 streams using HPACK header compression. Inspecting application payloads at the packet ring requires re-implementing a full user-space TCP reassembly and HTTP/2 state machine.
3. **Privilege & Blast-Radius Constraints:** `AF_XDP` requires `CAP_NET_ADMIN`, `CAP_BPF`, and host networking on GPU nodes, introducing security exposure and colliding with cluster CNIs (such as Cilium).

---

## Core Technical Invariants (`custos-core`)

`custos-core` is compiled with `#![no_std]` and `#![forbid(unsafe_code)]`. It validates contiguous byte slices (`&[u8]`) in a **single pass with zero heap allocations**:

1. **gRPC Frame Header Verification:**
   Validates that the leading byte has compression disabled (`0x00`) and that bytes `1..5` (big-endian `u32` declared length) match `slice.len() - 5`.
2. **Bounded 10-Byte Varint Decoding (`varint.rs`):**
   Unrolls Base-128 varint decoding up to a strict 10-byte ceiling. If byte index `9` (the 10th byte) has any bit above `0x01` set (which would overflow `u64::MAX`) or still carries a continuation bit (`0x80`), `ParseError::MalformedVarint` is raised immediately.
3. **Iterative Stack-Allocated Nesting Tracker (`scanner.rs`):**
   Tracks `Wire Type 2` submessage scopes using a fixed stack array `[ScopeFrame; MAX_DEPTH]` (`MAX_DEPTH = 16`). Any submessage exceeding depth `16` is rejected with `ParseError::NestingLimitExceeded(17)` without recursive function calls.
4. **KServe v2 Context-Aware Schema Walker & $O(1)$ Bulk Skipping:**
   Follows the KServe v2 `inference.ModelInferRequest` wire specification:
   - **Root Fields `1` (`model_name`), `2` (`model_version`), `3` (`id`), and `7` (`raw_input_contents`):** Skipped in **$O(1)$ time** by advancing the slice cursor past their length-delimited boundaries. Multi-megabyte float32 tensor buffers in Field 7 are never parsed as Protobuf tags, preventing both latency linear scans and false positives.
   - **Root Field `5` (`inputs` -> `InferInputTensor`):** Pushes an `MsgContext::InferInputTensor` frame onto the scope stack (up to `MAX_INPUT_TENSORS = 32` per request).
   - **`InferInputTensor` Field `3` (`shape`):** Supports both **packed repeated `int64`** (`Wire Type 2`, tag `0x1A`) and **unpacked repeated `int64`** (`Wire Type 0`, tag `0x18`). Each dimension varint is counted toward `DEFAULT_MAX_TAGS_SCANNED`, validated (`dim >= 0`, rejecting negative dimensions with `ParseError::NegativeDimension`), and multiplied into a per-tensor and cumulative request total via `i64::checked_mul` (catching 64-bit integer wraparounds with `ParseError::ShapeOverflow`). If any tensor or cumulative request total exceeds `DEFAULT_MAX_TENSOR_ELEMENTS` (`16,777,216` elements = `64 MiB` for `FP32`/`INT32`, `128 MiB` for `FP64`), `ParseError::BufferCeilingExceeded` is returned immediately.
5. **1-to-1 Per-Input Shape-to-Buffer Parity & `InferTensorContents` Verification:**
   Maps `InferInputTensor` Field `2` (`datatype`: `FP32`, `FP64`, `INT64`, `FP16`, `BF16`, `INT32`, `INT8`, `UINT8`, `BOOL`, `BYTES`, etc.) to its element byte width (rejecting missing or unknown datatypes) and enforces 1-to-1 positional parity between each input tensor `i` and either its corresponding `raw_input_contents[i]` chunk (Root Field `7`) or inline `InferTensorContents` (`Field 5` inside `InferInputTensor`). Swapped chunks, missing chunks, and element-count mismatches are rejected with `ParseError::PayloadSizeMismatch`. For variable-length `BYTES` tensors, `custos-core` walks the 4-byte little-endian `u32` length prefixes inside that input's `raw_input_contents[i]` chunk to verify that exactly $\prod \text{dim}_i$ length-prefixed strings fit within the chunk without over-read. *(Note: this enforces the KServe v2 wire invariant directly; NVIDIA's `CVE-2025-23320` and `CVE-2025-23334` advisories concern Triton Python-backend shared-memory region name disclosure on oversized payloads and subsequent shared-memory OOB read.)*
6. **Shallow Unknown-Field & Packed-Tag Ceiling (`CVE-2022-1941` / `CVE-2021-22569`-Class):**
   Bounds the total number of Protobuf TLV tags and packed dimension/element varints scanned per message to `DEFAULT_MAX_TAGS_SCANNED` (`1,024`), mitigating Protobuf parser resource-exhaustion bug classes (`CVE-2022-1941` in `protobuf-cpp` and `CVE-2021-22569` in `protobuf-java`).
7. **KServe v2 RPC Allowlisting & `ModelInfer` Shared-Memory Parameter Guard (`CVE-2024-0088`):**
   At the `RequestHeaders` stage in `custos-proc`, only allowlisted KServe v2 inference and read-only health/metadata RPCs (`ModelInfer`, `ModelStreamInfer`, `ServerLive`, `ServerReady`, `ModelReady`, `ModelMetadata`, `ModelConfig`) are admitted, and non-identity `grpc-encoding` headers (`gzip`, `deflate`) are rejected. Administrative and shared-memory RPCs (`SystemSharedMemoryRegister`, `SystemSharedMemoryUnregister`, `CudaSharedMemoryRegister`, `CudaSharedMemoryUnregister`, `RepositoryModelLoad`, `RepositoryModelUnload`, `TraceSetting`, `LogSettings`) are rejected immediately with `HTTP 403 Forbidden` and `gRPC PERMISSION_DENIED (7)` (`custos_denied:unauthorized_rpc_method`). Furthermore, because `CVE-2024-0088` can be triggered on an allowlisted `ModelInfer` call by injecting `shared_memory_region`, `shared_memory_offset`, or `shared_memory_byte_size` inside `InferInputTensor.parameters`, `InferRequestedOutputTensor.parameters`, or `ModelInferRequest.parameters`, `custos-core` inspects parameter map keys on the wire and rejects `shared_memory_*` keys with `ParseError::UnauthorizedSharedMemoryParameter`.

---

## Scientific Evaluation & Security Summary

`Custos-Gateway` is evaluated using [**`Custos-Bench`**](https://github.com/val-27/Custos-Bench), a coordinated-omission-free open-loop gRPC load generator and deterministic binary Protobuf exploit synthesizer:

| Threat Vector / CVE Class | Corpus Payloads (`Custos-Bench`) | `Custos-Gateway` Defense Invariant | Enforcement Stage & Action |
| :--- | :--- | :--- | :--- |
| **Shared-Memory Parameter Injection & Admin RPCs** (`CVE-2024-0088`) | `cve_2024_0088_shm_params_infer`, `shm_param_output_tensor`, `shm_param_request_level` + `rpc_*` admin probes | `:path` allowlisting + `ParameterMapEntry` `shared_memory_*` key rejection | `RequestHeaders` (`403`) & `RequestBody` (`400` / `INVALID_ARGUMENT`) |
| **Recursive Submessage, `SGROUP` & Compressed Bombs** (`CVE-2024-7254`-class) | `nesting_depth_{17..500}`, `sgroup_wire_type_3_bomb`, `grpc_compressed_flag_01` | Fixed-stack depth tracker (`MAX_DEPTH = 16`), Wire Type 3/4 rejection & `flag == 0x00` enforcement | `RequestBody` $\rightarrow$ `HTTP 400` / `gRPC INVALID_ARGUMENT (3)` |
| **Tensor Shape OOM & 64-Bit Wraparound** | `shape_neg_*`, `shape_wrap_64bit_*`, `shape_oom_massive_*`, `shape_reordered_tail` | `dim >= 0`, `i64::checked_mul`, per-tensor & cumulative `DEFAULT_MAX_TENSOR_ELEMENTS` ceiling | `RequestBody` $\rightarrow$ `HTTP 400` / `gRPC INVALID_ARGUMENT (3)` |
| **KServe v2 Per-Input Buffer Parity Mismatch** | `shape_buffer_mismatch_underread`, `chunk_swap_fp32`, `contents_fp32_unpacked_ceiling`, `bytes_masks_short_fp32`, `bytes_length_prefix_oversize` | 1-to-1 per-input byte parity between $\prod \text{dim}_i \times \text{sizeof}(\text{dtype})$ and Field 7 / `InferTensorContents` | `RequestBody` $\rightarrow$ `HTTP 400` / `gRPC INVALID_ARGUMENT (3)` |
| **Shallow Unknown-Field & Packed-Varint Flood** (`CVE-2022-1941` / `CVE-2021-22569`-class) | `unknown_field_ast_flood` (`1,500` unknown tags at `D=0`), `shape_packed_ones` (`100,000` packed `1`s) | Bounded TLV & packed-varint counter (`DEFAULT_MAX_TAGS_SCANNED = 1,024`) | `RequestBody` $\rightarrow$ `HTTP 400` / `gRPC INVALID_ARGUMENT (3)` |
| **Malformed / Unterminated Varints** | `varint_unterminated_{11,64}`, `varint_10th_byte_overflow`, `varint_truncated_eof` | Unrolled 10-byte Base-128 decoder with 10th-byte overflow guard | `RequestBody` $\rightarrow$ `HTTP 400` / `gRPC INVALID_ARGUMENT (3)` |
| **Benign ResNet-50 (`B=1..16`), `BYTES` & `D<=16`** | `benign_b1` (`602 KB`) $\rightarrow$ `benign_b16` (`9.63 MB`), `benign_bytes_tensor`, `nesting_depth_{15,16}` | $O(1)$ slice cursor jump over `raw_input_contents` & exact 4B `BYTES` prefix walk | `RequestBody` $\rightarrow$ `ALLOW (Continue)` (`0%` False Positive Rate) |

---

## Deployment & Evaluation Architectures

Paired with [**`Custos-Bench`**](https://github.com/val-27/Custos-Bench) to evaluate three unified architectures:

* **Unprotected Control (Direct Triton):** Client directly targets NVIDIA Triton Inference Server (`:8001` / `:30801`).
* **Proxy Baseline (Envoy Only):** Client targets Envoy Proxy (`envoy-baseline.yaml`, `:8002` / `:30802`) forwarding to Triton without `ext_proc`.
* **Custos Production (Gateway + Sidecar):** Client targets Envoy Proxy (`envoy-custos.yaml` / `k8s-topology1-gateway-sidecar`, `:8003` / `:30803`) co-located with the `custos-proc` Native Sidecar enforcing fail-closed `ext_proc` admission over `/var/run/custos/ext_proc.sock`.

---

## `custos-proc` CLI & Environment Reference

| Flag | Environment Variable | Default | Description |
| :--- | :--- | :--- | :--- |
| `--socket-path` | `CUSTOS_SOCKET_PATH` | `/var/run/custos/ext_proc.sock` | Unix Domain Socket path bound with `0660` permissions |
| `--max-nesting-depth` | `CUSTOS_MAX_NESTING_DEPTH` | `16` | Maximum allowed Protobuf submessage depth (`1..=16`) |
| `--max-tensor-elements` | `CUSTOS_MAX_TENSOR_ELEMENTS` | `16777216` | Maximum shape element product per `InferInputTensor` |
| `--max-tags-scanned` | `CUSTOS_MAX_TAGS_SCANNED` | `1024` | Maximum Protobuf TLV tags and packed varints scanned per message (`CVE-2022-1941` / `CVE-2021-22569`-class) |
| `--enforce-payload-parity` | `CUSTOS_ENFORCE_PAYLOAD_PARITY` | `true` | Enforce 1-to-1 per-input byte parity between declared tensor shape and `raw_input_contents` / `InferTensorContents` |
| `--max-message-size-mb` | `CUSTOS_MAX_MESSAGE_SIZE_MB` | `32` | Maximum gRPC message size accepted from Envoy in MiB |
| `--log-format` | `CUSTOS_LOG_FORMAT` | `json` | Structured log output format (`json`, `compact`, `pretty`) |
| `--log-level` | `CUSTOS_LOG_LEVEL` | `info` | Tracing filter directive when `RUST_LOG` is unset |
| `--log-admitted` | `CUSTOS_LOG_ADMITTED` | `true` | Emit per-request `INFO` logs on `ALLOW` (set `false` during high-RPS benchmarks) |
| `--stats-interval-secs` | `CUSTOS_STATS_INTERVAL_SECS` | `60` | Periodic cumulative telemetry heartbeat interval in seconds (`0` to disable) |
