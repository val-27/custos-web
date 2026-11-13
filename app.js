/* ==========================================================================
   Custos Interactive Visual Guide & Telemetry Engine
   ========================================================================== */

const WIRE_PAYLOADS = [
  {
    id: "benign_b1",
    group: "Benign KServe v2 Traffic",
    name: "benign_b1 (ResNet-50 B=1)",
    badge: "ALLOW",
    badgeClass: "badge-green",
    category: "benign",
    totalBytes: "602,175 B (framed)",
    verdict: "ALLOW (ResponseStatus::Continue)",
    httpStatus: "200 OK",
    grpcStatus: "0 (OK)",
    errorVariant: "None — Admitted",
    maxDepth: "1 / 16",
    tensorElements: "150,528 / 16,777,216 (588 KiB FP32)",
    skippedBytes: "602,131 B (O(1) cursor jump)",
    summary:
      "A normal request for an AI model called ResNet-50. The request includes a picture that's 224×224 pixels with 3 color channels (RGB). Custos checks the message structure and then skips over the image data without inspecting every byte.",
    segments: [
      {
        kind: "grpc",
        bytes: "00 00 09 30 3A",
        label: "gRPC Frame Header (5B)",
        offset: "0x00..0x05",
        detail:
          "Byte 0 = 0x00 (uncompressed). Bytes 1..4 = 0x0009303A (602,170 bytes big-endian), matching the exact remaining slice length."
      },
      {
        kind: "skip",
        bytes: "0A 08 72 65 73 6E 65 74 35 30",
        label: "Field 1: model_name",
        offset: "0x05..0x0F",
        detail:
          "Tag 0x0A (Root Field 1, Wire Type 2), length 8 ('resnet50'). Context-aware scanner skips string interior in O(1)."
      },
      {
        kind: "skip",
        bytes: "12 01 31  1A 09 62 65 6E 69 67 6E 5F 62 31",
        label: "Fields 2 & 3: version, id",
        offset: "0x0F..0x1D",
        detail:
          "Tag 0x12 (Field 2 model_version = '1') and Tag 0x1A (Field 3 id = 'benign_b1'). Skipped in O(1)."
      },
      {
        kind: "tag",
        bytes: "2A 21",
        label: "Field 5: inputs (InferInputTensor)",
        offset: "0x1D..0x1F",
        detail:
          "Tag 0x2A (Root Field 5, Wire Type 2), length 33 bytes. Pushes ScopeFrame { context: InputTensor, end_offset: 0x40, depth: 1 }."
      },
      {
        kind: "skip",
        bytes: "0A 0C 69 6E 70 75 74 5F 74 65 6E 73 6F 72  12 04 46 50 33 32",
        label: "Tensor Field 1 & 2: name, FP32",
        offset: "0x1F..0x33",
        detail:
          "Inside InputTensor scope: Field 1 name = 'input_tensor', Field 2 datatype = 'FP32'. Skipped in O(1)."
      },
      {
        kind: "shape",
        bytes: "1A 06 01 03 E0 01 E0 01",
        label: "Tensor Field 3: shape [1,3,224,224]",
        offset: "0x33..0x3B",
        detail:
          "Tag 0x1A (Packed Repeated int64, 6 bytes): dims = 1, 3, 224 (0xE0 0x01), 224 (0xE0 0x01). Checked product = 150,528 elements."
      },
      {
        kind: "skip",
        bytes: "3A 80 60 24 [602,112 B IEEE-754 floats]",
        label: "Field 7: raw_input_contents (O(1) Skip)",
        offset: "0x3B..0x9303F",
        detail:
          "Tag 0x3A (Root Field 7, Wire Type 2), varint length 602,112. Cursor jumps directly to EOF in O(1) without scanning float bytes as tags."
      }
    ]
  },
  {
    id: "benign_bytes_tensor",
    group: "Benign KServe v2 Traffic",
    name: "benign_bytes_tensor (BYTES [1, 2])",
    badge: "ALLOW",
    badgeClass: "badge-green",
    category: "benign",
    totalBytes: "139 B (framed)",
    verdict: "ALLOW (ResponseStatus::Continue)",
    httpStatus: "200 OK",
    grpcStatus: "0 (OK)",
    errorVariant: "None — Admitted (Variable-Width BYTES Parity Verified)",
    maxDepth: "1 / 16",
    tensorElements: "2 string elements (>= 8 B length prefixes)",
    skippedBytes: "118 B (O(1) cursor jump)",
    summary:
      "A legitimate variable-length string/bytes tensor (datatype = 'BYTES', shape [1, 2]). Unlike fixed-width tensors (FP32), BYTES elements are prefixed by 4-byte little-endian lengths in raw_input_contents. Custos walks each 4-byte u32 prefix inside the chunk to verify that exactly 2 elements fit without buffer over-read or false positives.",
    segments: [
      {
        kind: "grpc",
        bytes: "00 00 00 00 86",
        label: "gRPC Frame Header (5B)",
        offset: "0x00..0x05",
        detail: "Byte 0 = 0x00 (uncompressed). Bytes 1..4 = 0x00000086 (134 bytes big-endian)."
      },
      {
        kind: "tag",
        bytes: "2A 1B [0A 0A text_input  12 05 42 59 54 45 53]",
        label: "Field 5: datatype = 'BYTES' (Variable Width)",
        offset: "0x27..0x3E",
        detail:
          "Inside InferInputTensor scope: Field 2 datatype is 'BYTES' (0x42 59 54 45 53). Scanner sets tensor_is_bytes = true for input_specs[0]."
      },
      {
        kind: "shape",
        bytes: "1A 02 01 02",
        label: "Tensor Field 3: shape [1, 2] -> 2 Strings",
        offset: "0x3E..0x42",
        detail:
          "Packed shape [1, 2] = 2 elements. InputTensorSpec[0] records elements = 2, is_bytes = true (minimum 8 bytes of 4B length prefixes)."
      },
      {
        kind: "skip",
        bytes: "3A 48 [25 00 00 00 'classify:...' 1B 00 00 00 'model:...']",
        label: "Field 7: 72 B Length-Prefixed Strings (ALLOW)",
        offset: "0x42..0x8B",
        detail:
          "verify_bytes_chunk() walks 2 little-endian u32 prefixes (37 B + 27 B + 8 B prefixes = 72 B == raw_chunks[0].len). Admitted with 0% false positive rate."
      }
    ]
  },
  {
    id: "benign_contents_fp32_packed",
    group: "Benign KServe v2 Traffic",
    name: "benign_contents_fp32_packed (Inline TensorContents)",
    badge: "ALLOW",
    badgeClass: "badge-green",
    category: "tensor_contents",
    totalBytes: "87 B (framed)",
    verdict: "ALLOW (ResponseStatus::Continue)",
    httpStatus: "200 OK",
    grpcStatus: "0 (OK)",
    errorVariant: "None — Admitted (Inline InferTensorContents Verified)",
    maxDepth: "2 / 16 (InputTensor -> TensorContents)",
    tensorElements: "4 elements (16 B packed fp32_contents)",
    skippedBytes: "42 B (O(1) cursor jump)",
    summary:
      "A valid KServe v2 request using inline InferTensorContents (Field 5 inside InferInputTensor) instead of Root Field 7 raw_input_contents. Contains 4 packed IEEE-754 floats (16 bytes) whose bit patterns include 0xFF/0x9B bytes. Custos enters MsgContext::TensorContents, verifies 16 % 4 == 0 (4 elements == shape [4]), and skips the packed float bytes in O(1).",
    segments: [
      {
        kind: "grpc",
        bytes: "00 00 00 00 52",
        label: "gRPC Frame Header (5B)",
        offset: "0x00..0x05",
        detail: "Byte 0 = 0x00 (uncompressed). Bytes 1..4 = 0x00000052 (82 bytes big-endian)."
      },
      {
        kind: "tag",
        bytes: "2A 31 [0A 0C input_tensor  12 04 FP32  1A 01 04]",
        label: "Field 5: InferInputTensor FP32 [4]",
        offset: "0x24..0x3B",
        detail: "Declares input_tensor with datatype = 'FP32' and packed shape = [4] (4 elements expected)."
      },
      {
        kind: "skip",
        bytes: "2A 12 [32 10 FF FF FF FF 9B 06 80 3F ... (16 B)]",
        label: "InputTensor Field 5: packed fp32_contents (ALLOW)",
        offset: "0x3B..0x4F",
        detail:
          "Tag 0x2A inside InputTensor pushes MsgContext::TensorContents. Field 6 (Tag 0x32, Wire Type 2, len 16) adds 16 / 4 = 4 elements to contents_elements and skips the float bytes in O(1) without misparsing 0xFF as Protobuf varints."
      }
    ]
  },
  {
    id: "benign_shape_zero_axis",
    group: "Benign KServe v2 Traffic",
    name: "benign_shape_zero_axis (Zero-Length Axis [1, 0, 224, 224])",
    badge: "ALLOW",
    badgeClass: "badge-green",
    category: "shape_axis",
    totalBytes: "68 B (framed)",
    verdict: "ALLOW (ResponseStatus::Continue)",
    httpStatus: "200 OK",
    grpcStatus: "0 (OK)",
    errorVariant: "None — Admitted (0-Element Tensor Parity Verified)",
    maxDepth: "1 / 16",
    tensorElements: "0 / 16,777,216 (0 B expected)",
    skippedBytes: "26 B",
    summary:
      "A valid KServe v2 tensor with a zero-length dimension ([1, 0, 224, 224]) and a corresponding 0-byte raw_input_contents[0] chunk (3A 00). Custos permits dim == 0 (while rejecting dim < 0), computes shape_product = 0, and verifies raw_chunks[0].len == 0.",
    segments: [
      {
        kind: "grpc",
        bytes: "00 00 00 00 3F",
        label: "gRPC Frame Header (5B)",
        offset: "0x00..0x05",
        detail: "5-byte uncompressed gRPC frame header (63-byte body)."
      },
      {
        kind: "shape",
        bytes: "1A 06 01 00 E0 01 E0 01",
        label: "Packed Shape [1, 0, 224, 224] -> 0 Elements",
        offset: "0x39..0x41",
        detail:
          "accumulate_dimension() accepts non-negative dimensions (dim >= 0) using checked_mul. Product = 1 * 0 * 224 * 224 = 0 elements (0 bytes expected)."
      },
      {
        kind: "skip",
        bytes: "3A 00",
        label: "Field 7: 0-Byte raw_input_contents[0] (ALLOW)",
        offset: "0x41..0x43",
        detail:
          "Root Field 7 supplies a 0-byte chunk (raw_chunks[0].len == 0), matching input_specs[0] expected bytes (0)."
      }
    ]
  },
  {
    id: "benign_mixed_fp32_bytes",
    group: "Benign KServe v2 Traffic",
    name: "benign_mixed_fp32_bytes (Multi-Input FP32 + BYTES)",
    badge: "ALLOW",
    badgeClass: "badge-green",
    category: "bytes_prefix",
    totalBytes: "118 B (framed)",
    verdict: "ALLOW (ResponseStatus::Continue)",
    httpStatus: "200 OK",
    grpcStatus: "0 (OK)",
    errorVariant: "None — Admitted (Per-Input Fixed + Variable Parity)",
    maxDepth: "1 / 16",
    tensorElements: "Input 0: 2 FP32 (8 B) • Input 1: 2 BYTES (16 B)",
    skippedBytes: "66 B (O(1) cursor jump)",
    summary:
      "A multi-input KServe v2 request combining a fixed-width FP32 [2] tensor (8 bytes) and a variable-width BYTES [2] tensor (two 4-byte length-prefixed strings = 16 bytes). Custos validates each input_specs[i] against its own raw_chunks[i] independently.",
    segments: [
      {
        kind: "tag",
        bytes: "2A 15 [in0: FP32, shape [2]]  2A 17 [in1: BYTES, shape [2]]",
        label: "Two InferInputTensors: FP32 [2] + BYTES [2]",
        offset: "0x24..0x54",
        detail:
          "Records input_specs[0] = { FP32, shape_product: 2, expected: 8 B } and input_specs[1] = { BYTES, shape_product: 2 }."
      },
      {
        kind: "skip",
        bytes: "3A 08 [8 B FP32]  3A 10 [04 00 00 00 'abcd' 04 00 00 00 'efgh']",
        label: "Field 7 Chunks 0 & 1 Match 1-to-1 (ALLOW)",
        offset: "0x54..0x6E",
        detail:
          "raw_chunks[0].len == 8 matches input_specs[0], and verify_bytes_chunk(raw_chunks[1], 2) confirms two 4-byte strings cleanly partition the 16-byte chunk."
      }
    ]
  },
  {
    id: "grpc_compressed_flag_01",
    group: "Exploit Family 1: Nesting Bombs",
    name: "grpc_compressed_flag_01 (gzip Flag = 0x01)",
    badge: "REJECT",
    badgeClass: "badge-red",
    category: "compressed_frame",
    totalBytes: "62 B (framed)",
    verdict: "DENY (ImmediateResponse)",
    httpStatus: "400 Bad Request",
    grpcStatus: "3 (INVALID_ARGUMENT)",
    errorVariant: "ParseError::UnsupportedCompression(0x01)",
    maxDepth: "0 / 16 (Blocked at Byte 0)",
    tensorElements: "0 (Rejected Pre-Decompression)",
    skippedBytes: "0 B",
    summary:
      "A gRPC frame with byte 0 set to 0x01 (compressed / gzip), concealing a [1024, 1024, 1024] OOM tensor inside compressed bytes. Because a zero-copy wire scanner cannot read TLV tags inside compressed streams without risking zip-bomb memory amplification, Custos rejects flag != 0x00 and non-identity grpc-encoding headers.",
    segments: [
      {
        kind: "exploit",
        bytes: "01",
        label: "Byte 0: gRPC Compression Flag = 0x01 (ABORT)",
        offset: "0x00..0x01",
        detail:
          "Byte 0 of the 5-byte gRPC prefix is 0x01 (compressed). Custos enforces uncompressed wire inspection and immediately aborts at offset 0x00 with ParseError::UnsupportedCompression(0x01) -> custos_denied:unsupported_compression."
      },
      {
        kind: "grpc",
        bytes: "00 00 00 39",
        label: "Bytes 1..4: Declared Compressed Length (57B)",
        offset: "0x01..0x05",
        detail: "32-bit big-endian length of the zlib/gzip compressed stream."
      },
      {
        kind: "skip",
        bytes: "78 9C [55 B zlib-compressed OOM payload]",
        label: "Opaque Compressed Payload (Never Decompressed)",
        offset: "0x05..0x3E",
        detail: "Conceals a [1024, 1024, 1024] tensor bomb. Never decompressed or forwarded to Triton."
      }
    ]
  },
  {
    id: "nesting_depth_17",
    group: "Exploit Family 1: Nesting Bombs",
    name: "nesting_depth_17 (Boundary Breach)",
    badge: "REJECT",
    badgeClass: "badge-red",
    category: "nesting_bomb",
    totalBytes: "51 B (framed)",
    verdict: "DENY (ImmediateResponse)",
    httpStatus: "400 Bad Request",
    grpcStatus: "3 (INVALID_ARGUMENT)",
    errorVariant: "ParseError::NestingLimitExceeded(17)",
    maxDepth: "17 / 16 (BREACH)",
    tensorElements: "0",
    skippedBytes: "8 B",
    summary:
      "An attack: the message has 17 levels of nesting. Custos allows a maximum of 16 levels. This would crash normal parsers because they allocate memory for each level. Custos stops it immediately.",
    segments: [
      {
        kind: "grpc",
        bytes: "00 00 00 00 2E",
        label: "gRPC Header (46B body)",
        offset: "0x00..0x05",
        detail: "Uncompressed gRPC frame header declaring 46 bytes of Protobuf payload."
      },
      {
        kind: "skip",
        bytes: "0A 08 72 65 73 6E 65 74 35 30",
        label: "Field 1: model_name",
        offset: "0x05..0x0F",
        detail: "Valid model_name header ('resnet50') skipped in O(1)."
      },
      {
        kind: "tag",
        bytes: "22 22  22 20  22 1E ... (depths 1..16)",
        label: "16 Nested Wire Type 2 Scopes",
        offset: "0x0F..0x2F",
        detail:
          "Each 0x22 (Field 4 parameters) + length varint pushes a ScopeFrame onto the fixed stack array up to MAX_DEPTH = 16."
      },
      {
        kind: "exploit",
        bytes: "22 02 [08 01]",
        label: "Depth 17 Submessage Tag (ABORT)",
        offset: "0x2F..0x33",
        detail:
          "At offset 0x2F, depth == MAX_DEPTH (16). Encountering another Wire Type 2 submessage triggers ParseError::NestingLimitExceeded(17) -> custos_denied:nesting_limit_exceeded."
      }
    ]
  },
  {
    id: "sgroup_wire_type_3_bomb",
    group: "Exploit Family 1: Nesting Bombs",
    name: "sgroup_wire_type_3_bomb (CVE-2024-7254-Class)",
    badge: "REJECT",
    badgeClass: "badge-red",
    category: "wire_type_exploit",
    totalBytes: "273 B (framed)",
    verdict: "DENY (ImmediateResponse)",
    httpStatus: "400 Bad Request",
    grpcStatus: "3 (INVALID_ARGUMENT)",
    errorVariant: "ParseError::InvalidWireType(3)",
    maxDepth: "0 / 16 (Blocked at 1st SGROUP)",
    tensorElements: "0",
    skippedBytes: "8 B",
    summary:
      "Demonstrates the CVE-2024-7254 Protobuf bug class: 64 nested Wire Type 3 (SGROUP) group tags designed to bypass length-delimited recursion counters. Because KServe v2 is strictly Protobuf v3, Custos rejects Wire Type 3 & 4 on the very first tag.",
    segments: [
      {
        kind: "grpc",
        bytes: "00 00 00 01 0C",
        label: "gRPC Header (268B body)",
        offset: "0x00..0x05",
        detail: "5-byte uncompressed gRPC frame header declaring 268 bytes."
      },
      {
        kind: "skip",
        bytes: "0A 08 72 65 73 6E 65 74 35 30",
        label: "Field 1: model_name",
        offset: "0x05..0x0F",
        detail: "Valid model_name header ('resnet50') skipped in O(1)."
      },
      {
        kind: "exploit",
        bytes: "9B 06 [x64 SGROUP] 08 01 9C 06 [x64 EGROUP]",
        label: "Wire Type 3 SGROUP Tag (CVE-2024-7254-Class)",
        offset: "0x0F..0x111",
        detail:
          "Tag varint 0x9B 0x06 decodes to (field_number = 99, wire_type = 3). Because KServe v2 is strictly Protobuf v3, Custos rejects Wire Type 3 & 4 immediately on the very first tag with ParseError::InvalidWireType(3) -> custos_denied:invalid_wire_type."
      }
    ]
  },
  {
    id: "shape_neg_packed",
    group: "Exploit Family 2: Shape Overflows",
    name: "shape_neg_packed ([1, 3, -1, 224])",
    badge: "REJECT",
    badgeClass: "badge-red",
    category: "shape_overflow",
    totalBytes: "65 B (framed)",
    verdict: "DENY (ImmediateResponse)",
    httpStatus: "400 Bad Request",
    grpcStatus: "3 (INVALID_ARGUMENT)",
    errorVariant: "ParseError::NegativeDimension(-1)",
    maxDepth: "1 / 16",
    tensorElements: "Rejected at dim[2] = -1",
    skippedBytes: "26 B",
    summary:
      "An attack: declares a dimension of the image as negative one (-1). This confuses the AI system when it tries to allocate memory, because it can't make a negative-sized buffer. Custos rejects negative numbers immediately.",
    segments: [
      {
        kind: "grpc",
        bytes: "00 00 00 00 3C",
        label: "gRPC Header (60B body)",
        offset: "0x00..0x05",
        detail: "5-byte uncompressed gRPC header."
      },
      {
        kind: "tag",
        bytes: "2A 25 [0A 0C input_tensor 12 04 FP32]",
        label: "Field 5: InferInputTensor",
        offset: "0x1B..0x31",
        detail: "Enters InputTensor context; skips name and datatype strings in O(1)."
      },
      {
        kind: "shape",
        bytes: "1A 0E  01  03",
        label: "Packed Shape: dims[0..1] = 1, 3",
        offset: "0x31..0x35",
        detail: "Tag 0x1A (Packed shape, 14 bytes). First two dimensions decode cleanly: product = 1 * 3 = 3."
      },
      {
        kind: "exploit",
        bytes: "FF FF FF FF FF FF FF FF FF 01",
        label: "dim[2] = -1 (10-Byte Two's Complement)",
        offset: "0x35..0x3F",
        detail:
          "Decodes to u64::MAX, which casts to i64 = -1. accumulate_dimension() enforces dim > 0 and immediately rejects with ParseError::NegativeDimension(-1)."
      }
    ]
  },
  {
    id: "shape_wrap_64bit_packed",
    group: "Exploit Family 2: Shape Overflows",
    name: "shape_wrap_64bit ([2, 2^62, 2])",
    badge: "REJECT",
    badgeClass: "badge-red",
    category: "shape_overflow",
    totalBytes: "62 B (framed)",
    verdict: "DENY (ImmediateResponse)",
    httpStatus: "400 Bad Request",
    grpcStatus: "3 (INVALID_ARGUMENT)",
    errorVariant: "ParseError::ShapeOverflow",
    maxDepth: "1 / 16",
    tensorElements: "Overflow (> i64::MAX)",
    skippedBytes: "26 B",
    summary:
      "An attack: declares dimensions that are huge positive numbers, but when multiplied together they wrap around to zero or very small numbers. This tricks the AI system into allocating wrong-sized memory. Custos checks the math before allowing it.",
    segments: [
      {
        kind: "grpc",
        bytes: "00 00 00 00 39",
        label: "gRPC Header (57B body)",
        offset: "0x00..0x05",
        detail: "5-byte uncompressed gRPC header."
      },
      {
        kind: "shape",
        bytes: "1A 0C  02",
        label: "Packed Shape: dim[0] = 2",
        offset: "0x31..0x34",
        detail: "Tag 0x1A (12 bytes). Running shape_product initialized to 2."
      },
      {
        kind: "exploit",
        bytes: "80 80 80 80 80 80 80 80 40  02",
        label: "dim[1] = 2^62 (Checked Mul Overflow)",
        offset: "0x34..0x3E",
        detail:
          "dim[1] = 4,611,686,018,427,387,904 (2^62). In signed 64-bit arithmetic, 2i64.checked_mul(2^62) overflows i64::MAX (2^63 - 1) and returns None -> ParseError::ShapeOverflow."
      }
    ]
  },
  {
    id: "shape_reordered_tail",
    group: "Exploit Family 2: Shape Overflows",
    name: "shape_reordered_tail (Field 7 Before 5)",
    badge: "REJECT",
    badgeClass: "badge-red",
    category: "shape_overflow",
    totalBytes: "16,445 B (framed)",
    verdict: "DENY (ImmediateResponse)",
    httpStatus: "400 Bad Request",
    grpcStatus: "3 (INVALID_ARGUMENT)",
    errorVariant: "ParseError::BufferCeilingExceeded",
    maxDepth: "1 / 16",
    tensorElements: "1,073,741,824 > 16,777,216",
    skippedBytes: "16,410 B (O(1) jump)",
    summary:
      "An attack: puts 16 kilobytes of data at the start, then the malicious size declaration after. Some security tools only check the beginning of messages and would miss this. Custos reads through the entire message and catches the attack at the end.",
    segments: [
      {
        kind: "grpc",
        bytes: "00 00 00 40 38",
        label: "gRPC Header (16,440B)",
        offset: "0x00..0x05",
        detail: "5-byte uncompressed gRPC frame header."
      },
      {
        kind: "skip",
        bytes: "3A 80 80 01 [16,384 B of 0x00]",
        label: "Field 7: 16 KiB raw_input_contents First",
        offset: "0x1B..0x401F",
        detail:
          "Protobuf allows fields in arbitrary order. Custos decodes Tag 0x3A + length 16,384 and advances cursor by 16,384 in O(1) time."
      },
      {
        kind: "exploit",
        bytes: "2A 1D ... 1A 06 80 08 80 08 80 08",
        label: "Trailing Field 5: [1024, 1024, 1024]",
        offset: "0x401F..0x403D",
        detail:
          "Immediately after the O(1) jump, Custos inspects trailing Field 5: 1024 * 1024 * 1024 = 1,073,741,824 elements > 16,777,216 ceiling -> ParseError::BufferCeilingExceeded."
      }
    ]
  },
  {
    id: "shape_buffer_mismatch_underread",
    group: "Exploit Family 2: Shape Overflows",
    name: "shape_buffer_mismatch (KServe v2 Per-Input Parity)",
    badge: "REJECT",
    badgeClass: "badge-red",
    category: "shape_overflow",
    totalBytes: "123 B (framed)",
    verdict: "DENY (ImmediateResponse)",
    httpStatus: "400 Bad Request",
    grpcStatus: "3 (INVALID_ARGUMENT)",
    errorVariant: "ParseError::PayloadSizeMismatch { expected: 2408448, actual: 64 }",
    maxDepth: "1 / 16",
    tensorElements: "602,112 elements (2,408,448 B expected)",
    skippedBytes: "90 B (O(1) jump)",
    summary:
      "Declares a 4-image FP32 batch ([4, 3, 224, 224] = 2,408,448 bytes) that passes element-count limits, but supplies only 64 bytes in raw_input_contents[0], violating KServe v2 per-input buffer parity. Custos matches input_specs[i] 1-to-1 against raw_chunks[i] (or InferTensorContents).",
    segments: [
      {
        kind: "grpc",
        bytes: "00 00 00 00 76",
        label: "gRPC Header (118B body)",
        offset: "0x00..0x05",
        detail: "5-byte uncompressed gRPC frame header."
      },
      {
        kind: "tag",
        bytes: "2A 21 [0A 0C input_tensor 12 04 46 50 33 32]",
        label: "Field 5: datatype = FP32 (4B/elem)",
        offset: "0x1B..0x35",
        detail:
          "Inside InferInputTensor scope, kserve_datatype_byte_width('FP32') records tensor_elem_width = 4."
      },
      {
        kind: "shape",
        bytes: "1A 06 04 03 E0 01 E0 01",
        label: "Shape [4, 3, 224, 224] -> 2,408,448 B",
        offset: "0x35..0x3D",
        detail:
          "Packed shape product = 602,112 elements. On InferInputTensor scope exit, input_specs[0].expected_bytes = 602,112 * 4 = 2,408,448 bytes."
      },
      {
        kind: "exploit",
        bytes: "3A 40 [64 B of 0x00]",
        label: "Field 7: Only 64 B Supplied (ABORT)",
        offset: "0x3D..0x7B",
        detail:
          "Root Field 7 chunk 0 declares length 64 (0x40). At 1-to-1 per-input parity verification, raw_chunks[0].len (64) != input_specs[0].expected_bytes (2,408,448) -> ParseError::PayloadSizeMismatch -> custos_denied:payload_size_mismatch."
      }
    ]
  },
  {
    id: "varint_unterminated_11",
    group: "Exploit Family 3: Malformed Varints",
    name: "varint_unterminated_11 (11x 0xFF)",
    badge: "REJECT",
    badgeClass: "badge-red",
    category: "malformed_varint",
    totalBytes: "27 B (framed)",
    verdict: "DENY (ImmediateResponse)",
    httpStatus: "400 Bad Request",
    grpcStatus: "3 (INVALID_ARGUMENT)",
    errorVariant: "ParseError::MalformedVarint",
    maxDepth: "0 / 16",
    tensorElements: "0",
    skippedBytes: "8 B",
    summary:
      "An attack: sends a number that says 'there's more digits coming' but keeps going for 11 chunks instead of the maximum 10. The parser would loop forever or overflow trying to shift bits. Custos stops at 10 chunks.",
    segments: [
      {
        kind: "grpc",
        bytes: "00 00 00 00 16",
        label: "gRPC Header (22B body)",
        offset: "0x00..0x05",
        detail: "5-byte uncompressed gRPC frame header."
      },
      {
        kind: "skip",
        bytes: "0A 08 72 65 73 6E 65 74 35 30",
        label: "Field 1: model_name",
        offset: "0x05..0x0F",
        detail: "Valid model_name prefix ('resnet50')."
      },
      {
        kind: "tag",
        bytes: "08",
        label: "Tag 0x08 (Wire Type 0 Varint)",
        offset: "0x0F..0x10",
        detail: "Field 1, Wire Type 0 triggers decode_varint()."
      },
      {
        kind: "exploit",
        bytes: "FF FF FF FF FF FF FF FF FF [FF FF]",
        label: "11 Continuation Bytes (MSB = 1)",
        offset: "0x10..0x1B",
        detail:
          "At byte index i == 9 (the 10th byte), byte is 0xFF > 0x01. decode_varint() immediately aborts with ParseError::MalformedVarint -> custos_denied:malformed_varint."
      }
    ]
  },
  {
    id: "unknown_field_ast_flood",
    group: "Exploit Family 4: AST & RPC Exploits",
    name: "unknown_field_ast_flood (CVE-2022-1941-Class)",
    badge: "REJECT",
    badgeClass: "badge-red",
    category: "ast_flood",
    totalBytes: "4,515 B (framed)",
    verdict: "DENY (ImmediateResponse)",
    httpStatus: "400 Bad Request",
    grpcStatus: "3 (INVALID_ARGUMENT)",
    errorVariant: "ParseError::TagLimitExceeded { count: 1025, max: 1024 }",
    maxDepth: "0 / 16 (Flat Flood)",
    tensorElements: "0",
    skippedBytes: "8 B",
    summary:
      "Packs 1,500 unrecognized 2-byte varint tags at root depth (D=0) to trigger UnknownFieldSet heap amplification (the bug class in CVE-2022-1941 C++ libprotobuf and CVE-2021-22569 protobuf-java). Custos enforces a 1,024-tag scan ceiling and never allocates unknown fields.",
    segments: [
      {
        kind: "grpc",
        bytes: "00 00 00 11 9E",
        label: "gRPC Header (4,510B body)",
        offset: "0x00..0x05",
        detail: "5-byte uncompressed gRPC frame header."
      },
      {
        kind: "skip",
        bytes: "0A 08 72 65 73 6E 65 74 35 30",
        label: "Field 1: model_name ('resnet50')",
        offset: "0x05..0x0F",
        detail: "Tag #1 scanned; string payload skipped in O(1)."
      },
      {
        kind: "tag",
        bytes: "C0 0C 01 [x1,023 unknown tags]",
        label: "Tags #2..#1,024 (Field 200 Varints)",
        offset: "0x0F..0xC0C",
        detail:
          "Each 3-byte sequence (tag 0xC0 0x0C = field 200, wire type 0 + value 0x01) increments report.tags_scanned with zero heap allocation."
      },
      {
        kind: "exploit",
        bytes: "C0 0C 01 [Tag #1,025 -> ABORT]",
        label: "Tag #1,025 Breaches Ceiling (1,024)",
        offset: "0xC0C..0x11A3",
        detail:
          "At tag #1,025, report.tags_scanned > config.max_tags_scanned (1,024). Scanner immediately aborts with ParseError::TagLimitExceeded -> custos_denied:tag_limit_exceeded."
      }
    ]
  },
  {
    id: "cve_2024_0088_shm_params_infer",
    group: "Exploit Family 4: AST & RPC Exploits",
    name: "cve_2024_0088_shm_params_infer (CVE-2024-0088)",
    badge: "REJECT",
    badgeClass: "badge-red",
    category: "shm_param_injection",
    totalBytes: "182 B (framed)",
    verdict: "DENY (ImmediateResponse)",
    httpStatus: "400 Bad Request",
    grpcStatus: "3 (INVALID_ARGUMENT)",
    errorVariant: "ParseError::UnauthorizedSharedMemoryParameter",
    maxDepth: "2 / 16 (InputTensor -> ParameterMapEntry)",
    tensorElements: "150,528",
    skippedBytes: "43 B",
    summary:
      "Targets the allowlisted ModelInfer RPC (which passes a header-only :path check) and injects shared_memory_region, shared_memory_offset, and shared_memory_byte_size inside InferInputTensor.parameters (Field 4)—the public trigger for CVE-2024-0088. Custos inspects parameter map keys on the wire and blocks shared_memory_* injection.",
    segments: [
      {
        kind: "grpc",
        bytes: "00 00 00 00 B1",
        label: "gRPC Header (177B body)",
        offset: "0x00..0x05",
        detail: "5-byte uncompressed gRPC frame header on /inference.GRPCInferenceService/ModelInfer."
      },
      {
        kind: "tag",
        bytes: "2A 91 01 [0A 0C input_tensor  12 04 FP32  1A 06 01 03 E0 01 E0 01]",
        label: "Field 5: InferInputTensor [1, 3, 224, 224]",
        offset: "0x24..0x46",
        detail: "Normal-looking input_tensor header with valid FP32 shape [1, 3, 224, 224]."
      },
      {
        kind: "exploit",
        bytes: "22 2D [0A 14 'shared_memory_region'  12 15 1A 13 'triton_shm_internal']",
        label: "Field 4: parameters['shared_memory_region'] (ABORT)",
        offset: "0x46..0x75",
        detail:
          "Tag 0x22 (InputTensor Field 4: parameters map entry) pushes MsgContext::ParameterMapEntry (with InferParameter string_param = 3 / int64_param = 2). Inside it, Field 1 (Tag 0x0A) has key 'shared_memory_region'. Custos matches prefix 'shared_memory' and immediately aborts with ParseError::UnauthorizedSharedMemoryParameter."
      }
    ]
  },
  {
    id: "chunk_swap_fp32",
    group: "Exploit Family 5: Oracle Parity & Framing",
    name: "chunk_swap_fp32 (Multi-Tensor Per-Chunk Swap)",
    badge: "REJECT",
    badgeClass: "badge-red",
    category: "chunk_parity",
    totalBytes: "97 B (framed)",
    verdict: "DENY (ImmediateResponse)",
    httpStatus: "400 Bad Request",
    grpcStatus: "3 (INVALID_ARGUMENT)",
    errorVariant: "ParseError::PayloadSizeMismatch { expected: 16, actual: 4 }",
    maxDepth: "1 / 16",
    tensorElements: "Input 0: 4 FP32 (16 B) • Input 1: 1 FP32 (4 B)",
    skippedBytes: "42 B",
    summary:
      "Declares two FP32 inputs: in0 with shape [4] (16 bytes) and in1 with shape [1] (4 bytes), but supplies raw_input_contents[0] = 4 bytes and raw_input_contents[1] = 16 bytes. A naive total-sum check (20 B == 20 B) would pass this message, causing Triton to bind a 4-byte buffer to a 16-byte input. Custos enforces 1-to-1 per-input parity (raw_chunks[i].len == input_specs[i].expected_bytes).",
    segments: [
      {
        kind: "tag",
        bytes: "2A 0F [in0: FP32, shape [4]]  2A 0F [in1: FP32, shape [1]]",
        label: "Two Inputs: in0 Expects 16 B, in1 Expects 4 B",
        offset: "0x24..0x46",
        detail:
          "input_specs[0] records expected = 16 B; input_specs[1] records expected = 4 B."
      },
      {
        kind: "exploit",
        bytes: "3A 04 [4 B chunk 0]  3A 10 [16 B chunk 1] (ABORT)",
        label: "Swapped Field 7 Chunks [4 B, 16 B]",
        offset: "0x46..0x5E",
        detail:
          "At i = 0, raw_chunks[0].len (4) != input_specs[0].expected_bytes (16). Custos immediately rejects with ParseError::PayloadSizeMismatch { expected_bytes: 16, actual_bytes: 4 }."
      }
    ]
  },
  {
    id: "contents_fp32_unpacked_ceiling",
    group: "Exploit Family 5: Oracle Parity & Framing",
    name: "contents_fp32_unpacked_ceiling (64 MiB Inline Claim, 1 Float)",
    badge: "REJECT",
    badgeClass: "badge-red",
    category: "tensor_contents",
    totalBytes: "79 B (framed)",
    verdict: "DENY (ImmediateResponse)",
    httpStatus: "400 Bad Request",
    grpcStatus: "3 (INVALID_ARGUMENT)",
    errorVariant: "ParseError::PayloadSizeMismatch { expected: 67108864, actual: 4 }",
    maxDepth: "2 / 16 (InputTensor -> TensorContents)",
    tensorElements: "16,777,216 declared vs 1 supplied",
    skippedBytes: "26 B",
    summary:
      "Declares an FP32 tensor at the 16,777,216-element ceiling (64 MiB), omits Root Field 7 entirely, and supplies an inline InferTensorContents (Field 5) containing only a single 4-byte unpacked fp32_contents element (Wire Type 5). Custos counts inline TensorContents elements and rejects the 64 MiB vs 4 B mismatch.",
    segments: [
      {
        kind: "shape",
        bytes: "1A 04 80 80 80 08",
        label: "Packed Shape [16,777,216] (64 MiB FP32)",
        offset: "0x39..0x3F",
        detail:
          "Declares 16,777,216 FP32 elements (67,108,864 bytes expected)."
      },
      {
        kind: "exploit",
        bytes: "2A 05 [35 00 00 80 3F] (ABORT)",
        label: "TensorContents: Only 1 Unpacked Float (4 B)",
        offset: "0x3F..0x46",
        detail:
          "Inside MsgContext::TensorContents, Tag 0x35 (Field 6, Wire Type 5 fixed32) increments contents_elements to 1. On parity check, contents_elements (1) != shape_product (16,777,216) -> ParseError::PayloadSizeMismatch."
      }
    ]
  },
  {
    id: "bytes_length_prefix_oversize",
    group: "Exploit Family 5: Oracle Parity & Framing",
    name: "bytes_length_prefix_oversize (u32 Prefix Over-Read)",
    badge: "REJECT",
    badgeClass: "badge-red",
    category: "bytes_prefix",
    totalBytes: "76 B (framed)",
    verdict: "DENY (ImmediateResponse)",
    httpStatus: "400 Bad Request",
    grpcStatus: "3 (INVALID_ARGUMENT)",
    errorVariant: "ParseError::PayloadSizeMismatch { expected: 104, actual: 8 }",
    maxDepth: "1 / 16",
    tensorElements: "1 BYTES element (u32 len = 100 inside 8 B chunk)",
    skippedBytes: "32 B",
    summary:
      "Declares a 1-element BYTES tensor and supplies an 8-byte raw_input_contents chunk (>= 4 * 1 minimum bytes), but sets the 4-byte little-endian u32 length prefix inside the chunk to 100 (0x64000000). Custos decodes each 4-byte prefix inside verify_bytes_chunk() and blocks the 100-byte over-read.",
    segments: [
      {
        kind: "tag",
        bytes: "2A 18 [0A 06 prompt  12 05 BYTES  1A 01 01]",
        label: "InferInputTensor: BYTES [1]",
        offset: "0x24..0x3E",
        detail: "Declares 1 variable-length BYTES element."
      },
      {
        kind: "exploit",
        bytes: "3A 08 [64 00 00 00  'a' 'b' 'c' 'd'] (ABORT)",
        label: "Field 7: u32 Prefix = 100 Inside 8 B Chunk",
        offset: "0x3E..0x48",
        detail:
          "verify_bytes_chunk() reads little-endian u32 = 100 at offset 0. Required chunk size (4 + 100 = 104 B) exceeds actual chunk length (8 B) -> ParseError::PayloadSizeMismatch."
      }
    ]
  },
  {
    id: "shape_packed_ones",
    group: "Exploit Family 5: Oracle Parity & Framing",
    name: "shape_packed_ones (100,000 Packed Unit Dimensions)",
    badge: "REJECT",
    badgeClass: "badge-red",
    category: "shape_budget",
    totalBytes: "100,065 B (framed)",
    verdict: "DENY (ImmediateResponse)",
    httpStatus: "400 Bad Request",
    grpcStatus: "3 (INVALID_ARGUMENT)",
    errorVariant: "ParseError::TagLimitExceeded { count: 1025, max: 1024 }",
    maxDepth: "1 / 16",
    tensorElements: "Product = 1 (100,000 dims of 1)",
    skippedBytes: "26 B",
    summary:
      "Packs 100,000 dimensions of value 1 inside a single packed shape field (Tag 0x1A). Because 1^100000 == 1, the element product never exceeds max_tensor_elements. Custos counts each packed dimension varint toward max_tags_scanned (1,024) and aborts in microseconds at dimension #1,021.",
    segments: [
      {
        kind: "grpc",
        bytes: "00 00 01 86 DC",
        label: "gRPC Header (100,060 B)",
        offset: "0x00..0x05",
        detail: "5-byte uncompressed gRPC frame header."
      },
      {
        kind: "exploit",
        bytes: "1A 90 8D 06 [01 01 01 ... x100,000 -> ABORT at #1,025]",
        label: "Packed Shape Flood (Aborted at Tag/Varint #1,025)",
        offset: "0x39..0x186E1",
        detail:
          "Inside (MsgContext::InputTensor, 3), every packed dimension varint increments report.tags_scanned. At tag #1,025, Custos aborts immediately with ParseError::TagLimitExceeded instead of scanning all 100,000 bytes."
      }
    ]
  },
  {
    id: "rpc_system_shared_memory_register",
    group: "Exploit Family 5: Oracle Parity & Framing",
    name: "rpc_system_shared_memory_register (Admin RPC Path Block)",
    badge: "REJECT",
    badgeClass: "badge-red",
    category: "rpc",
    totalBytes: "5 B (framed)",
    verdict: "DENY (ImmediateResponse at RequestHeaders)",
    httpStatus: "403 Forbidden",
    grpcStatus: "7 (PERMISSION_DENIED)",
    errorVariant: "custos_denied:unauthorized_rpc_method",
    maxDepth: "0 / 16 (Rejected at HTTP/2 Headers)",
    tensorElements: "0 (Body Never Evaluated)",
    skippedBytes: "0 B",
    summary:
      "Targets Triton's unauthenticated SystemSharedMemoryRegister management RPC (:path = /inference.GRPCInferenceService/SystemSharedMemoryRegister). Custos enforces a strict unary KServe v2 :path allowlist during the RequestHeaders phase and rejects the call with HTTP 403 Forbidden / gRPC PERMISSION_DENIED (7) before reading the request body.",
    segments: [
      {
        kind: "exploit",
        bytes: ":path = /inference.GRPCInferenceService/SystemSharedMemoryRegister",
        label: "HTTP/2 RequestHeaders :path Check (ABORT -> 403 / gRPC 7)",
        offset: "Headers",
        detail:
          "is_allowed_kserve_rpc_path() only admits ModelInfer, ServerLive, ServerReady, ModelReady, ModelMetadata, and ModelConfig. All shared-memory registration, model repository load/unload, and bi-di streaming RPCs are rejected with HTTP 403 / gRPC status 7 (PERMISSION_DENIED)."
      }
    ]
  }
];

const TOPOLOGIES = {
  prod: {
    title: "With Custos",
    badge: "Production Protected",
    badgeClass: "badge-green",
    summary:
      "Envoy sends each request to Custos. Custos checks it. Safe requests go to the AI server. Custos blocks requests that fail the check.",
    nodes: [
      {
        title: "Request sender",
        meta: "Test client",
        desc: "Sends normal requests and test attacks.",
        cls: ""
      },
      {
        title: "Envoy gateway",
        meta: "Request gateway",
        desc: "Receives each request and sends it to Custos for a check.",
        cls: ""
      },
      {
        title: "Custos checker",
        meta: "Request safety check",
        desc: "Checks each request. Blocks unsafe requests and sends safe requests to the AI server.",
        cls: "highlight-custos"
      },
      {
        title: "AI server",
        meta: "Model server",
        desc: "Receives requests that pass the check and runs the model.",
        cls: ""
      }
    ],
    specs: [
      ["Manifest / Config", "configmap-envoy.yaml + deployment-gateway-pod.yaml"],
      ["IPC Transport", "In-Memory Unix Domain Socket (/var/run/custos/ext_proc.sock, 0660)"],
      ["Failure & Security Policy", "Fail-Closed (failure_mode_allow: false, 250ms timeout) • UID 10001, 0 Caps"],
      ["Attack Survival Verdict", "100% Benign Survival • 33/33 Exploits Dropped (59/59 Oracle Sweep) • 0% False Positives"]
    ]
  },
  baseline: {
    title: "Proxy only",
    badge: "Proxy Baseline",
    badgeClass: "badge-blue",
    summary:
      "Envoy sends each request straight to the AI server. It does not check the request data. This setup shows what happens without Custos.",
    nodes: [
      {
        title: "Request sender",
        meta: "Test client",
        desc: "Sends normal requests and test attacks.",
        cls: ""
      },
      {
        title: "Envoy gateway",
        meta: "Proxy only",
        desc: "Forwards each request. Does not check the request data.",
        cls: ""
      },
      {
        title: "AI server",
        meta: "No Custos check",
        desc: "Receives requests, including unsafe requests that the proxy does not detect.",
        cls: "highlight-danger"
      }
    ],
    specs: [
      ["Manifest / Config", "deployment-envoy-baseline-pod.yaml / envoy-baseline.yaml"],
      ["HTTP Filters", "envoy.filters.http.buffer (16 MiB) + envoy.filters.http.router (no ext_proc)"],
      ["Scientific Role", "Isolates Envoy HTTP/2 proxy & 16 MiB buffering cost from custos-proc UDS scan"],
      ["Vulnerability State", "Passes all 33 L7 Protobuf wire & parameter exploits (<16 MiB) to backend"]
    ]
  },
  control: {
    title: "No protection",
    badge: "Unprotected Control",
    badgeClass: "badge-red",
    summary:
      "Requests go straight to the AI server. They do not pass through Envoy or Custos.",
    nodes: [
      {
        title: "Request sender",
        meta: "Test client",
        desc: "Sends requests straight to the AI server.",
        cls: ""
      },
      {
        title: "AI server",
        meta: "Direct connection",
        desc: "Receives requests with no safety check before they arrive.",
        cls: "highlight-danger"
      }
    ],
    specs: [
      ["Data Path", "Direct HTTP/2 gRPC to triton-inference-svc (NodePort :30801 -> :9001)"],
      ["Admission Control", "None (Control Group)"],
      ["Scientific Role", "Establishes raw backend latency floor & unprotected worker stall behavior"],
      ["Vulnerability State", "Directly exposed to all 33 Protobuf wire, shape, parity & parameter exploits"]
    ]
  }
};

// Reference empirical evaluation dataset
const REFERENCE_TRIALS = [
  {
    "label": "homelab_control_steady-benign_fp32_rps100_mean_n5",
    "topology": "Unprotected Control",
    "regime": "steady-benign",
    "benign_profile": "ResNet-50 B=1 (FP32)",
    "rps": 100,
    "achieved_rps": 100.1,
    "fpr": 0.0,
    "tp_drop": null,
    "p50_ms": 7.18,
    "p90_ms": 7.7,
    "p95_ms": 7.8,
    "p99_ms": 8.03,
    "p999_ms": 8.18,
    "p9999_ms": 8.18,
    "cpu_per_1k": 65.75,
    "rss_mb": 29.39,
    "survival": "Control Floor (No Attack)",
    "trials_merged": 5
  },
  {
    "label": "homelab_baseline_steady-benign_fp32_rps100_mean_n5",
    "topology": "Proxy Baseline",
    "regime": "steady-benign",
    "benign_profile": "ResNet-50 B=1 (FP32)",
    "rps": 100,
    "achieved_rps": 100.0,
    "fpr": 0.0,
    "tp_drop": null,
    "p50_ms": 9.17,
    "p90_ms": 9.74,
    "p95_ms": 9.88,
    "p99_ms": 10.1,
    "p999_ms": 10.62,
    "p9999_ms": 10.62,
    "cpu_per_1k": 147.14,
    "rss_mb": 107.3,
    "survival": "Hardened Envoy Baseline (No Attack)",
    "trials_merged": 5
  },
  {
    "label": "homelab_prod_steady-benign_fp32_rps100_mean_n5",
    "topology": "Custos Production",
    "regime": "steady-benign",
    "benign_profile": "ResNet-50 B=1 (FP32)",
    "rps": 100,
    "achieved_rps": 99.9,
    "fpr": 0.0,
    "tp_drop": null,
    "p50_ms": 11.98,
    "p90_ms": 12.65,
    "p95_ms": 12.83,
    "p99_ms": 13.12,
    "p999_ms": 13.9,
    "p9999_ms": 13.9,
    "cpu_per_1k": 219.34,
    "rss_mb": 149.79,
    "survival": "100% Healthy (+2815 µs P50 vs Baseline)",
    "trials_merged": 5
  },
  {
    "label": "homelab_control_steady-benign_fp32_rps150_mean_n5",
    "topology": "Unprotected Control",
    "regime": "steady-benign",
    "benign_profile": "ResNet-50 B=1 (FP32)",
    "rps": 150,
    "achieved_rps": 150.0,
    "fpr": 0.0,
    "tp_drop": null,
    "p50_ms": 6.75,
    "p90_ms": 7.59,
    "p95_ms": 7.94,
    "p99_ms": 8.21,
    "p999_ms": 8.95,
    "p9999_ms": 8.95,
    "cpu_per_1k": 61.73,
    "rss_mb": 29.59,
    "survival": "Control Floor (No Attack)",
    "trials_merged": 5
  },
  {
    "label": "homelab_baseline_steady-benign_fp32_rps150_mean_n5",
    "topology": "Proxy Baseline",
    "regime": "steady-benign",
    "benign_profile": "ResNet-50 B=1 (FP32)",
    "rps": 150,
    "achieved_rps": 149.9,
    "fpr": 0.0,
    "tp_drop": null,
    "p50_ms": 8.82,
    "p90_ms": 9.66,
    "p95_ms": 9.94,
    "p99_ms": 10.46,
    "p999_ms": 13.37,
    "p9999_ms": 13.37,
    "cpu_per_1k": 127.78,
    "rss_mb": 107.53,
    "survival": "Hardened Envoy Baseline (No Attack)",
    "trials_merged": 5
  },
  {
    "label": "homelab_prod_steady-benign_fp32_rps150_mean_n5",
    "topology": "Custos Production",
    "regime": "steady-benign",
    "benign_profile": "ResNet-50 B=1 (FP32)",
    "rps": 150,
    "achieved_rps": 149.9,
    "fpr": 0.0,
    "tp_drop": null,
    "p50_ms": 9.9,
    "p90_ms": 10.93,
    "p95_ms": 11.23,
    "p99_ms": 11.85,
    "p999_ms": 13.32,
    "p9999_ms": 13.32,
    "cpu_per_1k": 148.4,
    "rss_mb": 150.03,
    "survival": "100% Healthy (+1077 µs P50 vs Baseline)",
    "trials_merged": 5
  },
  {
    "label": "homelab_control_steady-benign_bytes_rps100_mean_n5",
    "topology": "Unprotected Control",
    "regime": "steady-benign",
    "benign_profile": "BYTES Tensor [1, 2]",
    "rps": 100,
    "achieved_rps": 100.2,
    "fpr": 0.0,
    "tp_drop": null,
    "p50_ms": 1.72,
    "p90_ms": 2.23,
    "p95_ms": 2.31,
    "p99_ms": 2.42,
    "p999_ms": 2.48,
    "p9999_ms": 2.48,
    "cpu_per_1k": 7.46,
    "rss_mb": 29.65,
    "survival": "Control Floor (No Attack)",
    "trials_merged": 5
  },
  {
    "label": "homelab_baseline_steady-benign_bytes_rps100_mean_n5",
    "topology": "Proxy Baseline",
    "regime": "steady-benign",
    "benign_profile": "BYTES Tensor [1, 2]",
    "rps": 100,
    "achieved_rps": 100.2,
    "fpr": 0.0,
    "tp_drop": null,
    "p50_ms": 2.89,
    "p90_ms": 3.39,
    "p95_ms": 3.45,
    "p99_ms": 3.53,
    "p999_ms": 4.46,
    "p9999_ms": 4.46,
    "cpu_per_1k": 35.45,
    "rss_mb": 107.54,
    "survival": "Hardened Envoy Baseline (No Attack)",
    "trials_merged": 5
  },
  {
    "label": "homelab_prod_steady-benign_bytes_rps100_mean_n5",
    "topology": "Custos Production",
    "regime": "steady-benign",
    "benign_profile": "BYTES Tensor [1, 2]",
    "rps": 100,
    "achieved_rps": 100.1,
    "fpr": 0.0,
    "tp_drop": null,
    "p50_ms": 4.06,
    "p90_ms": 4.62,
    "p95_ms": 4.71,
    "p99_ms": 4.82,
    "p999_ms": 5.6,
    "p9999_ms": 5.6,
    "cpu_per_1k": 69.24,
    "rss_mb": 150.04,
    "survival": "100% Healthy (+1173 µs P50 vs Baseline)",
    "trials_merged": 5
  },
  {
    "label": "homelab_control_steady-benign_bytes_rps150_mean_n5",
    "topology": "Unprotected Control",
    "regime": "steady-benign",
    "benign_profile": "BYTES Tensor [1, 2]",
    "rps": 150,
    "achieved_rps": 150.2,
    "fpr": 0.0,
    "tp_drop": null,
    "p50_ms": 1.79,
    "p90_ms": 2.35,
    "p95_ms": 2.5,
    "p99_ms": 2.71,
    "p999_ms": 2.82,
    "p9999_ms": 2.82,
    "cpu_per_1k": 7.38,
    "rss_mb": 29.65,
    "survival": "Control Floor (No Attack)",
    "trials_merged": 5
  },
  {
    "label": "homelab_baseline_steady-benign_bytes_rps150_mean_n5",
    "topology": "Proxy Baseline",
    "regime": "steady-benign",
    "benign_profile": "BYTES Tensor [1, 2]",
    "rps": 150,
    "achieved_rps": 150.1,
    "fpr": 0.0,
    "tp_drop": null,
    "p50_ms": 2.98,
    "p90_ms": 3.6,
    "p95_ms": 3.73,
    "p99_ms": 3.96,
    "p999_ms": 4.69,
    "p9999_ms": 4.69,
    "cpu_per_1k": 34.87,
    "rss_mb": 107.54,
    "survival": "Hardened Envoy Baseline (No Attack)",
    "trials_merged": 5
  },
  {
    "label": "homelab_prod_steady-benign_bytes_rps150_mean_n5",
    "topology": "Custos Production",
    "regime": "steady-benign",
    "benign_profile": "BYTES Tensor [1, 2]",
    "rps": 150,
    "achieved_rps": 150.1,
    "fpr": 0.0,
    "tp_drop": null,
    "p50_ms": 3.95,
    "p90_ms": 4.55,
    "p95_ms": 4.69,
    "p99_ms": 4.92,
    "p999_ms": 5.26,
    "p9999_ms": 5.26,
    "cpu_per_1k": 67.24,
    "rss_mb": 150.04,
    "survival": "100% Healthy (+970 µs P50 vs Baseline)",
    "trials_merged": 5
  },
  {
    "label": "homelab_control_steady-benign_mixed_rps100_mean_n5",
    "topology": "Unprotected Control",
    "regime": "steady-benign",
    "benign_profile": "Mixed (FP32 + BYTES + D≤16)",
    "rps": 100,
    "achieved_rps": 100.2,
    "fpr": 0.0,
    "tp_drop": null,
    "p50_ms": 2.18,
    "p90_ms": 7.48,
    "p95_ms": 7.73,
    "p99_ms": 8.0,
    "p999_ms": 8.42,
    "p9999_ms": 8.42,
    "cpu_per_1k": 23.74,
    "rss_mb": 46.22,
    "survival": "Control Floor (No Attack)",
    "trials_merged": 5
  },
  {
    "label": "homelab_baseline_steady-benign_mixed_rps100_mean_n5",
    "topology": "Proxy Baseline",
    "regime": "steady-benign",
    "benign_profile": "Mixed (FP32 + BYTES + D≤16)",
    "rps": 100,
    "achieved_rps": 100.2,
    "fpr": 0.0,
    "tp_drop": null,
    "p50_ms": 3.35,
    "p90_ms": 9.89,
    "p95_ms": 10.1,
    "p99_ms": 10.46,
    "p999_ms": 10.88,
    "p9999_ms": 10.88,
    "cpu_per_1k": 66.26,
    "rss_mb": 134.91,
    "survival": "Hardened Envoy Baseline (No Attack)",
    "trials_merged": 5
  },
  {
    "label": "homelab_prod_steady-benign_mixed_rps100_mean_n5",
    "topology": "Custos Production",
    "regime": "steady-benign",
    "benign_profile": "Mixed (FP32 + BYTES + D≤16)",
    "rps": 100,
    "achieved_rps": 100.1,
    "fpr": 0.0,
    "tp_drop": null,
    "p50_ms": 4.53,
    "p90_ms": 12.87,
    "p95_ms": 13.14,
    "p99_ms": 13.46,
    "p999_ms": 13.94,
    "p9999_ms": 13.94,
    "cpu_per_1k": 115.31,
    "rss_mb": 201.87,
    "survival": "100% Healthy (+1184 µs P50 vs Baseline)",
    "trials_merged": 5
  },
  {
    "label": "homelab_control_steady-benign_mixed_rps150_mean_n5",
    "topology": "Unprotected Control",
    "regime": "steady-benign",
    "benign_profile": "Mixed (FP32 + BYTES + D≤16)",
    "rps": 150,
    "achieved_rps": 150.2,
    "fpr": 0.0,
    "tp_drop": null,
    "p50_ms": 1.96,
    "p90_ms": 7.43,
    "p95_ms": 7.69,
    "p99_ms": 8.08,
    "p999_ms": 8.66,
    "p9999_ms": 8.66,
    "cpu_per_1k": 23.5,
    "rss_mb": 46.22,
    "survival": "Control Floor (No Attack)",
    "trials_merged": 5
  },
  {
    "label": "homelab_baseline_steady-benign_mixed_rps150_mean_n5",
    "topology": "Proxy Baseline",
    "regime": "steady-benign",
    "benign_profile": "Mixed (FP32 + BYTES + D≤16)",
    "rps": 150,
    "achieved_rps": 150.1,
    "fpr": 0.0,
    "tp_drop": null,
    "p50_ms": 3.31,
    "p90_ms": 10.08,
    "p95_ms": 10.45,
    "p99_ms": 10.92,
    "p999_ms": 11.62,
    "p9999_ms": 11.62,
    "cpu_per_1k": 63.5,
    "rss_mb": 134.91,
    "survival": "Hardened Envoy Baseline (No Attack)",
    "trials_merged": 5
  },
  {
    "label": "homelab_prod_steady-benign_mixed_rps150_mean_n5",
    "topology": "Custos Production",
    "regime": "steady-benign",
    "benign_profile": "Mixed (FP32 + BYTES + D≤16)",
    "rps": 150,
    "achieved_rps": 150.1,
    "fpr": 0.0,
    "tp_drop": null,
    "p50_ms": 4.74,
    "p90_ms": 13.23,
    "p95_ms": 13.6,
    "p99_ms": 14.05,
    "p999_ms": 14.45,
    "p9999_ms": 14.45,
    "cpu_per_1k": 110.07,
    "rss_mb": 201.87,
    "survival": "100% Healthy (+1432 µs P50 vs Baseline)",
    "trials_merged": 5
  },
  {
    "label": "homelab_control_interleaved_mixed_rps100_mean_n5",
    "topology": "Unprotected Control",
    "regime": "interleaved",
    "benign_profile": "Mixed (FP32 + BYTES + D≤16)",
    "rps": 100,
    "achieved_rps": 100.1,
    "fpr": 0.0,
    "tp_drop": 0.0,
    "p50_ms": 2.2,
    "p90_ms": 7.53,
    "p95_ms": 7.83,
    "p99_ms": 8.07,
    "p999_ms": 8.39,
    "p9999_ms": 8.39,
    "cpu_per_1k": 15.97,
    "rss_mb": 46.22,
    "survival": "Degraded (37 Backend Runtime Faults)",
    "trials_merged": 5
  },
  {
    "label": "homelab_baseline_interleaved_mixed_rps100_mean_n5",
    "topology": "Proxy Baseline",
    "regime": "interleaved",
    "benign_profile": "Mixed (FP32 + BYTES + D≤16)",
    "rps": 100,
    "achieved_rps": 100.1,
    "fpr": 0.0,
    "tp_drop": 0.0,
    "p50_ms": 3.14,
    "p90_ms": 9.65,
    "p95_ms": 9.93,
    "p99_ms": 10.27,
    "p999_ms": 10.76,
    "p9999_ms": 10.76,
    "cpu_per_1k": 44.53,
    "rss_mb": 134.91,
    "survival": "Degraded (37 Backend Runtime Faults)",
    "trials_merged": 5
  },
  {
    "label": "homelab_prod_interleaved_mixed_rps100_mean_n5",
    "topology": "Custos Production",
    "regime": "interleaved",
    "benign_profile": "Mixed (FP32 + BYTES + D≤16)",
    "rps": 100,
    "achieved_rps": 100.1,
    "fpr": 0.0,
    "tp_drop": 1.0,
    "p50_ms": 4.61,
    "p90_ms": 12.96,
    "p95_ms": 13.27,
    "p99_ms": 13.65,
    "p999_ms": 15.09,
    "p9999_ms": 15.09,
    "cpu_per_1k": 76.19,
    "rss_mb": 201.87,
    "survival": "100% Protected (33/33 Exploits Dropped)",
    "trials_merged": 5
  },
  {
    "label": "homelab_control_interleaved_mixed_rps150_mean_n5",
    "topology": "Unprotected Control",
    "regime": "interleaved",
    "benign_profile": "Mixed (FP32 + BYTES + D≤16)",
    "rps": 150,
    "achieved_rps": 149.9,
    "fpr": 0.0,
    "tp_drop": 0.0,
    "p50_ms": 1.99,
    "p90_ms": 7.43,
    "p95_ms": 7.68,
    "p99_ms": 8.1,
    "p999_ms": 8.73,
    "p9999_ms": 8.73,
    "cpu_per_1k": 15.95,
    "rss_mb": 46.22,
    "survival": "Degraded (56 Backend Runtime Faults)",
    "trials_merged": 5
  },
  {
    "label": "homelab_baseline_interleaved_mixed_rps150_mean_n5",
    "topology": "Proxy Baseline",
    "regime": "interleaved",
    "benign_profile": "Mixed (FP32 + BYTES + D≤16)",
    "rps": 150,
    "achieved_rps": 149.9,
    "fpr": 0.0,
    "tp_drop": 0.0,
    "p50_ms": 3.35,
    "p90_ms": 10.07,
    "p95_ms": 10.4,
    "p99_ms": 10.9,
    "p999_ms": 11.47,
    "p9999_ms": 11.47,
    "cpu_per_1k": 42.96,
    "rss_mb": 134.91,
    "survival": "Degraded (56 Backend Runtime Faults)",
    "trials_merged": 5
  },
  {
    "label": "homelab_prod_interleaved_mixed_rps150_mean_n5",
    "topology": "Custos Production",
    "regime": "interleaved",
    "benign_profile": "Mixed (FP32 + BYTES + D≤16)",
    "rps": 150,
    "achieved_rps": 150.1,
    "fpr": 0.0,
    "tp_drop": 1.0,
    "p50_ms": 5.45,
    "p90_ms": 13.34,
    "p95_ms": 13.67,
    "p99_ms": 14.11,
    "p999_ms": 15.67,
    "p9999_ms": 15.67,
    "cpu_per_1k": 72.97,
    "rss_mb": 201.87,
    "survival": "100% Protected (33/33 Exploits Dropped)",
    "trials_merged": 5
  },
  {
    "label": "homelab_control_saturating-burst_mixed_rps500_mean_n5",
    "topology": "Unprotected Control",
    "regime": "saturating-burst",
    "benign_profile": "Mixed (FP32 + BYTES + D≤16)",
    "rps": 500,
    "achieved_rps": 915.9,
    "fpr": 0.0,
    "tp_drop": 0.0,
    "p50_ms": 308.96,
    "p90_ms": 511.18,
    "p95_ms": 511.18,
    "p99_ms": 511.34,
    "p999_ms": 511.34,
    "p9999_ms": 511.34,
    "cpu_per_1k": 37.09,
    "rss_mb": 46.22,
    "survival": "Backend Flooded (Benign P99 511.3 ms)",
    "trials_merged": 5
  },
  {
    "label": "homelab_baseline_saturating-burst_mixed_rps500_mean_n5",
    "topology": "Proxy Baseline",
    "regime": "saturating-burst",
    "benign_profile": "Mixed (FP32 + BYTES + D≤16)",
    "rps": 500,
    "achieved_rps": 912.9,
    "fpr": 0.0,
    "tp_drop": 0.0,
    "p50_ms": 323.12,
    "p90_ms": 516.84,
    "p95_ms": 517.94,
    "p99_ms": 518.0,
    "p999_ms": 518.0,
    "p9999_ms": 518.0,
    "cpu_per_1k": 81.99,
    "rss_mb": 134.91,
    "survival": "Backend Flooded (Benign P99 518.0 ms)",
    "trials_merged": 5
  },
  {
    "label": "homelab_prod_saturating-burst_mixed_rps500_mean_n5",
    "topology": "Custos Production",
    "regime": "saturating-burst",
    "benign_profile": "Mixed (FP32 + BYTES + D≤16)",
    "rps": 500,
    "achieved_rps": 3275.4,
    "fpr": 0.0,
    "tp_drop": 1.0,
    "p50_ms": 102.64,
    "p90_ms": 150.92,
    "p95_ms": 152.99,
    "p99_ms": 153.01,
    "p999_ms": 153.01,
    "p9999_ms": 153.01,
    "cpu_per_1k": 182.14,
    "rss_mb": 201.87,
    "survival": "100% Benign Survival (250/250 OK, Benign P99 153.0 ms)",
    "trials_merged": 5
  }
];

const ORACLE_SWEEP_ROWS = [
  {
    "name": "benign_b1",
    "category": "benign",
    "expected": "allow",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 602170,
    "prod_status": "OK",
    "prod_match": true,
    "prod_latency_ms": 8.85,
    "baseline_status": "OK",
    "baseline_match": true,
    "baseline_latency_ms": 7.77,
    "control_status": "OK",
    "control_match": true,
    "control_latency_ms": 6.31,
    "notes": "resnet50 FP32 NCHW [1,3,224,224] source=synthetic tensor_bytes=602112"
  },
  {
    "name": "benign_b2",
    "category": "benign",
    "expected": "allow",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 1204282,
    "prod_status": "OK",
    "prod_match": true,
    "prod_latency_ms": 17.23,
    "baseline_status": "OK",
    "baseline_match": true,
    "baseline_latency_ms": 14.25,
    "control_status": "OK",
    "control_match": true,
    "control_latency_ms": 11.25,
    "notes": "resnet50 FP32 NCHW [2,3,224,224] source=synthetic tensor_bytes=1204224"
  },
  {
    "name": "benign_b4",
    "category": "benign",
    "expected": "allow",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 2408507,
    "prod_status": "OK",
    "prod_match": true,
    "prod_latency_ms": 37.91,
    "baseline_status": "OK",
    "baseline_match": true,
    "baseline_latency_ms": 25.92,
    "control_status": "OK",
    "control_match": true,
    "control_latency_ms": 22.19,
    "notes": "resnet50 FP32 NCHW [4,3,224,224] source=synthetic tensor_bytes=2408448"
  },
  {
    "name": "benign_b8",
    "category": "benign",
    "expected": "allow",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 4816955,
    "prod_status": "OK",
    "prod_match": true,
    "prod_latency_ms": 64.71,
    "baseline_status": "OK",
    "baseline_match": true,
    "baseline_latency_ms": 48.27,
    "control_status": "OK",
    "control_match": true,
    "control_latency_ms": 43.38,
    "notes": "resnet50 FP32 NCHW [8,3,224,224] source=synthetic tensor_bytes=4816896"
  },
  {
    "name": "benign_b16",
    "category": "benign",
    "expected": "allow",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 9633852,
    "prod_status": "OK",
    "prod_match": true,
    "prod_latency_ms": 127.45,
    "baseline_status": "OK",
    "baseline_match": true,
    "baseline_latency_ms": 105.32,
    "control_status": "OK",
    "control_match": true,
    "control_latency_ms": 85.7,
    "notes": "resnet50 FP32 NCHW [16,3,224,224] source=synthetic tensor_bytes=9633792"
  },
  {
    "name": "benign_bytes_tensor",
    "category": "benign",
    "expected": "allow",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 134,
    "prod_status": "OK",
    "prod_match": true,
    "prod_latency_ms": 2.19,
    "baseline_status": "OK",
    "baseline_match": true,
    "baseline_latency_ms": 2.14,
    "control_status": "OK",
    "control_match": true,
    "control_latency_ms": 0.69,
    "notes": "KServe v2 BYTES tensor [1,2] with length-prefixed strings (73 B raw_input_contents)"
  },
  {
    "name": "nesting_depth_15",
    "category": "nesting_bomb",
    "expected": "allow",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 42,
    "prod_status": "OK",
    "prod_match": true,
    "prod_latency_ms": 1.95,
    "baseline_status": "OK",
    "baseline_match": true,
    "baseline_latency_ms": 2.23,
    "control_status": "OK",
    "control_match": true,
    "control_latency_ms": 0.56,
    "notes": "field-5 length-delimited wrap depth=15; boundary allow is D<=16"
  },
  {
    "name": "nesting_depth_16",
    "category": "nesting_bomb",
    "expected": "allow",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 44,
    "prod_status": "OK",
    "prod_match": true,
    "prod_latency_ms": 1.96,
    "baseline_status": "OK",
    "baseline_match": true,
    "baseline_latency_ms": 2.3,
    "control_status": "OK",
    "control_match": true,
    "control_latency_ms": 0.66,
    "notes": "field-5 length-delimited wrap depth=16; boundary allow is D<=16"
  },
  {
    "name": "nesting_depth_17",
    "category": "nesting_bomb",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 46,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.72,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 38.43,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.19,
    "notes": "field-5 length-delimited wrap depth=17; boundary allow is D<=16"
  },
  {
    "name": "nesting_depth_20",
    "category": "nesting_bomb",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 52,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.51,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 38.5,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.09,
    "notes": "field-5 length-delimited wrap depth=20; boundary allow is D<=16"
  },
  {
    "name": "nesting_depth_50",
    "category": "nesting_bomb",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 112,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.67,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 37.76,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.53,
    "notes": "field-5 length-delimited wrap depth=50; boundary allow is D<=16"
  },
  {
    "name": "nesting_depth_100",
    "category": "nesting_bomb",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 249,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 2.03,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 36.58,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.41,
    "notes": "field-5 length-delimited wrap depth=100; boundary allow is D<=16"
  },
  {
    "name": "nesting_depth_250",
    "category": "nesting_bomb",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 699,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.83,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 37.9,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.44,
    "notes": "field-5 length-delimited wrap depth=250; boundary allow is D<=16"
  },
  {
    "name": "nesting_depth_500",
    "category": "nesting_bomb",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 1449,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.93,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 36.82,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.55,
    "notes": "field-5 length-delimited wrap depth=500; boundary allow is D<=16"
  },
  {
    "name": "shape_neg_packed",
    "category": "shape_overflow",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 60,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.62,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 37.31,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.04,
    "notes": "packed shape [1,3,-1,224]; -1 is the 10-byte two's-complement varint"
  },
  {
    "name": "shape_neg_unpacked",
    "category": "shape_overflow",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 62,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.31,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 37.23,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.51,
    "notes": "unpacked shape [1,3,-1,224] via repeated tag 0x18"
  },
  {
    "name": "shape_wrap_64bit_packed",
    "category": "shape_overflow",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 57,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.15,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 37.35,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.4,
    "notes": "packed shape [2, 2**62, 2] whose product is 0 mod 2**64"
  },
  {
    "name": "shape_wrap_64bit_unpacked",
    "category": "shape_overflow",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 58,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.15,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 37.13,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.44,
    "notes": "unpacked shape [2, 2**62, 2]"
  },
  {
    "name": "shape_oom_massive_packed",
    "category": "shape_overflow",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 52,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.14,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 37.44,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.58,
    "notes": "packed shape [1024,1024,1024] ~= 1.07e9 elements"
  },
  {
    "name": "shape_oom_massive_unpacked",
    "category": "shape_overflow",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 53,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.31,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 36.64,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.14,
    "notes": "unpacked shape [1024,1024,1024]"
  },
  {
    "name": "shape_reordered_tail",
    "category": "shape_overflow",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 16440,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 2.01,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 38.73,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.63,
    "notes": "16 KiB field 7 precedes malicious field 5 [1024,1024,1024]"
  },
  {
    "name": "shape_buffer_mismatch_underread",
    "category": "shape_overflow",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 118,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.46,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 38.35,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.56,
    "notes": "KServe v2 shape-to-buffer parity mismatch: shape [4,3,224,224] FP32 (2,408,448 B expected) with 64 B raw_input_contents"
  },
  {
    "name": "varint_unterminated_11",
    "category": "malformed_varint",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 22,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.49,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 37.92,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.56,
    "notes": "tag 0x08 followed by 11 bytes of 0xFF (MSB=1)"
  },
  {
    "name": "varint_unterminated_64",
    "category": "malformed_varint",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 75,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.6,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 37.04,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.29,
    "notes": "tag 0x08 followed by 64 bytes of 0x80 (MSB=1)"
  },
  {
    "name": "varint_10th_byte_overflow",
    "category": "malformed_varint",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 21,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.65,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 38.2,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 36.91,
    "notes": "tag 0x08, 9x 0xFF, terminating 0x7F with bits above a 64-bit shift"
  },
  {
    "name": "varint_truncated_eof",
    "category": "malformed_varint",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 14,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.6,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 38.46,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.12,
    "notes": "tag 0x08 followed by 3 bytes of 0xFF and immediate EOF"
  },
  {
    "name": "sgroup_wire_type_3_bomb",
    "category": "wire_type_exploit",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 268,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.56,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 38.56,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.2,
    "notes": "CVE-2024-7254-class: 64 nested Wire Type 3 (SGROUP) tags bypassing recursion counters"
  },
  {
    "name": "unknown_field_ast_flood",
    "category": "ast_flood",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 4510,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.68,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 38.52,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.72,
    "notes": "CVE-2022-1941 / CVE-2021-22569-class: 1,500 shallow unknown tags at D=0 (> 1,024 tag limit)"
  },
  {
    "name": "cve_2024_0088_shm_params_infer",
    "category": "shm_param_injection",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 177,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.69,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 38.15,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.2,
    "notes": "CVE-2024-0088: shared_memory_region/offset/byte_size injected inside ModelInfer parameters map"
  },
  {
    "name": "grpc_compressed_flag_01",
    "category": "compressed_frame",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 57,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.41,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 38.11,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 36.35,
    "notes": "Compressed gRPC frame (flag=0x01 / gzip) concealing an OOM tensor payload from uncompressed wire inspection"
  },
  {
    "name": "benign_multichunk_aligned",
    "category": "chunk_parity",
    "expected": "allow",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 102,
    "prod_status": "OK",
    "prod_match": true,
    "prod_latency_ms": 2.49,
    "baseline_status": "OK",
    "baseline_match": true,
    "baseline_latency_ms": 2.35,
    "control_status": "OK",
    "control_match": true,
    "control_latency_ms": 0.99,
    "notes": "FP32 [4] then FP32 [1] with raw chunks of 16 then 4 bytes"
  },
  {
    "name": "benign_contents_fp32_unpacked",
    "category": "tensor_contents",
    "expected": "allow",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 86,
    "prod_status": "OK",
    "prod_match": true,
    "prod_latency_ms": 2.48,
    "baseline_status": "OK",
    "baseline_match": true,
    "baseline_latency_ms": 2.38,
    "control_status": "OK",
    "control_match": true,
    "control_latency_ms": 0.79,
    "notes": "FP32 [1,4] as four unpacked fp32_contents (field 6, wire type 5), no raw_input_contents"
  },
  {
    "name": "benign_contents_fp32_packed",
    "category": "tensor_contents",
    "expected": "allow",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 82,
    "prod_status": "OK",
    "prod_match": true,
    "prod_latency_ms": 2.53,
    "baseline_status": "OK",
    "baseline_match": true,
    "baseline_latency_ms": 2.45,
    "control_status": "OK",
    "control_match": true,
    "control_latency_ms": 0.82,
    "notes": "FP32 [1,4] as packed fp32_contents (field 6, wire type 2) holding float32 1,2,3,4, no raw_input_contents"
  },
  {
    "name": "benign_mixed_fp32_bytes",
    "category": "bytes_prefix",
    "expected": "allow",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 113,
    "prod_status": "OK",
    "prod_match": true,
    "prod_latency_ms": 2.52,
    "baseline_status": "OK",
    "baseline_match": true,
    "baseline_latency_ms": 2.3,
    "control_status": "OK",
    "control_match": true,
    "control_latency_ms": 0.8,
    "notes": "FP32 [1,4] raw of 16 bytes plus BYTES [1,2] with little-endian u32 prefixes"
  },
  {
    "name": "benign_param_binary_data_size",
    "category": "parameters",
    "expected": "allow",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 106,
    "prod_status": "OK",
    "prod_match": true,
    "prod_latency_ms": 2.48,
    "baseline_status": "OK",
    "baseline_match": true,
    "baseline_latency_ms": 2.37,
    "control_status": "OK",
    "control_match": true,
    "control_latency_ms": 0.9,
    "notes": "FP32 [1,4] with InferParameter key binary_data_size on int64_param field 2"
  },
  {
    "name": "benign_shape_zero_axis",
    "category": "shape_axis",
    "expected": "allow",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 63,
    "prod_status": "OK",
    "prod_match": true,
    "prod_latency_ms": 2.44,
    "baseline_status": "OK",
    "baseline_match": true,
    "baseline_latency_ms": 2.24,
    "control_status": "OK",
    "control_match": true,
    "control_latency_ms": 0.99,
    "notes": "FP32 [1,0,224,224] with an empty raw_input_contents. KServe allows a zero axis"
  },
  {
    "name": "benign_dtype_bool",
    "category": "datatype",
    "expected": "allow",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 58,
    "prod_status": "OK",
    "prod_match": true,
    "prod_latency_ms": 2.58,
    "baseline_status": "OK",
    "baseline_match": true,
    "baseline_latency_ms": 2.37,
    "control_status": "OK",
    "control_match": true,
    "control_latency_ms": 1.07,
    "notes": "BOOL [1,4] with a 4-byte raw chunk"
  },
  {
    "name": "benign_dtype_fp16",
    "category": "datatype",
    "expected": "allow",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 62,
    "prod_status": "OK",
    "prod_match": true,
    "prod_latency_ms": 2.57,
    "baseline_status": "OK",
    "baseline_match": true,
    "baseline_latency_ms": 2.24,
    "control_status": "OK",
    "control_match": true,
    "control_latency_ms": 1.04,
    "notes": "FP16 [1,4] with an 8-byte raw chunk"
  },
  {
    "name": "benign_dtype_bf16",
    "category": "datatype",
    "expected": "allow",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 62,
    "prod_status": "OK",
    "prod_match": true,
    "prod_latency_ms": 2.55,
    "baseline_status": "OK",
    "baseline_match": true,
    "baseline_latency_ms": 2.22,
    "control_status": "OK",
    "control_match": true,
    "control_latency_ms": 1.06,
    "notes": "BF16 [1,4] with an 8-byte raw chunk"
  },
  {
    "name": "benign_dtype_fp64",
    "category": "datatype",
    "expected": "allow",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 86,
    "prod_status": "OK",
    "prod_match": true,
    "prod_latency_ms": 2.37,
    "baseline_status": "OK",
    "baseline_match": true,
    "baseline_latency_ms": 2.4,
    "control_status": "OK",
    "control_match": true,
    "control_latency_ms": 0.96,
    "notes": "FP64 [1,4] with a 32-byte raw chunk"
  },
  {
    "name": "chunk_swap_fp32",
    "category": "chunk_parity",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 92,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.93,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 38.15,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.44,
    "notes": "FP32 [4] bound to a 4-byte chunk and FP32 [1] bound to a 16-byte chunk"
  },
  {
    "name": "chunk_omitted_fp32",
    "category": "chunk_parity",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 93,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.91,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 38.32,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.39,
    "notes": "Two tensors expecting 16 and 4 bytes, with a single 20-byte raw chunk"
  },
  {
    "name": "chunk_swap_reordered",
    "category": "chunk_parity",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 97,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 2.02,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 38.59,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.6,
    "notes": "Swapped raw chunks written before the inputs. Binding is by index, not wire order"
  },
  {
    "name": "contents_fp32_unpacked_short",
    "category": "tensor_contents",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 89,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.91,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 38.5,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.34,
    "notes": "FP32 [4,3,224,224] with four unpacked fp32 values and no raw_input_contents"
  },
  {
    "name": "contents_fp32_unpacked_ceiling",
    "category": "tensor_contents",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 74,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 2.12,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 38.37,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.17,
    "notes": "FP32 [16777216] with one unpacked fp32 value and no raw_input_contents"
  },
  {
    "name": "bytes_length_prefix_oversize",
    "category": "bytes_prefix",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 71,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.72,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 38.1,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.1,
    "notes": "BYTES [1] whose little-endian u32 length is 0xFFFFFFFF inside an 8-byte chunk"
  },
  {
    "name": "bytes_masks_short_fp32",
    "category": "bytes_prefix",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 97,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.9,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 38.35,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.17,
    "notes": "FP32 [4] chunk of 4 bytes compensated by a 16-byte BYTES chunk"
  },
  {
    "name": "shape_sum_four_ceilings",
    "category": "shape_budget",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 126,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.92,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 38.5,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.59,
    "notes": "Four FP32 [16777216] tensors and no raw chunks. Declared elements are 4 times the per-tensor ceiling"
  },
  {
    "name": "shape_packed_ones",
    "category": "shape_budget",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 100060,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 3.13,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 39.7,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 38.47,
    "notes": "One packed shape of 100000 dimensions of 1 (product stays 1). latency_ns is the measurement against the 250 ms ext_proc deadline"
  },
  {
    "name": "datatype_fp64_short_raw",
    "category": "datatype",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 76,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 2.06,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 38.58,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.31,
    "notes": "FP64 [1,4] with a 16-byte raw chunk (the FP32 length)"
  },
  {
    "name": "datatype_unknown_width",
    "category": "datatype",
    "expected": "reject",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 76,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.8,
    "baseline_status": "INTERNAL",
    "baseline_match": false,
    "baseline_latency_ms": 38.23,
    "control_status": "INTERNAL",
    "control_match": false,
    "control_latency_ms": 37.35,
    "notes": "Datatype 'FP32 ' (trailing space) on shape [1,4] with a 16-byte raw chunk. Unknown width fails closed"
  },
  {
    "name": "frame_single",
    "category": "framing",
    "expected": "allow",
    "framing": "http-body",
    "method": "ModelInfer",
    "tx_bytes": 57,
    "prod_status": "OK",
    "prod_match": true,
    "prod_latency_ms": 2.84,
    "baseline_status": "OK",
    "baseline_match": true,
    "baseline_latency_ms": 3.21,
    "control_status": "OK",
    "control_match": true,
    "control_latency_ms": 2.08,
    "notes": "One uncompressed gRPC frame whose declared length equals the body. Sent as the HTTP body, not via tonic"
  },
  {
    "name": "frame_two_concat",
    "category": "framing",
    "expected": "reject",
    "framing": "http-body",
    "method": "ModelInfer",
    "tx_bytes": 114,
    "prod_status": "INVALID_ARGUMENT",
    "prod_match": true,
    "prod_latency_ms": 1.94,
    "baseline_status": "OK",
    "baseline_match": false,
    "baseline_latency_ms": 3.02,
    "control_status": "OK",
    "control_match": false,
    "control_latency_ms": 1.36,
    "notes": "Two complete frames concatenated in one HTTP body"
  },
  {
    "name": "frame_stream_infer_two",
    "category": "framing",
    "expected": "reject",
    "framing": "http-body",
    "method": "ModelStreamInfer",
    "tx_bytes": 114,
    "prod_status": "PERMISSION_DENIED",
    "prod_match": true,
    "prod_latency_ms": 1.56,
    "baseline_status": "OTHER",
    "baseline_match": false,
    "baseline_latency_ms": 2.55,
    "control_status": "OTHER",
    "control_match": false,
    "control_latency_ms": 1.48,
    "notes": "ModelStreamInfer is not on the RPC allowlist. The body is also two frames"
  },
  {
    "name": "rpc_model_infer_empty",
    "category": "rpc",
    "expected": "allow",
    "framing": "protobuf",
    "method": "ModelInfer",
    "tx_bytes": 0,
    "prod_status": "OK",
    "prod_match": true,
    "prod_latency_ms": 1.81,
    "baseline_status": "OK",
    "baseline_match": true,
    "baseline_latency_ms": 2.49,
    "control_status": "OK",
    "control_match": true,
    "control_latency_ms": 0.83,
    "notes": "Empty ModelInfer message. The framed body is a zero-length protobuf"
  },
  {
    "name": "rpc_system_shared_memory_register",
    "category": "rpc",
    "expected": "reject",
    "framing": "protobuf",
    "method": "SystemSharedMemoryRegister",
    "tx_bytes": 0,
    "prod_status": "PERMISSION_DENIED",
    "prod_match": true,
    "prod_latency_ms": 1.15,
    "baseline_status": "OTHER",
    "baseline_match": false,
    "baseline_latency_ms": 1.88,
    "control_status": "OTHER",
    "control_match": false,
    "control_latency_ms": 0.54,
    "notes": "Header allowlist probe. Expected block is PERMISSION_DENIED or HTTP 403, and the body is not forwarded"
  },
  {
    "name": "rpc_cuda_shared_memory_register",
    "category": "rpc",
    "expected": "reject",
    "framing": "protobuf",
    "method": "CudaSharedMemoryRegister",
    "tx_bytes": 0,
    "prod_status": "PERMISSION_DENIED",
    "prod_match": true,
    "prod_latency_ms": 1.19,
    "baseline_status": "OTHER",
    "baseline_match": false,
    "baseline_latency_ms": 1.77,
    "control_status": "OTHER",
    "control_match": false,
    "control_latency_ms": 0.59,
    "notes": "Header allowlist probe. Expected block is PERMISSION_DENIED or HTTP 403"
  },
  {
    "name": "rpc_repository_model_load",
    "category": "rpc",
    "expected": "reject",
    "framing": "protobuf",
    "method": "RepositoryModelLoad",
    "tx_bytes": 0,
    "prod_status": "PERMISSION_DENIED",
    "prod_match": true,
    "prod_latency_ms": 1.27,
    "baseline_status": "OTHER",
    "baseline_match": false,
    "baseline_latency_ms": 1.61,
    "control_status": "OTHER",
    "control_match": false,
    "control_latency_ms": 0.58,
    "notes": "Header allowlist probe. Expected block is PERMISSION_DENIED or HTTP 403"
  },
  {
    "name": "rpc_repository_model_unload",
    "category": "rpc",
    "expected": "reject",
    "framing": "protobuf",
    "method": "RepositoryModelUnload",
    "tx_bytes": 0,
    "prod_status": "PERMISSION_DENIED",
    "prod_match": true,
    "prod_latency_ms": 1.34,
    "baseline_status": "OTHER",
    "baseline_match": false,
    "baseline_latency_ms": 1.65,
    "control_status": "OTHER",
    "control_match": false,
    "control_latency_ms": 0.6,
    "notes": "Header allowlist probe. Expected block is PERMISSION_DENIED or HTTP 403"
  }
];

let activeRegimeFilter = "interleaved";

// Lets motion-init.js animate freshly rendered DOM without coupling the two files.
function emit(name, detail) {
  document.dispatchEvent(new CustomEvent(name, { detail }));
}

// Scanner verdicts render as a glyph rather than a word. The accessible name
// still carries "Allowed" / "Rejected" so screen readers lose nothing.
function verdictIcon(kind) {
  const allow = kind === "allow";
  const label = allow ? "Allowed" : "Rejected";
  const path = allow
    ? '<path d="M5 10.6l3.4 3.4L15 6.8" />'
    : '<path d="M6.4 6.4l7.2 7.2M13.6 6.4l-7.2 7.2" />';
  return (
    `<span class="verdict-icon ${allow ? "is-allow" : "is-reject"}" role="img" aria-label="${label}" title="${label}">` +
    `<svg viewBox="0 0 20 20" aria-hidden="true" focusable="false">${path}</svg>` +
    `</span>`
  );
}

function verdictKind(payload) {
  return payload.badge === "ALLOW" ? "allow" : "reject";
}

// 1. Theme Toggle (Dark Mode <-> Light Mode)
function initTheme() {
  const btn = document.getElementById("theme-toggle");
  const label = document.getElementById("theme-label");
  const html = document.documentElement;

  // The inline <head> script already restored the saved flavour before paint;
  // sync the button label to whatever ended up applied.
  const applyLabel = () => {
    label.textContent =
      html.getAttribute("data-theme") === "latte" ? "Light Mode" : "Dark Mode";
  };
  applyLabel();

  btn.addEventListener("click", () => {
    const next = html.getAttribute("data-theme") === "latte" ? "mocha" : "latte";
    html.setAttribute("data-theme", next);
    applyLabel();
    try {
      localStorage.setItem("custos-theme", next);
    } catch (e) {
      /* storage blocked — flavour just won't persist across reloads */
    }
    renderDashboard();
    emit("custos:themechange", { theme: next });
  });
}

// 2. Interactive KServe v2 Builder & Byte-Stream Anatomy Inspector
const DTYPE_BYTE_WIDTHS = {
  FP32: 4,
  FP64: 8,
  INT64: 8,
  FP16: 2,
  BOOL: 1,
  BYTES: 0, // variable length via 4-byte u32 prefixes
  INVALID_DTYPE: -1
};

const MAX_I64 = 9223372036854775807n;
const MAX_TENSOR_ELEMENTS = 16777216n;
const MAX_NESTING_DEPTH = 16;
const MAX_TAGS_SCANNED = 1024;

let builderState = {
  presetId: "valid-multichunk",
  title: "Valid request · two inputs match their data",
  batchSize: 16,
  nestingDepth: 2,
  tagsScanned: 14,
  tensors: [
    { id: 1, name: "input_0", datatype: "FP32", shapeStr: "4", injectShm: false },
    { id: 2, name: "input_1", datatype: "FP32", shapeStr: "1", injectShm: false }
  ],
  chunks: [
    { id: 1, byteLength: 16, u32Prefix: 12 },
    { id: 2, byteLength: 4, u32Prefix: 0 }
  ]
};

let nextBuilderItemId = 10;

function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);
}

function loadBuilderPreset(presetId, customBatchSize) {
  const bSize = customBatchSize || 16;
  if (presetId === "valid-multichunk") {
    builderState = {
      presetId,
      title: "Valid request · two inputs match their data",
      batchSize: 16,
      nestingDepth: 2,
      tagsScanned: 14,
      tensors: [
        { id: ++nextBuilderItemId, name: "input_0", datatype: "FP32", shapeStr: "4", injectShm: false },
        { id: ++nextBuilderItemId, name: "input_1", datatype: "FP32", shapeStr: "1", injectShm: false }
      ],
      chunks: [
        { id: ++nextBuilderItemId, byteLength: 16, u32Prefix: 12 },
        { id: ++nextBuilderItemId, byteLength: 4, u32Prefix: 0 }
      ]
    };
  } else if (presetId === "chunk-swap") {
    builderState = {
      presetId,
      title: "Blocked request · data sizes are paired incorrectly",
      batchSize: 16,
      nestingDepth: 2,
      tagsScanned: 14,
      tensors: [
        { id: ++nextBuilderItemId, name: "input_0", datatype: "FP32", shapeStr: "4", injectShm: false },
        { id: ++nextBuilderItemId, name: "input_1", datatype: "FP32", shapeStr: "1", injectShm: false }
      ],
      chunks: [
        { id: ++nextBuilderItemId, byteLength: 4, u32Prefix: 0 },
        { id: ++nextBuilderItemId, byteLength: 16, u32Prefix: 12 }
      ]
    };
  } else if (presetId === "resnet-batch") {
    const rawBytes = bSize * 3 * 224 * 224 * 4;
    const mbLabel = (rawBytes / 1e6).toFixed(2);
    builderState = {
      presetId,
      title: `Large image batch · ${mbLabel} MB of input data`,
      batchSize: bSize,
      nestingDepth: 2,
      tagsScanned: 11,
      tensors: [
        {
          id: ++nextBuilderItemId,
          name: "INPUT__0",
          datatype: "FP32",
          shapeStr: `${bSize}, 3, 224, 224`,
          injectShm: false
        }
      ],
      chunks: [
        { id: ++nextBuilderItemId, byteLength: rawBytes, u32Prefix: rawBytes - 4 }
      ]
    };
  } else if (presetId === "shape-wrap") {
    builderState = {
      presetId,
      title: "Blocked request · impossible input shape",
      batchSize: 16,
      nestingDepth: 2,
      tagsScanned: 11,
      tensors: [
        {
          id: ++nextBuilderItemId,
          name: "INPUT__0",
          datatype: "FP32",
          shapeStr: "2, 4611686018427387904, 2",
          injectShm: false
        }
      ],
      chunks: [
        { id: ++nextBuilderItemId, byteLength: 0, u32Prefix: 0 }
      ]
    };
  } else if (presetId === "cve-2024-0088") {
    builderState = {
      presetId,
      title: "Blocked request · unexpected shared-memory setting",
      batchSize: 16,
      nestingDepth: 3,
      tagsScanned: 19,
      tensors: [
        {
          id: ++nextBuilderItemId,
          name: "INPUT__0",
          datatype: "FP32",
          shapeStr: "1, 4",
          injectShm: true
        }
      ],
      chunks: [
        { id: ++nextBuilderItemId, byteLength: 16, u32Prefix: 12 }
      ]
    };
  }

  document.querySelectorAll("#builder-preset-btns .preset-chip").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.preset === presetId);
  });

  const batchBar = document.getElementById("batch-scale-bar");
  if (batchBar) {
    batchBar.classList.toggle("is-visible", presetId === "resnet-batch");
    batchBar.querySelectorAll(".batch-btn").forEach((b) => {
      b.classList.toggle("active", Number(b.dataset.batch) === bSize);
    });
  }

  const depthSlider = document.getElementById("slider-depth");
  const tagsSlider = document.getElementById("slider-tags");
  if (depthSlider) depthSlider.value = String(builderState.nestingDepth);
  if (tagsSlider) tagsSlider.value = String(builderState.tagsScanned);

  renderBuilderAll();
}

function evaluateSingleTensor(tensor, chunk) {
  const rawParts = tensor.shapeStr
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  if (rawParts.length === 0) {
    return {
      ok: false,
      error: "ParseError::PayloadSizeMismatch (empty shape)",
      elements: 0n,
      expectedBytes: 0,
      actualBytes: chunk ? chunk.byteLength : 0,
      reason: "Empty shape array"
    };
  }

  let prod = 1n;
  for (const part of rawParts) {
    let dim;
    try {
      dim = BigInt(part);
    } catch (e) {
      return {
        ok: false,
        error: "ParseError::MalformedVarint",
        elements: 0n,
        expectedBytes: 0,
        actualBytes: chunk ? chunk.byteLength : 0,
        reason: `Invalid dimension "${part}"`
      };
    }

    if (dim < 0n) {
      return {
        ok: false,
        error: `ParseError::NegativeDimension(${dim.toString()})`,
        elements: 0n,
        expectedBytes: 0,
        actualBytes: chunk ? chunk.byteLength : 0,
        reason: `Negative axis (${dim.toString()})`
      };
    }

    if (dim > MAX_I64) {
      return {
        ok: false,
        error: "ParseError::ShapeOverflow (u64 > i64::MAX)",
        elements: prod,
        expectedBytes: 0,
        actualBytes: chunk ? chunk.byteLength : 0,
        reason: "Dimension exceeds i64::MAX"
      };
    }

    const nextProd = prod * dim;
    if (dim !== 0n && nextProd > MAX_I64) {
      return {
        ok: false,
        error: "ParseError::ShapeOverflow (i64::checked_mul wrap)",
        elements: prod,
        expectedBytes: 0,
        actualBytes: chunk ? chunk.byteLength : 0,
        reason: "64-bit integer multiplication overflow"
      };
    }
    prod = nextProd;

    if (prod > MAX_TENSOR_ELEMENTS) {
      return {
        ok: false,
        error: `ParseError::BufferCeilingExceeded (${prod.toLocaleString()} > 16,777,216)`,
        elements: prod,
        expectedBytes: Number(prod) * 4,
        actualBytes: chunk ? chunk.byteLength : 0,
        reason: "Exceeds per-tensor element ceiling"
      };
    }
  }

  if (tensor.injectShm) {
    return {
      ok: false,
      error: "ParseError::UnauthorizedSharedMemoryParameter",
      elements: prod,
      expectedBytes: 0,
      actualBytes: chunk ? chunk.byteLength : 0,
      reason: "shared_memory_region injected in parameters"
    };
  }

  const width = DTYPE_BYTE_WIDTHS[tensor.datatype];
  if (width === undefined || width < 0) {
    return {
      ok: false,
      error: `ParseError::PayloadSizeMismatch (unknown datatype "${tensor.datatype}")`,
      elements: prod,
      expectedBytes: 0,
      actualBytes: chunk ? chunk.byteLength : 0,
      reason: `Unknown datatype width (${tensor.datatype})`
    };
  }

  if (!chunk) {
    return {
      ok: false,
      error: "ParseError::PayloadSizeMismatch (missing raw_input_contents[i])",
      elements: prod,
      expectedBytes: width > 0 ? Number(prod) * width : Number(prod) * 4,
      actualBytes: 0,
      reason: "Missing corresponding Field 7 chunk"
    };
  }

  if (tensor.datatype === "BYTES") {
    const elemCount = Number(prod);
    const minRequired = elemCount * 4;
    const prefixLen = Math.max(0, Number(chunk.u32Prefix || 0));
    const totalNeeded = 4 + prefixLen + Math.max(0, elemCount - 1) * 4;
    if (chunk.byteLength < minRequired || (elemCount > 0 && totalNeeded > chunk.byteLength)) {
      return {
        ok: false,
        error: `ParseError::PayloadSizeMismatch (BYTES u32 prefix ${prefixLen}B > ${chunk.byteLength}B chunk)`,
        elements: prod,
        expectedBytes: totalNeeded,
        actualBytes: chunk.byteLength,
        reason: `4B length prefix (${prefixLen}B) over-reads ${chunk.byteLength}B chunk`
      };
    }
    return {
      ok: true,
      error: null,
      elements: prod,
      expectedBytes: chunk.byteLength,
      actualBytes: chunk.byteLength,
      reason: `BYTES [${rawParts.join(",")}] prefix walk aligned (${chunk.byteLength} B)`
    };
  }

  const expectedBytes = Number(prod) * width;
  if (chunk.byteLength !== expectedBytes) {
    return {
      ok: false,
      error: `ParseError::PayloadSizeMismatch { expected: ${expectedBytes}, actual: ${chunk.byteLength} }`,
      elements: prod,
      expectedBytes,
      actualBytes: chunk.byteLength,
      reason: `Expected ${expectedBytes.toLocaleString()} B, got ${chunk.byteLength.toLocaleString()} B`
    };
  }

  return {
    ok: true,
    error: null,
    elements: prod,
    expectedBytes,
    actualBytes: chunk.byteLength,
    reason: `${expectedBytes.toLocaleString()} B === ${chunk.byteLength.toLocaleString()} B`
  };
}

function evaluateBuilderState() {
  const tensorResults = builderState.tensors.map((t, idx) =>
    evaluateSingleTensor(t, builderState.chunks[idx])
  );

  let totalElements = 0n;
  for (const res of tensorResults) {
    totalElements += res.elements;
  }

  let firstError = null;
  if (builderState.nestingDepth > MAX_NESTING_DEPTH) {
    firstError = `ParseError::NestingLimitExceeded(${builderState.nestingDepth})`;
  } else if (builderState.tagsScanned > MAX_TAGS_SCANNED) {
    firstError = `ParseError::TagLimitExceeded (${builderState.tagsScanned} > 1,024)`;
  } else {
    for (const res of tensorResults) {
      if (!res.ok) {
        firstError = res.error;
        break;
      }
    }
    if (!firstError && totalElements > MAX_TENSOR_ELEMENTS) {
      firstError = `ParseError::BufferCeilingExceeded (cumulative ${totalElements.toLocaleString()} > 16,777,216)`;
    }
    if (!firstError && builderState.chunks.length !== builderState.tensors.length) {
      firstError = `ParseError::PayloadSizeMismatch (${builderState.tensors.length} inputs vs ${builderState.chunks.length} chunks)`;
    }
  }

  const metadataBytes = Math.max(
    36,
    5 + builderState.tensors.length * 29 + Math.max(0, builderState.tagsScanned - 10) * 2 + (builderState.nestingDepth - 1) * 2
  );
  const skippedBulkBytes = builderState.chunks.reduce((acc, c) => acc + Math.max(0, Number(c.byteLength) || 0), 0);
  const totalWireBytes = metadataBytes + skippedBulkBytes;

  return {
    ok: !firstError,
    error: firstError,
    tensorResults,
    totalElements,
    metadataBytes,
    skippedBulkBytes,
    totalWireBytes
  };
}

function renderBuilderAll() {
  const evalRes = evaluateBuilderState();

  // 1. Render Tensor Cards (Left Column)
  const tensorsListEl = document.getElementById("builder-tensors-list");
  if (tensorsListEl) {
    tensorsListEl.innerHTML = builderState.tensors
      .map((t, idx) => {
        const res = evalRes.tensorResults[idx];
        const dtypes = ["FP32", "FP64", "INT64", "FP16", "BOOL", "BYTES", "INVALID_DTYPE"];
        const optionsHtml = dtypes
          .map((dt) => `<option value="${dt}" ${t.datatype === dt ? "selected" : ""}>${dt}</option>`)
          .join("");
        const statusColor = res.ok ? "var(--ctp-green)" : "var(--ctp-red)";
        const statusIcon = res.ok ? "✓" : "✕";
        return `
          <div class="builder-item-card ${res.ok ? "is-valid" : "is-invalid"}" data-tensor-idx="${idx}">
            <div class="builder-card-top">
              <span class="builder-card-title mono">Input ${idx + 1} (<code>${escapeHTML(t.name)}</code>)</span>
              ${
                builderState.tensors.length > 1
                  ? `<button class="builder-remove-btn mono" data-remove-tensor="${idx}" type="button">Remove</button>`
                  : ""
              }
            </div>
            <div class="builder-fields-row">
              <div class="builder-field">
                <label class="mono">Datatype</label>
                <select class="builder-select" data-tensor-dtype="${idx}">
                  ${optionsHtml}
                </select>
              </div>
              <div class="builder-field">
                <label class="mono">Shape (dimensions)</label>
                <input type="text" class="builder-input" data-tensor-shape="${idx}" value="${escapeHTML(t.shapeStr)}" />
              </div>
            </div>
            <div class="builder-card-foot">
              <label class="builder-checkbox-label">
                <input type="checkbox" data-tensor-shm="${idx}" ${t.injectShm ? "checked" : ""} />
                <span>Inject unexpected shared-memory setting</span>
              </label>
              <span class="mono" style="color:${statusColor}; font-weight:600">${statusIcon} ${escapeHTML(res.reason)}</span>
            </div>
          </div>
        `;
      })
      .join("");

    tensorsListEl.querySelectorAll("[data-tensor-dtype]").forEach((sel) => {
      sel.addEventListener("change", () => {
        const i = Number(sel.dataset.tensorDtype);
        builderState.tensors[i].datatype = sel.value;
        builderState.title = "Custom request";
        renderBuilderAll();
      });
    });

    tensorsListEl.querySelectorAll("[data-tensor-shape]").forEach((inp) => {
      inp.addEventListener("input", () => {
        const i = Number(inp.dataset.tensorShape);
        builderState.tensors[i].shapeStr = inp.value;
        builderState.title = "Custom request";
        renderBuilderSummaryAndConnectors();
      });
      inp.addEventListener("change", () => renderBuilderAll());
    });

    tensorsListEl.querySelectorAll("[data-tensor-shm]").forEach((chk) => {
      chk.addEventListener("change", () => {
        const i = Number(chk.dataset.tensorShm);
        builderState.tensors[i].injectShm = chk.checked;
        builderState.title = "Custom request";
        renderBuilderAll();
      });
    });

    tensorsListEl.querySelectorAll("[data-remove-tensor]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const i = Number(btn.dataset.removeTensor);
        builderState.tensors.splice(i, 1);
        renderBuilderAll();
      });
    });
  }

  // 2. Render Raw Chunk Cards (Right Column)
  const chunksListEl = document.getElementById("builder-chunks-list");
  if (chunksListEl) {
    chunksListEl.innerHTML = builderState.chunks
      .map((c, idx) => {
        const pairedTensor = builderState.tensors[idx];
        const pairedRes = evalRes.tensorResults[idx];
        const isAligned = pairedRes ? pairedRes.ok : false;
        const isBytesTensor = pairedTensor && pairedTensor.datatype === "BYTES";
        const expectedB = pairedRes ? pairedRes.expectedBytes : 0;
        const pairStatus = !pairedRes
          ? "no matching input description"
          : pairedRes.ok
            ? "valid size and input"
            : pairedRes.actualBytes !== pairedRes.expectedBytes
              ? "size mismatch"
              : "input validation failed";

        return `
          <div class="builder-item-card ${isAligned ? "is-valid" : "is-invalid"}" data-chunk-idx="${idx}">
            <div class="builder-card-top">
              <span class="builder-card-title mono">Data for input ${idx + 1}</span>
              ${
                builderState.chunks.length > 1
                  ? `<button class="builder-remove-btn mono" data-remove-chunk="${idx}" type="button">Remove</button>`
                  : ""
              }
            </div>
            ${
              isBytesTensor
                ? `
              <div class="builder-fields-row">
                <div class="builder-field">
                  <label class="mono">4B u32 Prefix</label>
                  <input type="number" min="0" class="builder-input" data-chunk-prefix="${idx}" value="${escapeHTML(c.u32Prefix || 0)}" />
                </div>
                <div class="builder-field">
                  <label class="mono">Actual Chunk Bytes</label>
                  <input type="number" min="0" class="builder-input" data-chunk-bytes="${idx}" value="${escapeHTML(c.byteLength)}" />
                </div>
              </div>
            `
                : `
              <div class="builder-field">
                <label class="mono">Data size (bytes)</label>
                <input type="number" min="0" class="builder-input" data-chunk-bytes="${idx}" value="${escapeHTML(c.byteLength)}" />
              </div>
            `
            }
            <div class="builder-card-foot">
              <span class="mono" style="color:var(--ctp-subtext0)">
                ${pairedTensor
                  ? `Input ${idx + 1}: expected ${expectedB.toLocaleString()} bytes · actual ${c.byteLength.toLocaleString()} bytes · ${pairStatus}`
                  : "No matching input description for this data"}
              </span>
              ${
                pairedTensor
                  ? `<button class="builder-remove-btn mono" data-match-tensor="${idx}" type="button" style="border-color:var(--ctp-blue); color:var(--ctp-blue)">Set expected size (${expectedB.toLocaleString()} bytes)</button>`
                  : ""
              }
            </div>
          </div>
        `;
      })
      .join("");

    chunksListEl.querySelectorAll("[data-chunk-bytes]").forEach((inp) => {
      inp.addEventListener("input", () => {
        const i = Number(inp.dataset.chunkBytes);
        builderState.chunks[i].byteLength = Math.max(0, Number(inp.value) || 0);
        builderState.title = "Custom request";
        renderBuilderSummaryAndConnectors();
      });
      inp.addEventListener("change", () => renderBuilderAll());
    });

    chunksListEl.querySelectorAll("[data-chunk-prefix]").forEach((inp) => {
      inp.addEventListener("input", () => {
        const i = Number(inp.dataset.chunkPrefix);
        builderState.chunks[i].u32Prefix = Math.max(0, Number(inp.value) || 0);
        builderState.title = "Custom request";
        renderBuilderSummaryAndConnectors();
      });
      inp.addEventListener("change", () => renderBuilderAll());
    });

    chunksListEl.querySelectorAll("[data-match-tensor]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const i = Number(btn.dataset.matchTensor);
        const latestEval = evaluateBuilderState();
        const res = latestEval.tensorResults[i];
        if (res) {
          builderState.chunks[i].byteLength = Math.max(0, res.expectedBytes);
          if (builderState.tensors[i] && builderState.tensors[i].datatype === "BYTES") {
            builderState.chunks[i].u32Prefix = Math.max(0, builderState.chunks[i].byteLength - 4);
          }
          renderBuilderAll();
        }
      });
    });

    chunksListEl.querySelectorAll("[data-remove-chunk]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const i = Number(btn.dataset.removeChunk);
        builderState.chunks.splice(i, 1);
        renderBuilderAll();
      });
    });
  }

  renderBuilderSummaryAndConnectors();
}

function renderBuilderSummaryAndConnectors() {
  const evalRes = evaluateBuilderState();
  const hasBytesInput = builderState.tensors.some((tensor) => tensor.datatype === "BYTES");

  // Update stress slider value pills
  const depthValEl = document.getElementById("slider-depth-val");
  if (depthValEl) {
    depthValEl.textContent = `${builderState.nestingDepth} / ${MAX_NESTING_DEPTH}`;
    depthValEl.classList.toggle("is-danger", builderState.nestingDepth > MAX_NESTING_DEPTH);
  }
  const tagsValEl = document.getElementById("slider-tags-val");
  if (tagsValEl) {
    tagsValEl.textContent = `${builderState.tagsScanned.toLocaleString()} / ${MAX_TAGS_SCANNED.toLocaleString()}`;
    tagsValEl.classList.toggle("is-danger", builderState.tagsScanned > MAX_TAGS_SCANNED);
  }

  // Update Anatomy Header & Verdict Badge
  const titleEl = document.getElementById("ins-title");
  if (titleEl) titleEl.textContent = builderState.title;

  const badgeEl = document.getElementById("ins-badge");
  if (badgeEl) {
    const kind = evalRes.ok ? "allow" : "reject";
    const statusText = evalRes.ok ? "Allowed" : "Blocked";
    badgeEl.innerHTML = `${verdictIcon(kind)}<span class="verdict-text">${statusText}</span>`;
    badgeEl.className = `verdict-pill ${evalRes.ok ? "is-allow" : "is-reject"}`;
  }

  const summaryEl = document.getElementById("ins-summary");
  if (summaryEl) {
    if (evalRes.ok) {
      summaryEl.textContent = hasBytesInput
        ? `Allowed: all ${builderState.tensors.length} input${builderState.tensors.length === 1 ? "" : "s"} pass validation. Custos checks each BYTES length prefix; it skips over fixed-width tensor values without reading each one.`
        : `Allowed: all ${builderState.tensors.length} input${builderState.tensors.length === 1 ? "" : "s"} have data of the expected size. Custos checks the descriptions, then skips over ${evalRes.skippedBulkBytes.toLocaleString()} bytes of tensor data.`;
    } else {
      const failedInput = evalRes.tensorResults.findIndex((result) => !result.ok);
      const failedResult = failedInput >= 0 ? evalRes.tensorResults[failedInput] : null;
      summaryEl.textContent = failedResult && failedResult.actualBytes !== failedResult.expectedBytes
        ? `Blocked: input ${failedInput + 1} expects ${failedResult.expectedBytes.toLocaleString()} bytes, but its data has ${failedResult.actualBytes.toLocaleString()} bytes.`
        : `Blocked: this request fails a safety check (${evalRes.error}). Open Technical readout for the scanner detail.`;
    }
  }

  // Update Live Byte-Stream Anatomy Bar
  const totalB = Math.max(1, evalRes.totalWireBytes);
  const scannedPctReal = (evalRes.metadataBytes / totalB) * 100;
  const skippedPctReal = (evalRes.skippedBulkBytes / totalB) * 100;
  // Enlarge the metadata slice for legibility; the UI labels this bar as illustrative.
  const visualScannedPct =
    evalRes.skippedBulkBytes === 0
      ? 100
      : Math.min(82, Math.max(16, scannedPctReal));
  const visualSkippedPct = 100 - visualScannedPct;

  const segScanned = document.getElementById("anatomy-seg-scanned");
  const segSkipped = document.getElementById("anatomy-seg-skipped");
  if (segScanned && segSkipped) {
    segScanned.style.width = `${visualScannedPct}%`;
    segSkipped.style.width = `${visualSkippedPct}%`;
  }

  const fmtPct = (p) => (p > 0 && p < 0.01 ? "<0.01%" : `${p.toFixed(2)}%`);
  const fmtPctHigh = (p) => (p > 99.99 && p < 100 ? ">99.99%" : `${p.toFixed(2)}%`);

  const scannedShort = document.getElementById("anatomy-scanned-short");
  if (scannedShort) {
    scannedShort.textContent = `${evalRes.metadataBytes} B metadata checked`;
  }
  const skippedShort = document.getElementById("anatomy-skipped-short");
  if (skippedShort) {
    skippedShort.textContent =
      evalRes.skippedBulkBytes > 0
        ? hasBytesInput ? `${evalRes.skippedBulkBytes.toLocaleString()} B input data` : `${evalRes.skippedBulkBytes.toLocaleString()} B data skipped`
        : "No tensor data";
  }

  const scannedText = document.getElementById("anatomy-scanned-text");
  if (scannedText) {
    scannedText.textContent = `${evalRes.metadataBytes.toLocaleString()} bytes checked (${fmtPct(scannedPctReal)})`;
  }
  const skippedText = document.getElementById("anatomy-skipped-text");
  if (skippedText) {
    skippedText.textContent = hasBytesInput
      ? `${evalRes.skippedBulkBytes.toLocaleString()} bytes of input data`
      : `${evalRes.skippedBulkBytes.toLocaleString()} bytes skipped (${fmtPctHigh(skippedPctReal)})`;
  }

  // Update 6-Cell Scanner Verdict Grid
  const vError = document.getElementById("v-error");
  if (vError) {
    vError.textContent = evalRes.ok ? "ALLOW (ResponseStatus::Continue)" : evalRes.error;
    vError.style.color = evalRes.ok ? "var(--ctp-green)" : "var(--ctp-red)";
  }

  const vHttp = document.getElementById("v-http");
  if (vHttp) {
    vHttp.textContent = evalRes.ok
      ? "200 OK / gRPC OK (0)"
      : "400 Bad Request / INVALID_ARGUMENT (3)";
  }

  const vElements = document.getElementById("v-elements");
  if (vElements) {
    vElements.textContent = `${evalRes.totalElements.toLocaleString()} / 16,777,216`;
  }

  const vParity = document.getElementById("v-parity");
  if (vParity) {
    const alignedCount = evalRes.tensorResults.filter((r) => r.ok).length;
    const totalPairs = Math.max(builderState.tensors.length, builderState.chunks.length);
    const allAligned = alignedCount === totalPairs && builderState.tensors.length === builderState.chunks.length;
    vParity.textContent = allAligned
      ? `✓ ${alignedCount} / ${totalPairs} Chunks Aligned (1:1)`
      : `✕ Mismatch (${alignedCount} / ${totalPairs} Aligned)`;
    vParity.style.color = allAligned ? "var(--ctp-green)" : "var(--ctp-red)";
  }

  const vTags = document.getElementById("v-tags");
  if (vTags) {
    vTags.textContent = `${builderState.tagsScanned.toLocaleString()} / 1,024`;
    vTags.style.color = builderState.tagsScanned <= MAX_TAGS_SCANNED ? "var(--ctp-text)" : "var(--ctp-red)";
  }

  renderBuilderHexSegments(evalRes);
  requestAnimationFrame(drawParityConnectors);
}

function renderBuilderHexSegments(evalRes) {
  const stream = document.getElementById("hex-stream");
  if (!stream) return;

  const segments = [
    {
      kind: "grpc",
      bytes: `00 ${(evalRes.totalWireBytes - 5).toString(16).padStart(8, "0").toUpperCase().replace(/(..)/g, "$1 ").trim()}`,
      label: "Request frame header (5 bytes)",
      offset: "0x00..0x05",
      detail: `Compressed-Flag = 0x00 (uncompressed); big-endian u32 declared length = ${(evalRes.totalWireBytes - 5).toLocaleString()} bytes.`
    },
    {
      kind: builderState.nestingDepth > MAX_NESTING_DEPTH ? "exploit" : "tag",
      bytes: `0A 08 72 65 73 6E 65 74 35 30`,
      label: `Request metadata (nesting ${builderState.nestingDepth})`,
      offset: "0x05..0x0F",
      detail:
        builderState.nestingDepth > MAX_NESTING_DEPTH
          ? `REJECTED: Submessage depth D=${builderState.nestingDepth} exceeds MAX_DEPTH = 16 -> ParseError::NestingLimitExceeded(${builderState.nestingDepth}).`
          : `Root Field 1 (model_name) skipped in O(1); nesting tracker depth = ${builderState.nestingDepth} / 16.`
    }
  ];

  builderState.tensors.forEach((t, i) => {
    const res = evalRes.tensorResults[i];
    segments.push({
      kind: res.ok ? "shape" : "exploit",
      bytes: t.injectShm ? `2A .. 73 68 61 72 65 64 5F 6D 65 6D` : `2A 1C 12 ${t.datatype} 1A [${t.shapeStr}]`,
      label: `Input #${i + 1}: ${t.datatype} [${t.shapeStr}]`,
      offset: `Input[${i}]`,
      detail: res.ok
        ? `Input ${i + 1} is valid: ${t.datatype}, shape [${t.shapeStr}], ${res.elements.toLocaleString()} elements; expected data size ${res.expectedBytes.toLocaleString()} bytes.`
        : `Input ${i + 1} was blocked: ${res.error} (${res.reason}).`
    });
  });

  builderState.chunks.forEach((c, i) => {
    const res = evalRes.tensorResults[i];
    const ok = res ? res.ok : false;
    segments.push({
      kind: ok ? "skip" : "exploit",
      bytes: `3A [${c.byteLength.toLocaleString()} B raw_input_contents]`,
      label: `Input data #${i + 1} (${c.byteLength.toLocaleString()} bytes)`,
      offset: `Chunk[${i}]`,
      detail: ok
        ? builderState.tensors[i]?.datatype === "BYTES"
          ? `Data for input ${i + 1} is valid. Custos checks each 4-byte length prefix to confirm the string data fits.`
          : `Data for input ${i + 1} matches its expected size (${c.byteLength.toLocaleString()} bytes). Custos jumps over these bytes without reading each value.`
        : `Data for input ${i + 1} was blocked: ${res ? res.error : "No matching input description for this data"}.`
    });
  });

  if (builderState.tagsScanned > MAX_TAGS_SCANNED) {
    segments.push({
      kind: "exploit",
      bytes: `F8 0F 01 ... (x${builderState.tagsScanned})`,
      label: `Tag Flood (${builderState.tagsScanned} > 1,024)`,
      offset: "EOF",
      detail: `REJECTED: Scanned tag counter reached ${builderState.tagsScanned}, exceeding DEFAULT_MAX_TAGS_SCANNED (1,024) -> ParseError::TagLimitExceeded.`
    });
  }

  stream.innerHTML = "";
  segments.forEach((seg, idx) => {
    const el = document.createElement("div");
    el.className = `hex-segment ${idx === segments.length - 1 ? "selected" : ""}`;
    el.dataset.kind = seg.kind;
    el.setAttribute("role", "button");
    el.setAttribute("tabindex", "0");
    el.setAttribute("aria-label", `Show details for ${seg.label}`);
    el.setAttribute("aria-pressed", String(idx === segments.length - 1));
    const bytesEl = document.createElement("span");
    bytesEl.className = "hex-bytes mono";
    bytesEl.textContent = seg.bytes;
    const captionEl = document.createElement("span");
    captionEl.className = "hex-caption";
    captionEl.textContent = seg.label;
    el.append(bytesEl, captionEl);
    el.addEventListener("click", () => {
      stream.querySelectorAll(".hex-segment").forEach((s) => {
        s.classList.remove("selected");
        s.setAttribute("aria-pressed", "false");
      });
      el.classList.add("selected");
      el.setAttribute("aria-pressed", "true");
      showSegmentDetail(seg);
    });
    el.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        el.click();
      }
    });
    stream.appendChild(el);
  });

  showSegmentDetail(segments[segments.length - 1]);
}

function drawParityConnectors() {
  const svg = document.getElementById("parity-connector-svg");
  if (!svg) return;
  const svgRect = svg.getBoundingClientRect();
  if (svgRect.width === 0 || svgRect.height === 0) return;

  const evalRes = evaluateBuilderState();
  const tensorCards = document.querySelectorAll("#builder-tensors-list .builder-item-card");
  const chunkCards = document.querySelectorAll("#builder-chunks-list .builder-item-card");

  const styles = getComputedStyle(document.documentElement);
  const green = styles.getPropertyValue("--ctp-green").trim() || "#a6e3a1";
  const red = styles.getPropertyValue("--ctp-red").trim() || "#f38ba8";
  const crust = styles.getPropertyValue("--ctp-crust").trim() || "#11111b";

  const W = svgRect.width;
  const H = svgRect.height;
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);

  let out = "";
  const pairCount = Math.max(tensorCards.length, chunkCards.length);

  for (let i = 0; i < pairCount; i++) {
    const tCard = tensorCards[i];
    const cCard = chunkCards[i];
    const res = evalRes.tensorResults[i];
    const isOk = Boolean(tCard && cCard && res && res.ok);
    const strokeColor = isOk ? green : red;
    const dash = isOk ? "" : `stroke-dasharray="5,4"`;

    const y1 = tCard
      ? tCard.getBoundingClientRect().top - svgRect.top + tCard.getBoundingClientRect().height / 2
      : H / 2;
    const y2 = cCard
      ? cCard.getBoundingClientRect().top - svgRect.top + cCard.getBoundingClientRect().height / 2
      : y1;

    const midX = W / 2;
    const midY = (y1 + y2) / 2;
    const d = `M 4 ${y1} C ${W * 0.42} ${y1}, ${W * 0.58} ${y2}, ${W - 4} ${y2}`;

    out += `<path d="${d}" fill="none" stroke="${strokeColor}" stroke-width="2.5" ${dash} />`;
    out += `<circle cx="5" cy="${y1}" r="4" fill="${strokeColor}" />`;
    out += `<circle cx="${W - 5}" cy="${y2}" r="4" fill="${strokeColor}" />`;
    out += `<circle cx="${midX}" cy="${midY}" r="10" fill="${crust}" stroke="${strokeColor}" stroke-width="2" />`;
    out += `<text x="${midX}" y="${midY + 3.5}" fill="${strokeColor}" font-size="10" font-weight="700" text-anchor="middle">${isOk ? "✓" : "✕"}</text>`;
  }

  svg.innerHTML = out;
}

function initWireInspector() {
  const presetBtns = document.querySelectorAll("#builder-preset-btns [data-preset]");
  if (!presetBtns.length) return;

  presetBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      loadBuilderPreset(btn.dataset.preset);
    });
  });

  document.querySelectorAll("#batch-scale-bar [data-batch]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const b = Number(btn.dataset.batch) || 16;
      loadBuilderPreset("resnet-batch", b);
    });
  });

  const addTensorBtn = document.getElementById("add-tensor-btn");
  if (addTensorBtn) {
    addTensorBtn.addEventListener("click", () => {
      const idx = builderState.tensors.length;
      builderState.tensors.push({
        id: ++nextBuilderItemId,
        name: `input_${idx}`,
        datatype: "FP32",
        shapeStr: "1, 4",
        injectShm: false
      });
      builderState.title = "Custom request";
      renderBuilderAll();
    });
  }

  const addChunkBtn = document.getElementById("add-chunk-btn");
  if (addChunkBtn) {
    addChunkBtn.addEventListener("click", () => {
      builderState.chunks.push({
        id: ++nextBuilderItemId,
        byteLength: 16,
        u32Prefix: 12
      });
      builderState.title = "Custom request";
      renderBuilderAll();
    });
  }

  const swapChunksBtn = document.getElementById("swap-chunks-btn");
  if (swapChunksBtn) {
    swapChunksBtn.addEventListener("click", () => {
      if (builderState.chunks.length >= 2) {
        const first = builderState.chunks[0];
        builderState.chunks[0] = builderState.chunks[1];
        builderState.chunks[1] = first;
      } else if (builderState.chunks.length === 1) {
        builderState.chunks[0].byteLength = builderState.chunks[0].byteLength === 16 ? 4 : 16;
      }
      builderState.title = "Swapped Raw Chunks (1-to-1 Parity Test)";
      renderBuilderAll();
    });
  }

  const depthSlider = document.getElementById("slider-depth");
  if (depthSlider) {
    depthSlider.addEventListener("input", () => {
      builderState.nestingDepth = Number(depthSlider.value) || 1;
      renderBuilderSummaryAndConnectors();
    });
  }

  const tagsSlider = document.getElementById("slider-tags");
  if (tagsSlider) {
    tagsSlider.addEventListener("input", () => {
      builderState.tagsScanned = Number(tagsSlider.value) || 1;
      renderBuilderSummaryAndConnectors();
    });
  }

  window.addEventListener("resize", () => requestAnimationFrame(drawParityConnectors), { passive: true });
  loadBuilderPreset("valid-multichunk");
}

function showSegmentDetail(seg) {
  const box = document.getElementById("segment-detail");
  if (!box) return;
  box.replaceChildren();
  const heading = document.createElement("strong");
  heading.textContent = seg.label;
  const offset = document.createElement("span");
  offset.className = "mono offset";
  offset.textContent = ` · ${seg.offset}`;
  const bytes = document.createElement("code");
  bytes.className = "mono segment-bytes";
  bytes.textContent = seg.bytes;
  const detail = document.createElement("span");
  detail.className = "detail-text";
  detail.textContent = seg.detail;
  box.append(heading, offset, document.createTextNode(" — "), bytes, document.createElement("br"), detail);
  emit("custos:segmentrendered", { seg });
}

// 3. Topology Switcher
function initTopologies() {
  if (!document.getElementById("topo-title")) return;
  const buttons = document.querySelectorAll("[data-topo]");
  buttons.forEach((btn) => {
    btn.addEventListener("click", () => {
      buttons.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      renderTopology(btn.dataset.topo);
    });
  });
  renderTopology("prod");
}

function renderTopology(key) {
  const topo = TOPOLOGIES[key] || TOPOLOGIES.prod;
  document.getElementById("topo-title").textContent = topo.title;
  const badge = document.getElementById("topo-badge");
  badge.textContent = topo.badge;
  badge.className = `badge ${topo.badgeClass}`;
  document.getElementById("topo-summary").textContent = topo.summary;

  const flow = document.getElementById("topo-flow");
  flow.innerHTML = "";
  topo.nodes.forEach((node, index) => {
    const nodeEl = document.createElement("div");
    nodeEl.className = `flow-node ${node.cls}`;
    nodeEl.innerHTML = `
      <div class="flow-node-title">${node.title}</div>
      <div class="flow-node-meta mono">${node.meta}</div>
      <div class="flow-node-desc">${node.desc}</div>
    `;
    flow.appendChild(nodeEl);

    if (index < topo.nodes.length - 1) {
      const arrow = document.createElement("div");
      arrow.className = "flow-arrow mono";
      arrow.innerHTML = `<span>───►</span>`;
      flow.appendChild(arrow);
    }
  });

  const specGrid = document.getElementById("topo-specs");
  specGrid.innerHTML = topo.specs
    .map(
      ([k, v]) => `
      <div class="verdict-cell">
        <span class="k">${k}</span>
        <span class="v mono">${v}</span>
      </div>
    `
    )
    .join("");

  emit("custos:topologyrendered", { key });
}

// 4. Benchmark Telemetry Dashboard
function initDashboard() {
  if (!document.getElementById("trials-tbody")) return;
  const regimeBtns = document.querySelectorAll("[data-regime]");
  regimeBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      regimeBtns.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      activeRegimeFilter = btn.dataset.regime;
      renderDashboard();
    });
  });

  renderDashboard();
}

function renderDashboard() {
  if (!document.getElementById("trials-tbody")) return;
  renderBurstCdfSvg();
  renderBatchScalingSvg();

  const filtered =
    activeRegimeFilter === "all"
      ? REFERENCE_TRIALS
      : REFERENCE_TRIALS.filter((t) => t.regime === activeRegimeFilter);
  const rows = filtered.length > 0 ? filtered : REFERENCE_TRIALS;

  renderLatencySvg(rows);
  renderThroughputSvg(rows);
  renderTrialsTable(rows);

  emit("custos:dashboardrendered", { count: rows.length });
}

function renderBurstCdfSvg() {
  const svg = document.getElementById("burst-cdf-svg");
  if (!svg) return;
  const styles = getComputedStyle(document.documentElement);
  const gridColor = styles.getPropertyValue("--ctp-surface0").trim();
  const textColor = styles.getPropertyValue("--ctp-subtext0").trim();
  const greenColor = styles.getPropertyValue("--ctp-green").trim();
  const crustColor = styles.getPropertyValue("--ctp-crust").trim();

  const burstTrials = REFERENCE_TRIALS.filter((t) => t.regime === "saturating-burst");
  if (!burstTrials.length) return;

  const keys = ["p50_ms", "p90_ms", "p95_ms", "p99_ms", "p999_ms", "p9999_ms"];
  const labels = ["P50", "P90", "P95", "P99", "P99.9", "P99.99"];
  const W = 540;
  const H = 250;
  const padL = 56;
  const padR = 24;
  const padT = 22;
  const padB = 34;

  const minLog = 1; // 10 ms
  const maxLog = 3; // 1000 ms

  const xFor = (i) => padL + (i / (keys.length - 1)) * (W - padL - padR);
  const yFor = (val) => {
    const lv = Math.log10(Math.max(val, 10));
    const ratio = (lv - minLog) / (maxLog - minLog);
    return H - padB - ratio * (H - padT - padB);
  };

  let out = "";
  [10, 50, 100, 250, 500, 1000].forEach((v) => {
    const y = yFor(v);
    out += `<line x1="${padL}" y1="${y}" x2="${W - padR}" y2="${y}" stroke="${gridColor}" stroke-dasharray="3,3" />`;
    out += `<text x="${padL - 8}" y="${y + 4}" fill="${textColor}" font-size="9.5" text-anchor="end">${v}ms</text>`;
  });

  labels.forEach((lbl, i) => {
    const x = xFor(i);
    out += `<line x1="${x}" y1="${padT}" x2="${x}" y2="${H - padB}" stroke="${gridColor}" stroke-opacity="0.45" />`;
    out += `<text x="${x}" y="${H - 10}" fill="${textColor}" font-size="10" font-weight="600" text-anchor="middle">${lbl}</text>`;
  });

  // Draw P99 3.4x survival gap callout bracket between Baseline (518.0 ms) and Custos (153.0 ms)
  const p99X = xFor(3);
  const yTop = yFor(518.0);
  const yBot = yFor(153.01);
  const midY = (yTop + yBot) / 2;
  out += `<line x1="${p99X}" y1="${yTop + 4}" x2="${p99X}" y2="${yBot - 4}" stroke="${greenColor}" stroke-width="2" stroke-dasharray="4,3" />`;
  out += `<rect x="${p99X - 78}" y="${midY - 12}" width="156" height="22" rx="11" fill="${crustColor}" stroke="${greenColor}" stroke-width="1.5" />`;
  out += `<text x="${p99X}" y="${midY + 3}" fill="${greenColor}" font-size="9.5" font-weight="700" text-anchor="middle">3.4× Lower P99 (153.0 ms)</text>`;

  burstTrials.forEach((t, idx) => {
    const color = getTopologyColor(t.topology, styles);
    const pts = keys.map((k, i) => `${xFor(i)},${yFor(t[k] || 10)}`).join(" ");
    out += `<g class="chart-series" data-burst-idx="${idx}">`;
    out += `<polyline fill="none" stroke="${color}" stroke-width="2.8" points="${pts}" />`;
    keys.forEach((k, i) => {
      const val = t[k] || 10;
      out += `<circle class="chart-dot" data-burst-idx="${idx}" data-pct-idx="${i}" cx="${xFor(i)}" cy="${yFor(val)}" r="5" fill="${color}" stroke="var(--ctp-mantle)" stroke-width="1.5" />`;
    });
    out += `</g>`;
  });

  svg.innerHTML = out;

  svg.querySelectorAll(".chart-dot").forEach((dot) => {
    const idx = Number(dot.dataset.burstIdx);
    const pctIdx = Number(dot.dataset.pctIdx);
    const trial = burstTrials[idx];
    const color = getTopologyColor(trial.topology, styles);
    const pctLabel = labels[pctIdx];
    const pctVal = trial[keys[pctIdx]] || 0;

    dot.addEventListener("mouseenter", (evt) => {
      dot.setAttribute("r", "7");
      showChartTooltip(
        evt,
        trial,
        color,
        `${pctLabel} Burst Survival Latency`,
        `${pctVal.toFixed(2)} ms`
      );
    });
    dot.addEventListener("mousemove", moveChartTooltip);
    dot.addEventListener("mouseleave", () => {
      dot.setAttribute("r", "5");
      hideChartTooltip();
    });
  });
}

function renderBatchScalingSvg() {
  const svg = document.getElementById("batch-scaling-svg");
  if (!svg) return;
  const styles = getComputedStyle(document.documentElement);
  const gridColor = styles.getPropertyValue("--ctp-surface0").trim();
  const textColor = styles.getPropertyValue("--ctp-subtext0").trim();
  const greenColor = styles.getPropertyValue("--ctp-green").trim();
  const redColor = styles.getPropertyValue("--ctp-red").trim();
  const blueColor = styles.getPropertyValue("--ctp-blue").trim();
  const crustColor = styles.getPropertyValue("--ctp-crust").trim();

  const batches = [
    { b: "1 image", kb: "602 KB", bytes: 602112, custosMs: 0.014, linearMs: 0.62, udsDeltaMs: 1.08 },
    { b: "2 images", kb: "1.20 MB", bytes: 1204224, custosMs: 0.014, linearMs: 1.24, udsDeltaMs: 2.98 },
    { b: "4 images", kb: "2.41 MB", bytes: 2408448, custosMs: 0.015, linearMs: 2.48, udsDeltaMs: 11.99 },
    { b: "8 images", kb: "4.82 MB", bytes: 4816896, custosMs: 0.015, linearMs: 4.96, udsDeltaMs: 16.44 },
    { b: "16 images", kb: "9.63 MB", bytes: 9633792, custosMs: 0.015, linearMs: 9.92, udsDeltaMs: 22.13 }
  ];

  const W = 540;
  const H = 250;
  const padL = 56;
  const padR = 26;
  const padT = 22;
  const padB = 38;

  const minLog = -2; // 0.01 ms (10 µs)
  const maxLog = 1.5; // ~31.6 ms

  const xFor = (i) => padL + (i / (batches.length - 1)) * (W - padL - padR);
  const yFor = (val) => {
    const lv = Math.log10(Math.max(val, 0.01));
    const ratio = (lv - minLog) / (maxLog - minLog);
    return H - padB - ratio * (H - padT - padB);
  };

  let out = "";
  [
    { v: 0.01, lbl: "10µs" },
    { v: 0.1, lbl: "100µs" },
    { v: 1, lbl: "1ms" },
    { v: 10, lbl: "10ms" },
    { v: 25, lbl: "25ms" }
  ].forEach(({ v, lbl }) => {
    const y = yFor(v);
    out += `<line x1="${padL}" y1="${y}" x2="${W - padR}" y2="${y}" stroke="${gridColor}" stroke-dasharray="3,3" />`;
    out += `<text x="${padL - 8}" y="${y + 4}" fill="${textColor}" font-size="9.5" text-anchor="end">${lbl}</text>`;
  });

  batches.forEach((item, i) => {
    const x = xFor(i);
    out += `<line x1="${x}" y1="${padT}" x2="${x}" y2="${H - padB}" stroke="${gridColor}" stroke-opacity="0.45" />`;
    out += `<text x="${x}" y="${H - 18}" fill="${textColor}" font-size="10" font-weight="700" text-anchor="middle">${item.b}</text>`;
    out += `<text x="${x}" y="${H - 6}" fill="${textColor}" font-size="8.5" text-anchor="middle">${item.kb}</text>`;
  });

  // Series 1: O(N) Full-Byte Linear Parser
  const linearPts = batches.map((d, i) => `${xFor(i)},${yFor(d.linearMs)}`).join(" ");
  out += `<polyline fill="none" stroke="${redColor}" stroke-width="2.4" stroke-dasharray="5,4" points="${linearPts}" />`;

  // Series 2: Envoy UDS Serialization Delta (Prod - Baseline from ORACLE_SWEEP_ROWS)
  const udsPts = batches.map((d, i) => `${xFor(i)},${yFor(d.udsDeltaMs)}`).join(" ");
  out += `<polyline fill="none" stroke="${blueColor}" stroke-width="2.2" points="${udsPts}" />`;

  // Series 3: custos-core O(1) Wire Scanner (~14-15 µs flat across 602 KB -> 9.63 MB)
  const custosPts = batches.map((d, i) => `${xFor(i)},${yFor(d.custosMs)}`).join(" ");
  out += `<polyline fill="none" stroke="${greenColor}" stroke-width="3" points="${custosPts}" />`;

  // Mark the small amount of request data that Custos checks.
  const midX = xFor(2);
  const flatY = yFor(0.015);
  out += `<rect x="${midX - 96}" y="${flatY - 26}" width="192" height="20" rx="10" fill="${crustColor}" stroke="${greenColor}" stroke-width="1.5" />`;
  out += `<text x="${midX}" y="${flatY - 13}" fill="${greenColor}" font-size="9" font-weight="700" text-anchor="middle">Custos checks 63 bytes</text>`;

  batches.forEach((d, i) => {
    const x = xFor(i);
    out += `<circle class="chart-dot" data-batch-idx="${i}" data-kind="linear" cx="${x}" cy="${yFor(d.linearMs)}" r="4.5" fill="${redColor}" stroke="var(--ctp-mantle)" stroke-width="1.5" />`;
    out += `<circle class="chart-dot" data-batch-idx="${i}" data-kind="uds" cx="${x}" cy="${yFor(d.udsDeltaMs)}" r="4.5" fill="${blueColor}" stroke="var(--ctp-mantle)" stroke-width="1.5" />`;
    out += `<circle class="chart-dot" data-batch-idx="${i}" data-kind="custos" cx="${x}" cy="${yFor(d.custosMs)}" r="5.5" fill="${greenColor}" stroke="var(--ctp-mantle)" stroke-width="1.5" />`;
  });

  svg.innerHTML = out;

  svg.querySelectorAll(".chart-dot").forEach((dot) => {
    const idx = Number(dot.dataset.batchIdx);
    const kind = dot.dataset.kind;
    const item = batches[idx];

    dot.addEventListener("mouseenter", (evt) => {
      dot.setAttribute("r", "7");
      const tip = document.getElementById("chart-tooltip");
      if (!tip) return;
      const color = kind === "custos" ? greenColor : kind === "uds" ? blueColor : redColor;
      const title =
        kind === "custos"
          ? "Custos check time"
          : kind === "uds"
            ? "Time to move data through proxy"
            : "Time to read all data";
      const valText =
        kind === "custos"
          ? `${(item.custosMs * 1000).toFixed(0)} microseconds (63 bytes checked)`
          : kind === "uds"
            ? `${item.udsDeltaMs.toFixed(2)} milliseconds`
            : `${item.linearMs.toFixed(2)} milliseconds (${item.bytes.toLocaleString()} bytes read)`;

      tip.style.setProperty("--tooltip-accent", color);
      tip.innerHTML = `
        <div class="chart-tooltip-head">
          <span class="chart-tooltip-arch">
            <span class="legend-dot" style="background:${color}"></span>
            ${title}
          </span>
          <span class="badge badge-mauve" style="font-size:0.68rem">${item.b} (${item.kb})</span>
        </div>
        <div class="chart-tooltip-primary mono">${valText}</div>
        <div class="chart-tooltip-grid mono">
          <span>Request details checked: <strong>63 bytes</strong></span>
          <span>Request data: <strong>${item.bytes.toLocaleString()} bytes</strong></span>
        </div>
        <div class="chart-tooltip-verdict">
          Custos checks the request details, then jumps over the image data.
        </div>
      `;
      tip.hidden = false;
      moveChartTooltip(evt);
    });
    dot.addEventListener("mousemove", moveChartTooltip);
    dot.addEventListener("mouseleave", () => {
      dot.setAttribute("r", kind === "custos" ? "5.5" : "4.5");
      hideChartTooltip();
    });
  });
}

function getTopologyColor(topology, styles) {
  if (topology.includes("Custos") || topology.includes("Production")) {
    return styles.getPropertyValue("--ctp-green").trim();
  }
  if (topology.includes("Baseline") || topology.includes("Envoy")) {
    return styles.getPropertyValue("--ctp-blue").trim();
  }
  return styles.getPropertyValue("--ctp-red").trim();
}

function getTopologyLabel(topology) {
  if (topology.includes("Custos") || topology.includes("Production")) return "With Custos";
  if (topology.includes("Baseline") || topology.includes("Envoy")) return "Proxy only";
  return "No protection";
}

function getRegimeLabel(regime) {
  if (regime === "steady-benign") return "Normal requests";
  if (regime === "interleaved") return "Mixed traffic";
  if (regime === "saturating-burst") return "Attack burst";
  return "All test groups";
}

function getShortProfileTag(trial) {
  const prof = trial.benign_profile || "ResNet-50 B=1 (FP32)";
  const shortProf = prof.includes("BYTES Tensor")
    ? "Text data"
    : prof.includes("Mixed")
      ? "Mixed requests"
      : "Image batch";
  if (trial.regime === "saturating-burst") {
    return `${shortProf} • attack burst`;
  }
  return `${shortProf} • ${trial.rps} requests/second`;
}

function showChartTooltip(evt, trial, color, primaryLabel, primaryValue) {
  const tip = document.getElementById("chart-tooltip");
  if (!tip) return;
  const profile = trial.benign_profile || "ResNet-50 B=1 (FP32)";
  const rateDesc =
    trial.regime === "saturating-burst"
      ? `${trial.achieved_rps.toFixed(1)} requests/second during attack burst`
      : `${trial.achieved_rps.toFixed(1)} of ${trial.rps} requests/second`;
  const tpDropStr =
    trial.regime === "steady-benign" || trial.tp_drop === null || trial.tp_drop === undefined
      ? "Not used for normal requests only"
      : `${(Number(trial.tp_drop) * 100).toFixed(1)}%`;

  tip.style.setProperty("--tooltip-accent", color);
  tip.innerHTML = `
    <div class="chart-tooltip-head">
      <span class="chart-tooltip-arch">
        <span class="legend-dot" style="background:${color}"></span>
        ${getTopologyLabel(trial.topology)}
      </span>
      <span class="badge badge-mauve" style="font-size:0.68rem; padding:0.12rem 0.45rem">${getRegimeLabel(trial.regime)}</span>
    </div>
    <div class="chart-tooltip-tag mono">
      ${profile} • ${rateDesc}
    </div>
    <div class="chart-tooltip-primary mono">
      ${primaryLabel}: ${primaryValue}
    </div>
    <div class="chart-tooltip-grid mono">
      <span>P50: <strong>${trial.p50_ms.toFixed(2)} ms</strong></span>
      <span>P95: <strong>${(trial.p95_ms || trial.p90_ms).toFixed(2)} ms</strong></span>
      <span>P99: <strong>${trial.p99_ms.toFixed(2)} ms</strong></span>
      <span>P99.99: <strong>${trial.p9999_ms.toFixed(2)} ms</strong></span>
      <span>Attacks blocked: <strong>${tpDropStr}</strong></span>
      <span>Peak memory: <strong>${trial.rss_mb.toFixed(1)} MiB</strong></span>
    </div>
    <div class="chart-tooltip-verdict">
      ${trial.survival}
    </div>
  `;
  tip.hidden = false;
  moveChartTooltip(evt);
}

function moveChartTooltip(evt) {
  const tip = document.getElementById("chart-tooltip");
  if (!tip || tip.hidden) return;
  const offset = 14;
  const vw = window.innerWidth;
  const vh = window.innerHeight;
  const rect = tip.getBoundingClientRect();
  let x = evt.clientX + offset;
  let y = evt.clientY + offset;
  if (x + rect.width + 12 > vw) {
    x = Math.max(12, evt.clientX - rect.width - offset);
  }
  if (y + rect.height + 12 > vh) {
    y = Math.max(12, evt.clientY - rect.height - offset);
  }
  tip.style.left = `${x}px`;
  tip.style.top = `${y}px`;
}

function hideChartTooltip() {
  const tip = document.getElementById("chart-tooltip");
  if (tip) tip.hidden = true;
}

function setActiveChartSeries(activeIdx) {
  const latencySvg = document.getElementById("latency-svg");
  const throughputSvg = document.getElementById("throughput-svg");
  const isHover = activeIdx !== null && activeIdx !== undefined;

  if (latencySvg) {
    latencySvg.classList.toggle("is-hovering", isHover);
    latencySvg.querySelectorAll(".chart-series").forEach((g) => {
      const match = isHover && Number(g.dataset.seriesIdx) === activeIdx;
      g.classList.toggle("is-active", match);
      g.querySelectorAll(".chart-dot").forEach((d) => {
        if (!d.classList.contains("is-active")) {
          d.setAttribute("r", match ? "5.5" : "4.5");
        }
      });
    });
    if (!isHover) {
      latencySvg.querySelectorAll(".chart-dot").forEach((d) => {
        d.classList.remove("is-active");
        d.setAttribute("r", "4.5");
      });
    }
  }

  if (throughputSvg) {
    throughputSvg.classList.toggle("is-hovering", isHover);
    throughputSvg.querySelectorAll(".chart-bar-group").forEach((g) => {
      g.classList.toggle("is-active", isHover && Number(g.dataset.seriesIdx) === activeIdx);
    });
  }

  const tbody = document.getElementById("trials-tbody");
  if (tbody) {
    tbody.querySelectorAll("tr[data-series-idx]").forEach((tr) => {
      tr.classList.toggle("is-active-row", isHover && Number(tr.dataset.seriesIdx) === activeIdx);
    });
  }
}

function renderLatencySvg(trials) {
  const svg = document.getElementById("latency-svg");
  const styles = getComputedStyle(document.documentElement);
  const gridColor = styles.getPropertyValue("--ctp-surface0").trim();
  const textColor = styles.getPropertyValue("--ctp-subtext0").trim();

  const keys = ["p50_ms", "p90_ms", "p95_ms", "p99_ms", "p999_ms", "p9999_ms"];
  const labels = ["P50", "P90", "P95", "P99", "P99.9", "P99.99"];
  const W = 540;
  const H = 250;
  const padL = 54;
  const padR = 24;
  const padT = 20;
  const padB = 34;

  const allVals = trials.flatMap((t) => keys.map((k) => Math.max(t[k] || 0.1, 0.1)));
  const minLog = Math.floor(Math.log10(Math.min(...allVals, 0.2)));
  const maxLog = Math.ceil(Math.log10(Math.max(...allVals, 10)));

  const xFor = (i) => padL + (i / (keys.length - 1)) * (W - padL - padR);
  const yFor = (val) => {
    const lv = Math.log10(Math.max(val, 0.1));
    const ratio = (lv - minLog) / Math.max(maxLog - minLog, 1);
    return H - padB - ratio * (H - padT - padB);
  };

  let out = "";
  for (let exp = minLog; exp <= maxLog; exp++) {
    const v = Math.pow(10, exp);
    const y = yFor(v);
    out += `<line x1="${padL}" y1="${y}" x2="${W - padR}" y2="${y}" stroke="${gridColor}" stroke-dasharray="3,3" />`;
    out += `<text x="${padL - 8}" y="${y + 4}" fill="${textColor}" font-size="10" text-anchor="end">${v >= 1 ? v : v.toFixed(1)}ms</text>`;
  }

  labels.forEach((lbl, i) => {
    const x = xFor(i);
    out += `<line x1="${x}" y1="${padT}" x2="${x}" y2="${H - padB}" stroke="${gridColor}" stroke-opacity="0.45" />`;
    out += `<text x="${x}" y="${H - 10}" fill="${textColor}" font-size="10" font-weight="600" text-anchor="middle">${lbl}</text>`;
  });

  trials.forEach((t, idx) => {
    const color = getTopologyColor(t.topology, styles);
    const pts = keys.map((k, i) => `${xFor(i)},${yFor(t[k] || 0.1)}`).join(" ");
    out += `<g class="chart-series" data-series-idx="${idx}">`;
    out += `<polyline fill="none" stroke="${color}" stroke-width="2.4" points="${pts}" />`;
    keys.forEach((k, i) => {
      const val = t[k] || 0.1;
      out += `<circle class="chart-dot" data-series-idx="${idx}" data-pct-idx="${i}" cx="${xFor(i)}" cy="${yFor(val)}" r="4.5" fill="${color}" stroke="var(--ctp-mantle)" stroke-width="1.5" />`;
    });
    out += `</g>`;
  });

  svg.innerHTML = out;

  const seriesGroups = svg.querySelectorAll(".chart-series");
  seriesGroups.forEach((group) => {
    const idx = Number(group.dataset.seriesIdx);
    const trial = trials[idx];
    const color = getTopologyColor(trial.topology, styles);

    group.addEventListener("mouseenter", (evt) => {
      setActiveChartSeries(idx);
      showChartTooltip(
        evt,
        trial,
        color,
        `${getShortProfileTag(trial)} (P99)`,
        `${trial.p99_ms.toFixed(2)} ms`
      );
    });

    group.addEventListener("mousemove", (evt) => {
      moveChartTooltip(evt);
    });

    group.addEventListener("mouseleave", () => {
      setActiveChartSeries(null);
      hideChartTooltip();
    });
  });

  svg.querySelectorAll(".chart-dot").forEach((dot) => {
    const idx = Number(dot.dataset.seriesIdx);
    const pctIdx = Number(dot.dataset.pctIdx);
    const trial = trials[idx];
    const color = getTopologyColor(trial.topology, styles);
    const pctLabel = labels[pctIdx];
    const pctVal = trial[keys[pctIdx]] || 0;

    dot.addEventListener("mouseenter", (evt) => {
      evt.stopPropagation();
      setActiveChartSeries(idx);
      dot.classList.add("is-active");
      dot.setAttribute("r", "6.5");
      showChartTooltip(
        evt,
        trial,
        color,
        `${pctLabel} Latency (${getShortProfileTag(trial)})`,
        `${pctVal.toFixed(2)} ms`
      );
    });

    dot.addEventListener("mousemove", (evt) => {
      evt.stopPropagation();
      moveChartTooltip(evt);
    });

    dot.addEventListener("mouseleave", () => {
      dot.classList.remove("is-active");
      dot.setAttribute("r", "5.5");
    });
  });
}

function renderThroughputSvg(trials) {
  const svg = document.getElementById("throughput-svg");
  const styles = getComputedStyle(document.documentElement);
  const gridColor = styles.getPropertyValue("--ctp-surface0").trim();
  const textColor = styles.getPropertyValue("--ctp-subtext0").trim();

  const W = 540;
  const H = 250;
  const padL = 52;
  const padR = 20;
  const padT = 22;
  const padB = 46;

  const maxRps = Math.max(...trials.map((t) => Math.max(t.rps, t.achieved_rps, 200)), 200) * 1.12;
  let out = "";

  for (let i = 0; i <= 4; i++) {
    const val = Math.round((maxRps / 4) * i);
    const y = H - padB - (i / 4) * (H - padT - padB);
    out += `<line x1="${padL}" y1="${y}" x2="${W - padR}" y2="${y}" stroke="${gridColor}" stroke-dasharray="3,3" />`;
    out += `<text x="${padL - 8}" y="${y + 4}" fill="${textColor}" font-size="10" text-anchor="end">${val}</text>`;
  }

  const slotW = (W - padL - padR) / Math.max(trials.length, 1);
  const barW = Math.min(38, Math.max(slotW * 0.64, 6));
  const showValueLabels = trials.length <= 6;
  const showGroupTags = activeRegimeFilter !== "steady-benign" && activeRegimeFilter !== "all";

  // Draw subtle vertical dividers and one shared x-axis group tag per 3-bar triad
  const triadCount = Math.floor(trials.length / 3);
  if (triadCount >= 1 && trials.length % 3 === 0) {
    for (let g = 0; g < triadCount; g++) {
      const firstInTriad = trials[g * 3];
      const triadCenter = padL + slotW * (g * 3 + 1.5);
      if (g > 0) {
        const divX = padL + slotW * (g * 3);
        out += `<line x1="${divX}" y1="${padT}" x2="${divX}" y2="${H - padB + 6}" stroke="${gridColor}" stroke-opacity="0.7" />`;
      }
      if (showGroupTags) {
        const tagText = getShortProfileTag(firstInTriad);
        const fontSize = triadCount > 4 ? 8 : 9.5;
        out += `<text x="${triadCenter}" y="${H - 18}" fill="${textColor}" font-size="${fontSize}" font-weight="600" text-anchor="middle">${tagText}</text>`;
      }
    }
  }

  trials.forEach((t, idx) => {
    const cx = padL + slotW * (idx + 0.5);
    const h = (t.achieved_rps / maxRps) * (H - padT - padB);
    const y = H - padB - h;
    const color = getTopologyColor(t.topology, styles);

    out += `<g class="chart-bar-group" data-series-idx="${idx}">`;
    out += `<rect x="${cx - barW / 2}" y="${y}" width="${barW}" height="${Math.max(h, 3)}" rx="4" fill="${color}" />`;
    if (showValueLabels) {
      out += `<text x="${cx}" y="${y - 6}" fill="${textColor}" font-size="9.5" font-weight="600" text-anchor="middle">${t.achieved_rps.toFixed(0)} rps</text>`;
    }
    out += `</g>`;
  });

  svg.innerHTML = out;

  const barGroups = svg.querySelectorAll(".chart-bar-group");
  barGroups.forEach((group) => {
    const idx = Number(group.dataset.seriesIdx);
    const trial = trials[idx];
    const color = getTopologyColor(trial.topology, styles);
    const rateLabel =
      trial.regime === "saturating-burst"
        ? `${trial.achieved_rps.toFixed(1)} RPS (C=${trial.rps} fan-out)`
        : `${trial.achieved_rps.toFixed(1)} / ${trial.rps} RPS`;

    group.addEventListener("mouseenter", (evt) => {
      setActiveChartSeries(idx);
      showChartTooltip(
        evt,
        trial,
        color,
        `Requests completed per second (${getShortProfileTag(trial)})`,
        rateLabel
      );
    });

    group.addEventListener("mousemove", (evt) => {
      moveChartTooltip(evt);
    });

    group.addEventListener("mouseleave", () => {
      setActiveChartSeries(null);
      hideChartTooltip();
    });
  });
}

function renderTrialsTable(trials) {
  const tbody = document.getElementById("trials-tbody");
  tbody.innerHTML = trials
    .map(
      (t, idx) => {
        const isSteadyBenign = t.regime === "steady-benign" || t.tp_drop === null || t.tp_drop === undefined;
        const tpDropText = isSteadyBenign ? "N/A" : `${(Number(t.tp_drop) * 100).toFixed(1)}%`;
        const tpDropColor = isSteadyBenign
          ? "var(--ctp-overlay1)"
          : Number(t.tp_drop) >= 0.99
            ? "var(--ctp-green)"
            : "var(--ctp-subtext0)";
        const profile = t.benign_profile || "ResNet-50 B=1 (FP32)";
        const rateLabel =
          t.regime === "saturating-burst"
            ? `${t.achieved_rps.toFixed(1)} (C=${t.rps} fan-out)`
            : `${t.achieved_rps.toFixed(1)} / ${t.rps}`;
        return `
    <tr data-series-idx="${idx}">
      <td class="mono" style="font-weight:600">${getTopologyLabel(t.topology)}</td>
      <td><span class="badge badge-mauve">${getRegimeLabel(t.regime)}</span></td>
      <td class="mono" style="font-size:0.78rem; color:var(--ctp-subtext1)">${profile}</td>
      <td class="mono">${rateLabel}</td>
      <td class="mono">${t.p50_ms.toFixed(2)} ms</td>
      <td class="mono">${t.p99_ms.toFixed(2)} ms</td>
      <td class="mono">${t.p9999_ms.toFixed(2)} ms</td>
      <td class="mono">${(t.fpr * 100).toFixed(2)}%</td>
      <td class="mono" style="color: ${tpDropColor}; font-weight:600">
        ${tpDropText}
      </td>
      <td class="mono">${t.rss_mb.toFixed(1)} MiB</td>
      <td>${t.survival}</td>
    </tr>
  `;
      }
    )
    .join("");

  tbody.querySelectorAll("tr[data-series-idx]").forEach((tr) => {
    const idx = Number(tr.dataset.seriesIdx);
    tr.addEventListener("mouseenter", () => setActiveChartSeries(idx));
    tr.addEventListener("mouseleave", () => setActiveChartSeries(null));
  });
}

// 5. ELI5 explainers on the threat taxonomy cards.
function initEli5() {
  const triggers = Array.from(document.querySelectorAll(".eli5-trigger"));
  if (!triggers.length) return;

  const closeAll = (except) => {
    triggers.forEach((t) => {
      if (t !== except) t.setAttribute("aria-expanded", "false");
    });
  };

  triggers.forEach((trigger) => {
    trigger.addEventListener("click", (e) => {
      e.stopPropagation();
      const open = trigger.getAttribute("aria-expanded") === "true";
      closeAll(trigger);
      trigger.setAttribute("aria-expanded", open ? "false" : "true");
    });
  });

  document.addEventListener("click", () => closeAll(null));

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeAll(null);
  });
}

// 6. 5-Group Traffic-Light Oracle Verification Matrix
const expandedOracleGroups = new Set();

function classifyOracleRowGroup(row) {
  if (row.expected === "allow") {
    return "benign-boundary";
  }
  if (row.category === "nesting_bomb" || row.category === "wire_type_exploit") {
    return "nesting-sgroup";
  }
  if (
    row.category === "shape_overflow" ||
    row.category === "chunk_parity" ||
    row.category === "tensor_contents" ||
    row.category === "bytes_prefix" ||
    row.category === "datatype" ||
    (row.category === "shape_budget" && row.name !== "shape_packed_ones")
  ) {
    return "shape-parity";
  }
  if (
    row.category === "malformed_varint" ||
    row.category === "ast_flood" ||
    row.name === "shape_packed_ones"
  ) {
    return "varints-floods";
  }
  return "rpc-framing";
}

function initOracleSweep() {
  const tbody = document.getElementById("oracle-tbody");
  if (!tbody || typeof ORACLE_SWEEP_ROWS === "undefined") return;
  renderOracleTable();
}

function renderTrafficLightPill(isPass, labelText) {
  const icon = isPass ? "✓" : "✕";
  const cls = isPass ? "is-pass" : "is-fail";
  return `<span class="tl-pill mono ${cls}"><span>${icon}</span><span>${labelText}</span></span>`;
}

function renderOracleTable() {
  const tbody = document.getElementById("oracle-tbody");
  if (!tbody || typeof ORACLE_SWEEP_ROWS === "undefined") return;

  const groupDefs = [
    {
      id: "benign-boundary",
      title: "1. Normal requests and edge cases",
      subtitle: "Valid data, large images, and requests near the size limits",
      policy: "ALLOW (200 OK)",
      policyBadge: "badge-green",
      invariant: "Custos allows these requests."
    },
    {
      id: "nesting-sgroup",
      title: "2. Messages that are too deep",
      subtitle: "Messages with too many layers or unsupported message types",
      policy: "BLOCK (400 / Code 3)",
      policyBadge: "badge-red",
      invariant: "Custos blocks these requests."
    },
    {
      id: "shape-parity",
      title: "3. Wrong input sizes",
      subtitle: "Wrong shapes, missing data, mismatched sizes, or too much data",
      policy: "BLOCK (400 / Code 3)",
      policyBadge: "badge-red",
      invariant: "Custos checks each input against its data."
    },
    {
      id: "varints-floods",
      title: "4. Broken numbers or too many fields",
      subtitle: "Numbers that do not end or requests with too many fields",
      policy: "BLOCK (400 / Code 3)",
      policyBadge: "badge-red",
      invariant: "Custos stops at its number and field limits."
    },
    {
      id: "rpc-framing",
      title: "5. Hidden settings and blocked actions",
      subtitle: "Requests with admin actions, hidden memory settings, or bad frame data",
      policy: "BLOCK (403 / 400)",
      policyBadge: "badge-red",
      invariant: "Custos checks the request path, settings, and frame."
    }
  ];

  let html = "";

  groupDefs.forEach((g) => {
    const items = ORACLE_SWEEP_ROWS.filter((r) => classifyOracleRowGroup(r) === g.id);
    const total = items.length;
    const prodMatched = items.filter((r) => r.prod_match).length;
    const baseMatched = items.filter((r) => r.baseline_match).length;
    const ctrlMatched = items.filter((r) => r.control_match).length;
    const isAllowGroup = g.id === "benign-boundary";
    const isExpanded = expandedOracleGroups.has(g.id);

    const prodText = isAllowGroup
      ? `${prodMatched}/${total} Admitted`
      : `${prodMatched}/${total} Blocked`;
    const baseText = isAllowGroup
      ? `${baseMatched}/${total} Admitted`
      : `0/${total} Blocked`;
    const ctrlText = isAllowGroup
      ? `${ctrlMatched}/${total} Admitted`
      : `0/${total} Blocked`;

    html += `
      <tr class="tl-group-row" data-oracle-group="${g.id}">
        <td>
          <div class="tl-group-title">
            <span>${g.title}</span>
            <div class="tl-group-meta">
              <span class="badge badge-mauve mono">${total} payloads</span>
              <button class="tl-expand-btn mono" type="button">${isExpanded ? "Hide ▴" : "Inspect ▾"}</button>
            </div>
          </div>
          <span class="tl-group-sub">${g.subtitle}</span>
        </td>
        <td>${renderTrafficLightPill(prodMatched === total, prodText)}</td>
        <td>${renderTrafficLightPill(baseMatched === total, baseText)}</td>
        <td>${renderTrafficLightPill(ctrlMatched === total, ctrlText)}</td>
        <td style="font-size:0.78rem; color:var(--ctp-subtext1)">${g.invariant}</td>
      </tr>
    `;

    if (isExpanded) {
      const chipsHtml = items
        .map((r) => {
          const pIcon = r.prod_match ? "✓" : "✕";
          const bIcon = r.baseline_match ? "✓" : "✕";
          const cIcon = r.control_match ? "✓" : "✕";
          return `
            <div class="tl-payload-chip">
              <div class="tl-payload-chip-head mono">
                <span>${r.name}</span>
                <span style="color:var(--ctp-green)">${pIcon} ${r.prod_status} (${r.prod_latency_ms.toFixed(1)}ms)</span>
              </div>
              <div class="tl-payload-chip-note mono">
                Baseline: <span style="color:${r.baseline_match ? "var(--ctp-green)" : "var(--ctp-red)"}">${bIcon} ${r.baseline_status}</span> •
                Control: <span style="color:${r.control_match ? "var(--ctp-green)" : "var(--ctp-red)"}">${cIcon} ${r.control_status}</span>
              </div>
              <div class="tl-payload-chip-note">${r.notes}</div>
            </div>
          `;
        })
        .join("");

      html += `
        <tr class="tl-drawer-row">
          <td colspan="5">
            <div class="tl-drawer-grid">${chipsHtml}</div>
          </td>
        </tr>
      `;
    }
  });

  tbody.innerHTML = html;

  tbody.querySelectorAll(".tl-group-row").forEach((row) => {
    row.addEventListener("click", () => {
      const gid = row.dataset.oracleGroup;
      if (expandedOracleGroups.has(gid)) {
        expandedOracleGroups.delete(gid);
      } else {
        expandedOracleGroups.add(gid);
      }
      renderOracleTable();
    });
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initWireInspector();
  initTopologies();
  initDashboard();
  initOracleSweep();
  initEli5();
});
