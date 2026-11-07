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
      "A legitimate variable-length string/bytes tensor (datatype = 'BYTES', shape [1, 2]). Unlike fixed-width tensors (FP32), BYTES elements are prefixed by 4-byte lengths in raw_input_contents, so size != shape * elem_width. Custos tracks variable-width BYTES tensors and verifies the 4B-per-element lower bound without false positives.",
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
          "Inside InputTensor scope: Field 2 datatype is 'BYTES' (0x42 59 54 45 53). Scanner sets frame.is_bytes_dtype = true so exact fixed-width equality does not falsely reject this request."
      },
      {
        kind: "shape",
        bytes: "1A 02 01 02",
        label: "Tensor Field 3: shape [1, 2] -> min 8 B",
        offset: "0x3E..0x42",
        detail:
          "Packed shape [1, 2] = 2 elements. Because is_bytes_dtype is true, finalize_frame_stats records min_variable_input_bytes += 2 * 4 = 8 bytes (mandatory 4-byte length prefix per element)."
      },
      {
        kind: "skip",
        bytes: "3A 48 [25 00 00 00 'classify:...' 1B 00 00 00 'model:...']",
        label: "Field 7: 72 B Length-Prefixed Strings (ALLOW)",
        offset: "0x42..0x8B",
        detail:
          "Actual raw_input_contents is 72 bytes >= min_variable_input_bytes (8 bytes). Admitted with 0% false positive rate."
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
        bytes: "2A 22  2A 20  2A 1E ... (depths 1..16)",
        label: "16 Nested Wire Type 2 Scopes",
        offset: "0x0F..0x2F",
        detail:
          "Each 0x2A + length varint pushes a ScopeFrame onto the fixed stack array up to MAX_DEPTH = 16."
      },
      {
        kind: "exploit",
        bytes: "2A 02 [08 01]",
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
    name: "shape_buffer_mismatch (CVE-2025-23334-Class)",
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
      "Declares a 4-image FP32 batch ([4, 3, 224, 224] = 2,408,448 bytes) that passes element-count limits, but supplies only 64 bytes in raw_input_contents to trigger an out-of-bounds buffer over-read (CVE-2025-23334-class). Custos enforces exact byte parity for fixed-width tensors.",
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
          "Inside InputTensor scope, kserve_datatype_byte_width('FP32') records elem_byte_width = 4."
      },
      {
        kind: "shape",
        bytes: "1A 06 04 03 E0 01 E0 01",
        label: "Shape [4, 3, 224, 224] -> 2,408,448 B",
        offset: "0x35..0x3D",
        detail:
          "Packed shape product = 602,112 elements. On InputTensor scope exit, expected_raw_input_bytes += 602,112 * 4 = 2,408,448 bytes."
      },
      {
        kind: "exploit",
        bytes: "3A 40 [64 B of 0x00]",
        label: "Field 7: Only 64 B Supplied (ABORT)",
        offset: "0x3D..0x7B",
        detail:
          "Root Field 7 declares length 64 (0x40). At end-of-message parity verification, actual_raw_input_bytes (64) != expected_raw_input_bytes (2,408,448) -> ParseError::PayloadSizeMismatch -> custos_denied:payload_size_mismatch."
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
        bytes: "22 2D [0A 14 'shared_memory_region'  12 15 ...]",
        label: "Field 4: parameters['shared_memory_region'] (ABORT)",
        offset: "0x46..0x75",
        detail:
          "Tag 0x22 (InputTensor Field 4: parameters map entry) pushes MsgContext::ParameterMapEntry. Inside it, Field 1 (Tag 0x0A) has key 'shared_memory_region'. Custos matches prefix 'shared_memory' and immediately aborts with ParseError::UnauthorizedSharedMemoryParameter."
      }
    ]
  }
];

const TOPOLOGIES = {
  prod: {
    title: "Custos Production — Envoy Ingress Gateway + custos-proc Native Sidecar",
    badge: "Production Protected",
    badgeClass: "badge-green",
    summary:
      "The Custos setup with protection: A reverse proxy sits at the front door and passes requests to Custos for checking. Custos rejects bad messages before they reach the AI system. Requests then go to the AI inference server.",
    nodes: [
      {
        title: "gRPC Inference Client",
        meta: "custos-bench • RawCodec",
        desc: "Downstream callers or open-loop load generator transmitting KServe v2 tensors & wire exploits.",
        cls: ""
      },
      {
        title: "Gateway: Envoy Proxy",
        meta: "Port :8003 (:8001) • UID 10001",
        desc: "Terminates TLS/HTTP2, enforces CVE-2023-44487 flood limits, buffers body (16 MiB cap), fail-closed.",
        cls: ""
      },
      {
        title: "Sidecar: custos-proc",
        meta: "RAM UDS 0660 • drop: [ALL]",
        desc: "Zero-allocation #![no_std] TLV wire scanner & RPC allowlist. Drops all 20 exploits in <15 µs.",
        cls: "highlight-custos"
      },
      {
        title: "NVIDIA Triton Server",
        meta: "Upstream :9001 • GPU Node",
        desc: "ONNX Runtime ResNet-50 v1.5 backend. Only receives structurally verified KServe v2 requests.",
        cls: ""
      }
    ],
    specs: [
      ["IPC Transport", "In-Memory Unix Domain Socket (/var/run/custos/ext_proc.sock, 0660)"],
      ["Failure & Security Policy", "Fail-Closed (failure_mode_allow: false) • runAsNonRoot (UID 10001, 0 Caps)"],
      ["L7 & HTTP/2 Hardening", "KServe v2 RPC Allowlist + CVE-2023-44487 Rapid Reset Flood Limits"],
      ["Attack Survival Verdict", "100% Triton Uptime • 20/20 Exploits Dropped • 0% False Positives"]
    ]
  },
  baseline: {
    title: "Proxy Baseline — Standard Envoy HTTP/2 Ingress (No Custos Sidecar)",
    badge: "Proxy Baseline",
    badgeClass: "badge-blue",
    summary:
      "The baseline: A reverse proxy sits at the front but does NOT check messages—it just passes them straight through to the AI system. This shows how much speed is lost by using Custos.",
    nodes: [
      {
        title: "gRPC Inference Client",
        meta: "custos-bench • RawCodec",
        desc: "Fires steady-benign, 99%/1% interleaved, and 2,000-concurrency burst regimes.",
        cls: ""
      },
      {
        title: "Envoy Proxy (No Sidecar)",
        meta: "Port :8002 • Router Only",
        desc: "Standard HTTPConnectionManager + Router filter only. Blind to inner Protobuf TLV semantics.",
        cls: ""
      },
      {
        title: "NVIDIA Triton Server",
        meta: "Upstream :9001 • Exposed",
        desc: "Exposed to nesting bombs, 64-bit shape overflows, parity mismatches, and varint hangs.",
        cls: "highlight-danger"
      }
    ],
    specs: [
      ["Manifest / Config", "03-envoy-baseline.yaml / envoy-topology-b-baseline.yaml"],
      ["HTTP Filters", "envoy.filters.http.router only (no ext_proc sidecar)"],
      ["Scientific Role", "Isolates Envoy HTTP/2 proxy cost from custos-proc UDS wire-scanning cost"],
      ["Vulnerability State", "Vulnerable to all 6 L7 Protobuf wire & RPC exploit families"]
    ]
  },
  control: {
    title: "Unprotected Control — Direct NVIDIA Triton Inference Server",
    badge: "Unprotected Control",
    badgeClass: "badge-red",
    summary:
      "The unprotected setup: Requests go straight to the AI system with no checking at all. This shows what happens when there's no protection—attacks cause crashes or slow performance.",
    nodes: [
      {
        title: "gRPC Inference Client",
        meta: "custos-bench • RawCodec",
        desc: "Sends raw KServe v2 gRPC frames directly to Triton's native gRPC listener.",
        cls: ""
      },
      {
        title: "NVIDIA Triton Server",
        meta: "Port :8001 • Direct Ingress",
        desc: "Directly parses untrusted Protobuf wire bytes on C++ inference worker threads.",
        cls: "highlight-danger"
      }
    ],
    specs: [
      ["Data Path", "Direct HTTP/2 gRPC to tritonserver (:8001)"],
      ["Admission Control", "None (Control Group)"],
      ["Scientific Role", "Establishes raw inference latency floor & unprotected failure behavior"],
      ["Vulnerability State", "Directly exposed to C++ Protobuf parser, allocator & SHM RPC exploits"]
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
    "p50_ms": 6.83,
    "p90_ms": 7.42,
    "p95_ms": 7.53,
    "p99_ms": 7.75,
    "p999_ms": 8.31,
    "p9999_ms": 8.31,
    "cpu_per_1k": 171.0,
    "rss_mb": 37.0,
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
    "p50_ms": 9.05,
    "p90_ms": 9.55,
    "p95_ms": 9.68,
    "p99_ms": 9.92,
    "p999_ms": 11.13,
    "p9999_ms": 11.13,
    "cpu_per_1k": 272.25,
    "rss_mb": 103.8,
    "survival": "Hardened Envoy Baseline (No Attack)",
    "trials_merged": 5
  },
  {
    "label": "homelab_prod_steady-benign_fp32_rps100_mean_n5",
    "topology": "Custos Production",
    "regime": "steady-benign",
    "benign_profile": "ResNet-50 B=1 (FP32)",
    "rps": 100,
    "achieved_rps": 100.0,
    "fpr": 0.0,
    "tp_drop": null,
    "p50_ms": 11.3,
    "p90_ms": 12.16,
    "p95_ms": 12.33,
    "p99_ms": 12.82,
    "p999_ms": 15.76,
    "p9999_ms": 15.76,
    "cpu_per_1k": 191.0,
    "rss_mb": 108.5,
    "survival": "100% Healthy (+2246 µs P50 vs Baseline)",
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
    "p50_ms": 6.68,
    "p90_ms": 7.51,
    "p95_ms": 7.83,
    "p99_ms": 8.16,
    "p999_ms": 9.39,
    "p9999_ms": 9.39,
    "cpu_per_1k": 114.0,
    "rss_mb": 37.0,
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
    "p50_ms": 8.93,
    "p90_ms": 9.6,
    "p95_ms": 9.85,
    "p99_ms": 10.47,
    "p999_ms": 13.22,
    "p9999_ms": 13.22,
    "cpu_per_1k": 181.5,
    "rss_mb": 103.8,
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
    "p50_ms": 9.89,
    "p90_ms": 10.98,
    "p95_ms": 11.42,
    "p99_ms": 12.51,
    "p999_ms": 14.74,
    "p9999_ms": 14.74,
    "cpu_per_1k": 127.33,
    "rss_mb": 108.5,
    "survival": "100% Healthy (+961 µs P50 vs Baseline)",
    "trials_merged": 5
  },
  {
    "label": "homelab_control_steady-benign_bytes_rps150_mean_n5",
    "topology": "Unprotected Control",
    "regime": "steady-benign",
    "benign_profile": "BYTES Tensor [1, 2]",
    "rps": 150,
    "achieved_rps": 150.1,
    "fpr": 0.0,
    "tp_drop": null,
    "p50_ms": 1.82,
    "p90_ms": 2.41,
    "p95_ms": 2.55,
    "p99_ms": 2.78,
    "p999_ms": 3.75,
    "p9999_ms": 3.75,
    "cpu_per_1k": 91.2,
    "rss_mb": 37.0,
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
    "p50_ms": 2.88,
    "p90_ms": 3.49,
    "p95_ms": 3.65,
    "p99_ms": 3.86,
    "p999_ms": 4.16,
    "p9999_ms": 4.16,
    "cpu_per_1k": 145.2,
    "rss_mb": 103.8,
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
    "p50_ms": 3.92,
    "p90_ms": 4.54,
    "p95_ms": 4.69,
    "p99_ms": 4.91,
    "p999_ms": 5.26,
    "p9999_ms": 5.26,
    "cpu_per_1k": 101.87,
    "rss_mb": 108.5,
    "survival": "100% Healthy (+1044 µs P50 vs Baseline)",
    "trials_merged": 5
  },
  {
    "label": "homelab_control_steady-benign_mixed_rps150_mean_n5",
    "topology": "Unprotected Control",
    "regime": "steady-benign",
    "benign_profile": "Mixed (FP32 + BYTES + D≤16)",
    "rps": 150,
    "achieved_rps": 150.1,
    "fpr": 0.0,
    "tp_drop": null,
    "p50_ms": 1.94,
    "p90_ms": 7.36,
    "p95_ms": 7.64,
    "p99_ms": 8.06,
    "p999_ms": 8.37,
    "p9999_ms": 8.37,
    "cpu_per_1k": 91.2,
    "rss_mb": 37.0,
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
    "p50_ms": 3.03,
    "p90_ms": 9.53,
    "p95_ms": 9.96,
    "p99_ms": 10.49,
    "p999_ms": 10.91,
    "p9999_ms": 10.91,
    "cpu_per_1k": 145.2,
    "rss_mb": 103.8,
    "survival": "Hardened Envoy Baseline (No Attack)",
    "trials_merged": 5
  },
  {
    "label": "homelab_prod_steady-benign_mixed_rps150_mean_n5",
    "topology": "Custos Production",
    "regime": "steady-benign",
    "benign_profile": "Mixed (FP32 + BYTES + D≤16)",
    "rps": 150,
    "achieved_rps": 150.0,
    "fpr": 0.0,
    "tp_drop": null,
    "p50_ms": 4.91,
    "p90_ms": 12.67,
    "p95_ms": 13.14,
    "p99_ms": 13.92,
    "p999_ms": 14.7,
    "p9999_ms": 14.7,
    "cpu_per_1k": 101.87,
    "rss_mb": 108.5,
    "survival": "100% Healthy (+1884 µs P50 vs Baseline)",
    "trials_merged": 5
  },
  {
    "label": "homelab_control_interleaved_mixed_rps150_mean_n5",
    "topology": "Unprotected Control",
    "regime": "interleaved",
    "benign_profile": "Mixed (FP32 + BYTES + D≤16)",
    "rps": 150,
    "achieved_rps": 150.2,
    "fpr": 0.0,
    "tp_drop": 0.0,
    "p50_ms": 1.95,
    "p90_ms": 7.39,
    "p95_ms": 7.64,
    "p99_ms": 8.08,
    "p999_ms": 8.79,
    "p9999_ms": 8.79,
    "cpu_per_1k": 91.2,
    "rss_mb": 37.0,
    "survival": "Degraded (7 Backend Runtime Faults)",
    "trials_merged": 5
  },
  {
    "label": "homelab_baseline_interleaved_mixed_rps150_mean_n5",
    "topology": "Proxy Baseline",
    "regime": "interleaved",
    "benign_profile": "Mixed (FP32 + BYTES + D≤16)",
    "rps": 150,
    "achieved_rps": 150.1,
    "fpr": 0.0,
    "tp_drop": 0.0,
    "p50_ms": 3.09,
    "p90_ms": 9.71,
    "p95_ms": 10.04,
    "p99_ms": 10.56,
    "p999_ms": 10.94,
    "p9999_ms": 10.94,
    "cpu_per_1k": 145.2,
    "rss_mb": 103.8,
    "survival": "Degraded (7 Backend Runtime Faults)",
    "trials_merged": 5
  },
  {
    "label": "homelab_prod_interleaved_mixed_rps150_mean_n5",
    "topology": "Custos Production",
    "regime": "interleaved",
    "benign_profile": "Mixed (FP32 + BYTES + D≤16)",
    "rps": 150,
    "achieved_rps": 150.0,
    "fpr": 0.0,
    "tp_drop": 1.0,
    "p50_ms": 5.05,
    "p90_ms": 12.73,
    "p95_ms": 13.13,
    "p99_ms": 13.82,
    "p999_ms": 14.47,
    "p9999_ms": 14.47,
    "cpu_per_1k": 101.87,
    "rss_mb": 108.5,
    "survival": "100% Protected (22/22 Exploits Dropped)",
    "trials_merged": 5
  },
  {
    "label": "homelab_control_saturating-burst_mixed_rps500_mean_n5",
    "topology": "Unprotected Control",
    "regime": "saturating-burst",
    "benign_profile": "Mixed (FP32 + BYTES + D≤16)",
    "rps": 500,
    "achieved_rps": 915.0,
    "fpr": 0.0,
    "tp_drop": 0.0,
    "p50_ms": 308.65,
    "p90_ms": 512.18,
    "p95_ms": 512.28,
    "p99_ms": 512.28,
    "p999_ms": 512.28,
    "p9999_ms": 512.28,
    "cpu_per_1k": 136.8,
    "rss_mb": 37.0,
    "survival": "Backend Flooded (Benign P99 512.3 ms)",
    "trials_merged": 5
  },
  {
    "label": "homelab_baseline_saturating-burst_mixed_rps500_mean_n5",
    "topology": "Proxy Baseline",
    "regime": "saturating-burst",
    "benign_profile": "Mixed (FP32 + BYTES + D≤16)",
    "rps": 500,
    "achieved_rps": 902.6,
    "fpr": 0.0,
    "tp_drop": 0.0,
    "p50_ms": 338.27,
    "p90_ms": 523.76,
    "p95_ms": 524.45,
    "p99_ms": 524.5,
    "p999_ms": 524.5,
    "p9999_ms": 524.5,
    "cpu_per_1k": 217.8,
    "rss_mb": 103.8,
    "survival": "Backend Flooded (Benign P99 524.5 ms)",
    "trials_merged": 5
  },
  {
    "label": "homelab_prod_saturating-burst_mixed_rps500_mean_n5",
    "topology": "Custos Production",
    "regime": "saturating-burst",
    "benign_profile": "Mixed (FP32 + BYTES + D≤16)",
    "rps": 500,
    "achieved_rps": 2458.8,
    "fpr": 0.0,
    "tp_drop": 1.0,
    "p50_ms": 150.84,
    "p90_ms": 202.19,
    "p95_ms": 203.21,
    "p99_ms": 203.29,
    "p999_ms": 203.29,
    "p9999_ms": 203.29,
    "cpu_per_1k": 152.8,
    "rss_mb": 108.5,
    "survival": "100% Benign Survival (Benign P99 203.3 ms)",
    "trials_merged": 5
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

// 2. Wire Payload Inspector
function initWireInspector() {
  const sidebar = document.getElementById("payload-sidebar");
  if (!sidebar) return;
  const groups = {};
  for (const item of WIRE_PAYLOADS) {
    if (!groups[item.group]) groups[item.group] = [];
    groups[item.group].push(item);
  }

  sidebar.innerHTML = "";
  for (const [groupName, items] of Object.entries(groups)) {
    const header = document.createElement("div");
    header.className = "sidebar-group-title";
    header.textContent = groupName;
    sidebar.appendChild(header);

    for (const item of items) {
      const btn = document.createElement("button");
      btn.className = "payload-btn";
      btn.dataset.id = item.id;
      btn.innerHTML = `
        <span class="mono payload-name">${item.id}</span>
        ${verdictIcon(verdictKind(item))}
      `;
      btn.addEventListener("click", () => selectPayload(item.id));
      sidebar.appendChild(btn);
    }
  }

  selectPayload(WIRE_PAYLOADS[0].id);
}

function selectPayload(id) {
  const payload = WIRE_PAYLOADS.find((p) => p.id === id) || WIRE_PAYLOADS[0];
  document.querySelectorAll(".payload-btn").forEach((b) => {
    b.classList.toggle("active", b.dataset.id === payload.id);
  });

  document.getElementById("ins-title").textContent = payload.name;
  const badgeEl = document.getElementById("ins-badge");
  const kind = verdictKind(payload);
  // "ALLOW (ResponseStatus::Continue)" -> icon + "ResponseStatus::Continue"
  const detail = payload.verdict.replace(/^(?:ALLOW|DENY|REJECT)\s*\((.*)\)\s*$/i, "$1");
  badgeEl.innerHTML = `${verdictIcon(kind)}<span class="verdict-text">${detail}</span>`;
  badgeEl.className = `verdict-pill ${kind === "allow" ? "is-allow" : "is-reject"}`;
  document.getElementById("ins-summary").textContent = payload.summary;

  document.getElementById("v-error").textContent = payload.errorVariant;
  document.getElementById("v-http").textContent = `${payload.httpStatus} / gRPC ${payload.grpcStatus}`;
  document.getElementById("v-depth").textContent = payload.maxDepth;
  document.getElementById("v-elements").textContent = payload.tensorElements;
  document.getElementById("v-skipped").textContent = payload.skippedBytes;
  document.getElementById("v-bytes").textContent = payload.totalBytes;

  const stream = document.getElementById("hex-stream");
  stream.innerHTML = "";
  payload.segments.forEach((seg, idx) => {
    const el = document.createElement("div");
    el.className = `hex-segment ${idx === payload.segments.length - 1 ? "selected" : ""}`;
    el.dataset.kind = seg.kind;
    el.innerHTML = `
      <span class="hex-bytes mono">${seg.bytes}</span>
      <span class="hex-caption">${seg.label} (${seg.offset})</span>
    `;
    el.addEventListener("click", () => {
      stream.querySelectorAll(".hex-segment").forEach((s) => s.classList.remove("selected"));
      el.classList.add("selected");
      showSegmentDetail(seg);
    });
    stream.appendChild(el);
  });

  showSegmentDetail(payload.segments[payload.segments.length - 1]);
  emit("custos:payloadrendered", { id: payload.id });
}

function showSegmentDetail(seg) {
  const box = document.getElementById("segment-detail");
  box.innerHTML = `
    <strong>${seg.label}</strong> <span class="mono offset">[${seg.offset}]</span> —
    <code class="mono">${seg.bytes}</code><br/>
    <span class="detail-text">${seg.detail}</span>
  `;
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

function renderLatencySvg(trials) {
  const svg = document.getElementById("latency-svg");
  const styles = getComputedStyle(document.documentElement);
  const colors = [
    styles.getPropertyValue("--ctp-green").trim(),
    styles.getPropertyValue("--ctp-blue").trim(),
    styles.getPropertyValue("--ctp-red").trim(),
    styles.getPropertyValue("--ctp-mauve").trim()
  ];
  const gridColor = styles.getPropertyValue("--ctp-surface0").trim();
  const textColor = styles.getPropertyValue("--ctp-subtext0").trim();

  const keys = ["p50_ms", "p90_ms", "p95_ms", "p99_ms", "p999_ms", "p9999_ms"];
  const labels = ["P50", "P90", "P95", "P99", "P99.9", "P99.99"];
  const W = 540;
  const H = 240;
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
    out += `<text x="${x}" y="${H - 10}" fill="${textColor}" font-size="10" text-anchor="middle">${lbl}</text>`;
  });

  trials.forEach((t, idx) => {
    const color =
      t.topology.includes("Custos") || t.topology.includes("Production")
        ? colors[0]
        : t.topology.includes("Baseline") || t.topology.includes("Envoy")
          ? colors[1]
          : colors[2 + (idx % 2)];
    const pts = keys.map((k, i) => `${xFor(i)},${yFor(t[k] || 0.1)}`).join(" ");
    out += `<polyline fill="none" stroke="${color}" stroke-width="2.5" points="${pts}" />`;
    keys.forEach((k, i) => {
      out += `<circle cx="${xFor(i)}" cy="${yFor(t[k] || 0.1)}" r="3.5" fill="${color}" />`;
    });
  });

  svg.innerHTML = out;
}

function renderThroughputSvg(trials) {
  const svg = document.getElementById("throughput-svg");
  const styles = getComputedStyle(document.documentElement);
  const green = styles.getPropertyValue("--ctp-green").trim();
  const blue = styles.getPropertyValue("--ctp-blue").trim();
  const red = styles.getPropertyValue("--ctp-red").trim();
  const gridColor = styles.getPropertyValue("--ctp-surface0").trim();
  const textColor = styles.getPropertyValue("--ctp-subtext0").trim();

  const W = 540;
  const H = 280;
  const padL = 52;
  const padR = 20;
  const padT = 24;
  const padB = 80;

  const maxRps = Math.max(...trials.map((t) => Math.max(t.rps, t.achieved_rps, 1000)), 1000) * 1.1;
  let out = "";

  for (let i = 0; i <= 4; i++) {
    const val = Math.round((maxRps / 4) * i);
    const y = H - padB - (i / 4) * (H - padT - padB);
    out += `<line x1="${padL}" y1="${y}" x2="${W - padR}" y2="${y}" stroke="${gridColor}" stroke-dasharray="3,3" />`;
    out += `<text x="${padL - 8}" y="${y + 4}" fill="${textColor}" font-size="10" text-anchor="end">${val}</text>`;
  }

  const slotW = (W - padL - padR) / Math.max(trials.length, 1);
  const barW = Math.min(48, slotW * 0.55);

  trials.forEach((t, idx) => {
    const cx = padL + slotW * (idx + 0.5);
    const h = (t.achieved_rps / maxRps) * (H - padT - padB);
    const y = H - padB - h;
    const color =
      t.topology.includes("Custos") || t.topology.includes("Production")
        ? green
        : t.topology.includes("Baseline") || t.topology.includes("Envoy")
          ? blue
          : red;

    const dense = trials.length > 6;
    const valText = dense ? `${t.achieved_rps.toFixed(0)}` : `${t.achieved_rps.toFixed(0)} rps`;
    out += `<rect x="${cx - barW / 2}" y="${y}" width="${barW}" height="${Math.max(h, 2)}" rx="4" fill="${color}" />`;
    out += `<text x="${cx}" y="${y - 6}" fill="${textColor}" font-size="${dense ? 8 : 10}" text-anchor="middle">${valText}</text>`;
    const topology =
      t.topology.includes("Custos")
        ? dense ? "Prod" : "Production"
        : t.topology.includes("Baseline")
          ? dense ? "Base" : "Baseline"
          : dense ? "Ctrl" : "Control";
    const profShort =
      (t.benign_profile || "").includes("BYTES Tensor")
        ? "BYTES"
        : (t.benign_profile || "").includes("Mixed")
          ? "Mixed"
          : `FP32@${t.rps}`;
    
    out += `<text x="${cx}" y="${H - 54}" fill="${textColor}" font-size="${dense ? 7.5 : 9}" font-weight="600" text-anchor="middle">${topology}</text>`;
    out += `<text x="${cx}" y="${H - 42}" fill="${textColor}" font-size="${dense ? 7 : 8.5}" text-anchor="middle">${profShort}</text>`;
  });

  svg.innerHTML = out;
}

function renderTrialsTable(trials) {
  const tbody = document.getElementById("trials-tbody");
  tbody.innerHTML = trials
    .map(
      (t) => {
        const isSteadyBenign = t.regime === "steady-benign" || t.tp_drop === null || t.tp_drop === undefined;
        const tpDropText = isSteadyBenign ? "N/A" : `${(Number(t.tp_drop) * 100).toFixed(1)}%`;
        const tpDropColor = isSteadyBenign
          ? "var(--ctp-overlay1)"
          : Number(t.tp_drop) >= 0.99
            ? "var(--ctp-green)"
            : "var(--ctp-subtext0)";
        const profile = t.benign_profile || "ResNet-50 B=1 (FP32)";
        return `
    <tr>
      <td class="mono" style="font-weight:600">${t.topology}</td>
      <td><span class="badge badge-mauve">${t.regime}</span></td>
      <td class="mono" style="font-size:0.78rem; color:var(--ctp-subtext1)">${profile}</td>
      <td class="mono">${t.achieved_rps.toFixed(1)} / ${t.rps}</td>
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
}

// 5. ELI5 explainers on the threat taxonomy cards.
// Hover/focus is handled entirely in CSS; this adds tap-to-pin for touch
// devices (where :hover never fires) plus Escape and click-away to dismiss.
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

document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initWireInspector();
  initTopologies();
  initDashboard();
  initEli5();
});
