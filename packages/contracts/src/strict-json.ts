import {
  getNodeValue,
  parseTree,
  printParseErrorCode,
  type Node,
  type ParseError,
  type Segment,
} from "jsonc-parser";

/** Raw UTF-8 byte limit for each manifest, lock, or compatibility record. */
export const maximumContractJsonBytes = 1_048_576;

export const strictJsonDiagnosticCodes = [
  "JSON_INPUT_TOO_LARGE",
  "JSON_INVALID_UTF8",
  "JSON_SYNTAX_INVALID",
  "JSON_DUPLICATE_MEMBER",
  "JSON_ROOT_NOT_OBJECT",
] as const;

export type StrictJsonDiagnosticCode = (typeof strictJsonDiagnosticCodes)[number];

export const strictJsonDiagnosticDescriptions: Readonly<
  Record<StrictJsonDiagnosticCode, string>
> = {
  JSON_INPUT_TOO_LARGE:
    "The exact JSON input exceeds the 1,048,576-byte per-artifact limit.",
  JSON_INVALID_UTF8: "The exact JSON input is not valid UTF-8.",
  JSON_SYNTAX_INVALID:
    "The exact input is not strict JSON; comments, trailing commas, and trailing data are rejected.",
  JSON_DUPLICATE_MEMBER:
    "An object contains a duplicate decoded member name; member names must be unique at every nesting level.",
  JSON_ROOT_NOT_OBJECT: "The strict JSON root is not an object.",
};

export interface StrictJsonDiagnostic {
  readonly code: StrictJsonDiagnosticCode;
  readonly path: string;
  readonly message: string;
  readonly characterOffset?: number;
}

export interface StrictJsonDecodeSuccess<T extends object> {
  readonly valid: true;
  readonly value: T;
  readonly diagnostics: readonly [];
}

export interface StrictJsonDecodeFailure {
  readonly valid: false;
  readonly diagnostics: readonly StrictJsonDiagnostic[];
}

export type StrictJsonDecodeResult<T extends object> =
  | StrictJsonDecodeSuccess<T>
  | StrictJsonDecodeFailure;

function escapeJsonPointerSegment(segment: string): string {
  return segment.replaceAll("~", "~0").replaceAll("/", "~1");
}

function jsonPointer(path: readonly Segment[]): string {
  return path.length === 0
    ? ""
    : "/" +
        path
          .map((segment) => escapeJsonPointerSegment(String(segment)))
          .join("/");
}

function duplicateMemberDiagnostic(
  node: Node,
  path: readonly Segment[],
): StrictJsonDiagnostic | undefined {
  if (node.type === "object") {
    const seen = new Set<string>();
    for (const property of node.children ?? []) {
      const keyNode = property.children?.[0];
      const valueNode = property.children?.[1];
      if (keyNode === undefined || typeof keyNode.value !== "string") continue;

      const key = keyNode.value;
      const memberPath = [...path, key];
      if (seen.has(key)) {
        return {
          code: "JSON_DUPLICATE_MEMBER",
          path: jsonPointer(memberPath),
          message: strictJsonDiagnosticDescriptions.JSON_DUPLICATE_MEMBER,
          characterOffset: keyNode.offset,
        };
      }
      seen.add(key);

      if (valueNode !== undefined) {
        const nested = duplicateMemberDiagnostic(valueNode, memberPath);
        if (nested !== undefined) return nested;
      }
    }
    return undefined;
  }

  if (node.type === "array") {
    for (const [index, child] of (node.children ?? []).entries()) {
      const nested = duplicateMemberDiagnostic(child, [...path, index]);
      if (nested !== undefined) return nested;
    }
  }
  return undefined;
}

/**
 * Decode one exact-byte contract artifact as strict UTF-8 JSON.
 *
 * This function does not canonicalize or rewrite the supplied bytes. Callers
 * retain the original Uint8Array for SHA-256 binding and pass the decoded value
 * to JSON Schema validation only after this function succeeds.
 */
export function decodeStrictJsonObject<
  T extends object = Readonly<Record<string, unknown>>,
>(bytes: Uint8Array): StrictJsonDecodeResult<T> {
  if (bytes.byteLength > maximumContractJsonBytes) {
    return {
      valid: false,
      diagnostics: [
        {
          code: "JSON_INPUT_TOO_LARGE",
          path: "",
          message: strictJsonDiagnosticDescriptions.JSON_INPUT_TOO_LARGE,
        },
      ],
    };
  }

  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return {
      valid: false,
      diagnostics: [
        {
          code: "JSON_INVALID_UTF8",
          path: "",
          message: strictJsonDiagnosticDescriptions.JSON_INVALID_UTF8,
        },
      ],
    };
  }

  const parseErrors: ParseError[] = [];
  const root = parseTree(text, parseErrors, {
    allowEmptyContent: false,
    allowTrailingComma: false,
    disallowComments: true,
  });
  const firstParseError = parseErrors[0];
  if (firstParseError !== undefined || root === undefined) {
    const detail =
      firstParseError === undefined
        ? "ValueExpected"
        : printParseErrorCode(firstParseError.error);
    return {
      valid: false,
      diagnostics: [
        {
          code: "JSON_SYNTAX_INVALID",
          path: "",
          message: `${strictJsonDiagnosticDescriptions.JSON_SYNTAX_INVALID} Parser detail: ${detail}.`,
          ...(firstParseError === undefined
            ? {}
            : { characterOffset: firstParseError.offset }),
        },
      ],
    };
  }

  const duplicate = duplicateMemberDiagnostic(root, []);
  if (duplicate !== undefined) {
    return { valid: false, diagnostics: [duplicate] };
  }

  if (root.type !== "object") {
    return {
      valid: false,
      diagnostics: [
        {
          code: "JSON_ROOT_NOT_OBJECT",
          path: "",
          message: strictJsonDiagnosticDescriptions.JSON_ROOT_NOT_OBJECT,
          characterOffset: root.offset,
        },
      ],
    };
  }

  return {
    valid: true,
    value: getNodeValue(root) as T,
    diagnostics: [],
  };
}
