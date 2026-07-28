import { Ajv2020, type ErrorObject, type ValidateFunction } from "ajv/dist/2020.js";

import {
  decodeStrictJsonObject,
  type StrictJsonDiagnostic,
} from "./strict-json.js";

export interface ValidationSuccess {
  readonly valid: true;
  readonly errors: readonly [];
}

export interface ValidationFailure {
  readonly valid: false;
  readonly errors: readonly ErrorObject[];
}

export type ValidationResult = ValidationSuccess | ValidationFailure;

export interface ContractBytesValidationSuccess {
  readonly valid: true;
  readonly stage: "validated";
  readonly value: Readonly<Record<string, unknown>>;
  readonly errors: readonly [];
}

export interface ContractBytesDecodeFailure {
  readonly valid: false;
  readonly stage: "decode";
  readonly errors: readonly StrictJsonDiagnostic[];
}

export interface ContractBytesSchemaFailure {
  readonly valid: false;
  readonly stage: "schema";
  readonly errors: readonly ErrorObject[];
}

export type ContractBytesValidationResult =
  | ContractBytesValidationSuccess
  | ContractBytesDecodeFailure
  | ContractBytesSchemaFailure;

/**
 * Compile a closed Draft 2020-12 contract into a deterministic, local validator.
 * The returned function performs no network access and has no mutation behavior.
 */
export function compileContract(schema: object): (candidate: unknown) => ValidationResult {
  const ajv = new Ajv2020({
    allErrors: true,
    strict: true,
    validateFormats: false,
  });
  const validate: ValidateFunction = ajv.compile(schema);

  return (candidate: unknown): ValidationResult => {
    if (validate(candidate)) {
      return { valid: true, errors: [] };
    }

    return {
      valid: false,
      errors: (validate.errors ?? []).map((error) => ({ ...error })),
    };
  };
}

/**
 * Compile a strict exact-byte decoder followed by a closed Draft 2020-12 schema.
 * Strict decoding always completes before schema evaluation.
 */
export function compileContractBytes(
  schema: object,
): (bytes: Uint8Array) => ContractBytesValidationResult {
  const validate = compileContract(schema);

  return (bytes: Uint8Array): ContractBytesValidationResult => {
    const decoded = decodeStrictJsonObject(bytes);
    if (!decoded.valid) {
      return { valid: false, stage: "decode", errors: decoded.diagnostics };
    }

    const schemaResult = validate(decoded.value);
    if (!schemaResult.valid) {
      return { valid: false, stage: "schema", errors: schemaResult.errors };
    }

    return {
      valid: true,
      stage: "validated",
      value: decoded.value,
      errors: [],
    };
  };
}

export * from "./catalogs.js";
export * from "./profiles.js";
export * from "./semantic.js";
export * from "./strict-json.js";
