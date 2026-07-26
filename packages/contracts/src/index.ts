import { Ajv2020, type ErrorObject, type ValidateFunction } from "ajv/dist/2020.js";

export interface ValidationSuccess {
  readonly valid: true;
  readonly errors: readonly [];
}

export interface ValidationFailure {
  readonly valid: false;
  readonly errors: readonly ErrorObject[];
}

export type ValidationResult = ValidationSuccess | ValidationFailure;

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

export * from "./semantic.js";
