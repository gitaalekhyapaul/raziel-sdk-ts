import { Buffer } from "node:buffer";
import {
  type DescMessage,
  fromJson,
  type JsonValue,
  type MessageShape,
  ScalarType,
} from "@bufbuild/protobuf";

import { record } from "./transport.js";

/** Buf accepts several ProtoJSON spellings. The public HTTP contract accepts only these. */
export function parseProtoJson<Desc extends DescMessage>(
  schema: Desc,
  value: unknown,
): MessageShape<Desc> {
  checkJson(schema, value);
  return fromJson(schema, value as JsonValue);
}

function checkJson(schema: DescMessage, value: unknown): void {
  if (schema.typeName === "google.protobuf.Duration") {
    if (typeof value !== "string") throw new Error("invalid duration");
    return;
  }
  if (!record(value)) throw new Error("invalid object");
  if (
    schema.fields.some((field) => field.localName === "formatVersion") &&
    value.formatVersion !== 1
  ) {
    throw new Error("invalid version");
  }
  for (const [name, item] of Object.entries(value)) {
    const field = schema.fields.find((field) => field.jsonName === name);
    if (!field || item === null) throw new Error("invalid field");
    switch (field.fieldKind) {
      case "message":
        checkJson(field.message, item);
        break;
      case "list":
        if (!Array.isArray(item) || field.listKind !== "message") throw new Error("invalid list");
        for (const entry of item) checkJson(field.message, entry);
        break;
      case "enum":
        if (typeof item !== "string" || !field.enum.values.some((entry) => entry.name === item))
          throw new Error("invalid enum");
        break;
      case "scalar":
        checkScalar(field.scalar, item);
        break;
      default:
        throw new Error("unsupported field");
    }
  }
}

function checkScalar(type: ScalarType, value: unknown): void {
  switch (type) {
    case ScalarType.INT64:
    case ScalarType.SINT64:
    case ScalarType.SFIXED64:
      if (typeof value !== "string" || !/^(0|-?[1-9][0-9]{0,18})$/.test(value))
        throw new Error("invalid integer");
      return;
    case ScalarType.UINT64:
    case ScalarType.FIXED64:
      if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,19})$/.test(value))
        throw new Error("invalid integer");
      return;
    case ScalarType.BYTES:
      if (typeof value !== "string" || Buffer.from(value, "base64").toString("base64") !== value)
        throw new Error("invalid bytes");
      return;
    case ScalarType.STRING:
      if (typeof value !== "string") throw new Error("invalid string");
      return;
    case ScalarType.BOOL:
      if (typeof value !== "boolean") throw new Error("invalid boolean");
      return;
    default:
      if (typeof value !== "number" || !Number.isInteger(value)) throw new Error("invalid number");
  }
}
