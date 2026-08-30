import type { TokenEnvelope } from "../crypto/token-envelope";

export interface TokenEnvelopeRow {
  readonly envelope_schema_version: number;
  readonly key_version: number;
  readonly dek_iv: string;
  readonly wrapped_dek: string;
  readonly payload_iv: string;
  readonly ciphertext: string;
}

export function tokenEnvelopeToRow(envelope: TokenEnvelope): TokenEnvelopeRow {
  return {
    envelope_schema_version: envelope.schemaVersion,
    key_version: envelope.keyVersion,
    dek_iv: envelope.dekIv,
    wrapped_dek: envelope.wrappedDek,
    payload_iv: envelope.payloadIv,
    ciphertext: envelope.ciphertext,
  };
}

export function tokenEnvelopeFromRow(row: TokenEnvelopeRow): TokenEnvelope {
  if (
    row.envelope_schema_version !== 1 ||
    !Number.isSafeInteger(row.key_version) ||
    row.key_version < 1 ||
    row.dek_iv.length === 0 ||
    row.wrapped_dek.length === 0 ||
    row.payload_iv.length === 0 ||
    row.ciphertext.length === 0
  ) {
    throw new Error("stored token envelope is invalid");
  }
  return {
    schemaVersion: 1,
    keyVersion: row.key_version,
    dekIv: row.dek_iv,
    wrappedDek: row.wrapped_dek,
    payloadIv: row.payload_iv,
    ciphertext: row.ciphertext,
  };
}
