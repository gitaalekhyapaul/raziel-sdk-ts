import { Buffer } from "node:buffer";
import { webcrypto } from "node:crypto";
import { once } from "node:events";
import { createServer, type RequestListener } from "node:http";
import type { AddressInfo } from "node:net";

import { expect, it } from "vitest";

import {
  agentApiRequestSignatureMessage,
  createAgentIdentity,
  createRazielClient,
  createWebCryptoSigner,
  decodeHex,
  sha256,
} from "../src/index.ts";

async function serve(handler: RequestListener, run: (origin: string) => Promise<void>) {
  const server = createServer(handler);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address() as AddressInfo;
  try {
    await run(`http://127.0.0.1:${port}`);
  } finally {
    const closed = new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
    server.closeAllConnections();
    await closed;
  }
}

it("uses native fetch with two caller-owned keys and rejects a token/key mismatch", async () => {
  const identities = await Promise.all([createAgentIdentity(), createAgentIdentity()]);
  const registrations = await Promise.all(
    identities.map(async (identity, index) => {
      const tokenId = (index + 1).toString(16).repeat(32);
      const token = `rz1.${tokenId}.${Buffer.alloc(32, index + 1).toString("base64url")}`;
      return {
        tokenId,
        token,
        identity,
        key: await webcrypto.subtle.importKey("raw", identity.publicKey, "Ed25519", false, [
          "verify",
        ]),
        me: {
          formatVersion: 1,
          agentId: `test-agent-${index}`,
          audience: "test-only-installation",
          publicKey: Buffer.from(identity.publicKey).toString("base64"),
          keyThumbprint: Buffer.from(identity.keyThumbprint).toString("base64"),
          tokenExpiresAtUnixSeconds: "1800000000",
        },
      };
    }),
  );
  const observations: string[] = [];
  await serve(
    (request, response) => {
      void (async () => {
        const registration = registrations.find(
          ({ token }) => request.headers.authorization === `Bearer ${token}`,
        );
        const get = (name: string) => {
          const value = request.headers[name];
          if (typeof value !== "string") throw new Error("missing test header");
          return value;
        };
        const method = request.method;
        const target = request.url;
        if (method !== "GET" || target !== "/api/agent/v1/me")
          throw new Error("unexpected test request");
        expect(request.headers.cookie).toBeUndefined();
        expect(get("x-raziel-agent-version")).toBe("1");
        observations.push(get("x-raziel-agent-nonce"));
        if (!registration) throw new Error("missing test registration");
        const message = agentApiRequestSignatureMessage({
          formatVersion: 1,
          audience: registration.me.audience,
          tokenId: registration.tokenId,
          agentKeyThumbprint: registration.identity.keyThumbprint,
          requestMethod: method,
          canonicalRequestTarget: target,
          requestBodyHash: await sha256(new Uint8Array()),
          requestNonce: decodeHex(get("x-raziel-agent-nonce")),
          requestTimestampUnixSeconds: BigInt(get("x-raziel-agent-timestamp")),
        });
        const valid = await webcrypto.subtle.verify(
          "Ed25519",
          registration.key,
          decodeHex(get("x-raziel-agent-signature")),
          message,
        );
        response.writeHead(valid ? 200 : 401, { "Content-Type": "application/json" });
        response.end(
          JSON.stringify(
            valid ? registration.me : { error: { code: "NOT_AUTHORIZED", retryable: false } },
          ),
        );
      })().catch(() => {
        response.writeHead(500);
        response.end();
      });
    },
    async (baseUrl) => {
      for (const registration of registrations) {
        expect(
          await createRazielClient({
            baseUrl,
            audience: registration.me.audience,
            tokenProvider: () => registration.token,
            signer: createWebCryptoSigner(registration.identity),
          }).me(),
        ).toEqual(registration.me);
      }
      const first = registrations[0];
      const second = registrations[1];
      if (!first || !second) throw new Error("missing test registrations");
      await expect(
        createRazielClient({
          baseUrl,
          audience: first.me.audience,
          tokenProvider: () => first.token,
          signer: createWebCryptoSigner(second.identity),
        }).me(),
      ).rejects.toMatchObject({ code: "NOT_AUTHORIZED" });
    },
  );
  expect(new Set(observations).size).toBe(3);
});

it("does not follow redirects or resend credentials with native fetch", async () => {
  const identity = await createAgentIdentity();
  const paths: string[] = [];
  await serve(
    (request, response) => {
      paths.push(request.url ?? "");
      response.writeHead(302, { Location: "/credential-leak-target" });
      response.end();
    },
    async (baseUrl) => {
      await expect(
        createRazielClient({
          baseUrl,
          audience: "test-only-installation",
          tokenProvider: () => `rz1.${"11".repeat(16)}.${Buffer.alloc(32).toString("base64url")}`,
          signer: createWebCryptoSigner(identity),
        }).me(),
      ).rejects.toMatchObject({ code: "TRANSPORT_ERROR" });
    },
  );
  expect(paths).toEqual(["/api/agent/v1/me"]);
});
