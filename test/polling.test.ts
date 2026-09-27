import { create } from "@bufbuild/protobuf";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  type RequestOptions,
  AccessRequestSchema,
  AccessRequestState,
  RazielClientError,
} from "../src/index.ts";
import { pollingMethods } from "../src/polling.ts";

afterEach(() => vi.useRealTimers());
const row = (state: AccessRequestState) => create(AccessRequestSchema, { state });

describe("bounded request polling", () => {
  it("reads immediately, then backs off from five to thirty seconds without mutations", async () => {
    vi.useFakeTimers();
    const getAccessRequest = vi.fn().mockResolvedValue(row(AccessRequestState.PROVING));
    const waiting = pollingMethods({ getAccessRequest }).waitForAccessRequest("id");
    await vi.advanceTimersByTimeAsync(0);
    expect(getAccessRequest).toHaveBeenCalledTimes(1);
    for (const [delay, count] of [
      [5_000, 2],
      [10_000, 3],
      [20_000, 4],
      [30_000, 5],
    ] as const) {
      await vi.advanceTimersByTimeAsync(delay - 1);
      expect(getAccessRequest).toHaveBeenCalledTimes(count - 1);
      await vi.advanceTimersByTimeAsync(1);
      expect(getAccessRequest).toHaveBeenCalledTimes(count);
    }
    getAccessRequest.mockResolvedValue(row(AccessRequestState.READY));
    await vi.advanceTimersByTimeAsync(30_000);
    expect((await waiting).state).toBe(AccessRequestState.READY);
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each([
    AccessRequestState.AWAITING_SIGNATURE,
    AccessRequestState.WAITING_FOR_AGENT,
    AccessRequestState.READY,
    AccessRequestState.REJECTED,
    AccessRequestState.CANCELED,
    AccessRequestState.EXPIRED,
    AccessRequestState.FAILED,
  ])("returns state %s for explicit caller action", async (state) => {
    const getAccessRequest = vi.fn().mockResolvedValue(row(state));
    expect((await pollingMethods({ getAccessRequest }).waitForAccessRequest("id")).state).toBe(
      state,
    );
    expect(getAccessRequest).toHaveBeenCalledOnce();
  });

  it("honors retry-after without retrying authorization errors", async () => {
    vi.useFakeTimers();
    const getAccessRequest = vi
      .fn()
      .mockRejectedValueOnce(new RazielClientError("CAPACITY_EXCEEDED", 429, true, 25_000))
      .mockRejectedValue(new RazielClientError("NOT_AUTHORIZED", 401));
    const waiting = pollingMethods({ getAccessRequest }).waitForAccessRequest("id");
    const rejected = expect(waiting).rejects.toMatchObject({ code: "NOT_AUTHORIZED" });
    await vi.advanceTimersByTimeAsync(24_999);
    expect(getAccessRequest).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(1);
    await rejected;
    expect(getAccessRequest).toHaveBeenCalledTimes(2);
  });

  it("aborts a sleeping wait without canceling server work", async () => {
    vi.useFakeTimers();
    const getAccessRequest = vi.fn().mockResolvedValue(row(AccessRequestState.APPROVED_WAITING));
    const controller = new AbortController();
    const waiting = pollingMethods({ getAccessRequest }).waitForAccessRequest("id", {
      signal: controller.signal,
    });
    const rejected = expect(waiting).rejects.toMatchObject({ code: "ABORTED" });
    await vi.advanceTimersByTimeAsync(0);
    controller.abort();
    await rejected;
    expect(getAccessRequest).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("bounds a hung read by the caller deadline", async () => {
    vi.useFakeTimers();
    const getAccessRequest = vi.fn(
      (_id: string, _options?: RequestOptions) => new Promise<never>(() => {}),
    );
    const waiting = pollingMethods({ getAccessRequest }).waitForAccessRequest("id", {
      deadlineUnixMilliseconds: Date.now() + 100,
    });
    const rejected = expect(waiting).rejects.toMatchObject({ code: "TIMEOUT" });
    await vi.advanceTimersByTimeAsync(100);
    await rejected;
    expect(getAccessRequest.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
  });
});
