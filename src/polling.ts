import type { accessRequestMethods } from "./access-requests.js";
import { type AccessRequest, AccessRequestState } from "./public.js";
import { RazielClientError, type RequestOptions, withTimeout } from "./transport.js";

export interface WaitForAccessRequestOptions extends RequestOptions {
  /** Absolute Unix time in milliseconds. Default: 24 hours from this call. */
  readonly deadlineUnixMilliseconds?: number;
}

const STOP = new Set([
  AccessRequestState.AWAITING_SIGNATURE,
  AccessRequestState.WAITING_FOR_AGENT,
  AccessRequestState.READY,
  AccessRequestState.REJECTED,
  AccessRequestState.CANCELED,
  AccessRequestState.EXPIRED,
  AccessRequestState.FAILED,
]);

export function pollingMethods(
  access: Pick<ReturnType<typeof accessRequestMethods>, "getAccessRequest">,
) {
  return {
    async waitForAccessRequest(
      id: string,
      options: WaitForAccessRequestOptions = {},
    ): Promise<AccessRequest> {
      const remaining = (options.deadlineUnixMilliseconds ?? Date.now() + 86_400_000) - Date.now();
      if (!Number.isSafeInteger(remaining) || remaining > 2_147_483_647)
        throw new RazielClientError("INVALID_REQUEST");
      if (remaining <= 0) throw new RazielClientError("TIMEOUT");
      return withTimeout(remaining, options.signal, async (signal) => {
        let interval = 5_000;
        for (;;) {
          let delay = interval;
          try {
            const request = await access.getAccessRequest(id, { signal });
            if (STOP.has(request.state)) return request;
          } catch (error) {
            if (!(error instanceof RazielClientError) || !retryableRead(error)) throw error;
            delay = Math.max(delay, error.retryAfterMs ?? 0);
          }
          await sleep(delay, signal);
          interval = Math.min(interval * 2, 30_000);
        }
      });
    },
  };
}

function retryableRead(error: RazielClientError): boolean {
  return (
    error.code === "TRANSPORT_ERROR" ||
    error.code === "TIMEOUT" ||
    ((error.status === 429 || error.status === 503) && error.retryable)
  );
}

function sleep(milliseconds: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    signal.throwIfAborted();
    const finish = () => {
      signal.removeEventListener("abort", abort);
      resolve();
    };
    const timer = setTimeout(finish, milliseconds);
    const abort = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", abort);
      reject(signal.reason);
    };
    signal.addEventListener("abort", abort, { once: true });
  });
}
