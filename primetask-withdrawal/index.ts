// PrimeTask M-Pesa B2C withdrawal function (SANDBOX ONLY until verified).
// This matches the known public schema:
// withdrawal_requests(id, user_id, amount, currency, payout_method,
// payout_status, payout_details, provider_reference)
// wallets(user_id, balance)
// mpesa_b2c_attempts(withdrawal_request_id, originator_conversation_id,
// conversation_id, mpesa_transaction_id, status, result_code, result_payload, updated_at)
//
// Before using: verify the three pt_* SQL helper functions, all secret VALUES,
// and that the function's legacy JWT verification is OFF so Daraja callbacks
// can reach the handler. The handler authenticates payout requests itself.
// Do not treat a timeout or ambiguous API response as failure; do not retry it.

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function reply(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

const env = (name: string): string => (Deno.env.get(name) ?? "").trim();
const SUPABASE_URL = env("SUPABASE_URL").replace(/\/+$/, "");

// Supabase currently injects this legacy key in hosted Edge Functions.
// Do not use SUPABASE_SECRET_KEYS.default as a Bearer token: new sb_secret_ keys
// are API keys, not JWTs. We require the legacy service-role JWT for raw REST calls.
const SERVICE_ROLE_KEY =
  env("PT_SUPABASE_SERVICE_ROLE_KEY");

async function adminFetch(path: string, init: RequestInit = {}): Promise<Response> {
  if (!SUPABASE_URL || !SERVICE_ROLE_KEY) {
    throw new Error(
      "Server configuration missing: SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY is unavailable.",
    );
  }

  return await fetch(`${SUPABASE_URL}${path}`, {
    ...init,
    headers: {
      apikey: SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json",
      ...(init.headers ?? {}),
    },
  });
}

async function rpc(name: string, args: Record<string, unknown>): Promise<unknown> {
  const response = await adminFetch(`/rest/v1/rpc/${name}`, {
    method: "POST",
    body: JSON.stringify(args),
  });
  const raw = await response.text();
  if (!response.ok) {
    console.error(`Database RPC ${name} failed:`, response.status, raw);
    throw new Error(`Database operation ${name} failed (${response.status}).`);
  }
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

function normalizeKenyanPhone(input: unknown): string {
  let phone = "";
  if (typeof input === "string") {
    phone = input.trim();
    if (phone.startsWith("{")) {
      try {
        const obj = JSON.parse(phone);
        phone = String(obj.phone ?? obj.phone_number ?? obj.msisdn ?? "");
      } catch {
        phone = "";
      }
    }
  } else if (input && typeof input === "object") {
    const obj = input as Record<string, unknown>;
    phone = String(obj.phone ?? obj.phone_number ?? obj.msisdn ?? "");
  }

  phone = phone.replace(/\D/g, "");
  if (phone.startsWith("0") && phone.length === 10) {
    phone = `254${phone.slice(1)}`;
  } else if ((phone.startsWith("7") || phone.startsWith("1")) && phone.length === 9) {
    phone = `254${phone}`;
  }
  if (!/^254\d{9}$/.test(phone)) {
    throw new Error(
      "Invalid Kenyan M-Pesa number in payout_details. Expected 07XXXXXXXX, 01XXXXXXXX, or 254XXXXXXXXX.",
    );
  }
  return phone;
}

async function getDarajaAccessToken(): Promise<string> {
  const consumerKey = env("DARAJA_CONSUMER_KEY");
  const consumerSecret = env("DARAJA_CONSUMER_SECRET");
  if (!consumerKey || !consumerSecret) {
    throw new Error("DARAJA_CONSUMER_KEY or DARAJA_CONSUMER_SECRET is missing.");
  }

  const response = await fetch(
    "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
    {
      method: "GET",
      headers: {
        Authorization: `Basic ${btoa(`${consumerKey}:${consumerSecret}`)}`,
      },
    },
  );
  const body = await response.json().catch(() => null);
  if (!response.ok || !body?.access_token) {
    // Avoid logging credentials or token values.
    console.error("Daraja OAuth failed with HTTP status", response.status);
    throw new Error("Safaricom sandbox authentication failed. Check the credential values.");
  }
  return String(body.access_token);
}

async function updateAttempt(
  withdrawalId: string,
  fields: Record<string, unknown>,
  onlyIfStatus?: string,
): Promise<{ ok: boolean; rows: unknown[] }> {
  const filter = `/rest/v1/mpesa_b2c_attempts?withdrawal_request_id=eq.${encodeURIComponent(withdrawalId)}` +
    (onlyIfStatus ? `&status=eq.${encodeURIComponent(onlyIfStatus)}` : "");
  const response = await adminFetch(filter, {
    method: "PATCH",
    headers: { Prefer: "return=representation" },
    body: JSON.stringify({ ...fields, updated_at: new Date().toISOString() }),
  });
  const raw = await response.text();
  if (!response.ok) {
    console.error("Could not update M-Pesa attempt. HTTP", response.status, raw);
    return { ok: false, rows: [] };
  }
  try {
    return { ok: true, rows: raw ? JSON.parse(raw) : [] };
  } catch {
    return { ok: true, rows: [] };
  }
}

async function callbackHandler(request: Request, kind: "result" | "timeout"): Promise<Response> {
  const expectedToken = env("DARAJA_CALLBACK_TOKEN");
  const providedToken = new URL(request.url).searchParams.get("token") ?? "";
  if (!expectedToken || providedToken !== expectedToken) {
    return reply({ error: "Invalid callback token." }, 401);
  }

  const payload = await request.json().catch(() => null);
  if (!payload || typeof payload !== "object") {
    return reply({ error: "Invalid callback payload." }, 400);
  }

  const envelope = payload as Record<string, unknown>;
  const result = envelope.Result && typeof envelope.Result === "object"
    ? envelope.Result as Record<string, unknown>
    : null;
  const originatorId = String(result?.OriginatorConversationID ?? "");

  if (kind === "timeout") {
    // A timeout is ambiguous; never refund automatically on timeout.
    // Match by the stored Daraja originator ID, not by withdrawal_request_id.
    if (originatorId) {
      const timeoutResponse = await adminFetch(
        `/rest/v1/mpesa_b2c_attempts?originator_conversation_id=eq.${encodeURIComponent(originatorId)}&status=eq.processing`,
        {
          method: "PATCH",
          headers: { Prefer: "return=minimal" },
          body: JSON.stringify({
            status: "timeout_unknown",
            result_payload: payload,
            updated_at: new Date().toISOString(),
          }),
        },
      );
      if (!timeoutResponse.ok) {
        console.error("Could not record timeout callback. HTTP", timeoutResponse.status);
      }
    }
    return reply({ received: true });
  }

  if (!result || !originatorId || result.ResultCode === undefined) {
    return reply({ error: "Missing required Daraja result fields." }, 400);
  }

  // Safaricom B2C callbacks commonly put the receipt in ResultParameters,
  // rather than a top-level Result.TransactionID field.
  const resultParameters = result.ResultParameters && typeof result.ResultParameters === "object"
    ? result.ResultParameters as Record<string, unknown>
    : null;
  const parameterList = Array.isArray(resultParameters?.ResultParameter)
    ? resultParameters.ResultParameter as Array<Record<string, unknown>>
    : [];
  const parameterValue = (key: string): string | null => {
    const item = parameterList.find((entry) => String(entry?.Key ?? "") === key);
    return item?.Value === undefined || item?.Value === null ? null : String(item.Value);
  };
  const resultCode = String(result.ResultCode);
  const transactionId = String(
    result.TransactionID ?? parameterValue("TransactionReceipt") ?? parameterValue("TransactionID") ?? "",
  ).trim();

  try {
    await rpc("pt_finalize_withdrawal", {
      p_originator_conversation_id: originatorId,
      p_success: resultCode === "0",
      p_transaction_id: transactionId || null,
      p_result: payload,
    });
  } catch (error) {
    console.error("Could not finalize Daraja result callback.", {
      originatorId,
      resultCode,
      hasTransactionReceipt: Boolean(transactionId),
      error: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }
  return reply({ received: true });
}

Deno.serve(async (request: Request): Promise<Response> => {
  if (request.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }
  if (request.method !== "POST") {
    return reply({ error: "Use POST." }, 405);
  }

  try {
    const url = new URL(request.url);
    const action = url.searchParams.get("action");
    if (action === "result" || action === "timeout") {
      return await callbackHandler(request, action);
    }

    if (!SUPABASE_URL || !SERVICE_ROLE_KEY) {
      return reply({ error: "Supabase server configuration is missing." }, 503);
    }

    const bearer = (request.headers.get("Authorization") ?? "").match(/^Bearer\s+(.+)$/i)?.[1];
    if (!bearer) return reply({ error: "Please log in first." }, 401);

    const userResponse = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
      headers: {
        apikey: SERVICE_ROLE_KEY,
        Authorization: `Bearer ${bearer}`,
      },
    });
    if (!userResponse.ok) return reply({ error: "Your login session is invalid." }, 401);

    const user = await userResponse.json();
    if (!user?.id) return reply({ error: "Unable to identify logged-in user." }, 401);

    const body = await request.json().catch(() => null) as Record<string, unknown> | null;
    const withdrawalId = typeof body?.withdrawal_id === "string" ? body.withdrawal_id : "";
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(withdrawalId)) {
      return reply({ error: "Provide withdrawal_id as the UUID of your pending withdrawal." }, 400);
    }

    const rateText = env("DARAJA_USD_KES_RATE");
    const rate = Number(rateText);
    if (!rateText || !Number.isFinite(rate) || rate <= 0) {
      return reply({ error: "DARAJA_USD_KES_RATE is missing or invalid." }, 503);
    }

    const requestResponse = await adminFetch(
      `/rest/v1/withdrawal_requests?id=eq.${encodeURIComponent(withdrawalId)}&user_id=eq.${encodeURIComponent(String(user.id))}&select=id,amount,currency,payout_method,payout_status,payout_details,provider_reference`,
    );
    if (!requestResponse.ok) {
      console.error("Reading withdrawal failed. HTTP", requestResponse.status, await requestResponse.text());
      return reply({ error: "Could not read withdrawal request." }, 500);
    }
    const withdrawalRows = await requestResponse.json();
    const withdrawal = withdrawalRows[0];
    if (!withdrawal) return reply({ error: "Withdrawal not found for this user." }, 404);
    if (withdrawal.payout_status !== "pending") {
      return reply({ error: "Only pending withdrawals can be submitted.", payout_status: withdrawal.payout_status }, 409);
    }
    if (String(withdrawal.currency).toUpperCase() !== "USD" || String(withdrawal.payout_method).toLowerCase().replace(/[^a-z]/g, "") !== "mpesa") {
      return reply({ error: "This function accepts USD M-Pesa withdrawals only." }, 400);
    }

    const usdAmount = Number(withdrawal.amount);
    if (!Number.isFinite(usdAmount) || usdAmount <= 0) return reply({ error: "Invalid withdrawal amount." }, 400);
    const phone = normalizeKenyanPhone(withdrawal.payout_details);
    const kesAmount = Math.round(usdAmount * rate);
    if (!Number.isSafeInteger(kesAmount) || kesAmount < 1) return reply({ error: "Converted KES amount is invalid." }, 400);

    const initiatorName = env("DARAJA_INITIATOR_NAME");
    const securityCredential = env("DARAJA_SECURITY_CREDENTIAL");
    const shortcode = env("DARAJA_SHORTCODE");
    const callbackToken = env("DARAJA_CALLBACK_TOKEN");
    if (!initiatorName || !securityCredential || !shortcode || !callbackToken) {
      return reply({ error: "Missing Daraja initiator, encrypted security credential, shortcode, or callback token." }, 503);
    }

    // Obtain access token before reserving the wallet funds.
    const accessToken = await getDarajaAccessToken();

    // Atomically check the pending request, reserve wallet balance, and insert attempt.
    await rpc("pt_reserve_withdrawal", {
      p_withdrawal_id: withdrawalId,
      p_user_id: String(user.id),
    });

    // The merchant generates this ID before sending the B2C request, so a fast
    // callback can find the attempt and duplicate calls can be recognized.
    const originatorId = `PT${crypto.randomUUID().replace(/-/g, "")}`;
    const prepared = await updateAttempt(withdrawalId, {
      originator_conversation_id: originatorId,
      status: "processing",
    });

    if (!prepared.ok || prepared.rows.length !== 1) {
      // No request has been sent to Safaricom yet; a cancellation/refund is safe.
      await rpc("pt_cancel_withdrawal", {
        p_withdrawal_id: withdrawalId,
        p_reason: "Could not save the tracking ID before sending the B2C request.",
      });
      return reply({ error: "Could not prepare a safe payout tracking record. No Safaricom request was sent." }, 500);
    }

    const callbackBase = `${SUPABASE_URL}/functions/v1/primetask-withdrawal`;
    const tokenParam = encodeURIComponent(callbackToken);
    let darajaResponse: Response;
    try {
      darajaResponse = await fetch("https://sandbox.safaricom.co.ke/mpesa/b2c/v3/paymentrequest", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          OriginatorConversationID: originatorId,
          InitiatorName: initiatorName,
          SecurityCredential: securityCredential,
          CommandID: "BusinessPayment",
          Amount: kesAmount,
          PartyA: shortcode,
          PartyB: phone,
          Remarks: `PrimeTask withdrawal ${withdrawalId.slice(0, 8)}`,
          QueueTimeOutURL: `${callbackBase}?action=timeout&token=${tokenParam}`,
          ResultURL: `${callbackBase}?action=result&token=${tokenParam}`,
          // Safaricom's published B2C schema spells this field "Occassion".
          Occassion: `PT-${withdrawalId.slice(0, 12)}`,
        }),
      });
    } catch (error) {
      console.error("Daraja request transport failed; payout outcome is unknown.", error);
      await updateAttempt(withdrawalId, { status: "timeout_unknown" }, "processing");
      return reply({ status: "processing", message: "Safaricom response was not received. Funds remain reserved; do not retry until the transaction is reconciled.", withdrawal_id: withdrawalId }, 202);
    }

    const darajaBody = await darajaResponse.json().catch(() => null) as Record<string, unknown> | null;
    const responseCode = darajaBody?.ResponseCode;

    if (darajaResponse.ok && responseCode !== undefined && String(responseCode) !== "0") {
      // Clear explicit API rejection only. The request's outcome must be definite.
      await rpc("pt_cancel_withdrawal", {
        p_withdrawal_id: withdrawalId,
        p_reason: JSON.stringify({ http_status: darajaResponse.status, response_code: responseCode, response: darajaBody }),
      });
      return reply({ status: "failed", message: "Safaricom rejected the sandbox request; the reservation was cancelled.", details: darajaBody }, 502);
    }

    if (!darajaResponse.ok || !darajaBody || String(responseCode ?? "") !== "0") {
      console.error("Daraja response was ambiguous. HTTP", darajaResponse.status);
      await updateAttempt(withdrawalId, {
        status: "response_unknown",
        result_payload: darajaBody ?? { http_status: darajaResponse.status },
      }, "processing");
      return reply({ status: "processing", message: "Safaricom's response was inconclusive. Funds remain reserved; do not retry until reconciled.", withdrawal_id: withdrawalId }, 202);
    }

    // Do not overwrite attempt.status here: Safaricom may have called back already.
    const conversationId = String(darajaBody.ConversationID ?? "");
    const attemptUpdated = await updateAttempt(withdrawalId, {
      conversation_id: conversationId || null,
    });
    if (!attemptUpdated.ok) {
      console.error("Safaricom accepted the request, but ConversationID could not be saved.");
    }

    const providerResponse = await adminFetch(
      `/rest/v1/withdrawal_requests?id=eq.${encodeURIComponent(withdrawalId)}`,
      {
        method: "PATCH",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify({ provider_reference: originatorId }),
      },
    );
    if (!providerResponse.ok) {
      console.error("Could not save provider reference. HTTP", providerResponse.status);
    }

    return reply({
      status: "processing",
      message: "Safaricom accepted the sandbox request. Waiting for the result callback; this is not a real payment.",
      withdrawal_id: withdrawalId,
      amount_kes: kesAmount,
      provider_reference: originatorId,
    }, 202);
  } catch (error) {
    // Keep detailed server diagnostics in Logs, not in the client response.
    console.error("PrimeTask withdrawal handler error:", error);
    return reply({ error: error instanceof Error ? error.message : "Unexpected server error." }, 500);
  }
});
