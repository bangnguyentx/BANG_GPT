const UPSTREAM = "https://codex.fosta.app/v1";

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Access-Pin, X-Key-Index, X-Client-Keys",
    "Access-Control-Expose-Headers": "X-Key-Slot, X-Pool-Size"
  };
}

function getKeyPool(env, req) {
  const pool = [];
  if (env.FOSTA_API_KEYS) {
    env.FOSTA_API_KEYS.split(/[\n,;]+/).map(k => k.trim()).filter(Boolean).forEach(k => pool.push(k));
  }
  if (env.FOSTA_API_KEY_1) pool.push(env.FOSTA_API_KEY_1.trim());
  if (env.FOSTA_API_KEY_2) pool.push(env.FOSTA_API_KEY_2.trim());
  if (env.FOSTA_API_KEY_3) pool.push(env.FOSTA_API_KEY_3.trim());

  // Cho phép dùng key từ client Key Pool nếu server chưa cấu hình env
  const clientKeys = req.headers.get("X-Client-Keys");
  if (!pool.length && clientKeys) {
    clientKeys.split(",").map(k => k.trim()).filter(Boolean).forEach(k => pool.push(k));
  }
  return [...new Set(pool)];
}

export async function onRequest(context) {
  const { request, env, params } = context;

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }

  const subPath = Array.isArray(params.path) ? params.path.join("/") : (params.path || "");
  const url = new URL(request.url);

  // 1. Kiểm tra mã PIN bảo vệ (nếu có đặt ACCESS_PIN trong Cloudflare)
  const serverPin = (env.ACCESS_PIN || "").trim();
  const clientPin = (request.headers.get("X-Access-Pin") || "").trim();

  if (subPath === "health") {
    const keys = getKeyPool(env, request);
    return new Response(JSON.stringify({
      ok: true,
      proxy: true,
      pinRequired: Boolean(serverPin),
      pinValid: !serverPin || serverPin === clientPin,
      poolSize: keys.length
    }), { status: 200, headers: { "Content-Type": "application/json", ...corsHeaders() } });
  }

  if (serverPin && clientPin !== serverPin) {
    return new Response(JSON.stringify({
      error: { message: "Mã PIN không hợp lệ hoặc chưa đăng nhập.", code: "PIN_REQUIRED" }
    }), { status: 401, headers: { "Content-Type": "application/json", ...corsHeaders() } });
  }

  const keys = getKeyPool(env, request);
  if (!keys.length) {
    return new Response(JSON.stringify({
      error: { message: "Chưa cấu hình biến môi trường FOSTA_API_KEYS trên Cloudflare." }
    }), { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders() } });
  }

  // 2. Endpoint lấy thống kê hạn mức cho TẤT CẢ key trong pool
  if (subPath === "usage-all" && request.method === "GET") {
    const results = await Promise.all(keys.map(async (key, idx) => {
      try {
        const r = await fetch(`${UPSTREAM}/usage`, {
          headers: { "Authorization": `Bearer ${key}` }
        });
        const text = await r.text();
        let data;
        try { data = JSON.parse(text); } catch { data = { raw: text }; }
        return {
          slot: idx + 1,
          masked: `${key.slice(0, 8)}••••${key.slice(-4)}`,
          ok: r.ok,
          status: r.status,
          data
        };
      } catch (e) {
        return { slot: idx + 1, masked: `${key.slice(0, 8)}••••${key.slice(-4)}`, ok: false, error: e.message };
      }
    }));
    return new Response(JSON.stringify({ poolSize: keys.length, keys: results }), {
      status: 200,
      headers: { "Content-Type": "application/json", ...corsHeaders() }
    });
  }

  // 3. Round-Robin + Auto-Failover chống nghẽn
  const allowedPaths = ["chat/completions", "responses", "models", "usage", "images/generations"];
  if (!allowedPaths.includes(subPath)) {
    return new Response(JSON.stringify({ error: { message: "Endpoint không hỗ trợ." } }), {
      status: 404,
      headers: { "Content-Type": "application/json", ...corsHeaders() }
    });
  }

  const bodyBytes = request.method !== "GET" ? await request.arrayBuffer() : null;
  const reqIdxHeader = parseInt(request.headers.get("X-Key-Index") || "", 10);
  const startIdx = Number.isFinite(reqIdxHeader)
    ? Math.abs(reqIdxHeader) % keys.length
    : Math.floor(Date.now() / 1000) % keys.length;

  let lastResponse = null;
  let lastSlot = startIdx + 1;

  for (let attempt = 0; attempt < keys.length; attempt++) {
    const idx = (startIdx + attempt) % keys.length;
    const apiKey = keys[idx];
    lastSlot = idx + 1;

    try {
      const upstreamUrl = `${UPSTREAM}/${subPath}${url.search}`;
      const res = await fetch(upstreamUrl, {
        method: request.method,
        headers: {
          "Content-Type": request.headers.get("Content-Type") || "application/json",
          "Authorization": `Bearer ${apiKey}`
        },
        body: bodyBytes
      });

      // Nếu key bị 429 (tắc nghẽn), 401/402 (hết token), hoặc 5xx -> tự động chuyển key tiếp theo
      if ([401, 402, 429, 500, 502, 503, 504].includes(res.status) && attempt < keys.length - 1) {
        lastResponse = res;
        continue;
      }

      const headers = new Headers(res.headers);
      Object.entries(corsHeaders()).forEach(([k, v]) => headers.set(k, v));
      headers.set("X-Key-Slot", `Key #${lastSlot}`);
      headers.set("X-Pool-Size", String(keys.length));

      return new Response(res.body, {
        status: res.status,
        headers
      });
    } catch (err) {
      if (attempt === keys.length - 1) {
        return new Response(JSON.stringify({ error: { message: `Lỗi kết nối upstream: ${err.message}` } }), {
          status: 502,
          headers: { "Content-Type": "application/json", ...corsHeaders() }
        });
      }
    }
  }

  const fallbackText = lastResponse ? await lastResponse.text() : JSON.stringify({ error: { message: "Tất cả API key đều bận." } });
  return new Response(fallbackText, {
    status: lastResponse ? lastResponse.status : 503,
    headers: { "Content-Type": "application/json", "X-Key-Slot": `Key #${lastSlot}`, ...corsHeaders() }
  });
}
