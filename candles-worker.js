// "Light a candle" counter for www.rayhenryjohnson.de
// Cloudflare Worker + KV namespace bound as CANDLES.
//
//   GET  /candles  -> { "count": 142 }
//   POST /candles  -> lights a candle, returns { "count": 143 }
//
// Each visitor (by anonymised IP) can add one candle every 6 hours;
// extra clicks just return the current count. IPs are never stored
// in plain form — only a salted SHA-256 hash that expires after 6 hours.

const ALLOWED_ORIGINS = [
  "https://www.rayhenryjohnson.de",
  "https://rayhenryjohnson.de",
];
const COOLDOWN_SECONDS = 6 * 60 * 60;

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const cors = {
      "Access-Control-Allow-Origin": ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0],
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Vary": "Origin",
    };
    const json = (body, status = 200) =>
      new Response(JSON.stringify(body), {
        status,
        headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "no-store" },
      });

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

    const url = new URL(request.url);
    if (url.pathname !== "/candles") return json({ error: "not found" }, 404);

    let count = parseInt((await env.CANDLES.get("count")) || "0", 10);

    if (request.method === "GET") return json({ count });

    if (request.method === "POST") {
      if (!ALLOWED_ORIGINS.includes(origin)) return json({ error: "forbidden" }, 403);

      const ip = request.headers.get("CF-Connecting-IP") || "unknown";
      const data = new TextEncoder().encode((env.SALT || "ray-1964") + ip);
      const hash = [...new Uint8Array(await crypto.subtle.digest("SHA-256", data))]
        .map((b) => b.toString(16).padStart(2, "0")).join("");
      const key = "v:" + hash;

      if (await env.CANDLES.get(key)) return json({ count, already: true });

      count += 1;
      await env.CANDLES.put("count", String(count));
      await env.CANDLES.put(key, "1", { expirationTtl: COOLDOWN_SECONDS });
      return json({ count });
    }

    return json({ error: "method not allowed" }, 405);
  },
};