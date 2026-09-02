/**
 * 브릭시세 백엔드 (Cloudflare Worker)
 * -----------------------------------------
 * 이 워커는 브라우저(프론트엔드) 대신 브릭링크 API에 요청을 보내는
 * "중간 서버" 역할을 해요. API 키(Secret)는 여기(서버)에만 저장되고,
 * 사용자에게는 절대 노출되지 않아요.
 *
 * 사용 방법:
 *  GET https://<워커주소>/price?type=SET&no=75192-1&new_or_used=U
 *
 * 배포 전 꼭 할 일:
 *  Cloudflare 대시보드 → Settings → Variables and Secrets 에서
 *  아래 4개 이름으로 "Secret" 값을 추가하세요.
 *   - BL_CONSUMER_KEY
 *   - BL_CONSUMER_SECRET
 *   - BL_TOKEN_VALUE
 *   - BL_TOKEN_SECRET
 */

export default {
  async fetch(request, env) {
    // 어떤 웹사이트에서든 이 워커를 호출할 수 있게 CORS 허용
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      const url = new URL(request.url);

      if (url.pathname !== "/price") {
        return json({ error: "지원하지 않는 경로예요. /price 를 사용하세요." }, 404, corsHeaders);
      }

      const type = url.searchParams.get("type") || "SET"; // SET, PART, MINIFIG 등
      const no = url.searchParams.get("no"); // 예: 75192-1
      const newOrUsed = url.searchParams.get("new_or_used") || "U"; // N=새제품, U=중고
      const guideType = url.searchParams.get("guide_type") || "stock"; // stock=현재판매중, sold=판매완료
      const currency = url.searchParams.get("currency_code") || "KRW";

      if (!no) {
        return json({ error: "품번(no) 파라미터가 필요해요. 예: ?no=75192-1" }, 400, corsHeaders);
      }

      const apiPath = `/items/${encodeURIComponent(type)}/${encodeURIComponent(no)}/price`;
      const apiBase = "https://api.bricklink.com/api/store/v1";
      const queryParams = {
        guide_type: guideType,
        new_or_used: newOrUsed,
        currency_code: currency,
      };

      const targetUrl = apiBase + apiPath;

      const authHeader = await buildOAuthHeader({
        method: "GET",
        url: targetUrl,
        params: queryParams,
        consumerKey: env.BL_CONSUMER_KEY,
        consumerSecret: env.BL_CONSUMER_SECRET,
        tokenValue: env.BL_TOKEN_VALUE,
        tokenSecret: env.BL_TOKEN_SECRET,
      });

      const fullUrl = targetUrl + "?" + new URLSearchParams(queryParams).toString();

      const blResponse = await fetch(fullUrl, {
        headers: { Authorization: authHeader },
      });

      const data = await blResponse.json();

      if (!blResponse.ok) {
        return json({ error: "브릭링크 API 오류", detail: data }, blResponse.status, corsHeaders);
      }

      // 프론트엔드가 쓰기 편한 형태로 정리해서 반환
      const priceData = data.data || {};
      const result = {
        set_number: no,
        currency: priceData.currency_code || currency,
        low: Number(priceData.min_price),
        avg: Number(priceData.avg_price),
        high: Number(priceData.max_price),
        unit_quantity: priceData.unit_quantity,
        raw: priceData, // 원본 데이터도 함께 반환 (디버깅용)
      };

      return json(result, 200, corsHeaders);
    } catch (err) {
      return json({ error: "서버 오류", detail: String(err) }, 500, corsHeaders);
    }
  },
};

function json(obj, status, corsHeaders) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...corsHeaders },
  });
}

/**
 * 브릭링크 API용 OAuth 1.0a Authorization 헤더를 생성해요.
 * (브릭링크는 OAuth 1.0a 방식의 서명된 요청을 요구해요)
 */
async function buildOAuthHeader({ method, url, params, consumerKey, consumerSecret, tokenValue, tokenSecret }) {
  const oauthParams = {
    oauth_consumer_key: consumerKey,
    oauth_nonce: cryptoRandomString(32),
    oauth_signature_method: "HMAC-SHA1",
    oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
    oauth_token: tokenValue,
    oauth_version: "1.0",
  };

  const allParams = { ...params, ...oauthParams };

  const baseString = buildSignatureBaseString(method, url, allParams);
  const signingKey = `${percentEncode(consumerSecret)}&${percentEncode(tokenSecret)}`;
  const signature = await hmacSha1Base64(signingKey, baseString);

  oauthParams.oauth_signature = signature;

  const headerParams = Object.keys(oauthParams)
    .sort()
    .map((k) => `${percentEncode(k)}="${percentEncode(oauthParams[k])}"`)
    .join(", ");

  return `OAuth ${headerParams}`;
}

function buildSignatureBaseString(method, url, params) {
  const sortedParams = Object.keys(params)
    .sort()
    .map((k) => `${percentEncode(k)}=${percentEncode(params[k])}`)
    .join("&");

  return [method.toUpperCase(), percentEncode(url), percentEncode(sortedParams)].join("&");
}

function percentEncode(str) {
  return encodeURIComponent(str).replace(/[!*'()]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
}

function cryptoRandomString(length) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const randomValues = crypto.getRandomValues(new Uint8Array(length));
  let out = "";
  for (let i = 0; i < length; i++) out += chars[randomValues[i] % chars.length];
  return out;
}

async function hmacSha1Base64(key, message) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(key),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(message));
  return arrayBufferToBase64(signature);
}

function arrayBufferToBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}
