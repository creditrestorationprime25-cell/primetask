import { withSupabase } from 'npm:@supabase/server'

const OFFERWALL_URL = 'https://offerwall.me/taskapi.php'
const COUNTRY_CODES: Record<string, string> = {
  Kenya: 'KE',
  'South Africa': 'ZA',
  Tanzania: 'TZ',
  Uganda: 'UG',
}
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, apikey, content-type, x-client-info',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
}
function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: corsHeaders })
}
function bytesToLowerHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}
async function createIdentitySignature(secret: string, publicKey: string, userId: string, expiry: number): Promise<string> {
  const message = `offerwall-user-v1\n${publicKey}\n${userId}\n${expiry}`
  const encoder = new TextEncoder()
  const cryptoKey = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(message))
  return bytesToLowerHex(new Uint8Array(signature))
}
const handler = withSupabase({ auth: 'user' }, async (req, ctx) => {
  if (req.method !== 'GET') return jsonResponse({ error: 'Method not allowed' }, 405)
  const userId = ctx.userClaims?.id
  if (typeof userId !== 'string') return jsonResponse({ error: 'Unauthorized' }, 401)
  // Fail closed until a trusted client-IP source is confirmed for this project.
  const ip = req.headers.get('cf-connecting-ip')?.trim()
  if (!ip) return jsonResponse({ error: 'Trusted client IP unavailable' }, 503)
  const publicKey = Deno.env.get('OFFERWALL_PUBLIC_KEY')
  const secretKey = Deno.env.get('OFFERWALL_SECRET_KEY')
  const bearerToken = Deno.env.get('OFFERWALL_BEARER_TOKEN')
  if (!publicKey || !secretKey || !bearerToken) return jsonResponse({ error: 'Offerwall service unavailable' }, 503)
  const { data: profile, error: profileError } = await ctx.supabase.from('profiles').select('country').eq('id', userId).maybeSingle()
  if (profileError) return jsonResponse({ error: 'Unable to load user profile' }, 500)
  if (!profile?.country || !(profile.country in COUNTRY_CODES)) return jsonResponse({ error: 'A supported profile country is required' }, 422)
  const identityExpires = Math.floor(Date.now() / 1000) + 3600
  let identitySignature: string
  try { identitySignature = await createIdentitySignature(secretKey, publicKey, userId, identityExpires) }
  catch { return jsonResponse({ error: 'Offerwall service unavailable' }, 503) }
  const url = new URL(OFFERWALL_URL)
  url.search = new URLSearchParams({ api: publicKey, token: bearerToken, id: userId, ip, country: COUNTRY_CODES[profile.country], identityExpires: String(identityExpires), identitySignature }).toString()
  try {
    const response = await fetch(url, { method: 'GET', signal: AbortSignal.timeout(12000) })
    if (!response.ok) return jsonResponse({ error: 'Unable to retrieve tasks' }, 502)
    const text = await response.text()
    if (text.length > 1000000) return jsonResponse({ error: 'Unable to retrieve tasks' }, 502)
    let result: unknown
    try { result = JSON.parse(text) } catch { return jsonResponse({ error: 'Invalid response from task provider' }, 502) }
    if (typeof result !== 'object' || result === null || !('status' in result) || result.status !== 200 || !('data' in result) || !Array.isArray(result.data)) {
      return jsonResponse({ error: 'Task provider returned an unexpected response' }, 502)
    }
    return jsonResponse({ status: 200, data: result.data }, 200)
  } catch { return jsonResponse({ error: 'Unable to retrieve tasks' }, 502) }
})
export default {
  fetch(req: Request): Promise<Response> | Response {
    if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders })
    if (req.method !== 'GET') return jsonResponse({ error: 'Method not allowed' }, 405)
    return handler(req)
  },
    }
