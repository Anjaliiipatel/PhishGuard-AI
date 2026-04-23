import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

const SYSTEM_PROMPT = `You are a cybersecurity URL analyst. Given a single URL, assess the likelihood that it is a phishing / malicious link.

Consider these heuristics:
- Domain reputation, TLD abuse (.zip, .top, .xyz, free hosting), punycode/IDN homograph attacks
- Lookalike domains impersonating known brands (e.g. "paypa1.com", "g00gle-login.com", "apple-id-verify.support")
- Suspicious subdomains (brand-name.attacker.com)
- Excessive subdomains, hyphens, numbers in domain
- URL shorteners or redirect chains (bit.ly, tinyurl, t.co, ow.ly)
- Path/keywords like "verify", "login", "secure", "update-account", "wallet", "kyc", "gift"
- IP addresses instead of domains
- Non-HTTPS, mismatched protocol
- Encoded characters or excessive URL length
- Credential-harvesting query strings

Be calibrated:
- Well-known legitimate domains (google.com, github.com, microsoft.com, apple.com, amazon.com, etc.) on HTTPS with no suspicious path → very low risk (0-10%).
- Unknown domain, no obvious red flags → low-moderate (15-35%).
- Some red flags (suspicious keywords, odd TLD, lookalike) → moderate-high (45-75%).
- Multiple strong red flags / confirmed lookalike of major brand → high-critical (80-99%).

Always call the report_link_analysis function. Do not respond with prose.`;

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const { url } = await req.json();

    if (typeof url !== "string" || url.trim().length === 0 || url.length > 2048) {
      return new Response(JSON.stringify({ error: "Please provide a valid URL (max 2048 chars)." }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!LOVABLE_API_KEY) throw new Error("LOVABLE_API_KEY is not configured");

    const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-3-flash-preview",
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user", content: `Analyze this URL: ${url.trim()}` },
        ],
        tools: [
          {
            type: "function",
            function: {
              name: "report_link_analysis",
              description: "Return a structured phishing risk analysis for the given URL.",
              parameters: {
                type: "object",
                properties: {
                  phishingPercent: {
                    type: "number",
                    description: "Probability the URL is phishing/malicious, 0-100.",
                    minimum: 0,
                    maximum: 100,
                  },
                  verdict: {
                    type: "string",
                    enum: ["safe", "suspicious", "likely_phishing", "malicious"],
                    description: "Overall verdict bucket.",
                  },
                  brandImpersonation: {
                    type: "string",
                    description: "Name of the brand likely being impersonated, or empty string if none.",
                  },
                  redFlags: {
                    type: "array",
                    description: "List of concrete red flags detected. Empty array if none.",
                    items: { type: "string" },
                  },
                  positiveSignals: {
                    type: "array",
                    description: "Reasons the link looks legitimate.",
                    items: { type: "string" },
                  },
                  recommendation: {
                    type: "string",
                    description: "One-sentence action the user should take.",
                  },
                  summary: {
                    type: "string",
                    description: "2-3 sentence plain-English explanation.",
                  },
                },
                required: [
                  "phishingPercent",
                  "verdict",
                  "brandImpersonation",
                  "redFlags",
                  "positiveSignals",
                  "recommendation",
                  "summary",
                ],
                additionalProperties: false,
              },
            },
          },
        ],
        tool_choice: { type: "function", function: { name: "report_link_analysis" } },
      }),
    });

    if (!response.ok) {
      if (response.status === 429) {
        return new Response(JSON.stringify({ error: "Rate limits exceeded, please try again in a moment." }), {
          status: 429,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      if (response.status === 402) {
        return new Response(JSON.stringify({ error: "AI credits exhausted. Add funds in Settings → Workspace → Usage." }), {
          status: 402,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      const t = await response.text();
      console.error("AI gateway error:", response.status, t);
      return new Response(JSON.stringify({ error: "AI gateway error" }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const data = await response.json();
    const toolCall = data.choices?.[0]?.message?.tool_calls?.[0];
    if (!toolCall?.function?.arguments) {
      return new Response(JSON.stringify({ error: "AI did not return structured analysis." }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const analysis = JSON.parse(toolCall.function.arguments);

    return new Response(JSON.stringify({ analysis }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    console.error("analyze-link error:", e);
    return new Response(
      JSON.stringify({ error: e instanceof Error ? e.message : "Unknown error" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } },
    );
  }
});
