import { useState } from "react";
import { AlertTriangle, CheckCircle2, Link2, Loader2, Search, ShieldAlert, ShieldCheck, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";

type Verdict = "safe" | "suspicious" | "likely_phishing" | "malicious";

type Analysis = {
  phishingPercent: number;
  verdict: Verdict;
  brandImpersonation: string;
  redFlags: string[];
  positiveSignals: string[];
  recommendation: string;
  summary: string;
};

const ANALYZE_URL = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/analyze-link`;

const verdictConfig: Record<Verdict, { label: string; color: string; bg: string; border: string; ring: string; Icon: typeof ShieldCheck }> = {
  safe: {
    label: "LIKELY SAFE",
    color: "text-primary",
    bg: "bg-primary",
    border: "border-primary/40",
    ring: "stroke-primary",
    Icon: ShieldCheck,
  },
  suspicious: {
    label: "SUSPICIOUS",
    color: "text-accent",
    bg: "bg-accent",
    border: "border-accent/40",
    ring: "stroke-accent",
    Icon: AlertTriangle,
  },
  likely_phishing: {
    label: "LIKELY PHISHING",
    color: "text-warning",
    bg: "bg-warning",
    border: "border-warning/40",
    ring: "stroke-warning",
    Icon: ShieldAlert,
  },
  malicious: {
    label: "MALICIOUS",
    color: "text-destructive",
    bg: "bg-destructive",
    border: "border-destructive/40",
    ring: "stroke-destructive",
    Icon: ShieldAlert,
  },
};

function normalizeUrl(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) return "";
  if (/^https?:\/\//i.test(trimmed)) return trimmed;
  return `https://${trimmed}`;
}

function isLikelyUrl(input: string): boolean {
  const v = normalizeUrl(input);
  try {
    const u = new URL(v);
    return Boolean(u.hostname) && u.hostname.includes(".");
  } catch {
    return false;
  }
}

const LinkAnalyzer = () => {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [analyzedUrl, setAnalyzedUrl] = useState("");

  const handleAnalyze = async (e?: React.FormEvent) => {
    e?.preventDefault();
    if (!url.trim()) return;

    if (!isLikelyUrl(url)) {
      toast({
        title: "Invalid URL",
        description: "Please enter a valid web address (e.g. https://example.com).",
        variant: "destructive",
      });
      return;
    }

    const target = normalizeUrl(url);
    setLoading(true);
    setAnalysis(null);
    setAnalyzedUrl(target);

    try {
      const resp = await fetch(ANALYZE_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY}`,
        },
        body: JSON.stringify({ url: target }),
      });

      if (resp.status === 429) {
        toast({ title: "Slow down", description: "Too many requests. Please wait a moment.", variant: "destructive" });
        return;
      }
      if (resp.status === 402) {
        toast({
          title: "AI credits required",
          description: "Add funds in Settings → Workspace → Usage to continue.",
          variant: "destructive",
        });
        return;
      }

      const data = await resp.json();
      if (!resp.ok || !data.analysis) {
        throw new Error(data.error || "Analysis failed");
      }
      setAnalysis(data.analysis);
    } catch (err) {
      console.error(err);
      toast({
        title: "Analysis failed",
        description: err instanceof Error ? err.message : "Could not analyze link.",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const reset = () => {
    setAnalysis(null);
    setUrl("");
    setAnalyzedUrl("");
  };

  const config = analysis ? verdictConfig[analysis.verdict] : null;
  const percent = analysis?.phishingPercent ?? 0;

  // Ring chart math
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference - (percent / 100) * circumference;

  return (
    <section className="border border-border rounded-lg bg-card/50 overflow-hidden">
      <header className="px-4 py-3 border-b border-border bg-card/70 flex items-center gap-2">
        <div className="p-1.5 rounded-md bg-primary/10 border border-primary/20">
          <Link2 className="w-4 h-4 text-primary" />
        </div>
        <div className="flex-1 min-w-0">
          <h2 className="font-mono font-semibold text-sm text-foreground">Link Analyzer</h2>
          <p className="text-[11px] text-muted-foreground font-mono">
            Paste a URL to check for phishing risk
          </p>
        </div>
      </header>

      <div className="p-4 space-y-4">
        <form onSubmit={handleAnalyze} className="flex gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://suspicious-link.example.com/login"
              className="pl-9 font-mono text-sm"
              disabled={loading}
              maxLength={2048}
              aria-label="URL to analyze"
            />
          </div>
          <Button type="submit" disabled={loading || !url.trim()} className="shrink-0">
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : "Analyze"}
          </Button>
        </form>

        {/* Result */}
        {loading && (
          <div className="flex items-center gap-2 text-xs text-muted-foreground font-mono py-6 justify-center">
            <Loader2 className="w-4 h-4 animate-spin text-primary" />
            Scanning URL for threats…
          </div>
        )}

        {analysis && config && (
          <div className={cn("border rounded-lg p-5 space-y-4 animate-fade-in-up", config.border, "bg-background/40")}>
            {/* Header row */}
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-2 min-w-0">
                <config.Icon className={cn("w-5 h-5 shrink-0", config.color)} />
                <div className="min-w-0">
                  <div className={cn("text-xs font-mono font-bold", config.color)}>{config.label}</div>
                  <div className="text-[11px] text-muted-foreground font-mono truncate" title={analyzedUrl}>
                    {analyzedUrl}
                  </div>
                </div>
              </div>
              <button
                onClick={reset}
                className="p-1 text-muted-foreground hover:text-foreground rounded"
                aria-label="Clear result"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Ring chart + summary */}
            <div className="flex items-center gap-5">
              <div className="relative shrink-0" aria-label={`Phishing risk ${percent}%`}>
                <svg width="128" height="128" viewBox="0 0 128 128" className="-rotate-90">
                  <circle
                    cx="64"
                    cy="64"
                    r={radius}
                    fill="none"
                    className="stroke-secondary"
                    strokeWidth="10"
                  />
                  <circle
                    cx="64"
                    cy="64"
                    r={radius}
                    fill="none"
                    className={config.ring}
                    strokeWidth="10"
                    strokeLinecap="round"
                    strokeDasharray={circumference}
                    strokeDashoffset={dashOffset}
                    style={{ transition: "stroke-dashoffset 1s ease-out" }}
                  />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className={cn("text-2xl font-mono font-bold", config.color)}>{percent}%</span>
                  <span className="text-[9px] text-muted-foreground font-mono uppercase tracking-wider">phishing</span>
                </div>
              </div>

              <div className="flex-1 min-w-0">
                <p className="text-sm text-foreground leading-relaxed">{analysis.summary}</p>
                {analysis.brandImpersonation && (
                  <div className="mt-2 inline-flex items-center gap-1.5 text-[11px] font-mono px-2 py-1 rounded border border-warning/40 bg-warning/10 text-warning">
                    <AlertTriangle className="w-3 h-3" />
                    Impersonates: {analysis.brandImpersonation}
                  </div>
                )}
              </div>
            </div>

            {/* Recommendation */}
            <div className={cn("border rounded-md p-3 text-sm", config.border, "bg-secondary/30")}>
              <div className="text-[10px] font-mono font-bold text-muted-foreground mb-1">RECOMMENDATION</div>
              <p className={cn("font-medium", config.color)}>{analysis.recommendation}</p>
            </div>

            {/* Flags grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {analysis.redFlags.length > 0 && (
                <div className="border border-destructive/30 rounded-md p-3 bg-destructive/5">
                  <div className="text-[10px] font-mono font-bold text-destructive mb-2 flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3" /> RED FLAGS ({analysis.redFlags.length})
                  </div>
                  <ul className="space-y-1.5">
                    {analysis.redFlags.map((f, i) => (
                      <li key={i} className="text-xs text-foreground flex items-start gap-2">
                        <span className="text-destructive mt-0.5">×</span>
                        <span>{f}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {analysis.positiveSignals.length > 0 && (
                <div className="border border-primary/30 rounded-md p-3 bg-primary/5">
                  <div className="text-[10px] font-mono font-bold text-primary mb-2 flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" /> POSITIVE SIGNALS ({analysis.positiveSignals.length})
                  </div>
                  <ul className="space-y-1.5">
                    {analysis.positiveSignals.map((s, i) => (
                      <li key={i} className="text-xs text-foreground flex items-start gap-2">
                        <span className="text-primary mt-0.5">✓</span>
                        <span>{s}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            <p className="text-[10px] text-muted-foreground font-mono text-center pt-1">
              AI-assisted heuristic analysis. Do not click suspicious links even if marked safe.
            </p>
          </div>
        )}
      </div>
    </section>
  );
};

export default LinkAnalyzer;
