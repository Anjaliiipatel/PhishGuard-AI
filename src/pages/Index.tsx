import { useState } from "react";
import { Shield, ShieldCheck, Terminal } from "lucide-react";
import { threatScenarios } from "@/data/threatScenarios";
import ThreatCard from "@/components/ThreatCard";
import ChatFlow from "@/components/ChatFlow";
import AIChat from "@/components/AIChat";
import LinkAnalyzer from "@/components/LinkAnalyzer";

const Index = () => {
  const [selectedThreat, setSelectedThreat] = useState<string | null>(null);

  const selectedScenario = threatScenarios.find((s) => s.id === selectedThreat);

  return (
    <div className="min-h-screen bg-background flex flex-col">
      {/* Scan line effect */}
      <div className="fixed inset-0 pointer-events-none z-50 overflow-hidden opacity-[0.03]">
        <div className="w-full h-px bg-primary animate-scan-line" />
      </div>

      {!selectedScenario ? (
        <div className="flex-1 flex flex-col">
          {/* Hero */}
          <header className="border-b border-border bg-card/30">
            <div className="max-w-2xl mx-auto px-4 py-10 text-center">
              <div className="flex items-center justify-center gap-2 mb-4">
                <div className="p-2.5 rounded-lg bg-primary/10 border border-primary/20">
                  <ShieldCheck className="w-7 h-7 text-primary" />
                </div>
              </div>
              <h1 className="text-2xl md:text-3xl font-mono font-bold text-foreground mb-2 text-glow">
                CyberGuard
              </h1>
              <p className="text-muted-foreground text-sm max-w-md mx-auto">
                Detect, assess, and respond to cybersecurity threats with guided incident response
              </p>
              <div className="flex items-center justify-center gap-1.5 mt-3 text-xs text-muted-foreground font-mono">
                <Terminal className="w-3 h-3" />
                <span>Select a threat type to begin analysis</span>
              </div>
            </div>
          </header>

          {/* Threat Selection */}
          <main className="flex-1 max-w-2xl mx-auto w-full px-4 py-8 space-y-8">
            <LinkAnalyzer />

            <div>
              <div className="flex items-center gap-2 mb-3 text-xs font-mono text-muted-foreground uppercase tracking-wider">
                <span className="h-px flex-1 bg-border" />
                Threat scenarios
                <span className="h-px flex-1 bg-border" />
              </div>
              <div className="space-y-3">
                {threatScenarios.map((scenario) => (
                  <ThreatCard
                    key={scenario.id}
                    scenario={scenario}
                    onSelect={setSelectedThreat}
                  />
                ))}
              </div>
            </div>

            {/* Footer info */}
            <div className="mt-10 text-center">
              <div className="inline-flex items-center gap-1.5 text-xs text-muted-foreground font-mono bg-secondary/50 px-3 py-1.5 rounded-full border border-border">
                <Shield className="w-3 h-3 text-primary" />
                All guidance runs locally — no data is sent externally
              </div>
            </div>
          </main>
        </div>
      ) : (
        <div className="flex-1 flex flex-col max-w-2xl mx-auto w-full">
          <ChatFlow
            scenario={selectedScenario}
            onBack={() => setSelectedThreat(null)}
            onReset={() => setSelectedThreat(null)}
          />
        </div>
      )}

      <AIChat />
    </div>
  );
};

export default Index;
