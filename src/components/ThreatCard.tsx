import { Shield, ChevronRight } from "lucide-react";
import { ThreatScenario } from "@/data/threatScenarios";

interface ThreatCardProps {
  scenario: ThreatScenario;
  onSelect: (id: string) => void;
}

const colorMap = {
  primary: "border-primary/30 hover:border-primary/60 hover:glow-primary",
  accent: "border-accent/30 hover:border-accent/60 hover:glow-accent",
  destructive: "border-destructive/30 hover:border-destructive/60 hover:glow-destructive",
  warning: "border-warning/30 hover:border-warning/60",
};

const iconColorMap = {
  primary: "text-primary",
  accent: "text-accent",
  destructive: "text-destructive",
  warning: "text-warning",
};

const ThreatCard = ({ scenario, onSelect }: ThreatCardProps) => {
  const Icon = scenario.icon;

  return (
    <button
      onClick={() => onSelect(scenario.id)}
      className={`group w-full text-left bg-card border rounded-lg p-5 transition-all duration-300 ${colorMap[scenario.color]} hover:bg-secondary/50`}
    >
      <div className="flex items-start gap-4">
        <div className={`p-2.5 rounded-md bg-secondary ${iconColorMap[scenario.color]}`}>
          <Icon className="w-5 h-5" />
        </div>
        <div className="flex-1 min-w-0">
          <h3 className="font-mono font-semibold text-foreground mb-1">{scenario.title}</h3>
          <p className="text-sm text-muted-foreground leading-relaxed">{scenario.description}</p>
        </div>
        <ChevronRight className="w-5 h-5 text-muted-foreground group-hover:text-foreground transition-colors mt-1 shrink-0" />
      </div>
    </button>
  );
};

export default ThreatCard;
