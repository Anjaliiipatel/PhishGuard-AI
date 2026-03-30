import { useState, useEffect, useRef } from "react";
import { ArrowLeft, ArrowRight, Check, RotateCcw, Shield, ShieldAlert, ShieldCheck } from "lucide-react";
import { ThreatScenario, RecoveryStep } from "@/data/threatScenarios";

interface ChatFlowProps {
  scenario: ThreatScenario;
  onBack: () => void;
  onReset: () => void;
}

type Message = {
  id: string;
  type: "question" | "answer" | "system";
  text: string;
};

const priorityStyles = {
  critical: "border-destructive/40 bg-destructive/5",
  high: "border-warning/40 bg-warning/5",
  medium: "border-primary/40 bg-primary/5",
};

const priorityLabels = {
  critical: { text: "CRITICAL", class: "text-destructive" },
  high: { text: "HIGH", class: "text-warning" },
  medium: { text: "MEDIUM", class: "text-primary" },
};

const ChatFlow = ({ scenario, onBack, onReset }: ChatFlowProps) => {
  const [currentStep, setCurrentStep] = useState(0);
  const [answers, setAnswers] = useState<Record<string, string>>({});
  const [messages, setMessages] = useState<Message[]>([]);
  const [showRecovery, setShowRecovery] = useState(false);
  const [recoveryStep, setRecoveryStep] = useState(0);
  const [recoverySteps, setRecoverySteps] = useState<RecoveryStep[]>([]);
  const [guidedMode, setGuidedMode] = useState(false);
  const chatEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setMessages([
      {
        id: "intro",
        type: "system",
        text: `Analyzing: ${scenario.title}. Let's assess the situation.`,
      },
      {
        id: `q-0`,
        type: "question",
        text: scenario.questions[0].text,
      },
    ]);
  }, [scenario]);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, showRecovery, recoveryStep]);

  const handleAnswer = (questionId: string, answer: string, label: string) => {
    const newAnswers = { ...answers, [questionId]: answer };
    setAnswers(newAnswers);

    const newMessages: Message[] = [
      ...messages,
      { id: `a-${currentStep}`, type: "answer", text: label },
    ];

    const nextStep = currentStep + 1;

    if (nextStep < scenario.questions.length) {
      newMessages.push({
        id: `q-${nextStep}`,
        type: "question",
        text: scenario.questions[nextStep].text,
      });
      setCurrentStep(nextStep);
    } else {
      newMessages.push({
        id: "analysis",
        type: "system",
        text: "Analysis complete. Generating your personalized recovery plan...",
      });
      const steps = scenario.getRecoverySteps(newAnswers);
      setRecoverySteps(steps);
      setTimeout(() => setShowRecovery(true), 800);
    }

    setMessages(newMessages);
  };

  const currentQuestion = !showRecovery ? scenario.questions[currentStep] : null;

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center gap-3 p-4 border-b border-border bg-card/50">
        <button onClick={onBack} className="p-2 rounded-md hover:bg-secondary transition-colors text-muted-foreground hover:text-foreground">
          <ArrowLeft className="w-4 h-4" />
        </button>
        <div className="flex items-center gap-2">
          <scenario.icon className={`w-5 h-5 text-${scenario.color === "warning" ? "warning" : scenario.color}`} />
          <h2 className="font-mono font-semibold">{scenario.title}</h2>
        </div>
        {!showRecovery && (
          <span className="ml-auto text-xs text-muted-foreground font-mono">
            Step {currentStep + 1}/{scenario.questions.length}
          </span>
        )}
      </div>

      {/* Chat Area */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {messages.map((msg, i) => (
          <div
            key={msg.id}
            className={`animate-fade-in-up ${
              msg.type === "answer" ? "flex justify-end" : ""
            }`}
            style={{ animationDelay: `${i * 0.05}s` }}
          >
            {msg.type === "system" && (
              <div className="flex items-start gap-2.5 max-w-[85%]">
                <ShieldAlert className="w-4 h-4 text-primary mt-1 shrink-0" />
                <p className="text-sm text-muted-foreground font-mono">{msg.text}</p>
              </div>
            )}
            {msg.type === "question" && (
              <div className="bg-secondary/50 border border-border rounded-lg p-3.5 max-w-[85%]">
                <p className="text-sm text-foreground">{msg.text}</p>
              </div>
            )}
            {msg.type === "answer" && (
              <div className="bg-primary/15 border border-primary/30 rounded-lg px-3.5 py-2.5 max-w-[75%]">
                <p className="text-sm text-primary font-medium">{msg.text}</p>
              </div>
            )}
          </div>
        ))}

        {/* Quick Actions */}
        {currentQuestion && !showRecovery && (
          <div className="flex flex-wrap gap-2 pt-2 animate-fade-in-up">
            {currentQuestion.quickActions.map((action) => (
              <button
                key={action.value}
                onClick={() => handleAnswer(currentQuestion.id, action.value, action.label)}
                className="text-sm px-3.5 py-2 rounded-md border border-border bg-card hover:border-primary/50 hover:bg-primary/10 text-foreground transition-all duration-200"
              >
                {action.label}
              </button>
            ))}
          </div>
        )}

        {/* Recovery Plan */}
        {showRecovery && (
          <div className="space-y-4 animate-fade-in-up pt-2">
            <div className="flex items-center gap-2 border-b border-border pb-3">
              <ShieldCheck className="w-5 h-5 text-primary" />
              <h3 className="font-mono font-semibold">Recovery Plan</h3>
              <span className="text-xs text-muted-foreground ml-auto font-mono">
                {recoverySteps.length} steps
              </span>
            </div>

            {/* Toggle guided mode */}
            <div className="flex gap-2">
              <button
                onClick={() => setGuidedMode(false)}
                className={`text-xs px-3 py-1.5 rounded font-mono transition-colors ${
                  !guidedMode ? "bg-primary text-primary-foreground" : "bg-secondary text-muted-foreground hover:text-foreground"
                }`}
              >
                All Steps
              </button>
              <button
                onClick={() => { setGuidedMode(true); setRecoveryStep(0); }}
                className={`text-xs px-3 py-1.5 rounded font-mono transition-colors ${
                  guidedMode ? "bg-primary text-primary-foreground" : "bg-secondary text-muted-foreground hover:text-foreground"
                }`}
              >
                Guided Mode
              </button>
            </div>

            {guidedMode ? (
              <div className="space-y-4">
                <div className={`border rounded-lg p-4 ${priorityStyles[recoverySteps[recoveryStep].priority]}`}>
                  <div className="flex items-center justify-between mb-2">
                    <span className={`text-xs font-mono font-bold ${priorityLabels[recoverySteps[recoveryStep].priority].class}`}>
                      {priorityLabels[recoverySteps[recoveryStep].priority].text}
                    </span>
                    <span className="text-xs text-muted-foreground font-mono">
                      {recoveryStep + 1} of {recoverySteps.length}
                    </span>
                  </div>
                  <h4 className="font-semibold text-foreground mb-2">{recoverySteps[recoveryStep].title}</h4>
                  <p className="text-sm text-muted-foreground leading-relaxed">{recoverySteps[recoveryStep].description}</p>
                </div>

                <div className="flex items-center justify-between">
                  <button
                    onClick={() => setRecoveryStep((s) => Math.max(0, s - 1))}
                    disabled={recoveryStep === 0}
                    className="flex items-center gap-1.5 text-sm px-3 py-2 rounded-md border border-border bg-card hover:bg-secondary disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                  >
                    <ArrowLeft className="w-3.5 h-3.5" /> Back
                  </button>
                  {recoveryStep < recoverySteps.length - 1 ? (
                    <button
                      onClick={() => setRecoveryStep((s) => s + 1)}
                      className="flex items-center gap-1.5 text-sm px-3 py-2 rounded-md bg-primary text-primary-foreground hover:opacity-90 transition-opacity"
                    >
                      Next <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  ) : (
                    <button
                      onClick={onReset}
                      className="flex items-center gap-1.5 text-sm px-3 py-2 rounded-md bg-primary text-primary-foreground hover:opacity-90 transition-opacity"
                    >
                      <Check className="w-3.5 h-3.5" /> Done
                    </button>
                  )}
                </div>

                {/* Progress bar */}
                <div className="w-full bg-secondary rounded-full h-1">
                  <div
                    className="bg-primary h-1 rounded-full transition-all duration-300"
                    style={{ width: `${((recoveryStep + 1) / recoverySteps.length) * 100}%` }}
                  />
                </div>
              </div>
            ) : (
              <div className="space-y-3">
                {recoverySteps.map((step, i) => (
                  <div key={i} className={`border rounded-lg p-4 ${priorityStyles[step.priority]}`}>
                    <div className="flex items-center gap-2 mb-1.5">
                      <span className={`text-xs font-mono font-bold ${priorityLabels[step.priority].class}`}>
                        {priorityLabels[step.priority].text}
                      </span>
                    </div>
                    <h4 className="font-semibold text-foreground text-sm mb-1">{step.title}</h4>
                    <p className="text-xs text-muted-foreground leading-relaxed">{step.description}</p>
                  </div>
                ))}
              </div>
            )}

            {/* Security Notes */}
            <div className="border border-border rounded-lg p-4 bg-secondary/30 mt-4">
              <h4 className="text-xs font-mono font-bold text-primary mb-2 flex items-center gap-1.5">
                <Shield className="w-3.5 h-3.5" /> SECURITY NOTES
              </h4>
              <ul className="space-y-1.5">
                {scenario.securityNotes.map((note, i) => (
                  <li key={i} className="text-xs text-muted-foreground flex items-start gap-2">
                    <span className="text-primary mt-0.5">›</span> {note}
                  </li>
                ))}
              </ul>
            </div>

            {/* Reset */}
            <button
              onClick={onReset}
              className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors mx-auto pt-2"
            >
              <RotateCcw className="w-3.5 h-3.5" /> Start Over
            </button>
          </div>
        )}

        <div ref={chatEndRef} />
      </div>
    </div>
  );
};

export default ChatFlow;
