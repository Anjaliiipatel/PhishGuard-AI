import jsPDF from "jspdf";
import { ThreatScenario, RecoveryStep } from "@/data/threatScenarios";

type RiskLevel = "low" | "moderate" | "high" | "critical";

type ExportArgs = {
  scenario: ThreatScenario;
  answers: Record<string, string>;
  recoverySteps: RecoveryStep[];
  risk: RiskLevel;
  riskLabel: string;
  riskPercent: number;
  riskDescription: string;
};

// Brand colors (RGB) — match the dark green CyberGuard theme
const COLOR_BG = [12, 17, 23] as const;
const COLOR_PRIMARY = [29, 209, 110] as const;
const COLOR_TEXT = [230, 245, 235] as const;
const COLOR_MUTED = [150, 165, 158] as const;
const COLOR_BORDER = [40, 55, 48] as const;
const COLOR_CRITICAL = [232, 65, 66] as const;
const COLOR_WARNING = [246, 173, 47] as const;

const PRIORITY_COLORS: Record<RecoveryStep["priority"], readonly [number, number, number]> = {
  critical: COLOR_CRITICAL,
  high: COLOR_WARNING,
  medium: COLOR_PRIMARY,
};

const RISK_COLORS: Record<RiskLevel, readonly [number, number, number]> = {
  low: COLOR_PRIMARY,
  moderate: [78, 200, 215],
  high: COLOR_WARNING,
  critical: COLOR_CRITICAL,
};

export function exportIncidentPDF({
  scenario,
  answers,
  recoverySteps,
  risk,
  riskLabel,
  riskPercent,
  riskDescription,
}: ExportArgs) {
  const doc = new jsPDF({ unit: "pt", format: "a4" });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 40;
  const contentWidth = pageWidth - margin * 2;
  let y = margin;

  const setFill = (c: readonly [number, number, number]) => doc.setFillColor(c[0], c[1], c[2]);
  const setText = (c: readonly [number, number, number]) => doc.setTextColor(c[0], c[1], c[2]);
  const setDraw = (c: readonly [number, number, number]) => doc.setDrawColor(c[0], c[1], c[2]);

  const ensureSpace = (needed: number) => {
    if (y + needed > pageHeight - margin) {
      addBackground();
      doc.addPage();
      y = margin;
      addBackground();
    }
  };

  const addBackground = () => {
    setFill(COLOR_BG);
    doc.rect(0, 0, pageWidth, pageHeight, "F");
  };

  const drawText = (
    text: string,
    options: {
      size?: number;
      color?: readonly [number, number, number];
      bold?: boolean;
      mono?: boolean;
      x?: number;
      maxWidth?: number;
      lineHeight?: number;
    } = {},
  ) => {
    const {
      size = 10,
      color = COLOR_TEXT,
      bold = false,
      mono = false,
      x = margin,
      maxWidth = contentWidth,
      lineHeight = 1.4,
    } = options;
    doc.setFont(mono ? "courier" : "helvetica", bold ? "bold" : "normal");
    doc.setFontSize(size);
    setText(color);
    const lines = doc.splitTextToSize(text, maxWidth) as string[];
    const lh = size * lineHeight;
    for (const line of lines) {
      ensureSpace(lh);
      doc.text(line, x, y + size);
      y += lh;
    }
  };

  // ---------- Background ----------
  addBackground();

  // ---------- Header bar ----------
  setFill(COLOR_PRIMARY);
  doc.rect(0, 0, pageWidth, 6, "F");

  // ---------- Title block ----------
  y = margin + 8;
  drawText("CYBERGUARD", { size: 9, color: COLOR_PRIMARY, mono: true, bold: true });
  y += 2;
  drawText("Incident Response Report", { size: 22, bold: true, color: COLOR_TEXT });
  y += 4;
  const generated = new Date().toLocaleString();
  drawText(`Generated: ${generated}`, { size: 9, color: COLOR_MUTED, mono: true });
  y += 10;

  // Divider
  setDraw(COLOR_BORDER);
  doc.setLineWidth(0.5);
  doc.line(margin, y, pageWidth - margin, y);
  y += 18;

  // ---------- Threat type ----------
  drawText("THREAT TYPE", { size: 9, color: COLOR_MUTED, mono: true, bold: true });
  y += 2;
  drawText(scenario.title, { size: 16, bold: true });
  drawText(scenario.description, { size: 10, color: COLOR_MUTED });
  y += 14;

  // ---------- Risk Assessment card ----------
  ensureSpace(120);
  const cardX = margin;
  const cardY = y;
  const cardW = contentWidth;
  const cardH = 110;
  setFill([18, 26, 32]);
  setDraw(RISK_COLORS[risk]);
  doc.setLineWidth(1);
  doc.roundedRect(cardX, cardY, cardW, cardH, 6, 6, "FD");

  // Card content
  y = cardY + 16;
  doc.setFont("courier", "bold");
  doc.setFontSize(10);
  setText(COLOR_MUTED);
  doc.text("THREAT ASSESSMENT", cardX + 14, y);

  y += 18;
  doc.setFont("helvetica", "bold");
  doc.setFontSize(18);
  setText(RISK_COLORS[risk]);
  doc.text(riskLabel, cardX + 14, y);

  doc.setFont("courier", "normal");
  doc.setFontSize(11);
  setText(COLOR_MUTED);
  doc.text(`${riskPercent}%`, cardX + cardW - 14, y, { align: "right" });

  // Risk gauge bar
  y += 12;
  const gaugeX = cardX + 14;
  const gaugeW = cardW - 28;
  const gaugeH = 6;
  setFill(COLOR_BORDER);
  doc.roundedRect(gaugeX, y, gaugeW, gaugeH, 3, 3, "F");
  setFill(RISK_COLORS[risk]);
  doc.roundedRect(gaugeX, y, (gaugeW * riskPercent) / 100, gaugeH, 3, 3, "F");
  y += gaugeH + 12;

  // Description
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  setText(COLOR_TEXT);
  const descLines = doc.splitTextToSize(riskDescription, cardW - 28) as string[];
  doc.text(descLines, cardX + 14, y);

  // Stats row
  const counts = {
    critical: recoverySteps.filter((s) => s.priority === "critical").length,
    high: recoverySteps.filter((s) => s.priority === "high").length,
    medium: recoverySteps.filter((s) => s.priority === "medium").length,
  };
  const statsY = cardY + cardH - 22;
  const statW = (cardW - 28) / 3;
  const drawStat = (idx: number, count: number, label: string, color: readonly [number, number, number]) => {
    const sx = cardX + 14 + statW * idx;
    doc.setFont("courier", "bold");
    doc.setFontSize(14);
    setText(color);
    doc.text(String(count), sx, statsY);
    doc.setFont("courier", "normal");
    doc.setFontSize(8);
    setText(COLOR_MUTED);
    doc.text(label, sx + 18, statsY);
  };
  drawStat(0, counts.critical, "CRITICAL", COLOR_CRITICAL);
  drawStat(1, counts.high, "HIGH", COLOR_WARNING);
  drawStat(2, counts.medium, "MEDIUM", COLOR_PRIMARY);

  y = cardY + cardH + 22;

  // ---------- Assessment Summary (Q&A) ----------
  ensureSpace(40);
  drawText("ASSESSMENT SUMMARY", { size: 10, color: COLOR_PRIMARY, mono: true, bold: true });
  y += 4;

  scenario.questions.forEach((q, i) => {
    const ans = answers[q.id];
    const action = q.quickActions.find((a) => a.value === ans);
    const answerLabel = action?.label ?? ans ?? "—";

    ensureSpace(36);
    drawText(`Q${i + 1}. ${q.text}`, { size: 10, color: COLOR_TEXT, bold: true });
    drawText(`→ ${answerLabel}`, { size: 10, color: COLOR_PRIMARY, mono: true, x: margin + 10 });
    y += 6;
  });

  y += 8;
  // Divider
  setDraw(COLOR_BORDER);
  doc.line(margin, y, pageWidth - margin, y);
  y += 16;

  // ---------- Recovery Plan ----------
  drawText("RECOMMENDED RECOVERY STEPS", {
    size: 10,
    color: COLOR_PRIMARY,
    mono: true,
    bold: true,
  });
  y += 6;

  recoverySteps.forEach((step, i) => {
    const priorityColor = PRIORITY_COLORS[step.priority];
    const titleLines = doc.splitTextToSize(`${i + 1}. ${step.title}`, contentWidth - 24) as string[];
    const descLines = doc.splitTextToSize(step.description, contentWidth - 24) as string[];
    const blockH = 14 + titleLines.length * 14 + descLines.length * 13 + 18;

    ensureSpace(blockH + 6);

    // Card background
    setFill([18, 24, 30]);
    setDraw(COLOR_BORDER);
    doc.setLineWidth(0.5);
    doc.roundedRect(margin, y, contentWidth, blockH, 4, 4, "FD");

    // Priority stripe
    setFill(priorityColor);
    doc.rect(margin, y, 3, blockH, "F");

    // Priority label
    doc.setFont("courier", "bold");
    doc.setFontSize(8);
    setText(priorityColor);
    doc.text(step.priority.toUpperCase(), margin + 14, y + 14);

    // Title
    doc.setFont("helvetica", "bold");
    doc.setFontSize(11);
    setText(COLOR_TEXT);
    let ty = y + 28;
    titleLines.forEach((line) => {
      doc.text(line, margin + 14, ty);
      ty += 14;
    });

    // Description
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9.5);
    setText(COLOR_MUTED);
    descLines.forEach((line) => {
      doc.text(line, margin + 14, ty);
      ty += 13;
    });

    y += blockH + 8;
  });

  // ---------- Security Notes ----------
  if (scenario.securityNotes.length) {
    ensureSpace(40);
    y += 4;
    drawText("SECURITY NOTES", { size: 10, color: COLOR_PRIMARY, mono: true, bold: true });
    y += 4;
    scenario.securityNotes.forEach((note) => {
      ensureSpace(20);
      doc.setFont("helvetica", "normal");
      doc.setFontSize(9.5);
      setText(COLOR_PRIMARY);
      doc.text("›", margin, y + 10);
      const noteLines = doc.splitTextToSize(note, contentWidth - 14) as string[];
      setText(COLOR_TEXT);
      noteLines.forEach((line, idx) => {
        doc.text(line, margin + 14, y + 10 + idx * 12);
      });
      y += noteLines.length * 12 + 6;
    });
  }

  // ---------- Footer on every page ----------
  const total = doc.getNumberOfPages();
  for (let p = 1; p <= total; p++) {
    doc.setPage(p);
    doc.setFont("courier", "normal");
    doc.setFontSize(8);
    setText(COLOR_MUTED);
    doc.text("CyberGuard • Generated locally — no data shared", margin, pageHeight - 18);
    doc.text(`Page ${p} of ${total}`, pageWidth - margin, pageHeight - 18, { align: "right" });
  }

  const safeTitle = scenario.title.replace(/[^a-z0-9]+/gi, "-").toLowerCase();
  const stamp = new Date().toISOString().slice(0, 10);
  doc.save(`cyberguard-${safeTitle}-${stamp}.pdf`);
}
