const pptxgen = require("pptxgenjs");
const fs = require("fs");

const HL = JSON.parse(fs.readFileSync(__dirname + "/../results/headline.json", "utf8"));
const CO = JSON.parse(fs.readFileSync(__dirname + "/../results/coevolution.json", "utf8"));

// palette: payments-security. deep graphite dominates, one red accent, one slate.
const INK = "13151C";
const INK2 = "1E2230";
const PAPER = "FFFFFF";
const MUTE = "6B7280";
const LINE = "D8DBE2";
const RED = "D01C2F";
const SLATE = "3E5C76";

const HEAD = "Cambria";
const BODY = "Calibri";

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE"; // 13.3 x 7.5
pres.author = "ARTS";
pres.title = "ARTS: Agentic Red Team Simulator";

const W = 13.3, H = 7.5, M = 0.7;

function darkSlide() {
  const s = pres.addSlide();
  s.background = { color: INK };
  return s;
}
function lightSlide(kicker, title) {
  const s = pres.addSlide();
  s.background = { color: PAPER };
  if (kicker) {
    s.addText(kicker.toUpperCase(), {
      x: M, y: 0.42, w: 8, h: 0.28, fontFace: BODY, fontSize: 11, bold: true,
      color: RED, charSpacing: 2, margin: 0,
    });
  }
  if (title) {
    s.addText(title, {
      x: M, y: 0.72, w: W - 2 * M, h: 0.72, fontFace: HEAD, fontSize: 34, bold: true,
      color: INK, margin: 0,
    });
  }
  return s;
}
function chip(s, n, x, y) {
  s.addShape(pres.ShapeType.ellipse, {
    x, y, w: 0.42, h: 0.42, fill: { color: RED },
  });
  s.addText(String(n), {
    x, y, w: 0.42, h: 0.42, align: "center", valign: "middle",
    fontFace: BODY, fontSize: 14, bold: true, color: PAPER, margin: 0,
  });
}
function card(s, x, y, w, h, tint) {
  s.addShape(pres.ShapeType.roundRect, {
    x, y, w, h, rectRadius: 0.06,
    fill: { color: tint || "F4F5F8" },
    line: { color: LINE, width: 0.75 },
  });
}
function foot(s, txt) {
  s.addText(txt, {
    x: M, y: H - 0.62, w: W - 2 * M, h: 0.3, fontFace: BODY, fontSize: 9.5,
    color: MUTE, margin: 0,
  });
}

// ---------------------------------------------------------------- 1 title
{
  const s = darkSlide();
  s.addText("ARTS", {
    x: M, y: 2.0, w: 9, h: 1.0, fontFace: HEAD, fontSize: 66, bold: true,
    color: PAPER, margin: 0, charSpacing: 3,
  });
  s.addText("Agentic Red Team Simulator", {
    x: M, y: 3.05, w: 10, h: 0.5, fontFace: HEAD, fontSize: 26, color: "C9CEDA", margin: 0,
  });
  s.addText("A closed loop that invents agentic payment fraud, simulates it at scale,\nand defends against it without ever having seen a labelled example.", {
    x: M, y: 3.85, w: 8.6, h: 1.0, fontFace: BODY, fontSize: 15, color: "9AA3B2",
    lineSpacing: 24, margin: 0,
  });
  s.addShape(pres.ShapeType.rect, { x: M, y: 5.25, w: 0.9, h: 0.045, fill: { color: RED } });
  s.addText("Mastercard Innovation Challenge  ·  Global Fintech Fest 2026", {
    x: M, y: 5.55, w: 9, h: 0.32, fontFace: BODY, fontSize: 12.5, color: "7C8698", margin: 0,
  });
  s.addText("42", { x: 10.4, y: 1.95, w: 2.2, h: 0.9, fontFace: HEAD, fontSize: 54, bold: true, color: RED, align: "right", margin: 0 });
  s.addText("attack vectors mapped", { x: 9.4, y: 2.85, w: 3.2, h: 0.3, fontFace: BODY, fontSize: 11, color: "9AA3B2", align: "right", margin: 0 });
  s.addText("29", { x: 10.4, y: 3.35, w: 2.2, h: 0.9, fontFace: HEAD, fontSize: 54, bold: true, color: PAPER, align: "right", margin: 0 });
  s.addText("simulated end to end", { x: 9.4, y: 4.25, w: 3.2, h: 0.3, fontFace: BODY, fontSize: 11, color: "9AA3B2", align: "right", margin: 0 });
  s.addNotes("One line: we built the attacker and the defender, and the defender wins without labelled agentic fraud.");
}

// ---------------------------------------------------------------- 2 problem
{
  const s = lightSlide("The problem", "Agentic fraud is not harder to detect. It is invisible.");
  const items = [
    ["The authorization is valid", "Correct agentic token, passing attestation, inside the granted mandate. Nothing to decline on."],
    ["The user really consented", "Just not to this. The fraud lives in the gap between intent and cart, which the network never sees."],
    ["The evidence is somewhere else", "The utterance, the confirmation event, the memory write. All inside the agent platform."],
  ];
  items.forEach(([h, b], i) => {
    const y = 1.75 + i * 1.45;
    chip(s, i + 1, M, y + 0.08);
    s.addText(h, { x: M + 0.62, y: y, w: 6.4, h: 0.36, fontFace: BODY, fontSize: 17, bold: true, color: INK, margin: 0 });
    s.addText(b, { x: M + 0.62, y: y + 0.38, w: 6.4, h: 0.75, fontFace: BODY, fontSize: 13.5, color: MUTE, lineSpacing: 19, margin: 0 });
  });
  card(s, 8.2, 1.7, 4.4, 4.3, INK2);
  s.addText("What a fraud model\nsees today", { x: 8.55, y: 2.0, w: 3.7, h: 0.8, fontFace: HEAD, fontSize: 19, bold: true, color: PAPER, margin: 0 });
  s.addText([
    { text: "amount    $412.00\n", options: { color: "C9CEDA" } },
    { text: "mcc       5999\n", options: { color: "C9CEDA" } },
    { text: "token     agentic, attested\n", options: { color: "C9CEDA" } },
    { text: "mandate   valid, in scope\n", options: { color: "C9CEDA" } },
    { text: "3ds       frictionless\n", options: { color: "C9CEDA" } },
    { text: "decision  APPROVE", options: { color: "6EE7A8", bold: true } },
  ], { x: 8.55, y: 3.05, w: 3.7, h: 1.8, fontFace: "Courier New", fontSize: 12.5, lineSpacing: 20, margin: 0 });
  s.addText("Identical to a legitimate agent purchase.", { x: 8.55, y: 5.15, w: 3.7, h: 0.5, fontFace: BODY, fontSize: 11.5, italic: true, color: "9AA3B2", margin: 0 });
  s.addNotes("The point: this is not a degraded signal problem, it is a missing signal problem.");
}

// ---------------------------------------------------------------- 3 identify
{
  const s = lightSlide("Pillar 1 · Identify", "42 vectors across five families, weighted to agentic rails");
  const fam = [
    ["Agent hijack", "9", "The user's own agent is turned against them by content it ingests."],
    ["Mandate abuse", "8", "Fraudulent spend engineered to stay inside the granted envelope."],
    ["Identity spoofing", "8", "Agent or merchant is not who the counterparty believes."],
    ["Classical GenAI", "10", "Pre-agentic typologies where GenAI collapses cost and scale."],
    ["Cross rail", "7", "Refunds, stored value, B2B, mule networks, post-authorization."],
  ];
  fam.forEach(([n, c, d], i) => {
    const x = M + (i % 3) * 4.05;
    const y = 1.72 + Math.floor(i / 3) * 2.1;
    card(s, x, y, 3.75, 1.85);
    s.addText(c, { x: x + 0.25, y: y + 0.18, w: 1.0, h: 0.6, fontFace: HEAD, fontSize: 30, bold: true, color: RED, margin: 0 });
    s.addText(n, { x: x + 1.15, y: y + 0.3, w: 2.4, h: 0.35, fontFace: BODY, fontSize: 15, bold: true, color: INK, margin: 0 });
    s.addText(d, { x: x + 0.25, y: y + 0.85, w: 3.3, h: 0.85, fontFace: BODY, fontSize: 11.5, color: MUTE, lineSpacing: 16, margin: 0 });
  });
  card(s, M + 2 * 4.05, 3.82, 3.75, 1.85, INK2);
  s.addText("Every vector is machine readable", { x: M + 2 * 4.05 + 0.25, y: 4.0, w: 3.3, h: 0.6, fontFace: BODY, fontSize: 14, bold: true, color: PAPER, margin: 0 });
  s.addText("Mechanism, observable signals, a parameter genome with sampling ranges, and candidate defense features. One YAML feeds all three pillars.", {
    x: M + 2 * 4.05 + 0.25, y: 4.55, w: 3.3, h: 1.0, fontFace: BODY, fontSize: 11.5, color: "9AA3B2", lineSpacing: 16, margin: 0,
  });
  foot(s, "schema/taxonomy.yaml  ·  156 tunable parameters  ·  98 candidate detection features");
}

// ---------------------------------------------------------------- 4 vantage
{
  const s = lightSlide("The core idea", "Tag every field with who actually holds it");
  const views = [
    ["v_network", "69 fields", "What the rails carry today. The incumbent trains here.", LINE, INK],
    ["v_attested", "111 fields", "Adds issuer history plus every field an attestation could carry. The deployable target.", RED, PAPER],
    ["v_omniscient", "112 fields", "Everything. A ceiling, not a proposal.", SLATE, PAPER],
  ];
  views.forEach(([n, c, d, fill, fg], i) => {
    const x = M + i * 4.05;
    s.addShape(pres.ShapeType.roundRect, {
      x, y: 1.8, w: 3.75, h: 2.5, rectRadius: 0.06,
      fill: { color: i === 0 ? "F4F5F8" : fill }, line: { color: i === 0 ? LINE : fill, width: 1 },
    });
    s.addText(n, { x: x + 0.28, y: 2.05, w: 3.2, h: 0.4, fontFace: "Courier New", fontSize: 17, bold: true, color: i === 0 ? INK : fg, margin: 0 });
    s.addText(c, { x: x + 0.28, y: 2.5, w: 3.2, h: 0.35, fontFace: HEAD, fontSize: 22, bold: true, color: i === 0 ? RED : fg, margin: 0 });
    s.addText(d, { x: x + 0.28, y: 2.98, w: 3.2, h: 1.1, fontFace: BODY, fontSize: 12, color: i === 0 ? MUTE : "EDEFF4", lineSpacing: 17, margin: 0 });
  });
  s.addText("Generators emit whole records. Projection to a view happens once, in one function, before any model sees the data. The projection is the experiment.", {
    x: M, y: 4.6, w: 11.9, h: 0.6, fontFace: BODY, fontSize: 14.5, color: INK, lineSpacing: 22, margin: 0,
  });
  card(s, M, 5.35, 11.9, 1.1, "FBEEF0");
  s.addText("This reframes the finding. The detector is not weak, the evidence is stranded on the far side of a trust boundary. That turns a model problem into a network design problem, and names the exact fields worth attesting.", {
    x: M + 0.3, y: 5.55, w: 11.3, h: 0.75, fontFace: BODY, fontSize: 13.5, color: "7A1220", lineSpacing: 19, margin: 0,
  });
}

// ---------------------------------------------------------------- 5 generate
{
  const s = lightSlide("Pillar 2 · Generate", "Fidelity is enforced by the harness, not promised in prose");
  const rules = [
    ["Attacks must authorize cleanly", "Every generator starts from a well formed approved authorization and changes only what the attack changes. The smoke test fails the build if agentic attack approval drops below 90%."],
    ["Genomes are checked against the taxonomy", "check_params rejects any sampled value outside the declared range, so code and taxonomy cannot drift apart."],
    ["Episodes are grouped, never split", "Correlated records share a campaign_id and all splits group on it. A row level split would leak the attack into training."],
    ["Fraud rate means what a payments person means", "Per episode prevalence is converted to a record level rate. Without it, fan-out vectors silently swamp the dataset."],
  ];
  rules.forEach(([h, b], i) => {
    const x = M + (i % 2) * 6.15;
    const y = 1.75 + Math.floor(i / 2) * 2.35;
    card(s, x, y, 5.85, 2.05);
    chip(s, i + 1, x + 0.28, y + 0.28);
    s.addText(h, { x: x + 0.85, y: y + 0.28, w: 4.8, h: 0.42, fontFace: BODY, fontSize: 15, bold: true, color: INK, margin: 0 });
    s.addText(b, { x: x + 0.28, y: y + 0.85, w: 5.3, h: 1.0, fontFace: BODY, fontSize: 12, color: MUTE, lineSpacing: 17, margin: 0 });
  });
  foot(s, "29 attack generators · 3 benign generators · records validated against an ISO 8583 derived schema with agentic extensions");
}

// ---------------------------------------------------------------- 6 experiment design
{
  const s = lightSlide("Pillar 3 · Defend", "Seven arms, one honest question");
  const rows = [
    ["A", "supervised, v_network", "The incumbent. Trained on benign plus classical fraud only."],
    ["B", "supervised, v_attested", "Same labels, better evidence."],
    ["C", "novelty, v_network", "Isolation forest fitted on legitimate traffic only."],
    ["D", "novelty, v_attested", "Same, with provenance."],
    ["E", "supervised oracle", "Agentic attacks in training. Upper reference, not a claim."],
    ["F", "invariants only", "Nine consent checks. No model, no labels."],
    ["G", "hybrid, D or F", "The proposed defense."],
  ];
  rows.forEach(([k, n, d], i) => {
    const y = 1.7 + i * 0.63;
    s.addShape(pres.ShapeType.roundRect, { x: M, y, w: 0.44, h: 0.44, rectRadius: 0.08, fill: { color: k === "G" ? RED : INK2 } });
    s.addText(k, { x: M, y, w: 0.44, h: 0.44, align: "center", valign: "middle", fontFace: BODY, fontSize: 13, bold: true, color: PAPER, margin: 0 });
    s.addText(n, { x: M + 0.62, y: y + 0.04, w: 2.9, h: 0.36, fontFace: "Courier New", fontSize: 12.5, bold: k === "G", color: k === "G" ? RED : INK, margin: 0 });
    s.addText(d, { x: M + 3.65, y: y + 0.05, w: 4.6, h: 0.36, fontFace: BODY, fontSize: 12, color: MUTE, margin: 0 });
  });
  card(s, 8.7, 1.7, 3.9, 4.4, INK2);
  s.addText("Protocol", { x: 9.0, y: 1.95, w: 3.3, h: 0.4, fontFace: HEAD, fontSize: 20, bold: true, color: PAPER, margin: 0 });
  s.addText([
    { text: "Agentic attacks never appear in training. Every treatment number is zero shot.\n\n", options: {} },
    { text: "The alert threshold is fixed at 0.5% of legitimate traffic and calibrated on a held-out benign slice, never on training rows.\n\n", options: {} },
    { text: "Splits group on campaign_id.\n\n", options: {} },
    { text: "60,000 episodes, 29 attack generators, fixed seed.", options: {} },
  ], { x: 9.0, y: 2.5, w: 3.3, h: 3.3, fontFace: BODY, fontSize: 12, color: "C9CEDA", lineSpacing: 17, margin: 0 });
}

// ---------------------------------------------------------------- 7 result: blindness
{
  const s = lightSlide("Result 1", "The incumbent is blind, not merely degraded");
  const vec = ["AGH-01", "AGH-07", "MND-02", "MND-04", "MND-07", "MND-05", "MND-01", "XRL-06"];
  const label = {
    "AGH-01": "Checkout injection", "AGH-07": "Email injection", "MND-02": "Cart substitution",
    "MND-04": "Sub-cap structuring", "MND-07": "Recurring hijack", "MND-05": "Allowlist aliasing",
    "MND-01": "Memory poisoning", "XRL-06": "Mule network",
  };
  const A = HL.arms["A supervised v_network"].treatment_by_vector;
  const G = HL.arms["G hybrid     v_attested"].treatment_by_vector;
  s.addChart(pres.ChartType.bar, [
    { name: "Arm A, network view", labels: vec.map(v => label[v]), values: vec.map(v => A[v].recall) },
    { name: "Arm G, attested view", labels: vec.map(v => label[v]), values: vec.map(v => G[v].recall) },
  ], {
    x: M, y: 1.65, w: 8.1, h: 4.6, barDir: "bar", barGrouping: "clustered",
    chartColors: [SLATE, RED], showLegend: true, legendPos: "t", legendFontFace: BODY, legendFontSize: 11,
    showValue: true, dataLabelPosition: "outEnd", dataLabelFormatCode: "0%", dataLabelFontSize: 9, dataLabelColor: INK,
    catAxisLabelColor: INK, catAxisLabelFontSize: 11, catAxisLabelFontFace: BODY,
    valAxisLabelColor: MUTE, valAxisLabelFontSize: 10, valAxisMaxVal: 1, valAxisLabelFormatCode: "0%",
    valGridLine: { color: "EDEFF2", size: 1 }, catGridLine: { style: "none" },
    barGapWidthPct: 55,
  });
  s.addText("Detection rate by attack, at a fixed 0.5% alert budget", { x: M, y: 6.35, w: 8, h: 0.3, fontFace: BODY, fontSize: 10.5, color: MUTE, margin: 0 });
  card(s, 9.1, 1.65, 3.5, 4.6);
  s.addText("Read the zeros", { x: 9.4, y: 1.95, w: 2.9, h: 0.4, fontFace: HEAD, fontSize: 19, bold: true, color: INK, margin: 0 });
  s.addText("Eighteen of twenty-one agentic vectors sit at exactly 0.00 for the incumbent. These are the attacks the taxonomy predicted would be invisible at the network, and they are.\n\nThe last row is the counterweight. Mule networks are caught by the incumbent and missed by ours.\n\nSo the deployment shape is an OR of both detectors, not a replacement.", {
    x: 9.4, y: 2.5, w: 2.9, h: 3.5, fontFace: BODY, fontSize: 12, color: MUTE, lineSpacing: 17, margin: 0,
  });
}

// ---------------------------------------------------------------- 8 negative result
{
  const s = lightSlide("Result 2", "The result that forced a redesign");
  card(s, M, 1.7, 5.7, 2.2, "F4F5F8");
  s.addText("What we expected", { x: M + 0.3, y: 1.95, w: 5.1, h: 0.35, fontFace: BODY, fontSize: 14, bold: true, color: MUTE, margin: 0 });
  s.addText("Give the supervised model the attested provenance fields and it recovers.", { x: M + 0.3, y: 2.4, w: 5.1, h: 1.1, fontFace: HEAD, fontSize: 17, color: INK, lineSpacing: 24, margin: 0 });
  card(s, M, 4.1, 5.7, 2.2, "FBEEF0");
  s.addText("What happened", { x: M + 0.3, y: 4.35, w: 5.1, h: 0.35, fontFace: BODY, fontSize: 14, bold: true, color: RED, margin: 0 });
  s.addText("Recall moved from 0.344 to 0.355. Statistically nothing.", { x: M + 0.3, y: 4.8, w: 5.1, h: 1.1, fontFace: HEAD, fontSize: 17, color: "7A1220", lineSpacing: 24, margin: 0 });
  s.addText("Why", { x: 6.9, y: 1.75, w: 5.7, h: 0.4, fontFace: HEAD, fontSize: 22, bold: true, color: INK, margin: 0 });
  s.addText("A supervised model trained only on classical fraud has never seen one example where an intent-to-cart mismatch meant fraud. It never learns to use the column.\n\nBetter evidence does not help a model whose labels never contained the pattern. And in the real world there is barely any labelled agentic fraud to train on, so this is not a temporary problem.\n\nThe conclusion is structural: the defense cannot be supervised.", {
    x: 6.9, y: 2.3, w: 5.7, h: 3.0, fontFace: BODY, fontSize: 14, color: MUTE, lineSpacing: 21, margin: 0,
  });
  card(s, 6.9, 5.5, 5.7, 0.85, INK2);
  s.addText("We report this because a judge would ask. It is also what makes the next slide credible.", {
    x: 7.15, y: 5.68, w: 5.2, h: 0.5, fontFace: BODY, fontSize: 12.5, italic: true, color: "C9CEDA", margin: 0,
  });
}

// ---------------------------------------------------------------- 9 the defense
{
  const s = lightSlide("Result 3", "A defense that needs no labelled agentic fraud");
  const arms = ["A supervised v_network", "C novelty    v_network", "D novelty    v_attested", "F invariants v_attested", "G hybrid     v_attested"];
  const names = ["A network\nsupervised", "C network\nnovelty", "D attested\nnovelty", "F invariants\nonly", "G hybrid\nproposed"];
  s.addChart(pres.ChartType.bar, [
    { name: "Ranking quality, AUC", labels: names, values: arms.map(a => HL.arms[a].treatment.roc_auc) },
    { name: "Detection at 0.5% alerts", labels: names, values: arms.map(a => HL.arms[a].treatment.recall) },
  ], {
    x: M, y: 1.7, w: 7.6, h: 4.3, barDir: "col", barGrouping: "clustered",
    chartColors: [SLATE, RED], showLegend: true, legendPos: "t", legendFontFace: BODY, legendFontSize: 11,
    showValue: true, dataLabelPosition: "outEnd", dataLabelFormatCode: "0.00", dataLabelFontSize: 9, dataLabelColor: INK,
    catAxisLabelColor: INK, catAxisLabelFontSize: 10.5, catAxisLabelFontFace: BODY,
    valAxisLabelColor: MUTE, valAxisLabelFontSize: 10, valAxisMaxVal: 1,
    valGridLine: { color: "EDEFF2", size: 1 }, catGridLine: { style: "none" }, barGapWidthPct: 45,
  });
  s.addText("Agentic attacks, none of which appear in training", { x: M, y: 6.1, w: 7.5, h: 0.3, fontFace: BODY, fontSize: 10.5, color: MUTE, margin: 0 });
  card(s, 8.6, 1.7, 4.0, 4.3, INK2);
  s.addText("Arm G", { x: 8.9, y: 1.95, w: 3.4, h: 0.4, fontFace: HEAD, fontSize: 22, bold: true, color: PAPER, margin: 0 });
  s.addText("0.963", { x: 8.9, y: 2.5, w: 3.4, h: 0.7, fontFace: HEAD, fontSize: 44, bold: true, color: RED, margin: 0 });
  s.addText("AUC on unseen agentic attacks, at a 0.5% alert rate", { x: 8.9, y: 3.2, w: 3.4, h: 0.55, fontFace: BODY, fontSize: 12, color: "9AA3B2", lineSpacing: 16, margin: 0 });
  s.addText("Novelty detection fitted on legitimate traffic, ORed with nine consent invariants. Neither half uses a fraud label.\n\nThey fail on disjoint attacks, so the combiner is a rank-max, not an average. Averaging halved whichever detector was firing and cost us an entire vector.", {
    x: 8.9, y: 3.95, w: 3.4, h: 2.0, fontFace: BODY, fontSize: 12, color: "C9CEDA", lineSpacing: 17, margin: 0,
  });
}

// ---------------------------------------------------------------- 10 invariants
{
  const s = lightSlide("Why it works", "Nine properties a well-formed agentic authorization must have");
  const inv = [
    "The submitted basket is the one the user consented to",
    "The amount charged is the amount consented",
    "The cart matches what the user asked for",
    "A payee change came from the user, not from ingested content",
    "The merchant is the allowlisted merchant, not a lookalike",
    "The amount is not parked immediately below the cap",
    "The mandate is inside its validity window",
    "The agent that executed is the agent that was enrolled",
    "The one-time code was consumed by the session that requested it",
  ];
  inv.forEach((t, i) => {
    const x = M + (i % 2) * 6.15;
    const y = 1.7 + Math.floor(i / 2) * 0.62;
    s.addShape(pres.ShapeType.ellipse, { x, y: y + 0.06, w: 0.22, h: 0.22, fill: { color: RED } });
    s.addText(t, { x: x + 0.4, y, w: 5.6, h: 0.42, fontFace: BODY, fontSize: 13, color: INK, margin: 0 });
  });
  card(s, M, 5.5, 11.9, 1.1, "F4F5F8");
  s.addText("None of these is learned from fraud. Each is a contract term, checkable the moment the provenance field is attested, and explainable to an analyst in one sentence. That is why they generalise to attacks nobody has seen.", {
    x: M + 0.3, y: 5.72, w: 11.3, h: 0.7, fontFace: BODY, fontSize: 13.5, color: INK, lineSpacing: 19, margin: 0,
  });
}

// ---------------------------------------------------------------- 11 coevolution
{
  const s = lightSlide("The loop closes", "We attacked our own defense for eight generations");
  const pick = ["AGH-01", "AGH-03", "MND-05", "MND-01", "AGH-07"];
  const lbl = { "AGH-01": "AGH-01 checkout injection", "AGH-03": "AGH-03 hidden DOM", "MND-05": "MND-05 allowlist aliasing", "MND-01": "MND-01 memory poisoning", "AGH-07": "AGH-07 email injection" };
  const rounds = ["0", "1", "2", "3", "4", "5", "6", "7"];
  s.addChart(pres.ChartType.line, pick.map(v => ({
    name: lbl[v] || v, labels: rounds, values: CO.per_vector[v].evasion_curve,
  })), {
    x: M, y: 1.7, w: 7.7, h: 4.3,
    chartColors: [RED, "E8734A", SLATE, "7C8698", "2E7D4F"],
    showLegend: true, legendPos: "b", legendFontFace: BODY, legendFontSize: 10,
    lineSize: 3, lineSmooth: false,
    catAxisLabelColor: INK, catAxisLabelFontSize: 11, catAxisTitle: "generation", showCatAxisTitle: true,
    catAxisTitleFontSize: 10, catAxisTitleColor: MUTE,
    valAxisLabelColor: MUTE, valAxisLabelFontSize: 10, valAxisMaxVal: 1, valAxisLabelFormatCode: "0%",
    valGridLine: { color: "EDEFF2", size: 1 }, catGridLine: { style: "none" },
  });
  s.addText("Share of mutated genomes that evade arm G", { x: M, y: 6.1, w: 7.5, h: 0.3, fontFace: BODY, fontSize: 10.5, color: MUTE, margin: 0 });
  card(s, 8.7, 1.7, 3.9, 2.05, "FBEEF0");
  s.addText("Statistical signals erode", { x: 9.0, y: 1.92, w: 3.3, h: 0.35, fontFace: BODY, fontSize: 14, bold: true, color: "7A1220", margin: 0 });
  s.addText("AGH-01 goes from 0% evasion to 94% in seven generations of mutation inside the declared ranges.", { x: 9.0, y: 2.35, w: 3.3, h: 1.2, fontFace: BODY, fontSize: 12, color: "7A1220", lineSpacing: 17, margin: 0 });
  card(s, 8.7, 3.95, 3.9, 2.05, "EAF3EE");
  s.addText("Invariants do not", { x: 9.0, y: 4.17, w: 3.3, h: 0.35, fontFace: BODY, fontSize: 14, bold: true, color: "1E5B3A", margin: 0 });
  s.addText("AGH-07, MND-01, MND-02, MND-04 and XRL-04 never evade once. You cannot mutate a genome into not having mutated the payee.", { x: 9.0, y: 4.6, w: 3.3, h: 1.3, fontFace: BODY, fontSize: 12, color: "1E5B3A", lineSpacing: 17, margin: 0 });
  foot(s, "Every vector's difficulty in the taxonomy is now a measured evasion rate, replacing the hand-set prior. Several priors were badly wrong.");
}

// ---------------------------------------------------------------- 12 feasibility
{
  const s = lightSlide("Real-world feasibility", "The ask is small, specific, and already on the roadmap");
  const steps = [
    ["Attest, do not transmit", "Intent is carried as an embedding and a consent hash, never as the user's transcript. The network learns that the cart diverged, not what was said."],
    ["Reuse the mandate envelope", "Agent Pay, Trusted Agent Protocol and AP2 already carry an agent identity and a mandate. Every field we need is an extension of that envelope, not a new rail."],
    ["Deploy beside the incumbent", "The hybrid runs as an OR with the existing model. Classical fraud keeps its detector, agentic fraud gets one, and the alert budget stays at 0.5%."],
    ["Cold start is solved", "The defense needs zero labelled agentic fraud, which is exactly the position every issuer is in today."],
  ];
  steps.forEach(([h, b], i) => {
    const y = 1.7 + i * 1.25;
    chip(s, i + 1, M, y + 0.05);
    s.addText(h, { x: M + 0.65, y, w: 4.6, h: 0.38, fontFace: BODY, fontSize: 16, bold: true, color: INK, margin: 0 });
    s.addText(b, { x: 5.6, y: y + 0.02, w: 7.0, h: 1.0, fontFace: BODY, fontSize: 13, color: MUTE, lineSpacing: 18, margin: 0 });
  });
  foot(s, "The vantage model in schema/auth_record.yaml names every field, its holder, and whether attestation could carry it.");
}

// ---------------------------------------------------------------- 13 limitations
{
  const s = lightSlide("What we would not claim", "Limitations, stated before you find them");
  const lim = [
    ["Per-vector counts are small", "Between 26 and 406 test records per attack after the 200,000 episode run. Adequate for the arm-level claims, thin for the smallest vectors."],
    ["The oracle is too good", "Arm E reaches 1.000 with agentic attacks in training. Real fraud is less separable than simulated fraud, even with perfect labels."],
    ["No settlement clock", "Refund abuse and merchant bust-out are approximated on the authorization record rather than modelled on their own timeline."],
    ["Recalibration is not a cure", "After coevolution, refitting the defense on fresh benign traffic restores some vectors and not others. We report both."],
  ];
  lim.forEach(([h, b], i) => {
    const x = M + (i % 2) * 6.15;
    const y = 1.75 + Math.floor(i / 2) * 2.35;
    card(s, x, y, 5.85, 2.05);
    s.addText(h, { x: x + 0.3, y: y + 0.28, w: 5.25, h: 0.4, fontFace: BODY, fontSize: 15, bold: true, color: INK, margin: 0 });
    s.addText(b, { x: x + 0.3, y: y + 0.78, w: 5.25, h: 1.05, fontFace: BODY, fontSize: 12.5, color: MUTE, lineSpacing: 18, margin: 0 });
  });
}

// ---------------------------------------------------------------- 14 close
{
  const s = darkSlide();
  s.addText("The loop, in one line", {
    x: M, y: 1.5, w: 10, h: 0.6, fontFace: BODY, fontSize: 13, bold: true, color: RED, charSpacing: 2, margin: 0,
  });
  s.addText("We invented 42 ways to rob an agent, built 29 of them,\nfound our own detector blind to eighteen of them, and shipped a defense\nthat catches them without a single labelled example.", {
    x: M, y: 2.15, w: 11.5, h: 2.0, fontFace: HEAD, fontSize: 28, color: PAPER, lineSpacing: 44, margin: 0,
  });
  const stats = [["42", "vectors mapped"], ["29", "simulated"], ["0.963", "AUC, unseen attacks"], ["0.5%", "alert budget"]];
  stats.forEach(([v, l], i) => {
    const x = M + i * 3.05;
    s.addText(v, { x, y: 4.7, w: 2.8, h: 0.7, fontFace: HEAD, fontSize: 36, bold: true, color: i === 2 ? RED : PAPER, margin: 0 });
    s.addText(l, { x, y: 5.42, w: 2.8, h: 0.35, fontFace: BODY, fontSize: 11.5, color: "9AA3B2", margin: 0 });
  });
  s.addText("Code, taxonomy, experiments and prototype all reproduce from a fixed seed.", {
    x: M, y: 6.4, w: 11, h: 0.35, fontFace: BODY, fontSize: 12, italic: true, color: "7C8698", margin: 0,
  });
}

pres.writeFile({ fileName: __dirname + "/ARTS_walkthrough.pptx" }).then(f => console.log("wrote", f));
