import type { ReactNode } from "react";
import { METRICS_URL } from "@/lib/links";
import {
  ArrowUpRight,
  BracesIcon,
  FileTextIcon,
  KeyIcon,
  ListIcon,
  MessageAlertIcon,
  ShieldIcon,
  TerminalIcon,
  TriangleAlertIcon,
  UserIcon,
} from "./icons";

interface Policy {
  name: string;
  /** Which side of the agent it runs on, in the README's terms. */
  phase: string;
  icon: ReactNode;
  does: string;
}

// The README's policy table, in the README's order. This is a claim about what
// the package does, so it changes when that table changes and not before.
const POLICIES: Policy[] = [
  {
    name: "Prompt injection",
    phase: "input",
    icon: <TerminalIcon size={18} />,
    does: "Scores role injection, prompt extraction, goal hijacking and delimiter or indirect injection, and denies at a threshold.",
  },
  {
    name: "Toxicity",
    phase: "input",
    icon: <MessageAlertIcon size={18} />,
    does: "Detects threats, hate speech, harassment and self-harm content, and denies at a threshold.",
  },
  {
    name: "Harmful request",
    phase: "input",
    icon: <TriangleAlertIcon size={18} />,
    does: "Scores requests for harmful capability, from malware and weapons to doxxing and covert surveillance, by the shape of the ask rather than its vocabulary.",
  },
  {
    name: "PII",
    phase: "output",
    icon: <UserIcon size={18} />,
    does: "Redacts or denies emails, phone numbers, SSNs, Luhn-checked card numbers, API keys and IP addresses.",
  },
  {
    name: "Secrets",
    phase: "input + output",
    icon: <KeyIcon size={18} />,
    does: "Redacts or denies AWS, GitHub and Slack tokens, JWTs and private-key blocks, and flags internal URLs separately.",
  },
  {
    name: "Compliance",
    phase: "input + output",
    icon: <FileTextIcon size={18} />,
    does: "Presets named for what they check: PHI detection, a credential output guard and a data-access audit. It assists a compliance program and certifies nothing.",
  },
  {
    name: "Tool firewall",
    phase: "input",
    icon: <ShieldIcon size={18} />,
    does: "Allowlists, denials, role checks and argument limits on the tool call itself. It can hold a call for human approval.",
  },
  {
    name: "Output schema",
    phase: "output",
    icon: <BracesIcon size={18} />,
    does: "Validates the response against a Pydantic schema, scans it for dangerous content, and can check it against a source.",
  },
  {
    name: "Audit",
    phase: "input + output",
    icon: <ListIcon size={18} />,
    does: "Writes every action to the event store. It goes last, so its events carry the final risk score.",
  },
];

export function Policies() {
  return (
    <section id="policies" className="section">
      <div className="container">
        <p className="eyebrow">Built-in policies</p>
        <h2 className="section__title">Nine policies. No network calls.</h2>
        <p className="section__lede">
          Each one is regex, heuristics, checksums or declarative rules. None calls a model or a
          server, and CI fails if one tries — which is the only reason this page can run without
          a backend. The demo above exercises seven of them, plus the audit trail.
        </p>

        <ul className="bento">
          {POLICIES.map((p) => (
            <li key={p.name} className="card">
              <div className="card__head">
                <span className="card__icon">{p.icon}</span>
                <span className="tag">{p.phase}</span>
              </div>
              <h3 className="card__name">{p.name}</h3>
              <p className="card__text">{p.does}</p>
            </li>
          ))}
        </ul>

        {/* The other half of the claim. A pattern bank that only lists what it
            catches is making the pitch a security tool should not make. */}
        <div className="limits">
          <div>
            <h3 className="limits__title">What they do not catch</h3>
            <p className="limits__text">
              Attacks in languages other than English, novel paraphrase, and anything that needs
              to understand a sentence rather than match it. The published numbers include the
              held-out phrasings a pattern bank mostly misses.
            </p>
          </div>
          <a className="btn btn--ghost" href={METRICS_URL}>
            Measured detection numbers
            <ArrowUpRight size={14} />
          </a>
        </div>
      </div>
    </section>
  );
}
