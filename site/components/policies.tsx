import type { ReactNode } from "react";
import { METRICS_URL } from "@/lib/links";
import {
  ArrowUpRight,
  BracesIcon,
  DropletIcon,
  FileTextIcon,
  KeyIcon,
  ListIcon,
  MessageAlertIcon,
  ShieldIcon,
  TerminalIcon,
  TriangleAlertIcon,
  UserIcon,
} from "./icons";

// The headline rows of docs/metrics.md: detection as measured on 2026-10-11,
// the model runs on 2026-10-14. Hand-copied: when a number changes there, it
// changes here.
const MEASURED = [
  {
    value: "118 / 118",
    label: "attacks blocked in the shapes the patterns were written for, 30 of them disguised",
  },
  {
    value: "2 to 7%",
    label: "of attacks blocked when nobody wrote a pattern for the phrasing, across three sets",
  },
  {
    value: "4 / 988",
    label: "benign prompts wrongly blocked, across three public sets nobody here wrote",
  },
  {
    value: "0 / 3,456",
    label:
      "attacked conversations in which Claude Haiku 4.5 or Sonnet 5.5 followed the planted instruction, on AgentDojo",
  },
  {
    value: "11 / 16",
    label:
      "of AgentDojo's banking tasks on which the session rule asked a person, with Sonnet 5.5 doing the work: as often as asking every time",
  },
];

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
    does: "Stops a prompt that tries to overrule the operator: \"ignore your instructions\", a new persona, a request for the system prompt. Scored against a pattern bank and denied at a threshold.",
  },
  {
    name: "Toxicity",
    phase: "input",
    icon: <MessageAlertIcon size={18} />,
    does: "Stops the agent being used to write a threat, hate speech or harassment. Self-harm is scored as its own category, which this page uses to show resources instead of a bare refusal.",
  },
  {
    name: "Harmful request",
    phase: "input",
    icon: <TriangleAlertIcon size={18} />,
    does: "Stops a request for something that does harm, from a keylogger to a doxxing guide. It reads the shape of the ask, not its vocabulary, so \"kill the process\" passes.",
  },
  {
    name: "PII",
    phase: "output",
    icon: <UserIcon size={18} />,
    does: "Keeps personal data out of the reply: emails, phone numbers, SSNs, IP addresses, and card numbers that pass the Luhn checksum a real card has to.",
  },
  {
    name: "Secrets",
    phase: "input + output",
    icon: <KeyIcon size={18} />,
    does: "Masks a pasted credential before the model is given it: AWS, GitHub and Slack tokens, JWTs and private keys. Internal URLs are flagged separately.",
  },
  {
    name: "Compliance",
    phase: "input + output",
    icon: <FileTextIcon size={18} />,
    does: "Flags regulated content, such as patient identifiers in a chart note. Its presets are named for what they check, and it assists a compliance program without certifying anything.",
  },
  {
    name: "Tool firewall",
    phase: "tool call",
    icon: <ShieldIcon size={18} />,
    does: "Decides whether a tool call may run, from rules you write: which tools, which roles, which argument values. A refund over the limit is refused, and a risky call can wait for a human.",
  },
  {
    name: "Session taint",
    phase: "tool call",
    icon: <DropletIcon size={18} />,
    does: "Remembers what a session has read. Once the agent has read something a stranger could have written, such as a web page or an issue, every call that changes anything waits for a person. It reads none of the text, so it cannot be talked round, and it asks often: on 11 of 16 tasks in a measured run.",
  },
  {
    name: "Output schema",
    phase: "output",
    icon: <BracesIcon size={18} />,
    does: "Makes sure the reply is the shape your code expects, by validating it against a Pydantic schema. It can also scan for dangerous content and check the reply against a source.",
  },
  {
    name: "Audit",
    phase: "input + output",
    icon: <ListIcon size={18} />,
    does: "Keeps a record of every action and every refusal, with the policy that decided and the final risk score. It goes last so its events carry that score.",
  },
];

export function Policies() {
  return (
    <section id="policies" className="section">
      <div className="container">
        <p className="eyebrow">Built-in policies</p>
        <h2 className="section__title">Ten policies. No network calls.</h2>
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
              to understand a sentence rather than match it. Measured on attacks nobody wrote a
              pattern for, the detectors block 2 to 7%, and that number is published next to
              the 100% ones. The tool rules, approvals and redaction do not depend on
              recognising an attack. With real models on AgentDojo, the models ignored every
              planted instruction themselves: the model is the first line, and these are the
              limits behind it.
            </p>
          </div>
          <a className="btn btn--ghost" href={METRICS_URL}>
            Measured detection numbers
            <ArrowUpRight size={14} />
          </a>
          <dl className="measured">
            {MEASURED.map((m) => (
              <div key={m.value}>
                <dt>{m.label}</dt>
                <dd>{m.value}</dd>
              </div>
            ))}
          </dl>
        </div>
      </div>
    </section>
  );
}
