import type { ReactNode } from "react";
import { CheckIcon, PauseIcon, RedactIcon, SlashIcon } from "./icons";

const BEFORE = [
  "Prompt injection",
  "Toxicity",
  "Harmful request",
  "Secrets",
  "Compliance",
  "Tool firewall",
  "Audit",
];
const AFTER = ["Output schema", "PII", "Secrets", "Compliance", "Audit"];

const DECISIONS: { name: string; tone: string; icon: ReactNode; text: string }[] = [
  {
    name: "Allow.",
    tone: "allow",
    icon: <CheckIcon size={20} />,
    text: "Nothing matched, so the call goes through untouched.",
  },
  {
    name: "Redact.",
    tone: "mutate",
    icon: <RedactIcon size={20} />,
    text: "The text is rewritten before it travels any further.",
  },
  {
    name: "Deny.",
    tone: "deny",
    icon: <SlashIcon size={20} />,
    text: "Before the agent, it never runs. After it, the response is withheld.",
  },
  {
    name: "Require approval.",
    tone: "approval",
    icon: <PauseIcon size={20} />,
    text: "Held for a human. An approval is single-use and expires after an hour.",
  },
];

// The README's "Wrap an Agent" example, trimmed to the call that matters.
const SAMPLE = `from sdk import PIIPolicy, PromptInjectionPolicy, SecretsPolicy, SecureAgent

secure = SecureAgent(
    agent=MyAgent(),
    policies=[
        PromptInjectionPolicy(threshold=0.5),  # blocks injection attempts
        PIIPolicy(mode="redact"),              # redacts PII from output
        SecretsPolicy(mode="redact"),          # redacts credentials
    ],
)

result = await secure.invoke({"input": "..."})`;

// Comment, string, keyword, number, call — in that order of precedence.
const TOKEN =
  /(#.*$)|("[^"]*")|\b(from|import|await)\b|\b(\d+(?:\.\d+)?)\b|\b([A-Za-z_]\w*)(?=\()/gm;

/**
 * Enough highlighting for one snippet. A dozen lines of Python do not need a
 * tokenizer shipped to the browser to colour them.
 */
function highlight(code: string): ReactNode[] {
  const out: ReactNode[] = [];
  let last = 0;
  for (const m of code.matchAll(TOKEN)) {
    const at = m.index ?? 0;
    if (at > last) out.push(code.slice(last, at));
    const kind = m[1] ? "c" : m[2] || m[4] ? "s" : m[3] ? "k" : "n";
    out.push(
      <span key={at} className={`tok-${kind}`}>
        {m[0]}
      </span>,
    );
    last = at + m[0].length;
  }
  out.push(code.slice(last));
  return out;
}

export function Pipeline() {
  return (
    <section id="pipeline" className="section">
      <div className="container split">
        <div className="split__text">
          <h2 className="duo">
            The pipeline has no detection logic.
            <span>
              It runs every policy before the agent, then the agent, then every policy after it.
              All the judgement lives in the policies, so you can swap one, configure them from
              YAML, or write your own.
            </span>
          </h2>
        </div>

        <div className="split__body">
          <div className="flow">
            <div className="flow__lane">
              <span className="flow__label">
                <code>before_action</code> — a deny here and the agent never runs
              </span>
              <ul className="flow__chips">
                {BEFORE.map((name) => (
                  <li key={name} className="tag">
                    {name}
                  </li>
                ))}
              </ul>
            </div>
            <div className="flow__agent">
              <span>Your agent</span>
            </div>
            <div className="flow__lane">
              <span className="flow__label">
                <code>after_action</code> — a deny here withholds the response
              </span>
              <ul className="flow__chips">
                {AFTER.map((name) => (
                  <li key={name} className="tag">
                    {name}
                  </li>
                ))}
              </ul>
            </div>
            <p className="flow__note">
              The order is yours to set. Audit goes last, so its events carry the final risk
              score.
            </p>
          </div>

          <ul className="keys">
            {DECISIONS.map((d) => (
              <li key={d.name} className={`key tone--${d.tone}`}>
                <span className="key__icon">{d.icon}</span>
                <p>
                  <strong>{d.name}</strong> {d.text}
                </p>
              </li>
            ))}
          </ul>

          <figure className="code">
            <figcaption className="code__bar">
              <span>Wrap an agent</span>
              <span className="code__file">python</span>
            </figcaption>
            <pre className="code__body">
              <code>{highlight(SAMPLE)}</code>
            </pre>
            <p className="code__note">
              Installs from source with <code>pip install -e .</code> and three dependencies:
              pydantic, structlog and pyyaml.
            </p>
          </figure>
        </div>
      </div>
    </section>
  );
}
