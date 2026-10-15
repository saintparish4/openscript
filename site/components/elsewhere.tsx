import { ArrowUpRight, BrowserIcon, TerminalIcon } from "@/components/icons";
import { SOURCE_URL } from "@/lib/links";
import type { ReactNode } from "react";

interface Place {
  name: string;
  tag: string;
  icon: ReactNode;
  does: string;
  href: string;
  link: string;
}

// The two other places the same package runs. Each line is a claim the
// README makes in the same words, limit included: change one, change both.
const PLACES: Place[] = [
  {
    name: "A hook for Claude Code",
    tag: "Claude Code",
    icon: <TerminalIcon size={18} />,
    does: "openscript-hook runs the tool rules on the calls Claude Code makes. It checks their arguments, holds the MCP calls you list once the session has read a web page or an issue, masks secrets in what a tool returns, and writes a line for every decision. It can refuse or ask, never approve, and adds about 150\u00a0ms before a call.",
    href: `${SOURCE_URL}#6-guard-claude-code-with-a-hook`,
    link: "How to install it, and its limits",
  },
  {
    name: "A browser extension",
    tag: "Chrome",
    icon: <BrowserIcon size={18} />,
    does: "The same package in a Chrome side panel, around a scripted browsing agent. Every page it opens, reads or submits goes through the tool rules: a page that talks to the agent provokes a form post the rules refuse, and a purchase waits for you. It guards its own agent's actions, not your browsing.",
    href: `${SOURCE_URL}/tree/master/extension`,
    link: "Load it unpacked",
  },
];

export function Elsewhere() {
  return (
    <section id="elsewhere" className="section">
      <div className="container">
        <p className="eyebrow">Beyond this page</p>
        <h2 className="section__title">The same rules, around other agents.</h2>
        <p className="section__lede">
          The demo is one place the package runs. These are two more, each built from the same
          policies and each checked in a real host: a Claude Code session, and Chromium.
        </p>

        <ul className="bento bento--pair">
          {PLACES.map((p) => (
            <li key={p.name} className="card">
              <div className="card__head">
                <span className="card__icon">{p.icon}</span>
                <span className="tag">{p.tag}</span>
              </div>
              <h3 className="card__name">{p.name}</h3>
              <p className="card__text">{p.does}</p>
              <a className="card__link" href={p.href}>
                {p.link}
                <ArrowUpRight size={13} />
              </a>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
