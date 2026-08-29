import { DemoSection } from "@/components/demo-section";

export default function Page() {
  return (
    <main>
      <header className="masthead">
        <h1>OpenScript</h1>
        <p className="lede">
          A policy pipeline that sits between an application and its LLM agent, and refuses to
          pass along the things that should not go through. This page runs the real package —
          compiled to WebAssembly, in your browser.
        </p>
      </header>

      <DemoSection />

      <footer className="footer">
        <p>
          Nine built-in policies, no network calls: prompt injection, toxicity, harmful requests,
          PII, secrets, compliance, tool firewall, output schema and audit logging. The demo
          exercises seven of them plus the audit trail.
        </p>
        <p>
          <a href="https://github.com/saintparish4/openscript">Source</a>
        </p>
      </footer>
    </main>
  );
}
