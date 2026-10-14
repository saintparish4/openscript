import { DemoSection } from "@/components/demo-section";
import { EXAMPLES } from "@/lib/examples";
import { Hero } from "@/components/hero";
import { ArrowUpRight, GitHubIcon, Mark } from "@/components/icons";
import { Pipeline } from "@/components/pipeline";
import { Policies } from "@/components/policies";
import { SiteNav } from "@/components/site-nav";
import { METRICS_URL, SOURCE_URL } from "@/lib/links";

// The senders, once each, in the order the gallery introduces them.
const CAST = [...new Map(EXAMPLES.map((ex) => [ex.persona.name, ex.persona])).values()];

export default function Page() {
  return (
    <>
      <SiteNav />

      <main id="top">
        {/* The hero and the demo share one backdrop, so the window sits in the
            light rather than under it — and stays in the first screenful. */}
        <div className="stage">
          <Hero />
          <section id="demo" className="demo container" aria-label="Demo">
            {/* Who is talking and what to do, before the list asks for a click.
                Kept to a line and a row so the window stays in the first screen. */}
            <div className="cast">
              <p className="cast__lede">
                {EXAMPLES.length} prompts from seven people, three each: a customer, a
                contractor, a support agent, three engineers and an analyst with a browsing
                agent. Pick one and it runs through the real pipeline, next to what would have
                happened without it.
              </p>
              <ul className="cast__people">
                {CAST.map((person) => (
                  <li key={person.name}>
                    <span className="avatar" aria-hidden="true">
                      {person.name[0]}
                    </span>
                    <span>
                      <strong>{person.name}</strong>
                      <span className="cast__role">
                        {/* The job comes first in every role, before the comma.
                            A phone has room for that much and no more. */}
                        {person.role.split(",")[0]}
                        {person.role.includes(",") ? (
                          <span className="cast__detail">
                            ,{person.role.split(",").slice(1).join(",")}
                          </span>
                        ) : null}
                      </span>
                    </span>
                  </li>
                ))}
              </ul>
            </div>
            <DemoSection />
            <p className="privacy">
              These run in this browser. There is no server to send them to — open the network
              tab and watch. There is no LLM either: the agent here is a stand-in that repeats
              what it is given, which is exactly the leak the output policies exist to catch.
              The policies are the real ones.
            </p>
          </section>
        </div>

        <Policies />
        <Pipeline />

        <section className="section closing">
          <div className="container">
            <h2 className="duo">
              Don&rsquo;t take the page&rsquo;s word for it.
              <span>
                Every prompt in the gallery runs against the real policies in CI, and the
                detection numbers are published with the misses left in.
              </span>
            </h2>
            <div className="hero__actions">
              <a className="btn" href={SOURCE_URL}>
                <GitHubIcon size={15} />
                View the source
              </a>
              <a className="btn btn--ghost" href={METRICS_URL}>
                Measured detection numbers
                <ArrowUpRight size={14} />
              </a>
            </div>
          </div>
        </section>
      </main>

      <footer className="footer">
        <div className="container footer__inner">
          <p className="brand">
            <Mark />
            OpenScript
          </p>
          <p className="footer__line">
            A security-gateway SDK for Python LLM and agent workflows. This site is static files:
            no server, and nothing to send a prompt to.
          </p>
          <ul className="footer__links">
            <li>
              <a href="#demo">Demo</a>
            </li>
            <li>
              <a href={SOURCE_URL}>Source</a>
            </li>
            <li>
              <a href={METRICS_URL}>Measured detection numbers</a>
            </li>
          </ul>
        </div>
      </footer>
    </>
  );
}
