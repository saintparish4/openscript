import type { KeyboardEvent, ReactNode, Ref } from "react";
import { EXAMPLES, type Example } from "@/lib/examples";
import type { Outcome } from "@/lib/outcome";
import { Mark } from "./icons";

/** The three senders, in the order the gallery introduces them. */
export const PEOPLE = [...new Set(EXAMPLES.map((ex) => ex.persona.name))];

const MOVES: Record<string, (at: number, last: number) => number> = {
  ArrowDown: (at, last) => Math.min(at + 1, last),
  ArrowUp: (at) => Math.max(at - 1, 0),
  Home: () => 0,
  End: (_, last) => last,
};

interface Props {
  selectedId: string;
  /** Sender name to show, or "" for everyone. */
  filter?: string;
  /** What each prompt came to, for the ones that have been run. */
  outcomes?: Record<string, Outcome>;
  status: ReactNode;
  children: ReactNode;
  /** Run a prompt. Omitted while the panel is not live, which disables the list. */
  onRun?: (example: Example) => void;
  /** Show a prompt without running it — what the arrow keys do. */
  onPreview?: (example: Example) => void;
  onFilter?: (name: string) => void;
  windowRef?: Ref<HTMLDivElement>;
  detailRef?: Ref<HTMLDivElement>;
}

/**
 * The window the demo lives in: a list of prompts on one side, whatever the
 * selected one came to on the other.
 *
 * Presentational on purpose. The live panel is loaded with `ssr: false`, so the
 * frame around it is rendered from here by both the placeholder and the panel —
 * the gallery is on screen from first paint and nothing jumps when the runtime
 * arrives.
 *
 * The bar across the top is a title, not a search field. A free-text box was
 * removed from this demo deliberately and nothing here should look like one.
 */
export function DemoWindow({
  selectedId,
  filter = "",
  outcomes = {},
  status,
  children,
  onRun,
  onPreview,
  onFilter,
  windowRef,
  detailRef,
}: Props) {
  const visible = filter ? EXAMPLES.filter((ex) => ex.persona.name === filter) : EXAMPLES;

  /**
   * Arrow keys walk the list, the way they do in the launcher this window is
   * modelled on. Scoped to the list rather than the page: a global handler
   * would take the arrow keys away from scrolling.
   *
   * The preview is driven from here and not from focus. A row takes focus on
   * mousedown, and swapping the pane at that moment moves the page under the
   * pointer before the click has finished — which loses the click.
   */
  const walk = (event: KeyboardEvent<HTMLUListElement>) => {
    const move = MOVES[event.key];
    if (!move) return;
    const rows = Array.from(event.currentTarget.querySelectorAll<HTMLButtonElement>("button"));
    const at = rows.indexOf(document.activeElement as HTMLButtonElement);
    if (at < 0) return;
    event.preventDefault();
    const to = move(at, rows.length - 1);
    rows[to]?.focus();
    if (visible[to]) onPreview?.(visible[to]);
  };

  return (
    <div className="window" ref={windowRef}>
      <header className="window__bar">
        <h2 className="window__title">Pick a prompt to run</h2>
        <div className="seg" role="group" aria-label="Show prompts from">
          {["", ...PEOPLE].map((name) => (
            <button
              key={name || "everyone"}
              type="button"
              className="seg__item"
              aria-pressed={filter === name}
              disabled={!onFilter}
              onClick={() => onFilter?.(name)}
            >
              {name || "Everyone"}
            </button>
          ))}
        </div>
      </header>

      <div className="window__body">
        <ul className="list" onKeyDown={walk}>
          {visible.map((ex) => {
            const outcome = outcomes[ex.id];
            return (
              <li key={ex.id}>
                <button
                  type="button"
                  className="row"
                  aria-current={ex.id === selectedId ? "true" : undefined}
                  disabled={!onRun}
                  onClick={() => onRun?.(ex)}
                >
                  <span className="avatar" aria-hidden="true">
                    {ex.persona.name[0]}
                  </span>
                  <span className="row__label">{ex.label}</span>
                  {outcome ? (
                    <span className={`row__outcome tone--${outcome.tone}`}>
                      <span>{outcome.label}</span>
                    </span>
                  ) : null}
                  <span className="row__teaser">{ex.teaser}</span>
                </button>
              </li>
            );
          })}
        </ul>

        <div className="detail" ref={detailRef}>
          {children}
        </div>
      </div>

      <footer className="window__foot">
        <span className="window__status" aria-hidden="true">
          <Mark size={18} />
          <span>{status}</span>
        </span>
        <span className="window__keys" aria-hidden="true">
          <span>
            Run prompt <kbd>↵</kbd>
          </span>
          <span>
            Navigate <kbd>↑</kbd>
            <kbd>↓</kbd>
          </span>
        </span>
      </footer>
    </div>
  );
}
