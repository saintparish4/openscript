/**
 * Before/after for a mutated response. Redactions arrive as `[REDACTED:label]`
 * or a run of asterisks, so the changed spans can be highlighted without
 * diffing: the markers are the diff.
 */
const SPLIT = /(\[REDACTED:[a-z_]+\]|\*{3,})/g;
// Separate, non-global: `test` on a /g regex advances lastIndex between calls
// and would report every other match as a miss.
const IS_MARKER = /^(\[REDACTED:[a-z_]+\]|\*{3,})$/;

interface Props {
  before: string;
  after: string;
  /** What each side is. The same view serves both directions: what was sent
   *  against what the model was given, and what the model produced against
   *  what the caller got back. */
  beforeLabel: string;
  afterLabel: string;
}

export function DiffView({ before, after, beforeLabel, afterLabel }: Props) {
  if (!before || !after || before === after) return null;
  return (
    <div className="diff">
      <div className="diff__side">
        <span className="label">{beforeLabel}</span>
        <p className="diff__text diff__text--before">{before}</p>
      </div>
      <div className="diff__side">
        <span className="label">{afterLabel}</span>
        <p className="diff__text">
          {after.split(SPLIT).map((part, i) =>
            IS_MARKER.test(part) ? <mark key={i}>{part}</mark> : <span key={i}>{part}</span>,
          )}
        </p>
      </div>
    </div>
  );
}
