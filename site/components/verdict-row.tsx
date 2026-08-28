import type { PolicyRow, Verdict } from "@/lib/types";

const VERDICT_LABEL: Record<Verdict, string> = {
  allow: "Allow",
  flag: "Flagged",
  mutate: "Redacted",
  deny: "Deny",
  approval: "Needs approval",
  skipped: "Not applicable",
  not_reached: "Not reached",
};

export function VerdictRow({ row }: { row: PolicyRow }) {
  const inert = row.verdict === "skipped" || row.verdict === "not_reached";
  return (
    <li className={`verdict verdict--${row.verdict}`}>
      <div className="verdict__head">
        <span className="verdict__policy">{row.policy}</span>
        <span className="verdict__badge">{VERDICT_LABEL[row.verdict]}</span>
      </div>
      <p className="verdict__why">{row.explanation}</p>
      {!inert && row.risk !== null && (
        <div className="verdict__meter" aria-hidden="true">
          <span style={{ width: `${Math.round(row.risk * 100)}%` }} />
        </div>
      )}
      {!inert && row.risk !== null && (
        <span className="verdict__risk">risk {row.risk.toFixed(2)}</span>
      )}
    </li>
  );
}
