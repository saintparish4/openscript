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
  // A policy that never ran has no score worth showing, whatever it reported.
  const inert = row.verdict === "skipped" || row.verdict === "not_reached";
  const risk = inert ? null : row.risk;
  return (
    <li className={`verdict verdict--${row.verdict}`}>
      <div className="verdict__head">
        <span className="verdict__policy">{row.policy}</span>
        {risk !== null && <span className="verdict__risk">risk {risk.toFixed(2)}</span>}
        <span className="verdict__badge">{VERDICT_LABEL[row.verdict]}</span>
      </div>
      <p className="verdict__why">{row.explanation}</p>
      {risk !== null && (
        <div className="verdict__meter" aria-hidden="true">
          <span style={{ width: `${Math.round(risk * 100)}%` }} />
        </div>
      )}
    </li>
  );
}
