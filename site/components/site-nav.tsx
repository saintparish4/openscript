import { METRICS_URL, SOURCE_URL } from "@/lib/links";
import { GitHubIcon, Mark } from "./icons";

export function SiteNav() {
  return (
    <div className="nav">
      <nav className="nav__inner" aria-label="Main">
        <a className="brand" href="#top">
          <Mark />
          OpenScript
        </a>
        <ul className="nav__links">
          <li>
            <a href="#demo">Demo</a>
          </li>
          <li>
            <a href="#policies">Policies</a>
          </li>
          <li>
            <a href="#pipeline">Pipeline</a>
          </li>
          <li>
            <a href={METRICS_URL}>Numbers</a>
          </li>
        </ul>
        <a className="btn" href={SOURCE_URL}>
          <GitHubIcon size={15} />
          GitHub
        </a>
      </nav>
    </div>
  );
}
