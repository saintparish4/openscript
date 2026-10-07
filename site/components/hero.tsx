import { SOURCE_URL } from "@/lib/links";
import { ArrowDown, GitHubIcon } from "./icons";

// Each beam: where it sits across the fan, how far down it starts, how long it
// runs and how bright it is. Uneven on purpose — a regular comb reads as a
// pattern, and this is meant to read as light.
const BEAMS = [
  { x: 210, y: 150, h: 620, o: 0.5 },
  { x: 372, y: 40, h: 860, o: 0.85 },
  { x: 534, y: -40, h: 980, o: 1 },
  { x: 696, y: 20, h: 900, o: 0.95 },
  { x: 858, y: -60, h: 940, o: 1 },
  { x: 1020, y: 60, h: 800, o: 0.8 },
  { x: 1182, y: 200, h: 560, o: 0.45 },
];

/**
 * The light behind the hero, drawn rather than shipped as an image: seven
 * blurred bars, pushed around by noise so their edges break up into grain.
 * It is static, so the filter is paid for once per paint and never animated.
 */
function Beams() {
  return (
    <svg
      className="beams"
      viewBox="0 0 1440 900"
      preserveAspectRatio="xMidYMid slice"
      aria-hidden="true"
      focusable="false"
    >
      <defs>
        <linearGradient id="beam" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#ff2a48" stopOpacity="0" />
          <stop offset="0.1" stopColor="#e3163a" />
          <stop offset="0.45" stopColor="#ff3350" />
          <stop offset="0.74" stopColor="#ff7c93" />
          <stop offset="0.9" stopColor="#2b7fa5" stopOpacity="0.55" />
          <stop offset="1" stopColor="#2b7fa5" stopOpacity="0" />
        </linearGradient>
        <filter
          id="beam-grain"
          x="-10%"
          y="-10%"
          width="120%"
          height="120%"
          colorInterpolationFilters="sRGB"
        >
          <feGaussianBlur stdDeviation="10" result="soft" />
          <feTurbulence type="fractalNoise" baseFrequency="0.9" numOctaves="2" seed="4" />
          <feDisplacementMap in="soft" scale="42" xChannelSelector="R" yChannelSelector="G" />
        </filter>
      </defs>
      <g filter="url(#beam-grain)" transform="rotate(-45 720 450)">
        {BEAMS.map((b) => (
          <rect
            key={b.x}
            x={b.x}
            y={b.y}
            width="112"
            height={b.h}
            rx="56"
            fill="url(#beam)"
            opacity={b.o}
          />
        ))}
      </g>
    </svg>
  );
}

export function Hero() {
  return (
    <>
      <Beams />
      <header className="hero">
        <h1>A checkpoint between your app and its agent.</h1>
        <p className="hero__lede">
          OpenScript is a policy pipeline that sits between an application and its LLM agent, and
          refuses to pass along the things that should not go through.
        </p>
        <div className="hero__actions">
          <a className="btn" href="#demo">
            <ArrowDown size={15} />
            Run the demo
          </a>
          <a className="btn btn--ghost" href={SOURCE_URL}>
            <GitHubIcon size={15} />
            View source
          </a>
        </div>
        <p className="hero__note">
          This page runs the real package — compiled to WebAssembly, in your browser.
        </p>
      </header>
    </>
  );
}
