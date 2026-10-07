import type { Metadata, Viewport } from "next";
// Self-hosted. A font CDN would be a third party in the network tab of a page
// whose main claim is what is not in its network tab.
import "@fontsource-variable/inter/wght.css";
import "@fontsource-variable/jetbrains-mono/wght.css";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://openscript-rho.vercel.app"),
  title: "OpenScript — see the policy pipeline run",
  description:
    "An interactive demo of the OpenScript security gateway. Every policy runs in your browser; nothing you run is sent anywhere.",
  openGraph: {
    type: "website",
    siteName: "OpenScript",
  },
  twitter: {
    card: "summary_large_image",
  },
};

export const viewport: Viewport = {
  themeColor: "#07080a",
  colorScheme: "dark",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
