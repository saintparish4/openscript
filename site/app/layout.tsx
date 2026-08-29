import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://openscript-rho.vercel.app"),
  title: "OpenScript — see the policy pipeline run",
  description:
    "An interactive demo of the OpenScript security gateway. Every policy runs in your browser; nothing you type is sent anywhere.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
