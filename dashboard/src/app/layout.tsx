import type { Metadata, Viewport } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});

const jbMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jbmono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Red Teams — Mission Control",
  description:
    "Live mission control for autonomous red-team agent operations: runs, event stream, findings, approvals and kill chain.",
  applicationName: "Red Teams",
};

export const viewport: Viewport = {
  themeColor: "#0B0E14",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={`${inter.variable} ${jbMono.variable}`}>
      <body className="min-h-screen bg-bg font-sans text-ink antialiased">
        {children}
      </body>
    </html>
  );
}
