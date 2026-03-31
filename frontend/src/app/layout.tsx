// -----------------------------------------------------------------------
// app/layout.tsx — Root layout
//
// This wraps every single page in the app. Think of it as the outer shell.
// Anything placed here (nav bars, footers, etc.) would appear on all pages.
//
// For now it just:
//   - Sets the browser tab title and description (used by search engines)
//   - Applies the global CSS (dark background, base font styles)
//   - Renders {children}, which is whatever page the user navigated to
// -----------------------------------------------------------------------

import type { Metadata } from "next";
import "./globals.css";

// Metadata shows up in the browser tab and in Google search results
export const metadata: Metadata = {
  title: "TENEX SOC Analyzer",
  description: "AI-powered ZScaler log analysis for SOC analysts",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    // lang="en" helps screen readers and search engines
    // antialiased makes text look smoother on screens
    <html lang="en" className="h-full antialiased">
      {/* {children} is replaced by whichever page the user is on */}
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
