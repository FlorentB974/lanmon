import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "LAN Monitor",
  description: "Network device monitoring application",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="bg-surface-900 text-white antialiased">
        {children}
      </body>
    </html>
  );
}
