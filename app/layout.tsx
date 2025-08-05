import './globals.css';
import type { Metadata } from 'next';
import { Providers } from './providers';
import { Toaster } from '@/components/ui/sonner';
import { Suspense } from 'react';

export const metadata: Metadata = {
  title: 'The Maple Epoch - Breaking News & Latest Updates',
  description: 'Stay informed with real-time coverage of breaking news, politics, business, technology, health, sports, and entertainment.',
  keywords: 'news, breaking news, politics, business, technology, health, sports, entertainment, world news',
  authors: [{ name: 'The Maple Epoch Editorial Team' }],
  creator: 'The Maple Epoch',
  publisher: 'The Maple Epoch',
  openGraph: {
    title: 'The Maple Epoch - Breaking News & Latest Updates',
    description: 'Stay informed with real-time coverage of breaking news, politics, business, technology, health, sports, and entertainment.',
    url: 'https://mapleepoch.com',
    siteName: 'The Maple Epoch',
    images: [
      {
        url: '/og-image.jpg',
        width: 1200,
        height: 630,
        alt: 'The Maple Epoch News',
      },
    ],
    locale: 'en_US',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'The Maple Epoch - Breaking News & Latest Updates',
    description: 'Stay informed with real-time coverage of breaking news, politics, business, technology, health, sports, and entertainment.',
    images: ['/og-image.jpg'],
  },
  viewport: {
    width: 'device-width',
    initialScale: 1,
    maximumScale: 1,
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="font-sans">
        <Providers>
          <Suspense fallback={
            <div className="min-h-screen bg-white dark:bg-gray-900 flex items-center justify-center">
              <div className="text-center">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto mb-4"></div>
                <p className="text-gray-600 dark:text-gray-300">Loading...</p>
              </div>
            </div>
          }>
            {children}
          </Suspense>
          <Toaster />
        </Providers>
      </body>
    </html>
  );
}