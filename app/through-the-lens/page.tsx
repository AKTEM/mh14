import { Header } from '@/components/header';
import { Footer } from '@/components/footer';
import { ThroughTheLens } from '@/components/through-the-lens';
import { ChevronRight } from 'lucide-react';
import Link from 'next/link';
import { getThroughTheLens } from '@/lib/wordpress';

async function getThroughTheLensData() {
  try {
    const posts = await getThroughTheLens(12);
    return posts;
  } catch (error) {
    console.error('Error fetching Through the Lens data:', error);
    return [];
  }
}

export default async function ThroughTheLensPage() {
  const articles = await getThroughTheLensData();

  return (
    <div className="min-h-screen bg-white dark:bg-gray-900">
      <Header />
      <main className="pt-32">
        {/* Breadcrumb */}
        <div className="bg-gray-50 dark:bg-gray-800 py-4">
          <div className="container mx-auto px-4">
            <nav className="flex items-center space-x-2 text-sm text-gray-600 dark:text-gray-400">
              <Link href="/" className="hover:text-red-600 transition-colors">Home</Link>
              <ChevronRight className="w-4 h-4" />
              <span className="text-gray-900 dark:text-white">Through the Lens</span>
            </nav>
          </div>
        </div>

        {/* Page Header */}
        <div className="bg-gradient-to-r from-purple-600 to-pink-600 text-white py-16">
          <div className="container mx-auto px-4">
            <div className="text-center">
              <h1 className="text-4xl md:text-6xl font-bold mb-4">Through the Lens</h1>
              <p className="text-xl opacity-90 max-w-2xl mx-auto">
                Professional photography insights, local secrets, and seasonal guides to help you 
                capture the essence of Canada through your lens.
              </p>
            </div>
          </div>
        </div>

        {/* Through the Lens Content */}
        <div className="container mx-auto px-4 py-12">
          <ThroughTheLens articles={articles} />
        </div>
      </main>
      <Footer />
    </div>
  );
}