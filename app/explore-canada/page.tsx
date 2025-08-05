import { Header } from '@/components/header';
import { Footer } from '@/components/footer';
import { ExploreCanada } from '@/components/explore-canada';
import { ChevronRight } from 'lucide-react';
import Link from 'next/link';
import { getExploreCanada } from '@/lib/wordpress';

async function getExploreCandaData() {
  try {
    const posts = await getExploreCanada(12);
    return posts;
  } catch (error) {
    console.error('Error fetching Explore Canada data:', error);
    return [];
  }
}

export default async function ExploreCandaPage() {
  const articles = await getExploreCandaData();

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
              <span className="text-gray-900 dark:text-white">Explore Canada</span>
            </nav>
          </div>
        </div>

        {/* Page Header */}
        <div className="bg-gradient-to-r from-indigo-600 to-cyan-600 text-white py-16">
          <div className="container mx-auto px-4">
            <div className="text-center">
              <h1 className="text-4xl md:text-6xl font-bold mb-4">Explore Canada</h1>
              <p className="text-xl opacity-90 max-w-2xl mx-auto">
                Uncover Canada's most spectacular destinations, from hidden gems off the beaten path 
                to iconic landmarks that define our nation's natural beauty.
              </p>
            </div>
          </div>
        </div>

        {/* Explore Canada Content */}
        <div className="container mx-auto px-4 py-12">
          <ExploreCanada articles={articles} />
        </div>
      </main>
      <Footer />
    </div>
  );
}