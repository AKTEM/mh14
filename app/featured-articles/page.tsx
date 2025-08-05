import { Header } from '@/components/header';
import { Footer } from '@/components/footer';
import { FeaturedArticles } from '@/components/featured-articles';
import { ChevronRight } from 'lucide-react';
import Link from 'next/link';
import { getFeaturedArticles } from '@/lib/wordpress';

async function getFeaturedArticlesData() {
  try {
    const posts = await getFeaturedArticles(12);
    return posts;
  } catch (error) {
    console.error('Error fetching Featured Articles data:', error);
    return [];
  }
}

export default async function FeaturedArticlesPage() {
  const articles = await getFeaturedArticlesData();

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
              <span className="text-gray-900 dark:text-white">Featured Articles</span>
            </nav>
          </div>
        </div>

        {/* Page Header */}
        <div className="bg-gradient-to-r from-amber-600 to-yellow-600 text-white py-16">
          <div className="container mx-auto px-4">
            <div className="text-center">
              <h1 className="text-4xl md:text-6xl font-bold mb-4">Featured Articles</h1>
              <p className="text-xl opacity-90 max-w-2xl mx-auto">
                Comprehensive analysis and thoughtful commentary on Canadian culture, history, and current events 
                that shape our nation's identity and future.
              </p>
            </div>
          </div>
        </div>

        {/* Featured Articles Content */}
        <div className="container mx-auto px-4 py-12">
          <FeaturedArticles articles={articles} />
        </div>
      </main>
      <Footer />
    </div>
  );
}