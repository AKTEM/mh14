import { Header } from '@/components/header';
import { Footer } from '@/components/footer';
import { BookNook } from '@/components/booknook';
import { ChevronRight } from 'lucide-react';
import Link from 'next/link';
import { getBookNook } from '@/lib/wordpress';

async function getBookNookData() {
  try {
    const posts = await getBookNook(12);
    return posts;
  } catch (error) {
    console.error('Error fetching BookNook data:', error);
    return [];
  }
}

export default async function BookNookPage() {
  const articles = await getBookNookData();

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
              <span className="text-gray-900 dark:text-white">BookNook</span>
            </nav>
          </div>
        </div>

        {/* Page Header */}
        <div className="bg-gradient-to-r from-amber-600 to-yellow-600 text-white py-16">
          <div className="container mx-auto px-4">
            <div className="text-center">
              <h1 className="text-4xl md:text-6xl font-bold mb-4">BookNook</h1>
              <p className="text-xl opacity-90 max-w-2xl mx-auto">
                Discover your next great read with our curated book reviews, author interviews, 
                and literary insights from Canadian and international authors.
              </p>
            </div>
          </div>
        </div>

        {/* BookNook Content */}
        <div className="container mx-auto px-4 py-12">
          <BookNook articles={articles} />
        </div>
      </main>
      <Footer />
    </div>
  );
}