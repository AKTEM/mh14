import { Header } from '@/components/header';
import { Footer } from '@/components/footer';
import { YouMayHaveMissed } from '@/components/you-may-have-missed';
import { ChevronRight } from 'lucide-react';
import Link from 'next/link';
import { getYouMayHaveMissed } from '@/lib/wordpress';

async function getYouMayHaveMissedData() {
  try {
    const posts = await getYouMayHaveMissed(12);
    return posts;
  } catch (error) {
    console.error('Error fetching You May Have Missed data:', error);
    return [];
  }
}

export default async function YouMayHaveMissedPage() {
  const articles = await getYouMayHaveMissedData();

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
              <span className="text-gray-900 dark:text-white">You May Have Missed</span>
            </nav>
          </div>
        </div>

        {/* Page Header */}
        <div className="bg-gradient-to-r from-amber-600 to-orange-600 text-white py-16">
          <div className="container mx-auto px-4">
            <div className="text-center">
              <h1 className="text-4xl md:text-6xl font-bold mb-4">You May Have Missed</h1>
              <p className="text-xl opacity-90 max-w-2xl mx-auto">
                Catch up on significant news and stories that may have slipped past your radar. 
                Stay informed with these important updates from recent days.
              </p>
            </div>
          </div>
        </div>

        {/* You May Have Missed Content */}
        <div className="container mx-auto px-4 py-12">
          <YouMayHaveMissed articles={articles} />
        </div>
      </main>
      <Footer />
    </div>
  );
}