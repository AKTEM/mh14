import { Header } from '@/components/header';
import { Footer } from '@/components/footer';
import { DailyMaple } from '@/components/daily-maple';
import { ChevronRight } from 'lucide-react';
import Link from 'next/link';
import { getDailyMaple } from '@/lib/wordpress';

async function getDailyMapleData() {
  try {
    const posts = await getDailyMaple(12);
    return posts;
  } catch (error) {
    console.error('Error fetching Daily Maple data:', error);
    return [];
  }
}

export default async function DailyMaplePage() {
  const articles = await getDailyMapleData();

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
              <span className="text-gray-900 dark:text-white">Daily Maple</span>
            </nav>
          </div>
        </div>

        {/* Page Header */}
        <div className="bg-gradient-to-r from-red-600 to-orange-600 text-white py-16">
          <div className="container mx-auto px-4">
            <div className="text-center">
              <h1 className="text-4xl md:text-6xl font-bold mb-4">Daily Maple</h1>
              <p className="text-xl opacity-90 max-w-2xl mx-auto">
                Your daily dose of Canadian news and insights. Start your day with the most 
                important Canadian stories, from coast to coast to coast.
              </p>
            </div>
          </div>
        </div>

        {/* Daily Maple Content */}
        <div className="container mx-auto px-4 py-12">
          <DailyMaple articles={articles} />
        </div>
      </main>
      <Footer />
    </div>
  );
}