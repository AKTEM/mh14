import { Header } from '@/components/header';
import { Footer } from '@/components/footer';
import { Events } from '@/components/events';
import { ChevronRight } from 'lucide-react';
import Link from 'next/link';
import { getEvents } from '@/lib/wordpress';

async function getEventsData() {
  try {
    const posts = await getEvents(12);
    return posts;
  } catch (error) {
    console.error('Error fetching Events data:', error);
    return [];
  }
}

export default async function EventsPage() {
  const articles = await getEventsData();

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
              <span className="text-gray-900 dark:text-white">Events</span>
            </nav>
          </div>
        </div>

        {/* Page Header */}
        <div className="bg-gradient-to-r from-rose-600 to-pink-600 text-white py-16">
          <div className="container mx-auto px-4">
            <div className="text-center">
              <h1 className="text-4xl md:text-6xl font-bold mb-4">Events</h1>
              <p className="text-xl opacity-90 max-w-2xl mx-auto">
                Discover festivals, conferences, and cultural events happening across Canada. 
                From coast to coast celebrations that showcase our nation's vibrant spirit.
              </p>
            </div>
          </div>
        </div>

        {/* Events Content */}
        <div className="container mx-auto px-4 py-12">
          <Events articles={articles} />
        </div>
      </main>
      <Footer />
    </div>
  );
}