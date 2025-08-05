import { Header } from '@/components/header';
import { Footer } from '@/components/footer';
import { MapleVoices } from '@/components/maple-voices';
import { ChevronRight } from 'lucide-react';
import Link from 'next/link';
import { getMapleVoices } from '@/lib/wordpress';

async function getMapleVoicesData() {
  try {
    const posts = await getMapleVoices(12);
    return posts;
  } catch (error) {
    console.error('Error fetching Maple Voices data:', error);
    return [];
  }
}

export default async function MapleVoicesPage() {
  const articles = await getMapleVoicesData();

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
              <span className="text-gray-900 dark:text-white">Maple Voices</span>
            </nav>
          </div>
        </div>

        {/* Page Header */}
        <div className="bg-gradient-to-r from-green-600 to-teal-600 text-white py-16">
          <div className="container mx-auto px-4">
            <div className="text-center">
              <h1 className="text-4xl md:text-6xl font-bold mb-4">Maple Voices</h1>
              <p className="text-xl opacity-90 max-w-2xl mx-auto">
                Authentic voices sharing Canadian experiences across travel, food, culture, history, 
                achievements, and arts. Real stories from real Canadians.
              </p>
            </div>
          </div>
        </div>

        {/* Maple Voices Content */}
        <div className="container mx-auto px-4 py-12">
          <MapleVoices articles={articles} />
        </div>
      </main>
      <Footer />
    </div>
  );
}