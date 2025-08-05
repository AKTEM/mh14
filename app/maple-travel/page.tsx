import { Header } from '@/components/header';
import { Footer } from '@/components/footer';
import { MapleTravel } from '@/components/maple-travel';
import { ChevronRight } from 'lucide-react';
import Link from 'next/link';
import { getMapleTravel } from '@/lib/wordpress';

async function getMapleTravelData() {
  try {
    const posts = await getMapleTravel(12);
    return posts;
  } catch (error) {
    console.error('Error fetching Maple Travel data:', error);
    return [];
  }
}

export default async function MapleTravelPage() {
  const articles = await getMapleTravelData();

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
              <span className="text-gray-900 dark:text-white">Maple Travel</span>
            </nav>
          </div>
        </div>

        {/* Page Header */}
        <div className="bg-gradient-to-r from-blue-600 to-green-600 text-white py-16">
          <div className="container mx-auto px-4">
            <div className="text-center">
              <h1 className="text-4xl md:text-6xl font-bold mb-4">Maple Travel</h1>
              <p className="text-xl opacity-90 max-w-2xl mx-auto">
                Discover Canada's breathtaking destinations with expert guides, insider tips, 
                and unforgettable travel experiences from coast to coast to coast.
              </p>
            </div>
          </div>
        </div>

        {/* Maple Travel Content */}
        <div className="container mx-auto px-4 py-12">
          <MapleTravel articles={articles} />
        </div>
      </main>
      <Footer />
    </div>
  );
}