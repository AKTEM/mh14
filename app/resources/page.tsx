import { Header } from '@/components/header';
import { Footer } from '@/components/footer';
import { Resources } from '@/components/resources';
import { ChevronRight } from 'lucide-react';
import Link from 'next/link';
import { getResources } from '@/lib/wordpress';

async function getResourcesData() {
  try {
    const posts = await getResources(12);
    return posts;
  } catch (error) {
    console.error('Error fetching Resources data:', error);
    return [];
  }
}

export default async function ResourcesPage() {
  const articles = await getResourcesData();

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
              <span className="text-gray-900 dark:text-white">Resources</span>
            </nav>
          </div>
        </div>

        {/* Page Header */}
        <div className="bg-gradient-to-r from-slate-600 to-gray-600 text-white py-16">
          <div className="container mx-auto px-4">
            <div className="text-center">
              <h1 className="text-4xl md:text-6xl font-bold mb-4">Resources</h1>
              <p className="text-xl opacity-90 max-w-2xl mx-auto">
                Comprehensive resources covering Canadian history, culture, and travel. 
                Essential guides and references for understanding Canada's rich heritage.
              </p>
            </div>
          </div>
        </div>

        {/* Resources Content */}
        <div className="container mx-auto px-4 py-12">
          <Resources articles={articles} />
        </div>
      </main>
      <Footer />
    </div>
  );
}