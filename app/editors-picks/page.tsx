import { Header } from '@/components/header';
import { Footer } from '@/components/footer';
import { EditorsPicks } from '@/components/editors-picks';
import { ChevronRight } from 'lucide-react';
import Link from 'next/link';
import { getEditorsPicks } from '@/lib/wordpress';

async function getEditorsPicksData() {
  try {
    const posts = await getEditorsPicks(12);
    return posts;
  } catch (error) {
    console.error('Error fetching Editor\'s Picks data:', error);
    return [];
  }
}

export default async function EditorsPicksPage() {
  const articles = await getEditorsPicksData();

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
              <span className="text-gray-900 dark:text-white">Editor's Picks</span>
            </nav>
          </div>
        </div>

        {/* Page Header */}
        <div className="bg-gradient-to-r from-red-600 to-red-700 text-white py-16">
          <div className="container mx-auto px-4">
            <div className="text-center">
              <h1 className="text-4xl md:text-6xl font-bold mb-4">Editor's Picks</h1>
              <p className="text-xl opacity-90 max-w-2xl mx-auto">
                Curated stories from our editorial team. Hand-picked articles that showcase 
                the most important and compelling news of the day.
              </p>
            </div>
          </div>
        </div>

        {/* Editor's Picks Content */}
        <div className="container mx-auto px-4 py-12">
          <EditorsPicks articles={articles} />
        </div>
      </main>
      <Footer />
    </div>
  );
}