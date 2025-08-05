import { Header } from '@/components/header';
import { Footer } from '@/components/footer';
import { TheFridayPost } from '@/components/the-friday-post';
import { ChevronRight } from 'lucide-react';
import Link from 'next/link';
import { getTheFridayPost } from '@/lib/wordpress';

async function getTheFridayPostData() {
  try {
    const posts = await getTheFridayPost(12);
    return posts;
  } catch (error) {
    console.error('Error fetching The Friday Post data:', error);
    return [];
  }
}

export default async function TheFridayPostPage() {
  const articles = await getTheFridayPostData();

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
              <span className="text-gray-900 dark:text-white">The Friday Post</span>
            </nav>
          </div>
        </div>

        {/* Page Header */}
        <div className="bg-gradient-to-r from-violet-600 to-purple-600 text-white py-16">
          <div className="container mx-auto px-4">
            <div className="text-center">
              <h1 className="text-4xl md:text-6xl font-bold mb-4">The Friday Post</h1>
              <p className="text-xl opacity-90 max-w-2xl mx-auto">
                Dive deep into Canadian stories with our weekly podcast series. Authentic conversations, 
                expert interviews, and compelling narratives that showcase the Canadian experience.
              </p>
            </div>
          </div>
        </div>

        {/* The Friday Post Content */}
        <div className="container mx-auto px-4 py-12">
          <TheFridayPost articles={articles} />
        </div>
      </main>
      <Footer />
    </div>
  );
}