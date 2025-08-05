import Link from 'next/link';
import { Header } from '@/components/header';
import { Footer } from '@/components/footer';
import { Button } from '@/components/ui/button';
import { Home, Search, ArrowLeft } from 'lucide-react';

export default function NotFound() {
  return (
    <div className="min-h-screen bg-white dark:bg-gray-900">
      <Header />
      <main className="pt-32">
        <div className="container mx-auto px-4 py-16">
          <div className="text-center max-w-2xl mx-auto">
            <div className="mb-8">
              <h1 className="text-6xl font-bold text-red-600 mb-4">404</h1>
              <h2 className="text-3xl font-bold text-gray-900 dark:text-white mb-4">
                Article Not Found
              </h2>
              <p className="text-lg text-gray-600 dark:text-gray-300 mb-8">
                The article you're looking for doesn't exist or may have been moved. 
                Don't worry, there's plenty of other great content to explore!
              </p>
            </div>

            <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
              <Button asChild size="lg" className="bg-red-600 hover:bg-red-700">
                <Link href="/" className="flex items-center space-x-2">
                  <Home className="w-5 h-5" />
                  <span>Back to Home</span>
                </Link>
              </Button>
              
              <Button asChild variant="outline" size="lg">
                <Link href="/search" className="flex items-center space-x-2">
                  <Search className="w-5 h-5" />
                  <span>Search Articles</span>
                </Link>
              </Button>
            </div>

            <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-6">
              <Link href="/politics" className="group p-6 bg-gray-50 dark:bg-gray-800 rounded-xl hover:bg-red-50 dark:hover:bg-red-950 transition-colors">
                <h3 className="font-semibold text-gray-900 dark:text-white group-hover:text-red-600 mb-2">
                  Politics
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-300">
                  Latest political news and government updates
                </p>
              </Link>
              
              <Link href="/business" className="group p-6 bg-gray-50 dark:bg-gray-800 rounded-xl hover:bg-red-50 dark:hover:bg-red-950 transition-colors">
                <h3 className="font-semibold text-gray-900 dark:text-white group-hover:text-red-600 mb-2">
                  Business
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-300">
                  Market insights and economic analysis
                </p>
              </Link>
              
              <Link href="/technology" className="group p-6 bg-gray-50 dark:bg-gray-800 rounded-xl hover:bg-red-50 dark:hover:bg-red-950 transition-colors">
                <h3 className="font-semibold text-gray-900 dark:text-white group-hover:text-red-600 mb-2">
                  Technology
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-300">
                  Tech innovations and digital trends
                </p>
              </Link>
            </div>
          </div>
        </div>
      </main>
      <Footer />
    </div>
  );
}