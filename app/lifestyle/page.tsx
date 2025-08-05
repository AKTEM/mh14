import { Header } from '@/components/header';
import { Footer } from '@/components/footer';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Clock, Eye, User, TrendingUp, ChevronRight } from 'lucide-react';
import Link from 'next/link';
import { getLifestyle, fallbackPosts } from '@/lib/wordpress';

async function getLifestyleData() {
  try {
    const posts = await getLifestyle(12);
    return posts.length > 0 ? posts : fallbackPosts.filter(post => 
      post.category.toLowerCase() === 'lifestyle'
    ).slice(0, 12);
  } catch (error) {
    console.error('Error fetching lifestyle data:', error);
    return fallbackPosts.filter(post => 
      post.category.toLowerCase() === 'lifestyle'
    ).slice(0, 12);
  }
}

export default async function LifestylePage() {
  const articles = await getLifestyleData();

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
              <span className="text-gray-900 dark:text-white">Lifestyle</span>
            </nav>
          </div>
        </div>

        {/* Page Header */}
        <div className="bg-gradient-to-r from-pink-600 to-rose-600 text-white py-16">
          <div className="container mx-auto px-4">
            <div className="text-center">
              <h1 className="text-4xl md:text-6xl font-bold mb-4">Lifestyle</h1>
              <p className="text-xl opacity-90 max-w-2xl mx-auto">
                Discover the latest trends in lifestyle, wellness, fashion, food, and culture. 
                Your guide to living well and staying inspired.
              </p>
            </div>
          </div>
        </div>

        {/* Articles Grid */}
        <div className="container mx-auto px-4 py-12">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {articles.map((article) => (
              <div 
                key={article.id}
                className="group bg-white dark:bg-gray-800 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300 transform hover:scale-[1.02] overflow-hidden"
              >
                <div className="aspect-video relative">
                  <img 
                    src={article.image} 
                    alt={article.title}
                    className="w-full h-full object-cover group-hover:scale-110 transition-transform duration-300"
                  />
                  <div className="absolute inset-0 bg-gradient-to-t from-black/60 to-transparent" />
                  
                  <div className="absolute top-3 left-3 flex space-x-2">
                    <Badge className="bg-pink-600 hover:bg-pink-700 text-white">
                      LIFESTYLE
                    </Badge>
                    {article.isTrending && (
                      <Badge className="bg-rose-500 hover:bg-rose-600 text-white">
                        <TrendingUp className="w-3 h-3 mr-1" />
                        TRENDING
                      </Badge>
                    )}
                  </div>
                </div>
                
                <div className="p-6">
                  <h3 className="font-bold text-lg mb-3 text-gray-900 dark:text-white group-hover:text-pink-600 transition-colors line-clamp-2">
                    <Link href={`/article/${article.id}`}>
                      {article.title}
                    </Link>
                  </h3>
                  <p className="text-gray-600 dark:text-gray-300 text-sm mb-4 line-clamp-3">
                    {article.excerpt}
                  </p>
                  
                  <div className="flex items-center justify-between text-xs text-gray-500 dark:text-gray-400 mb-4">
                    <div className="flex items-center space-x-3">
                      <div className="flex items-center space-x-1">
                        <User className="w-3 h-3" />
                        <span>{article.author}</span>
                      </div>
                      <div className="flex items-center space-x-1">
                        <Clock className="w-3 h-3" />
                        <span>{article.readTime}</span>
                      </div>
                    </div>
                    <div className="flex items-center space-x-1">
                      <Eye className="w-3 h-3" />
                      <span>{article.views}</span>
                    </div>
                  </div>
                  
                  <Button 
                    asChild
                    variant="outline"
                    className="w-full border-pink-200 text-pink-600 hover:bg-pink-50 hover:border-pink-300 dark:border-pink-800 dark:text-pink-400 dark:hover:bg-pink-950"
                  >
                    <Link href={`/article/${article.id}`}>
                      Read Full Story
                    </Link>
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </main>
      <Footer />
    </div>
  );
}