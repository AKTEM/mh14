"use client";

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { Header } from '@/components/header';
import { Footer } from '@/components/footer';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import { 
  Clock, 
  Eye, 
  User, 
  Calendar, 
  Share2, 
  Facebook, 
  Twitter, 
  Linkedin,
  ChevronRight,
  Heart,
  MessageCircle,
  Bookmark,
  Newspaper
} from 'lucide-react';
import { getLatestHeadlines, TransformedPost } from '@/lib/wordpress';
import { CommentsSection } from '@/components/comments-section';

interface ArticleClientPageProps {
  article: any;
}

export function ArticleClientPage({ article }: ArticleClientPageProps) {
  const [isLiked, setIsLiked] = useState(false);
  const [isBookmarked, setIsBookmarked] = useState(false);
  const [latestHeadlines, setLatestHeadlines] = useState<TransformedPost[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    async function fetchLatestHeadlines() {
      try {
        setIsLoading(true);
        const headlines = await getLatestHeadlines(3);
        setLatestHeadlines(headlines);
      } catch (error) {
        console.error('Error fetching latest headlines:', error);
        setLatestHeadlines([]);
      } finally {
        setIsLoading(false);
      }
    }
    fetchLatestHeadlines();
  }, []);

  if (!article) {
    return (
      <div className="min-h-screen bg-white dark:bg-gray-900">
        <Header />
        <main className="pt-32">
          <div className="container mx-auto px-4 py-8">
            <div className="text-center">
              <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">
                Article Not Found
              </h1>
              <p className="text-gray-600 dark:text-gray-300 mb-8">
                The article you're looking for doesn't exist or has been moved.
              </p>
              <Button asChild>
                <Link href="/">Return to Home</Link>
              </Button>
            </div>
          </div>
        </main>
        <Footer />
      </div>
    );
  }

  const publishDate = new Date(article.publishDate);

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
              <span className="text-gray-900 dark:text-white">{article.category}</span>
            </nav>
          </div>
        </div>

        <div className="container mx-auto px-4 py-8">
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
            {/* Main Content */}
            <div className="lg:col-span-3">
              <article className="bg-white dark:bg-gray-800 rounded-xl shadow-lg overflow-hidden">
                {/* Article Header */}
                <div className="relative">
                  <img 
                    src={article.image} 
                    alt={article.title}
                    className="w-full h-64 md:h-80 object-cover"
                  />
                  <div className="absolute inset-0 bg-gradient-to-t from-black/60 to-transparent" />
                  <div className="absolute bottom-6 left-6 right-6">
                    <Badge className="bg-red-600 hover:bg-red-700 text-white mb-4">
                      {article.category}
                    </Badge>
                    <h1 className="text-2xl md:text-4xl font-bold text-white mb-4 leading-tight">
                      {article.title}
                    </h1>
                  </div>
                </div>

                {/* Article Meta */}
                <div className="p-6 border-b border-gray-200 dark:border-gray-700">
                  <div className="flex items-center justify-between flex-wrap gap-4">
                    <div className="flex items-center space-x-4">
                      <div>
                        <div className="font-medium text-gray-900 dark:text-white">
                          {article.author.name}
                        </div>
                        <div className="text-sm text-gray-500 dark:text-gray-400">
                          Writer
                        </div>
                      </div>
                    </div>
                    
                    <div className="flex items-center space-x-4 text-sm text-gray-500 dark:text-gray-400">
                      <div className="flex items-center space-x-1">
                        <Calendar className="w-4 h-4" />
                        <span>{publishDate.toLocaleDateString()}</span>
                      </div>
                      <div className="flex items-center space-x-1">
                        <Clock className="w-4 h-4" />
                        <span>{article.readTime}</span>
                      </div>
                      <div className="flex items-center space-x-1">
                        <Eye className="w-4 h-4" />
                        <span>{article.views}</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Article Content */}
                <div className="p-6">
                  <div 
                    className="wordpress-content prose prose-lg max-w-none dark:prose-invert 
                      prose-headings:text-gray-900 dark:prose-headings:text-white 
                      prose-a:text-red-600 hover:prose-a:text-red-700
                      prose-strong:text-gray-900 dark:prose-strong:text-white
                      prose-p:text-gray-700 dark:prose-p:text-gray-300
                      prose-p:leading-relaxed prose-p:mb-4
                      prose-ul:text-gray-700 dark:prose-ul:text-gray-300
                      prose-ol:text-gray-700 dark:prose-ol:text-gray-300
                      prose-blockquote:text-gray-600 dark:prose-blockquote:text-gray-400
                      prose-blockquote:border-red-500"
                    dangerouslySetInnerHTML={{ __html: article.content }}
                  />
                </div>

                {/* Article Tags */}
                <div className="p-6 border-t border-gray-200 dark:border-gray-700">
                  <div className="flex flex-wrap gap-2 mb-6">
                    {article.tags.map((tag: string) => (
                      <Badge key={tag} variant="secondary" className="hover:bg-red-50 hover:text-red-600 cursor-pointer">
                        {tag}
                      </Badge>
                    ))}
                  </div>

                  {/* Article Actions */}
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4">
                      {/* <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setIsLiked(!isLiked)}
                        className={`${isLiked ? 'text-red-600 border-red-600' : ''}`}
                      >
                        <Heart className={`w-4 h-4 mr-2 ${isLiked ? 'fill-current' : ''}`} />
                        {article.likes + (isLiked ? 1 : 0)}
                      </Button>
                      
                      <Button variant="outline" size="sm">
                        <MessageCircle className="w-4 h-4 mr-2" />
                        {article.comments}
                      </Button> */}
                      
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setIsBookmarked(!isBookmarked)}
                        className={`${isBookmarked ? 'text-red-600 border-red-600' : ''}`}
                      >
                        <Bookmark className={`w-4 h-4 mr-2 ${isBookmarked ? 'fill-current' : ''}`} />
                        Save
                      </Button>
                    </div>

                    <div className="flex items-center space-x-2">
                      <span className="text-sm text-gray-500 dark:text-gray-400 mr-2">Share:</span>
                      <Button variant="outline" size="sm">
                        <Facebook className="w-4 h-4" />
                      </Button>
                      <Button variant="outline" size="sm">
                        <Twitter className="w-4 h-4" />
                      </Button>
                      <Button variant="outline" size="sm">
                        <Linkedin className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>
                </div>

                {/* Author Bio */}
                <div className="p-6 bg-gray-50 dark:bg-gray-700 border-t border-gray-200 dark:border-gray-700">
                  <div className="flex items-start space-x-4">
                    <div>
                      <h3 className="font-bold text-gray-900 dark:text-white mb-2">
                        About {article.author.name}
                      </h3>
                      <p className="text-gray-600 dark:text-gray-300 text-sm">
                        {article.author.bio}
                      </p>
                    </div>
                  </div>
                </div>
              </article>
            </div>

            {/* Sidebar */}
            <div className="lg:col-span-1">
              <div className="sticky top-32 space-y-6">
                {/* Latest Headlines */}
                <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6">
                  <div className="flex items-center space-x-2 mb-4">
                    <Newspaper className="w-5 h-5 text-red-600" />
                    <h3 className="text-lg font-bold text-gray-900 dark:text-white">
                      Latest Headlines
                    </h3>
                  </div>
                  
                  {isLoading ? (
                    <div className="space-y-4">
                      {[1, 2, 3].map((i) => (
                        <div key={i} className="animate-pulse">
                          <div className="aspect-video bg-gray-200 dark:bg-gray-700 rounded-lg mb-2"></div>
                          <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded mb-2"></div>
                          <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-3/4"></div>
                        </div>
                      ))}
                    </div>
                  ) : latestHeadlines.length > 0 ? (
                    <div className="space-y-4">
                      {latestHeadlines.map((headline) => (
                        <div key={headline.id} className="group">
                          <Link href={`/article/${headline.id}`} className="block">
                            <div className="aspect-video relative mb-2 rounded-lg overflow-hidden">
                              <img 
                                src={headline.image} 
                                alt={headline.title}
                                className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
                              />
                            </div>
                            <Badge variant="secondary" className="mb-2 text-xs">
                              {headline.category}
                            </Badge>
                            <h4 className="font-medium text-sm text-gray-900 dark:text-white group-hover:text-red-600 transition-colors line-clamp-2 mb-1">
                              {headline.title}
                            </h4>
                            <p className="text-xs text-gray-600 dark:text-gray-400">
                              {headline.author} • {headline.readTime}
                            </p>
                          </Link>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-8">
                      <Newspaper className="w-12 h-12 text-gray-300 dark:text-gray-600 mx-auto mb-3" />
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        No headlines available
                      </p>
                    </div>
                  )}
                </div>

                {/* Advertisement Space */}
                <div className="bg-gray-100 dark:bg-gray-800 rounded-xl p-6 text-center">
                  <p className="text-gray-500 dark:text-gray-400 text-sm">Advertisement</p>
                  <div className="mt-4 h-48 bg-gray-200 dark:bg-gray-700 rounded-lg flex items-center justify-center">
                    <span className="text-gray-400 dark:text-gray-500">Ad Space</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Comments Section */}
        <div className="container mx-auto px-4 pb-8">
          <CommentsSection articleId={article.id} />
        </div>
      </main>
      <Footer />
    </div>
  );
}