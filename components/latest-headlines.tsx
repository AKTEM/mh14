"use client";

import Link from 'next/link';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Clock, Eye, User, TrendingUp, Newspaper } from 'lucide-react';
import { TransformedPost } from '@/lib/wordpress';

interface LatestHeadlinesProps {
  articles: TransformedPost[];
}

export function LatestHeadlines({ articles }: LatestHeadlinesProps) {
  const displayedArticles = articles.slice(0, 3);

  return (
    <section className="space-y-8">
      <div className="flex items-center space-x-3">
        <Newspaper className="w-8 h-8 text-red-600" />
        <h2 className="text-3xl font-bold text-gray-900 dark:text-white">
          Latest Headlines
        </h2>
        <div className="flex-1 h-1 bg-red-600 rounded-full ml-4"></div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {displayedArticles.map((article) => (
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
              
              {/* Badges */}
              <div className="absolute top-3 left-3 flex space-x-2">
                {article.isTrending && (
                  <Badge className="bg-red-600 hover:bg-red-700 text-white">
                    <TrendingUp className="w-3 h-3 mr-1" />
                    TRENDING
                  </Badge>
                )}
                <Badge variant="secondary" className="bg-white/90 text-gray-900 hover:bg-white text-xs">
                  {article.category}
                </Badge>
              </div>
            </div>
            
            <div className="p-5">
              <h3 className="font-bold text-lg mb-3 text-gray-900 dark:text-white group-hover:text-red-600 transition-colors line-clamp-2">
                <Link href={`/article/${article.id}`}>
                  {article.title}
                </Link>
              </h3>
              <p className="text-gray-600 dark:text-gray-300 text-sm mb-4 line-clamp-2">
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
                className="w-full border-red-200 text-red-600 hover:bg-red-50 hover:border-red-300 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
              >
                <Link href={`/article/${article.id}`}>
                  Read Full Story
                </Link>
              </Button>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}