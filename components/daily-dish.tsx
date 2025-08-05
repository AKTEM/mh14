"use client";

import Link from 'next/link';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Coffee, Clock, Eye, User } from 'lucide-react';

const dailyDishArticles = [
  {
    id: 1,
    title: "Morning Brew: What's Trending in Business Today",
    excerpt: "Your daily dose of the most important business news and market insights to start your day informed.",
    category: "Business",
    image: "https://images.pexels.com/photos/3184292/pexels-photo-3184292.jpeg?auto=compress&cs=tinysrgb&w=400",
    author: "Alex Thompson",
    readTime: "5 min read",
    views: "2.7k views",
    isToday: true
  },
  {
    id: 2,
    title: "Tech Talk: The Latest Innovations Changing Our World",
    excerpt: "Discover the cutting-edge technologies and innovations that are shaping our future.",
    category: "Technology",
    image: "https://images.pexels.com/photos/3861972/pexels-photo-3861972.jpeg?auto=compress&cs=tinysrgb&w=400",
    author: "Jennifer Kim",
    readTime: "7 min read",
    views: "3.1k views"
  },
  {
    id: 3,
    title: "Culture Corner: Arts and Entertainment Highlights",
    excerpt: "Explore the latest happenings in arts, culture, and entertainment from around the globe.",
    category: "Entertainment",
    image: "https://images.pexels.com/photos/7991579/pexels-photo-7991579.jpeg?auto=compress&cs=tinysrgb&w=400",
    author: "Michael Rodriguez",
    readTime: "6 min read",
    views: "1.9k views"
  }
];

export function DailyDish() {
  return (
    <section className="space-y-8">
      <div className="flex items-center space-x-3">
        <Coffee className="w-8 h-8 text-red-600" />
        <h2 className="text-3xl font-bold text-gray-900 dark:text-white">
          Daily Dish
        </h2>
        <div className="flex-1 h-1 bg-red-600 rounded-full ml-4"></div>
      </div>

      <div className="bg-gradient-to-r from-red-50 to-orange-50 dark:from-red-950 dark:to-orange-950 rounded-xl p-6 mb-8">
        <div className="text-center">
          <Coffee className="w-12 h-12 text-red-600 mx-auto mb-3" />
          <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-2">
            Your Daily News Brew
          </h3>
          <p className="text-gray-600 dark:text-gray-300 max-w-2xl mx-auto">
            Start your day with our carefully curated selection of the most important stories, 
            served fresh every morning with expert analysis and insights.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {dailyDishArticles.map((article) => (
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
              
              {/* Coffee Badge */}
              <div className="absolute top-3 left-3 flex space-x-2">
                <Badge className="bg-red-600 hover:bg-red-700 text-white">
                  <Coffee className="w-3 h-3 mr-1" />
                  DAILY DISH
                </Badge>
                {article.isToday && (
                  <Badge className="bg-orange-500 hover:bg-orange-600 text-white">
                    TODAY
                  </Badge>
                )}
                <Badge variant="secondary" className="bg-white/90 text-gray-900 hover:bg-white text-xs">
                  {article.category}
                </Badge>
              </div>
            </div>
            
            <div className="p-6">
              <h3 className="font-bold text-lg mb-3 text-gray-900 dark:text-white group-hover:text-red-600 transition-colors line-clamp-2">
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
                className="w-full border-red-200 text-red-600 hover:bg-red-50 hover:border-red-300 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
              >
                <Link href={`/article/${article.id}`}>
                  Read Today's Dish
                </Link>
              </Button>
            </div>
          </div>
        ))}
      </div>
      
      <div className="text-center">
        <Button 
          asChild
          size="lg"
          className="bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 text-white px-8 py-3"
        >
          <Link href="/daily-dish">
            View All Daily Dishes
          </Link>
        </Button>
      </div>
    </section>
  );
}