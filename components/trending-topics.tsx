"use client";

import Link from 'next/link';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { TrendingUp, ArrowRight, Hash } from 'lucide-react';

const trendingTopics = [
  {
    id: 1,
    topic: "#EconomicPolicy",
    count: "12.5k posts",
    description: "Federal Reserve policy changes spark global discussion",
    category: "Politics",
    trend: "+45%"
  },
  {
    id: 2,
    topic: "#AIRevolution",
    count: "8.9k posts",
    description: "Artificial intelligence breakthroughs dominate tech news",
    category: "Technology",
    trend: "+32%"
  },
  {
    id: 3,
    topic: "#ClimateAction",
    count: "7.2k posts",
    description: "International climate summit reaches historic agreements",
    category: "Environment",
    trend: "+28%"
  },
  {
    id: 4,
    topic: "#HealthTech",
    count: "5.8k posts",
    description: "Medical technology innovations transform healthcare",
    category: "Health",
    trend: "+22%"
  },
  {
    id: 5,
    topic: "#GlobalMarkets",
    count: "4.6k posts",
    description: "International markets respond to economic developments",
    category: "Business",
    trend: "+18%"
  },
  {
    id: 6,
    topic: "#SpaceExploration",
    count: "3.9k posts",
    description: "New discoveries expand our understanding of the universe",
    category: "Science",
    trend: "+15%"
  }
];

export function TrendingTopics() {
  return (
    <section className="space-y-8">
      <div className="flex items-center space-x-3">
        <TrendingUp className="w-8 h-8 text-red-600" />
        <h2 className="text-3xl font-bold text-gray-900 dark:text-white">
          Trending Topics
        </h2>
        <div className="flex-1 h-1 bg-red-600 rounded-full ml-4"></div>
      </div>

      <div className="bg-gradient-to-r from-red-50 to-orange-50 dark:from-red-950 dark:to-orange-950 rounded-xl p-6 mb-8">
        <div className="text-center">
          <Hash className="w-12 h-12 text-red-600 mx-auto mb-3" />
          <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-2">
            What's Trending Now
          </h3>
          <p className="text-gray-600 dark:text-gray-300 max-w-2xl mx-auto">
            Discover the most discussed topics and trending conversations across all news categories.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-2 gap-6">
        {trendingTopics.map((topic) => (
          <div 
            key={topic.id}
            className="group bg-white dark:bg-gray-800 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300 transform hover:scale-[1.02] overflow-hidden border border-gray-100 dark:border-gray-700"
          >
            <div className="p-6">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center space-x-2">
                  <Hash className="w-5 h-5 text-red-600" />
                  <span className="font-bold text-lg text-red-600 group-hover:text-red-700 transition-colors">
                    {topic.topic.replace('#', '')}
                  </span>
                </div>
                <div className="flex items-center space-x-1 text-green-600 text-sm font-medium">
                  <TrendingUp className="w-4 h-4" />
                  <span>{topic.trend}</span>
                </div>
              </div>
              
              <p className="text-gray-600 dark:text-gray-300 text-sm mb-4 line-clamp-2">
                {topic.description}
              </p>
              
              <div className="flex items-center justify-between mb-4">
                <Badge variant="secondary" className="text-xs">
                  {topic.category}
                </Badge>
                <span className="text-xs text-gray-500 dark:text-gray-400 font-medium">
                  {topic.count}
                </span>
              </div>
              
              <Button 
                asChild
                variant="outline"
                className="w-full border-red-200 text-red-600 hover:bg-red-50 hover:border-red-300 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950 group"
              >
                <Link href={`/topic/${topic.topic.replace('#', '').toLowerCase()}`} className="flex items-center justify-center space-x-2">
                  <span>Explore Topic</span>
                  <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
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
          <Link href="/trending">
            View All Trending Topics
          </Link>
        </Button>
      </div>
    </section>
  );
}