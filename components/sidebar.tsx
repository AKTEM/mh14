"use client";

import { useState } from 'react';
import Link from 'next/link';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { TrendingUp, Eye, Mail, Facebook, Twitter, Instagram, Youtube, Linkedin } from 'lucide-react';

const trendingArticles = [
  {
    id: 1,
    title: "Economic Policy Changes Impact Global Markets",
    views: "12.5k views",
    rank: 1
  },
  {
    id: 2,
    title: "Technology Giants Report Record Earnings",
    views: "8.3k views",
    rank: 2
  },
  {
    id: 3,
    title: "Climate Summit Reaches Historic Agreement",
    views: "7.1k views",
    rank: 3
  },
  {
    id: 4,
    title: "Sports Championship Finals This Weekend",
    views: "6.8k views",
    rank: 4
  },
  {
    id: 5,
    title: "Healthcare Innovation Breakthrough",
    views: "5.4k views",
    rank: 5
  }
];

const mostReadArticles = [
  {
    id: 1,
    title: "Breaking: Federal Reserve Announces Rate Changes",
    category: "Business",
    views: "25.7k views"
  },
  {
    id: 2,
    title: "AI Revolution Transforms Medical Diagnosis",
    category: "Technology",
    views: "18.9k views"
  },
  {
    id: 3,
    title: "International Trade War Escalates",
    category: "Politics",
    views: "15.2k views"
  },
  {
    id: 4,
    title: "Space Mission Discovers New Planets",
    category: "Science",
    views: "12.8k views"
  },
  {
    id: 5,
    title: "Entertainment Industry Merger Announced",
    category: "Entertainment",
    views: "10.5k views"
  }
];

export function Sidebar() {
  const [email, setEmail] = useState('');

  const handleNewsletterSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Handle newsletter subscription
    console.log('Newsletter subscription:', email);
    setEmail('');
  };

  return (
    <div className="space-y-8">
      {/* Trending Now */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6">
        <div className="flex items-center space-x-2 mb-6">
          <TrendingUp className="w-5 h-5 text-red-600" />
          <h3 className="text-xl font-bold text-gray-900 dark:text-white">Trending Now</h3>
        </div>
        
        <div className="space-y-4">
          {trendingArticles.map((article) => (
            <div key={article.id} className="flex items-start space-x-3 group">
              <div className="flex-shrink-0 w-8 h-8 bg-red-600 text-white rounded-full flex items-center justify-center text-sm font-bold">
                {article.rank}
              </div>
              <div className="flex-1 min-w-0">
                <Link href={`/article/${article.id}`} className="block">
                  <h4 className="text-sm font-medium text-gray-900 dark:text-white group-hover:text-red-600 transition-colors line-clamp-2">
                    {article.title}
                  </h4>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                    {article.views}
                  </p>
                </Link>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Most Read */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6">
        <div className="flex items-center space-x-2 mb-6">
          <Eye className="w-5 h-5 text-red-600" />
          <h3 className="text-xl font-bold text-gray-900 dark:text-white">Most Read</h3>
        </div>
        
        <div className="space-y-4">
          {mostReadArticles.map((article) => (
            <div key={article.id} className="group pb-4 border-b border-gray-200 dark:border-gray-700 last:border-b-0 last:pb-0">
              <Link href={`/article/${article.id}`} className="block">
                <h4 className="text-sm font-medium text-gray-900 dark:text-white group-hover:text-red-600 transition-colors line-clamp-2 mb-2">
                  {article.title}
                </h4>
                <div className="flex items-center justify-between">
                  <Badge variant="secondary" className="text-xs">
                    {article.category}
                  </Badge>
                  <span className="text-xs text-gray-500 dark:text-gray-400">
                    {article.views}
                  </span>
                </div>
              </Link>
            </div>
          ))}
        </div>
      </div>

      {/* Social Media */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6">
        <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-6">
          Follow Us
        </h3>
        
        <div className="grid grid-cols-2 gap-4">
          <Button 
            variant="outline" 
            className="flex items-center space-x-2 border-red-200 text-red-600 hover:bg-red-50 hover:border-red-300 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
          >
            <Facebook className="w-4 h-4" />
            <span className="text-sm">Facebook</span>
          </Button>
          
          <Button 
            variant="outline" 
            className="flex items-center space-x-2 border-red-200 text-red-600 hover:bg-red-50 hover:border-red-300 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
          >
            <Twitter className="w-4 h-4" />
            <span className="text-sm">Twitter</span>
          </Button>
          
          <Button 
            variant="outline" 
            className="flex items-center space-x-2 border-red-200 text-red-600 hover:bg-red-50 hover:border-red-300 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
          >
            <Instagram className="w-4 h-4" />
            <span className="text-sm">Instagram</span>
          </Button>
          
          <Button 
            variant="outline" 
            className="flex items-center space-x-2 border-red-200 text-red-600 hover:bg-red-50 hover:border-red-300 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
          >
            <Youtube className="w-4 h-4" />
            <span className="text-sm">YouTube</span>
          </Button>
          
          <Button 
            variant="outline" 
            className="flex items-center space-x-2 border-red-200 text-red-600 hover:bg-red-50 hover:border-red-300 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950 col-span-2"
          >
            <Linkedin className="w-4 h-4" />
            <span className="text-sm">LinkedIn</span>
          </Button>
        </div>
      </div>
    </div>
  );
}