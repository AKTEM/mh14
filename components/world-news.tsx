"use client";

import React from 'react';
import Link from 'next/link';
import { useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Globe, Clock, Eye, User, MapPin, ChevronDown, ChevronUp } from 'lucide-react';
import { TransformedPost } from '@/lib/wordpress';

interface WorldNewsProps {
  africaArticle: TransformedPost | null;
  americasArticle: TransformedPost | null;
  australiaArticle: TransformedPost | null;
  asiaArticle: TransformedPost | null;
  europeArticle: TransformedPost | null;
  ukArticle: TransformedPost | null;
  allArticles: {
    africaNews: TransformedPost[];
    americasNews: TransformedPost[];
    australiaNews: TransformedPost[];
    asiaNews: TransformedPost[];
    europeNews: TransformedPost[];
    ukNews: TransformedPost[];
    canadaNews: TransformedPost[];
  };
}

export const WorldNews: React.FC<WorldNewsProps> = ({ 
  africaArticle, 
  americasArticle, 
  australiaArticle, 
  asiaArticle, 
  europeArticle, 
  ukArticle,
  allArticles
}) => {
  const [showAll, setShowAll] = useState(false);

  // Create fallback articles for demonstration when WordPress doesn't have content
  const fallbackArticles = [
    {
      id: 201,
      title: "African Union Summit Addresses Continental Trade Agreements",
      excerpt: "Leaders from across Africa gather to discuss new trade partnerships and economic cooperation initiatives.",
      content: "<p>African Union Summit addresses continental trade...</p>",
      category: "Politics",
      image: "https://images.pexels.com/photos/3184292/pexels-photo-3184292.jpeg?auto=compress&cs=tinysrgb&w=400",
      author: "Amara Okafor",
      readTime: "5 min read",
      views: "8.3k views",
      publishDate: new Date().toISOString(),
      slug: "african-union-summit",
      tags: ["africa", "politics", "trade"],
      region: "Africa"
    },
    {
      id: 202,
      title: "Brazil's Economic Recovery Shows Strong Growth in Q4",
      excerpt: "South America's largest economy demonstrates resilience with impressive quarterly growth figures.",
      content: "<p>Brazil's economic recovery shows strong growth...</p>",
      category: "Business",
      image: "https://images.pexels.com/photos/3861972/pexels-photo-3861972.jpeg?auto=compress&cs=tinysrgb&w=400",
      author: "Carlos Rodriguez",
      readTime: "6 min read",
      views: "12.1k views",
      publishDate: new Date().toISOString(),
      slug: "brazil-economic-recovery",
      tags: ["americas", "business", "economy"],
      region: "Americas"
    },
    {
      id: 203,
      title: "Mexico Announces Major Infrastructure Investment Plan",
      excerpt: "Government unveils ambitious infrastructure projects to boost connectivity across North America.",
      content: "<p>Mexico announces major infrastructure investment...</p>",
      category: "Politics",
      image: "https://images.pexels.com/photos/4386466/pexels-photo-4386466.jpeg?auto=compress&cs=tinysrgb&w=400",
      author: "Maria Gonzalez",
      readTime: "7 min read",
      views: "9.7k views",
      publishDate: new Date().toISOString(),
      slug: "mexico-infrastructure-plan",
      tags: ["americas", "politics", "infrastructure"],
      region: "Americas"
    },
    {
      id: 204,
      title: "Argentina's Agricultural Exports Reach Record Highs",
      excerpt: "The country's agricultural sector shows remarkable performance with unprecedented export volumes.",
      content: "<p>Argentina's agricultural exports reach record highs...</p>",
      category: "Business",
      image: "https://images.pexels.com/photos/1884574/pexels-photo-1884574.jpeg?auto=compress&cs=tinysrgb&w=400",
      author: "Diego Fernandez",
      readTime: "4 min read",
      views: "6.8k views",
      publishDate: new Date().toISOString(),
      slug: "argentina-agricultural-exports",
      tags: ["americas", "business", "agriculture"],
      region: "Americas"
    },
    {
      id: 205,
      title: "Chile's Renewable Energy Initiative Gains International Recognition",
      excerpt: "The country's commitment to clean energy attracts global attention and investment.",
      content: "<p>Chile's renewable energy initiative gains recognition...</p>",
      category: "Environment",
      image: "https://images.pexels.com/photos/7991579/pexels-photo-7991579.jpeg?auto=compress&cs=tinysrgb&w=400",
      author: "Isabella Martinez",
      readTime: "5 min read",
      views: "7.4k views",
      publishDate: new Date().toISOString(),
      slug: "chile-renewable-energy",
      tags: ["americas", "environment", "energy"],
      region: "Americas"
    },
    {
      id: 206,
      title: "Australia's Tech Sector Attracts Record Investment",
      excerpt: "The Australian technology industry sees unprecedented levels of venture capital and international investment.",
      content: "<p>Australia's tech sector attracts record investment...</p>",
      category: "Technology",
      image: "https://images.pexels.com/photos/2990644/pexels-photo-2990644.jpeg?auto=compress&cs=tinysrgb&w=400",
      author: "James Wilson",
      readTime: "6 min read",
      views: "10.2k views",
      publishDate: new Date().toISOString(),
      slug: "australia-tech-investment",
      tags: ["australia", "technology", "investment"],
      region: "Australia"
    },
    {
      id: 207,
      title: "Japan's Innovation in Sustainable Transportation",
      excerpt: "Japanese companies lead the way in developing eco-friendly transportation solutions for urban environments.",
      content: "<p>Japan's innovation in sustainable transportation...</p>",
      category: "Technology",
      image: "https://images.pexels.com/photos/3483098/pexels-photo-3483098.jpeg?auto=compress&cs=tinysrgb&w=400",
      author: "Yuki Tanaka",
      readTime: "8 min read",
      views: "13.5k views",
      publishDate: new Date().toISOString(),
      slug: "japan-sustainable-transportation",
      tags: ["asia", "technology", "transportation"],
      region: "Asia"
    },
    {
      id: 208,
      title: "South Korea's Cultural Export Success Continues",
      excerpt: "K-pop, K-dramas, and Korean cuisine continue to gain global popularity and economic impact.",
      content: "<p>South Korea's cultural export success continues...</p>",
      category: "Entertainment",
      image: "https://images.pexels.com/photos/4164418/pexels-photo-4164418.jpeg?auto=compress&cs=tinysrgb&w=400",
      author: "Min-jun Park",
      readTime: "5 min read",
      views: "16.8k views",
      publishDate: new Date().toISOString(),
      slug: "south-korea-cultural-exports",
      tags: ["asia", "entertainment", "culture"],
      region: "Asia"
    },
    {
      id: 209,
      title: "European Union Strengthens Climate Commitments",
      excerpt: "EU member states agree on enhanced climate targets and increased funding for green transition initiatives.",
      content: "<p>European Union strengthens climate commitments...</p>",
      category: "Environment",
      image: "https://images.pexels.com/photos/3184292/pexels-photo-3184292.jpeg?auto=compress&cs=tinysrgb&w=400",
      author: "Sophie Mueller",
      readTime: "7 min read",
      views: "11.9k views",
      publishDate: new Date().toISOString(),
      slug: "eu-climate-commitments",
      tags: ["europe", "environment", "climate"],
      region: "Europe"
    },
    {
      id: 210,
      title: "UK's Post-Brexit Trade Relations Show Positive Growth",
      excerpt: "New trade agreements and partnerships demonstrate the UK's evolving economic relationships globally.",
      content: "<p>UK's post-Brexit trade relations show positive growth...</p>",
      category: "Business",
      image: "https://images.pexels.com/photos/3861972/pexels-photo-3861972.jpeg?auto=compress&cs=tinysrgb&w=400",
      author: "Oliver Thompson",
      readTime: "6 min read",
      views: "14.3k views",
      publishDate: new Date().toISOString(),
      slug: "uk-trade-relations",
      tags: ["uk", "business", "trade"],
      region: "UK"
    }
  ];

  // Combine all WordPress articles from all regions
  const allWordPressArticles = [
    ...allArticles.africaNews.map(article => ({ ...article, region: "Africa" })),
    ...allArticles.americasNews.map(article => ({ ...article, region: "Americas" })),
    ...allArticles.australiaNews.map(article => ({ ...article, region: "Australia" })),
    ...allArticles.asiaNews.map(article => ({ ...article, region: "Asia" })),
    ...allArticles.europeNews.map(article => ({ ...article, region: "Europe" })),
    ...allArticles.ukNews.map(article => ({ ...article, region: "UK" })),
    ...allArticles.canadaNews.map(article => ({ ...article, region: "Canada" }))
  ];

  // Sort by date (newest first) and use fallback if needed
  const sortedWordPressArticles = allWordPressArticles.sort((a, b) => 
    new Date(b.publishDate).getTime() - new Date(a.publishDate).getTime()
  );
  
  // If we don't have enough WordPress articles, supplement with fallback articles
  const articles = sortedWordPressArticles.length >= 6 ? sortedWordPressArticles : [...sortedWordPressArticles, ...fallbackArticles].slice(0, 20);

  const displayedArticles = showAll ? articles : articles.slice(0, 6);

  return (
    <section className="space-y-8">
      <div className="flex items-center space-x-3">
        <Globe className="w-8 h-8 text-red-600" />
        <h2 className="text-3xl font-bold text-gray-900 dark:text-white">
          World News
        </h2>
        <div className="flex-1 h-1 bg-red-600 rounded-full ml-4"></div>
      </div>

      <div className="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-950 dark:to-indigo-950 rounded-xl p-6 mb-8">
        <div className="text-center">
          <MapPin className="w-12 h-12 text-red-600 mx-auto mb-3" />
          <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-2">
            Global News from Every Continent
          </h3>
          <p className="text-gray-600 dark:text-gray-300 max-w-2xl mx-auto">
            Stay informed with breaking news and important developments from Africa, Americas, 
            Australia, Asia, Europe, and the United Kingdom.
          </p>
        </div>
      </div>

      {/* Display articles in rows of 3 */}
      {Array.from({ length: Math.ceil(displayedArticles.length / 3) }, (_, rowIndex) => (
        <div key={`row-${rowIndex}`} className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {displayedArticles.slice(rowIndex * 3, (rowIndex + 1) * 3).map((article) => (
            <div 
              key={article.id}
              className="group bg-white dark:bg-gray-800 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300 transform hover:scale-[1.02] overflow-hidden w-full"
            >
              <div className="aspect-video relative">
                <img 
                  src={article.image} 
                  alt={article.title}
                  className="w-full h-64 object-cover group-hover:scale-110 transition-transform duration-300"
                />
                <div className="absolute inset-0 bg-gradient-to-t from-black/60 to-transparent" />
                
                <div className="absolute top-3 left-3 flex space-x-2">
                  <Badge className="bg-red-600 hover:bg-red-700 text-white">
                    <Globe className="w-3 h-3 mr-1" />
                    WORLD
                  </Badge>
                  <Badge variant="secondary" className="bg-white/90 text-gray-900 hover:bg-white text-xs">
                    {article.region || article.category}
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
                    Read World News
                  </Link>
                </Button>
              </div>
            </div>
          ))}
        </div>
      ))}
      
      <div className="text-center">
        {articles.length > 6 && (
          <>
            <Button
              onClick={() => setShowAll(!showAll)}
              size="lg"
              className="bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 text-white px-8 py-3 flex items-center space-x-2 mx-auto"
            >
              <span>{showAll ? 'Show Less' : 'View All World News'}</span>
              {showAll ? (
                <ChevronUp className="w-5 h-5" />
              ) : (
                <ChevronDown className="w-5 h-5" />
              )}
            </Button>
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-2">
              Showing {displayedArticles.length} of {articles.length} articles
            </p>
          </>
        )}
        {articles.length <= 6 && articles.length > 0 && (
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-2">
            Showing {displayedArticles.length} of {articles.length} articles
          </p>
        )}
      </div>
    </section>
  );
};