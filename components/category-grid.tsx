"use client";

import Link from 'next/link';
import { 
  Globe,
  Globe2, 
  BookOpen, 
  Star, 
  Coffee, 
  Clock, 
  ShoppingBag,
  Zap,
  TrendingUp,
  Users,
  Heart,
  Camera,
  Music,
  Mountain,
  FileText,
  MessageSquare,
  Compass,
  Calendar,
  Headphones
} from 'lucide-react';

const categories = [
  {
    id: 1,
    title: "World News",
    description: "Global stories from every continent",
    icon: Globe,
    href: "/world",
    gradient: "from-red-500 to-red-600",
    subcategories: ["Africa", "Americas", "Australia", "Asia", "Europe", "UK", "Canada"]
  },
  {
    id: 2,
    title: "BookNook",
    description: "Literary reviews and book recommendations",
    icon: BookOpen,
    href: "/booknook",
    gradient: "from-red-600 to-red-700"
  },
  {
    id: 3,
    title: "Editor's Picks",
    description: "Curated stories from our editorial team",
    icon: Star,
    href: "/editors-picks",
    gradient: "from-red-500 to-orange-500"
  },
  {
    id: 4,
    title: "Daily Maple",
    description: "Your daily dose of Canadian news and insights",
    icon: Coffee,
    href: "/daily-maple",
    gradient: "from-orange-500 to-red-500"
  },
  {
    id: 13,
    title: "Maple Travel",
    description: "Discover Canada's breathtaking destinations",
    icon: Mountain,
    href: "/maple-travel",
    gradient: "from-blue-500 to-green-500"
  },
  {
    id: 14,
    title: "Through the Lens",
    description: "Photography insights and local secrets",
    icon: Camera,
    href: "/through-the-lens",
    gradient: "from-purple-500 to-pink-500"
  },
  {
    id: 15,
    title: "Featured Articles",
    description: "In-depth Canadian culture and current events",
    icon: FileText,
    href: "/featured-articles",
    gradient: "from-amber-500 to-yellow-500"
  },
  {
    id: 16,
    title: "Maple Voices",
    description: "Stories from Canadians across the nation",
    icon: MessageSquare,
    href: "/maple-voices",
    gradient: "from-green-500 to-teal-500"
  },
  {
    id: 17,
    title: "Explore Canada",
    description: "Hidden gems and iconic landmarks",
    icon: Compass,
    href: "/explore-canada",
    gradient: "from-indigo-500 to-cyan-500"
  },
  {
    id: 18,
    title: "Resources",
    description: "Canadian history, culture, and travel guides",
    icon: BookOpen,
    href: "/resources",
    gradient: "from-slate-500 to-gray-500"
  },
  {
    id: 19,
    title: "Events",
    description: "Canadian festivals, conferences, and celebrations",
    icon: Calendar,
    href: "/events",
    gradient: "from-rose-500 to-pink-500"
  },
  {
    id: 20,
    title: "The Friday Post",
    description: "Podcasts showcasing Canadian experiences",
    icon: Headphones,
    href: "/friday-post",
    gradient: "from-violet-500 to-purple-500"
  },
  {
    id: 21,
    title: "Continent",
    description: "Canada's global impact and North American spotlight",
    icon: Globe2,
    href: "/continent",
    gradient: "from-emerald-500 to-teal-500"
  },
  {
    id: 5,
    title: "You May Have Missed",
    description: "Important stories you might have overlooked",
    icon: Clock,
    href: "/you-may-have-missed",
    gradient: "from-red-700 to-red-800"
  },
  {
    id: 6,
    title: "Shop a Tale",
    description: "Discover books and literary merchandise",
    icon: ShoppingBag,
    href: "/shop-a-tale",
    gradient: "from-red-600 to-red-700"
  },
  {
    id: 7,
    title: "The Friday Post",
    description: "Podcasts showcasing Canadian experiences",
    icon: Zap,
    href: "/the-friday-post",
    gradient: "from-red-500 to-red-600"
  },
  {
    id: 8,
    title: "Business",
    description: "Market insights and economic analysis",
    icon: TrendingUp,
    href: "/business",
    gradient: "from-red-600 to-red-700"
  },
  {
    id: 9,
    title: "Politics",
    description: "Political news and government updates",
    icon: Users,
    href: "/politics",
    gradient: "from-red-700 to-red-800"
  },
  {
    id: 10,
    title: "Lifestyle",
    description: "Wellness, fashion, food, and culture trends",
    icon: Heart,
    href: "/lifestyle",
    gradient: "from-red-500 to-red-600"
  },
  {
    id: 11,
    title: "Health",
    description: "Health news and medical breakthroughs",
    icon: Heart,
    href: "/health",
    gradient: "from-red-600 to-red-700"
  },
  {
    id: 12,
    title: "Sports",
    description: "Sports coverage and athletic achievements",
    icon: Camera,
    href: "/sports",
    gradient: "from-red-600 to-red-700"
  },
  {
    id: 13,
    title: "Entertainment",
    description: "Arts, culture, and entertainment news",
    icon: Music,
    href: "/entertainment",
    gradient: "from-red-500 to-orange-500"
  }
];

export function CategoryGrid() {
  return (
    <section className="py-12 space-y-8">
      <div className="text-center">
        <h2 className="text-3xl font-bold text-gray-900 dark:text-white mb-4">
          Explore Categories
        </h2>
        <p className="text-gray-600 dark:text-gray-300 max-w-2xl mx-auto">
          Discover news and stories across all the topics that matter to you. 
          From global affairs to local insights, we've got you covered.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {categories.map((category) => {
          const IconComponent = category.icon;
          return (
            <Link
              key={category.id}
              href={category.href}
              className="group block"
            >
              <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300 transform hover:scale-[1.02] overflow-hidden">
                <div className={`p-6 bg-gradient-to-br ${category.gradient} text-white`}>
                  <IconComponent className="w-8 h-8 mb-3" />
                  <h3 className="text-lg font-bold mb-2">{category.title}</h3>
                  <p className="text-sm opacity-90 line-clamp-2">{category.description}</p>
                </div>
                
                {category.subcategories && (
                  <div className="p-4 bg-gray-50 dark:bg-gray-700">
                    <div className="flex flex-wrap gap-2">
                      {category.subcategories.slice(0, 3).map((sub) => (
                        <span 
                          key={sub}
                          className="text-xs bg-white dark:bg-gray-600 text-gray-700 dark:text-gray-300 px-2 py-1 rounded-full"
                        >
                          {sub}
                        </span>
                      ))}
                      {category.subcategories.length > 3 && (
                        <span className="text-xs text-gray-500 dark:text-gray-400 px-2 py-1">
                          +{category.subcategories.length - 3} more
                        </span>
                      )}
                    </div>
                  </div>
                )}
                
                <div className="p-4 bg-white dark:bg-gray-800">
                  <div className="flex items-center justify-between text-sm text-gray-600 dark:text-gray-400">
                    <span>Explore category</span>
                    <span className="text-red-600 group-hover:text-red-700 transition-colors">→</span>
                  </div>
                </div>
              </div>
            </Link>
          );
        })}
      </div>
    </section>
  );
}