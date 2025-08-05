const API_URL = process.env.NEXT_PUBLIC_WORDPRESS_API_URL || 'https://mapleepoch.com/wp-json/wp/v2';

export interface WordPressPost {
  id: number;
  date: string;
  date_gmt: string;
  guid: {
    rendered: string;
  };
  modified: string;
  modified_gmt: string;
  slug: string;
  status: string;
  type: string;
  link: string;
  title: {
    rendered: string;
  };
  content: {
    rendered: string;
    protected: boolean;
  };
  excerpt: {
    rendered: string;
    protected: boolean;
  };
  author: number;
  featured_media: number;
  comment_status: string;
  ping_status: string;
  sticky: boolean;
  template: string;
  format: string;
  meta: any;
  categories: number[];
  tags: number[];
  _embedded?: {
    author?: Array<{
      id: number;
      name: string;
      url: string;
      description: string;
      link: string;
      slug: string;
      avatar_urls: {
        [key: string]: string;
      };
    }>;
    'wp:featuredmedia'?: Array<{
      id: number;
      date: string;
      slug: string;
      type: string;
      link: string;
      title: {
        rendered: string;
      };
      author: number;
      caption: {
        rendered: string;
      };
      alt_text: string;
      media_type: string;
      mime_type: string;
      media_details: {
        width: number;
        height: number;
        file: string;
        sizes: {
          [key: string]: {
            file: string;
            width: number;
            height: number;
            mime_type: string;
            source_url: string;
          };
        };
      };
      source_url: string;
    }>;
    'wp:term'?: Array<Array<{
      id: number;
      link: string;
      name: string;
      slug: string;
      taxonomy: string;
    }>>;
  };
}

export interface WordPressCategory {
  id: number;
  count: number;
  description: string;
  link: string;
  name: string;
  slug: string;
  taxonomy: string;
  parent: number;
  meta: any;
}

export interface TransformedPost {
  id: number;
  title: string;
  excerpt: string;
  content: string;
  category: string;
  image: string;
  author: string;
  readTime: string;
  views: string;
  publishDate: string;
  slug: string;
  featured?: boolean;
  isTrending?: boolean;
  isBreaking?: boolean;
  tags: string[];
}

// Cache for API responses
const cache = new Map();
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

async function fetchWithCache(url: string, options?: RequestInit) {
  const cacheKey = url + JSON.stringify(options);
  const cached = cache.get(cacheKey);
  
  if (cached && Date.now() - cached.timestamp < CACHE_DURATION) {
    return cached.data;
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout
    
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    cache.set(cacheKey, { data, timestamp: Date.now() });
    return data;
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') {
      console.error('WordPress API request timeout:', url);
    } else {
      console.error('WordPress API fetch error:', error);
    }
    // Return cached data if available, even if expired
    if (cached) {
      return cached.data;
    }
    throw error;
  }
}

export async function getPosts(params: {
  per_page?: number;
  page?: number;
  categories?: string;
  search?: string;
  _embed?: boolean;
  sticky?: boolean;
} = {}): Promise<WordPressPost[]> {
  const searchParams = new URLSearchParams();
  
  if (params.per_page) searchParams.append('per_page', params.per_page.toString());
  if (params.page) searchParams.append('page', params.page.toString());
  if (params.categories) searchParams.append('categories', params.categories);
  if (params.search) searchParams.append('search', params.search);
  if (params._embed !== false) searchParams.append('_embed', 'true');
  if (params.sticky) searchParams.append('sticky', 'true');
  
  // Always sort by date (newest first)
  searchParams.append('orderby', 'date');
  searchParams.append('order', 'desc');

  const url = `${API_URL}/posts?${searchParams.toString()}`;
  return fetchWithCache(url);
}

export async function getPost(id: number): Promise<WordPressPost> {
  const url = `${API_URL}/posts/${id}?_embed=true`;
  return fetchWithCache(url);
}

export async function getPostBySlug(slug: string): Promise<WordPressPost> {
  const url = `${API_URL}/posts?slug=${slug}&_embed=true`;
  const posts = await fetchWithCache(url);
  return posts[0];
}

export async function getCategories(): Promise<WordPressCategory[]> {
  const url = `${API_URL}/categories?per_page=100`;
  return fetchWithCache(url);
}

export async function getPostsByCategory(categorySlug: string, limit: number = 10): Promise<WordPressPost[]> {
  try {
    const categories = await getCategories();
    const category = categories.find(cat => cat.slug === categorySlug);
    
    if (!category) {
      console.warn(`Category not found: ${categorySlug}. Available categories:`, categories.map(cat => cat.slug));
      return [];
    }

    return getPosts({
      categories: category.id.toString(),
      per_page: limit,
      _embed: true
    });
  } catch (error) {
    console.error(`Error fetching posts for category ${categorySlug}:`, error);
    return [];
  }
}

// Transform WordPress post to our frontend format
export function transformPost(post: WordPressPost): TransformedPost {
  const author = post._embedded?.author?.[0]?.name || 'Unknown Author';
  const featuredImage = post._embedded?.['wp:featuredmedia']?.[0]?.source_url || 
    'https://images.pexels.com/photos/3184292/pexels-photo-3184292.jpeg?auto=compress&cs=tinysrgb&w=400';
  
  // Get category name
  const categories = post._embedded?.['wp:term']?.[0] || [];
  const category = categories.length > 0 ? categories[0].name : 'General';
  
  // Extract plain text from excerpt
  const excerptText = post.excerpt.rendered.replace(/<[^>]*>/g, '').trim();
  
  // Clean and preserve HTML content structure
  const cleanContent = post.content.rendered
    .replace(/\r\n/g, '\n')
    .replace(/\n\n+/g, '\n\n')
    .trim();
  
  // Calculate read time (rough estimate: 200 words per minute)
  const wordCount = cleanContent.replace(/<[^>]*>/g, '').split(/\s+/).length;
  const readTime = Math.max(1, Math.ceil(wordCount / 200));
  
  // Generate random views (in a real app, this would come from analytics)
  const views = `${(Math.random() * 5 + 1).toFixed(1)}k views`;
  
  // Get tags
  const tags = post._embedded?.['wp:term']?.[1]?.map(tag => tag.name) || [];

  return {
    id: post.id,
    title: post.title.rendered,
    excerpt: excerptText || post.title.rendered,
    content: cleanContent,
    category,
    image: featuredImage,
    author,
    readTime: `${readTime} min read`,
    views,
    publishDate: post.date,
    slug: post.slug,
    tags,
    featured: post.sticky,
    isTrending: Math.random() > 0.7, // Random trending status
    isBreaking: Math.random() > 0.9, // Random breaking status
  };
}

// Get posts for specific sections
export async function getLatestHeadlines(limit: number = 3): Promise<TransformedPost[]> {
  try {
    const posts = await getPosts({ per_page: limit, _embed: true });
    return posts.map(transformPost);
  } catch (error) {
    console.error('Error fetching latest headlines:', error);
    return [];
  }
}

export async function getEditorsPicks(limit: number = 3): Promise<TransformedPost[]> {
  try {
    // First try to get posts from "editors-picks" category
    const editorsPosts = await getPostsByCategory('editors-picks', Math.max(limit, 20));
    if (editorsPosts.length > 0) {
      return editorsPosts.map(post => ({ ...transformPost(post), featured: true }));
    }
    
    // If no editors-picks category, try "editor-picks" (alternative slug)
    const editorPicksPosts = await getPostsByCategory('editor-picks', Math.max(limit, 20));
    if (editorPicksPosts.length > 0) {
      return editorPicksPosts.map(post => ({ ...transformPost(post), featured: true }));
    }
    
    // Try sticky posts as fallback
    const stickyPosts = await getPosts({ per_page: Math.max(limit, 20), _embed: true, sticky: true });
    if (stickyPosts.length > 0) {
      return stickyPosts.map(post => ({ ...transformPost(post), featured: true }));
    }
    
    // If still no posts, get recent posts and mark them as featured
    const recentPosts = await getPosts({ per_page: Math.max(limit, 20), _embed: true });
    return recentPosts.map(post => ({ ...transformPost(post), featured: true }));
  } catch (error) {
    console.error('Error fetching editor\'s picks:', error);
    return [];
  }
}

// Section-specific functions
export async function getDailyMaple(limit: number = 3): Promise<TransformedPost[]> {
  return getPostsByCategory('daily-maple', Math.max(limit, 20)).then(posts => posts.map(transformPost));
}

export async function getMapleTravel(limit: number = 3): Promise<TransformedPost[]> {
  return getPostsByCategory('maple-travel', Math.max(limit, 20)).then(posts => posts.map(transformPost));
}

export async function getThroughTheLens(limit: number = 3): Promise<TransformedPost[]> {
  return getPostsByCategory('through-the-lens', Math.max(limit, 20)).then(posts => posts.map(transformPost));
}

export async function getFeaturedArticles(limit: number = 3): Promise<TransformedPost[]> {
  return getPostsByCategory('featured-articles', Math.max(limit, 20)).then(posts => posts.map(transformPost));
}

export async function getMapleVoices(limit: number = 3): Promise<TransformedPost[]> {
  return getPostsByCategory('maple-voices', Math.max(limit, 20)).then(posts => posts.map(transformPost));
}

export async function getExploreCanada(limit: number = 3): Promise<TransformedPost[]> {
  return getPostsByCategory('explore-canada', Math.max(limit, 20)).then(posts => posts.map(transformPost));
}

export async function getResources(limit: number = 3): Promise<TransformedPost[]> {
  return getPostsByCategory('resources', Math.max(limit, 20)).then(posts => posts.map(transformPost));
}

export async function getEvents(limit: number = 3): Promise<TransformedPost[]> {
  return getPostsByCategory('events', Math.max(limit, 20)).then(posts => posts.map(transformPost));
}

export async function getContinent(limit: number = 3): Promise<TransformedPost[]> {
  return getPostsByCategory('continent', Math.max(limit, 20)).then(posts => posts.map(transformPost));
}

export async function getCanadaNews(limit: number = 1): Promise<TransformedPost[]> {
  return getPostsByCategory('canada', Math.max(limit, 20)).then(posts => posts.map(transformPost));
}

export async function getYouMayHaveMissed(limit: number = 3): Promise<TransformedPost[]> {
  return getPostsByCategory('you-may-have-missed', Math.max(limit, 20)).then(posts => posts.map(transformPost));
}

// World News functions for specific regions
export async function getAfricaNews(limit: number = 1): Promise<TransformedPost[]> {
  return getPostsByCategory('africa', Math.max(limit, 20)).then(posts => posts.map(transformPost));
}

export async function getAmericasNews(limit: number = 1): Promise<TransformedPost[]> {
  return getPostsByCategory('americas', Math.max(limit, 20)).then(posts => posts.map(transformPost));
}

export async function getAustraliaNews(limit: number = 1): Promise<TransformedPost[]> {
  return getPostsByCategory('australia', Math.max(limit, 20)).then(posts => posts.map(transformPost));
}

export async function getAsiaNews(limit: number = 1): Promise<TransformedPost[]> {
  return getPostsByCategory('asia', Math.max(limit, 20)).then(posts => posts.map(transformPost));
}

export async function getEuropeNews(limit: number = 1): Promise<TransformedPost[]> {
  return getPostsByCategory('europe', Math.max(limit, 20)).then(posts => posts.map(transformPost));
}

export async function getUKNews(limit: number = 1): Promise<TransformedPost[]> {
  return getPostsByCategory('uk', Math.max(limit, 20)).then(posts => posts.map(transformPost));
}

// BookNook and Lifestyle Wire functions
export async function getBookNook(limit: number = 3): Promise<TransformedPost[]> {
  return getPostsByCategory('booknook', Math.max(limit, 20)).then(posts => posts.map(transformPost));
}

export async function getTheFridayPost(limit: number = 3): Promise<TransformedPost[]> {
  return getPostsByCategory('the-friday-post', Math.max(limit, 20)).then(posts => posts.map(transformPost));
}

export async function getLifestyle(limit: number = 3): Promise<TransformedPost[]> {
  return getPostsByCategory('lifestyle', Math.max(limit, 20)).then(posts => posts.map(transformPost));
}

// Fallback data for when WordPress is unavailable
export const fallbackPosts: TransformedPost[] = [
  {
    id: 1,
    title: "Federal Budget 2024: Major Infrastructure Investment Announced",
    excerpt: "Government unveils $50 billion infrastructure plan focusing on green energy, transportation, and digital connectivity across all provinces.",
    content: "<p>Government unveils major infrastructure investment...</p>",
    category: "Politics",
    image: "https://images.pexels.com/photos/3184292/pexels-photo-3184292.jpeg?auto=compress&cs=tinysrgb&w=400",
    author: "Sarah Mitchell",
    readTime: "6 min read",
    views: "15.2k views",
    publishDate: new Date().toISOString(),
    slug: "federal-budget-2024",
    tags: ["politics", "budget", "infrastructure"],
    featured: true
  },
  {
    id: 2,
    title: "Canadian Tech Sector Sees Record Growth in Q4 2024",
    excerpt: "Technology companies report unprecedented expansion with AI and clean tech leading the surge in innovation and investment.",
    content: "<p>Technology companies report unprecedented expansion...</p>",
    category: "Business",
    image: "https://images.pexels.com/photos/3861972/pexels-photo-3861972.jpeg?auto=compress&cs=tinysrgb&w=400",
    author: "Michael Chen",
    readTime: "8 min read",
    views: "12.8k views",
    publishDate: new Date().toISOString(),
    slug: "tech-sector-growth",
    tags: ["business", "technology", "growth"],
    featured: true
  },
  {
    id: 3,
    title: "Universal Pharmacare Program Launches Nationwide",
    excerpt: "Historic healthcare expansion provides prescription drug coverage for all Canadians, marking a significant milestone in public health policy.",
    content: "<p>Historic healthcare expansion provides prescription drug coverage...</p>",
    category: "Health",
    image: "https://images.pexels.com/photos/4386466/pexels-photo-4386466.jpeg?auto=compress&cs=tinysrgb&w=400",
    author: "Dr. Amanda Rodriguez",
    readTime: "7 min read",
    views: "18.5k views",
    publishDate: new Date().toISOString(),
    slug: "universal-pharmacare",
    tags: ["health", "healthcare", "policy"],
    featured: true
  },
  {
    id: 4,
    title: "Canadian Olympic Team Prepares for Paris 2024 with Record Roster",
    excerpt: "Team Canada announces largest ever Olympic delegation with strong medal prospects across multiple disciplines.",
    content: "<p>Team Canada announces largest ever Olympic delegation with strong medal prospects across multiple disciplines. The 2024 Paris Olympics will see Canada represented by over 300 athletes competing in various sports.</p><h2>Record Participation</h2><p>This year's team represents the largest Canadian Olympic delegation in history, with athletes qualifying across traditional strongholds like swimming and hockey, as well as emerging sports like skateboarding and sport climbing.</p><h2>Medal Prospects</h2><p>Canadian Olympic officials are optimistic about medal prospects, with several athletes ranked among the world's top competitors in their respective disciplines.</p>",
    category: "Sports",
    image: "https://images.pexels.com/photos/1884574/pexels-photo-1884574.jpeg?auto=compress&cs=tinysrgb&w=400",
    author: "David Park",
    readTime: "5 min read",
    views: "11.3k views",
    publishDate: new Date().toISOString(),
    slug: "olympic-team-2024",
    tags: ["sports", "olympics", "canada"]
  },
  {
    id: 5,
    title: "Canadian Film Industry Celebrates International Recognition",
    excerpt: "Multiple Canadian productions receive major international awards, highlighting the country's growing influence in global entertainment.",
    content: "<p>Multiple Canadian productions receive major international awards, highlighting the country's growing influence in global entertainment. From documentaries to feature films, Canadian creators are making their mark on the world stage.</p><h2>Award Winners</h2><p>Several Canadian films and documentaries have received recognition at major international film festivals, showcasing the diversity and quality of Canadian storytelling.</p><h2>Industry Growth</h2><p>The Canadian film industry has seen significant growth in recent years, supported by government initiatives and increased international co-productions.</p>",
    category: "Entertainment",
    image: "https://images.pexels.com/photos/7991579/pexels-photo-7991579.jpeg?auto=compress&cs=tinysrgb&w=400",
    author: "Emma Thompson",
    readTime: "6 min read",
    views: "8.9k views",
    publishDate: new Date().toISOString(),
    slug: "canadian-film-recognition",
    tags: ["entertainment", "film", "awards"]
  },
  {
    id: 6,
    title: "Provincial Leaders Meet for Climate Action Summit",
    excerpt: "Premiers from across Canada gather to discuss coordinated response to climate change and sustainable development goals.",
    content: "<p>Premiers from across Canada gather to discuss coordinated response to climate change and sustainable development goals. The summit aims to align provincial policies with federal climate targets.</p><h2>Key Discussions</h2><p>The summit focuses on carbon pricing, renewable energy investments, and adaptation strategies for climate change impacts across different regions.</p><h2>Collaborative Approach</h2><p>Provincial leaders emphasize the importance of working together to address climate challenges while supporting economic growth and job creation.</p>",
    category: "Politics",
    image: "https://images.pexels.com/photos/2990644/pexels-photo-2990644.jpeg?auto=compress&cs=tinysrgb&w=400",
    author: "Robert Wilson",
    readTime: "9 min read",
    views: "7.2k views",
    publishDate: new Date().toISOString(),
    slug: "climate-action-summit",
    tags: ["politics", "climate", "environment"]
  }
];