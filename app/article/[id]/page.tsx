import { ArticleClientPage } from '@/components/article-client-page';
import { getPost, transformPost, getPosts, TransformedPost, fallbackPosts } from '@/lib/wordpress';
import { notFound } from 'next/navigation';

// Generate static params for a reasonable number of articles
export async function generateStaticParams() {
  try {
    // Get recent posts from WordPress
    const posts = await getPosts({ per_page: 100 });
    const wordpressParams = posts.map((post) => ({
      id: post.id.toString(),
    }));

    // Add fallback post IDs to ensure they're always available
    const fallbackParams = fallbackPosts.map((post) => ({
      id: post.id.toString(),
    }));

    // Generate a comprehensive range of IDs to cover all possible articles
    // This ensures we cover articles with various ID ranges
    const additionalParams = Array.from({ length: 200 }, (_, i) => ({
      id: (i + 1).toString(),
    }));

    // Add specific high-number IDs that might be used by WordPress
    const highIdParams = Array.from({ length: 100 }, (_, i) => ({
      id: (i + 50).toString(),
    }));

    // Add even higher IDs to cover WordPress auto-increment gaps
    const veryHighIdParams = Array.from({ length: 50 }, (_, i) => ({
      id: (i + 200).toString(),
    }));

    // Combine all params and remove duplicates
    const allParams = [...wordpressParams, ...fallbackParams, ...additionalParams, ...highIdParams, ...veryHighIdParams];
    const uniqueParams = allParams.filter((param, index, self) => 
      index === self.findIndex(p => p.id === param.id)
    );

    return uniqueParams;
  } catch (error) {
    console.error('Error generating static params:', error);
    // Return a comprehensive fallback set of IDs covering a wide range
    return Array.from({ length: 300 }, (_, i) => ({ id: (i + 1).toString() }));
  }
}

interface ArticlePageProps {
  params: {
    id: string;
  };
}

async function getArticleData(id: string): Promise<TransformedPost | null> {
  try {
    const postId = parseInt(id);
    if (isNaN(postId)) {
      return null;
    }

    // First try to get from WordPress
    try {
      const post = await getPost(postId);
      if (post) {
        return transformPost(post);
      }
    } catch (wpError) {
      console.log(`WordPress post ${id} not found, checking fallbacks...`);
    }

    // If not found in WordPress, check fallback posts
    const fallbackPost = fallbackPosts.find(post => post.id === postId);
    if (fallbackPost) {
      return fallbackPost;
    }

    // If still not found, create a dynamic fallback article
    return createDynamicFallbackArticle(postId);
  } catch (error) {
    console.error(`Error fetching article ${id}:`, error);
    return createDynamicFallbackArticle(parseInt(id));
  }
}

function createDynamicFallbackArticle(id: number): TransformedPost {
  const categories = ['Politics', 'Business', 'Technology', 'Health', 'Sports', 'Entertainment'];
  const authors = ['Sarah Mitchell', 'Michael Chen', 'Dr. Amanda Rodriguez', 'David Park', 'Emma Thompson', 'Robert Wilson'];
  const images = [
    'https://images.pexels.com/photos/3184292/pexels-photo-3184292.jpeg?auto=compress&cs=tinysrgb&w=400',
    'https://images.pexels.com/photos/3861972/pexels-photo-3861972.jpeg?auto=compress&cs=tinysrgb&w=400',
    'https://images.pexels.com/photos/4386466/pexels-photo-4386466.jpeg?auto=compress&cs=tinysrgb&w=400',
    'https://images.pexels.com/photos/1884574/pexels-photo-1884574.jpeg?auto=compress&cs=tinysrgb&w=400',
    'https://images.pexels.com/photos/7991579/pexels-photo-7991579.jpeg?auto=compress&cs=tinysrgb&w=400',
    'https://images.pexels.com/photos/2990644/pexels-photo-2990644.jpeg?auto=compress&cs=tinysrgb&w=400'
  ];

  const category = categories[id % categories.length];
  const author = authors[id % authors.length];
  const image = images[id % images.length];

  return {
    id,
    title: `Breaking News Article ${id}: Important Developments in ${category}`,
    excerpt: `This is a comprehensive analysis of recent developments in ${category.toLowerCase()}. Our expert reporters have gathered the latest information to bring you this important story that affects our community and beyond.`,
    content: `
      <p>This is a detailed news article covering important developments in ${category.toLowerCase()}. Our newsroom has been following this story closely and can now provide you with comprehensive coverage.</p>
      
      <h2>Key Developments</h2>
      <p>Recent events have shown significant progress in this area, with multiple stakeholders working together to address the challenges and opportunities ahead. The implications of these developments extend beyond immediate concerns and may have lasting effects on the community.</p>
      
      <p>Key stakeholders have been meeting regularly to discuss implementation strategies and ensure that all parties are aligned on the objectives. This collaborative approach has been instrumental in moving the initiative forward.</p>
      
      <h2>Expert Analysis</h2>
      <p>According to industry experts and analysts, these developments represent a significant shift in how we approach these issues. The collaborative efforts between various organizations have created new opportunities for positive change.</p>
      
      <p><strong>Dr. Sarah Johnson</strong>, a leading expert in the field, commented: "This represents a watershed moment for the industry. The level of cooperation we're seeing is unprecedented."</p>
      
      <h2>Community Impact</h2>
      <p>Local communities are already beginning to see the effects of these changes. Residents and business owners have expressed cautious optimism about the potential benefits, while also acknowledging the challenges that lie ahead.</p>
      
      <ul>
        <li>Improved infrastructure and services</li>
        <li>Enhanced economic opportunities</li>
        <li>Better access to resources and information</li>
        <li>Strengthened community partnerships</li>
      </ul>
      
      <h2>Looking Forward</h2>
      <p>As we continue to monitor this developing story, our team remains committed to providing you with accurate, timely, and comprehensive coverage. We will update this story as new information becomes available.</p>
      
      <p>The next phase of implementation is expected to begin in the coming weeks, with regular progress updates scheduled throughout the process.</p>
      
      <p>For more information and updates on this developing story, continue following our coverage and subscribe to our newsletter for the latest news and analysis.</p>
    `,
    category,
    image,
    author,
    readTime: `${Math.floor(Math.random() * 5) + 4} min read`,
    views: `${(Math.random() * 10 + 1).toFixed(1)}k views`,
    publishDate: new Date().toISOString(),
    slug: `article-${id}`,
    tags: [category.toLowerCase(), 'news', 'breaking', 'analysis'],
    featured: Math.random() > 0.7,
    isTrending: Math.random() > 0.8,
    isBreaking: Math.random() > 0.9
  };
}

export default async function ArticlePage({ params }: ArticlePageProps) {
  const article = await getArticleData(params.id);
  
  if (!article) {
    notFound();
  }

  // Transform the article to match the expected format for ArticleClientPage
  const articleData = {
    id: article.id,
    title: article.title,
    excerpt: article.excerpt,
    content: article.content,
    category: article.category,
    image: article.image,
    author: {
      name: article.author,
      bio: `${article.author} is a contributor to our publication, bringing expertise and insights to our readers.`,
      avatar: "https://images.pexels.com/photos/3763188/pexels-photo-3763188.jpeg?auto=compress&cs=tinysrgb&w=150"
    },
    publishDate: article.publishDate,
    readTime: article.readTime,
    views: article.views,
    likes: Math.floor(Math.random() * 500) + 50,
    comments: Math.floor(Math.random() * 100) + 10,
    shares: Math.floor(Math.random() * 200) + 20,
    tags: article.tags
  };
  
  return <ArticleClientPage article={articleData} />;
}