import { Header } from '@/components/header';
import { HeroSection } from '@/components/hero-section';
import { LatestHeadlines } from '@/components/latest-headlines';
import { EditorsPicks } from '@/components/editors-picks';
import { YouMayHaveMissed } from '@/components/you-may-have-missed';
import { DailyMaple } from '@/components/daily-maple';
import { MapleTravel } from '@/components/maple-travel';
import { ThroughTheLens } from '@/components/through-the-lens';
import { FeaturedArticles } from '@/components/featured-articles';
import { MapleVoices } from '@/components/maple-voices';
import { ExploreCanada } from '@/components/explore-canada';
import { Resources } from '@/components/resources';
import { Events } from '@/components/events';
import { CategoryGrid } from '@/components/category-grid';
import { WorldNews } from '@/components/world-news';
import { BookNook } from '@/components/booknook';
import { TheFridayPost } from '@/components/the-friday-post';
import { Footer } from '@/components/footer';
import { 
  getLatestHeadlines,
  getEditorsPicks,
  getDailyMaple,
  getMapleTravel,
  getThroughTheLens,
  getFeaturedArticles,
  getMapleVoices,
  getExploreCanada,
  getResources,
  getEvents,
  getYouMayHaveMissed,
  getBookNook,
  getTheFridayPost,
  getPosts,
  transformPost,
  fallbackPosts,
  getPostsByCategory,
  getAfricaNews,
  getAmericasNews,
  getAustraliaNews,
  getAsiaNews,
  getEuropeNews,
  getUKNews,
  getCanadaNews,
  TransformedPost
} from '@/lib/wordpress';

async function getHomePageData() {
  try {
    // Fetch articles from specific categories for hero section
    const targetCategories = ['politics', 'business', 'technology', 'health', 'sports', 'entertainment'];
    const heroArticlesPromises = targetCategories.map(category => 
      getPostsByCategory(category, 3).then(posts => posts.map(transformPost))
    );
    
    // Get Editor's Picks from WordPress (sticky posts)
    const editorsPicksPromise = getEditorsPicks(3);
    
    const [
      latestHeadlines,
      editorsPicks,
      dailyMaple,
      mapleTravel,
      throughTheLens,
      featuredArticles,
      mapleVoices,
      exploreCanada,
      resources,
      events,
      youMayHaveMissed,
      bookNook,
      heroArticles,
      theFridayPost,
      africaNews,
      americasNews,
      australiaNews,
      asiaNews,
      europeNews,
      ukNews,
      canadaNews,
      ...categoryArticles
    ] = await Promise.allSettled([
      getLatestHeadlines(3),
      editorsPicksPromise,
      getDailyMaple(20),
      getMapleTravel(20),
      getThroughTheLens(20),
      getFeaturedArticles(20),
      getMapleVoices(20),
      getExploreCanada(20),
      getResources(20),
      getEvents(20),
      getYouMayHaveMissed(20),
      getBookNook(20),
      getTheFridayPost(20),
      getPosts({ per_page: 9, _embed: true }).then(posts => posts.map(transformPost)),
      getAfricaNews(20),
      getAmericasNews(20),
      getAustraliaNews(20),
      getAsiaNews(20),
      getEuropeNews(20),
      getUKNews(20),
      getCanadaNews(20),
      ...heroArticlesPromises
    ]);

    // Combine articles from all target categories for hero section
    const combinedHeroArticles: TransformedPost[] = [];
    categoryArticles.forEach(result => {
      if (result.status === 'fulfilled') {
        combinedHeroArticles.push(...result.value);
      }
    });

    return {
      latestHeadlines: latestHeadlines.status === 'fulfilled' ? latestHeadlines.value : fallbackPosts.slice(0, 3),
      editorsPicks: editorsPicks.status === 'fulfilled' ? editorsPicks.value : fallbackPosts.slice(0, 20),
      dailyMaple: dailyMaple.status === 'fulfilled' ? dailyMaple.value : fallbackPosts.slice(0, 20),
      mapleTravel: mapleTravel.status === 'fulfilled' ? mapleTravel.value : fallbackPosts.slice(0, 20),
      throughTheLens: throughTheLens.status === 'fulfilled' ? throughTheLens.value : fallbackPosts.slice(0, 20),
      featuredArticles: featuredArticles.status === 'fulfilled' ? featuredArticles.value : fallbackPosts.slice(0, 20),
      mapleVoices: mapleVoices.status === 'fulfilled' ? mapleVoices.value : fallbackPosts.slice(0, 20),
      exploreCanada: exploreCanada.status === 'fulfilled' ? exploreCanada.value : fallbackPosts.slice(0, 20),
      resources: resources.status === 'fulfilled' ? resources.value : fallbackPosts.slice(0, 20),
      events: events.status === 'fulfilled' ? events.value : fallbackPosts.slice(0, 20),
      youMayHaveMissed: youMayHaveMissed.status === 'fulfilled' ? youMayHaveMissed.value : fallbackPosts.slice(0, 20),
      bookNook: bookNook.status === 'fulfilled' ? bookNook.value : fallbackPosts.slice(0, 20),
      theFridayPost: theFridayPost.status === 'fulfilled' ? theFridayPost.value : fallbackPosts.slice(0, 20),
      heroArticles: combinedHeroArticles.length > 0 ? combinedHeroArticles : (heroArticles.status === 'fulfilled' ? heroArticles.value : fallbackPosts.slice(0, 9)),
      africaNews: africaNews.status === 'fulfilled' ? africaNews.value : [],
      americasNews: americasNews.status === 'fulfilled' ? americasNews.value : [],
      australiaNews: australiaNews.status === 'fulfilled' ? australiaNews.value : [],
      asiaNews: asiaNews.status === 'fulfilled' ? asiaNews.value : [],
      europeNews: europeNews.status === 'fulfilled' ? europeNews.value : [],
      ukNews: ukNews.status === 'fulfilled' ? ukNews.value : [],
      canadaNews: canadaNews.status === 'fulfilled' ? canadaNews.value : [],
    };
  } catch (error) {
    console.error('Error fetching homepage data:', error);
    return {
      latestHeadlines: fallbackPosts.slice(0, 3),
      editorsPicks: fallbackPosts.slice(0, 20),
      dailyMaple: fallbackPosts.slice(0, 20),
      mapleTravel: fallbackPosts.slice(0, 20),
      throughTheLens: fallbackPosts.slice(0, 20),
      featuredArticles: fallbackPosts.slice(0, 20),
      mapleVoices: fallbackPosts.slice(0, 20),
      exploreCanada: fallbackPosts.slice(0, 20),
      resources: fallbackPosts.slice(0, 20),
      events: fallbackPosts.slice(0, 20),
      youMayHaveMissed: fallbackPosts.slice(0, 20),
      bookNook: fallbackPosts.slice(0, 20),
      theFridayPost: fallbackPosts.slice(0, 20),
      heroArticles: fallbackPosts.slice(0, 9),
      africaNews: [],
      americasNews: [],
      australiaNews: [],
      asiaNews: [],
      europeNews: [],
      ukNews: [],
      canadaNews: [],
    };
  }
}

export default async function Home() {
  const data = await getHomePageData();

  return (
    <div className="min-h-screen bg-white dark:bg-gray-900">
      <Header />
      <main>
        <HeroSection articles={data.heroArticles} />
        <div className="container mx-auto px-4 py-8">
          <div className="space-y-12">
            <WorldNews 
              africaArticle={Array.isArray(data.africaNews) ? data.africaNews[0] || null : data.africaNews}
              americasArticle={Array.isArray(data.americasNews) ? data.americasNews[0] || null : data.americasNews}
              australiaArticle={Array.isArray(data.australiaNews) ? data.australiaNews[0] || null : data.australiaNews}
              asiaArticle={Array.isArray(data.asiaNews) ? data.asiaNews[0] || null : data.asiaNews}
              europeArticle={Array.isArray(data.europeNews) ? data.europeNews[0] || null : data.europeNews}
              ukArticle={Array.isArray(data.ukNews) ? data.ukNews[0] || null : data.ukNews}
              allArticles={{
                africaNews: Array.isArray(data.africaNews) ? data.africaNews : [],
                americasNews: Array.isArray(data.americasNews) ? data.americasNews : [],
                australiaNews: Array.isArray(data.australiaNews) ? data.australiaNews : [],
                asiaNews: Array.isArray(data.asiaNews) ? data.asiaNews : [],
                europeNews: Array.isArray(data.europeNews) ? data.europeNews : [],
                ukNews: Array.isArray(data.ukNews) ? data.ukNews : [],
                canadaNews: Array.isArray(data.canadaNews) ? data.canadaNews : []
              }}
            />
            <LatestHeadlines articles={data.latestHeadlines} />
            <EditorsPicks articles={data.editorsPicks} />
            <YouMayHaveMissed articles={data.youMayHaveMissed} />
            <DailyMaple articles={data.dailyMaple} />
            <MapleTravel articles={data.mapleTravel} />
            <ThroughTheLens articles={data.throughTheLens} />
            <FeaturedArticles articles={data.featuredArticles} />
            <MapleVoices articles={data.mapleVoices} />
            <ExploreCanada articles={data.exploreCanada} />
            <Resources articles={data.resources} />
            <Events articles={data.events} />
            <BookNook articles={data.bookNook} />
            <TheFridayPost articles={data.theFridayPost} />
            <div className="mt-16">
              <CategoryGrid />
            </div>
          </div>
        </div>
      </main>
      <Footer />
    </div>
  );
}