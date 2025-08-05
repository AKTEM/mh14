import { Header } from '@/components/header';
import { Footer } from '@/components/footer';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ShoppingBag, Star, Heart, ChevronRight } from 'lucide-react';
import Link from 'next/link';

const products = [
  {
    id: 1,
    title: "The Handmaid's Tale - Margaret Atwood",
    price: "$24.99",
    originalPrice: "$29.99",
    image: "https://images.pexels.com/photos/1029141/pexels-photo-1029141.jpeg?auto=compress&cs=tinysrgb&w=400",
    rating: 4.8,
    reviews: 1247,
    category: "Canadian Literature",
    bestseller: true
  },
  {
    id: 2,
    title: "Anne of Green Gables - L.M. Montgomery",
    price: "$19.99",
    originalPrice: "$24.99",
    image: "https://images.pexels.com/photos/1029141/pexels-photo-1029141.jpeg?auto=compress&cs=tinysrgb&w=400",
    rating: 4.9,
    reviews: 892,
    category: "Classic Fiction",
    bestseller: true
  },
  {
    id: 3,
    title: "Life of Pi - Yann Martel",
    price: "$22.99",
    originalPrice: "$27.99",
    image: "https://images.pexels.com/photos/1029141/pexels-photo-1029141.jpeg?auto=compress&cs=tinysrgb&w=400",
    rating: 4.7,
    reviews: 634,
    category: "Adventure Fiction"
  },
  {
    id: 4,
    title: "The Book of Negroes - Lawrence Hill",
    price: "$26.99",
    originalPrice: "$31.99",
    image: "https://images.pexels.com/photos/1029141/pexels-photo-1029141.jpeg?auto=compress&cs=tinysrgb&w=400",
    rating: 4.6,
    reviews: 445,
    category: "Historical Fiction"
  },
  {
    id: 5,
    title: "Alias Grace - Margaret Atwood",
    price: "$23.99",
    originalPrice: "$28.99",
    image: "https://images.pexels.com/photos/1029141/pexels-photo-1029141.jpeg?auto=compress&cs=tinysrgb&w=400",
    rating: 4.5,
    reviews: 567,
    category: "Historical Mystery"
  },
  {
    id: 6,
    title: "The Diviners - Margaret Laurence",
    price: "$21.99",
    originalPrice: "$26.99",
    image: "https://images.pexels.com/photos/1029141/pexels-photo-1029141.jpeg?auto=compress&cs=tinysrgb&w=400",
    rating: 4.4,
    reviews: 289,
    category: "Literary Fiction"
  }
];

export default function ShopATalePage() {
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
              <span className="text-gray-900 dark:text-white">Shop a Tale</span>
            </nav>
          </div>
        </div>

        {/* Page Header */}
        <div className="bg-gradient-to-r from-red-600 to-red-700 text-white py-16">
          <div className="container mx-auto px-4">
            <div className="text-center">
              <ShoppingBag className="w-16 h-16 mx-auto mb-4" />
              <h1 className="text-4xl md:text-6xl font-bold mb-4">Shop a Tale</h1>
              <p className="text-xl opacity-90 max-w-2xl mx-auto">
                Discover books and literary merchandise curated by our editorial team. 
                Support Canadian authors and find your next great read.
              </p>
            </div>
          </div>
        </div>

        {/* Products Grid */}
        <div className="container mx-auto px-4 py-12">
          <div className="mb-8">
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">
              Featured Canadian Literature
            </h2>
            <p className="text-gray-600 dark:text-gray-300">
              Handpicked selection of the finest Canadian books and literary works
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {products.map((product) => (
              <div 
                key={product.id}
                className="group bg-white dark:bg-gray-800 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300 transform hover:scale-[1.02] overflow-hidden"
              >
                <div className="aspect-square relative">
                  <img 
                    src={product.image} 
                    alt={product.title}
                    className="w-full h-full object-cover group-hover:scale-110 transition-transform duration-300"
                  />
                  <div className="absolute inset-0 bg-gradient-to-t from-black/60 to-transparent" />
                  
                  <div className="absolute top-3 left-3 flex space-x-2">
                    {product.bestseller && (
                      <Badge className="bg-red-600 hover:bg-red-700 text-white">
                        BESTSELLER
                      </Badge>
                    )}
                    <Badge variant="secondary" className="bg-white/90 text-gray-900 hover:bg-white text-xs">
                      {product.category}
                    </Badge>
                  </div>

                  <div className="absolute top-3 right-3">
                    <Button variant="ghost" size="sm" className="text-white hover:text-red-500">
                      <Heart className="w-5 h-5" />
                    </Button>
                  </div>
                </div>
                
                <div className="p-6">
                  <h3 className="font-bold text-lg mb-2 text-gray-900 dark:text-white group-hover:text-red-600 transition-colors line-clamp-2">
                    {product.title}
                  </h3>
                  
                  <div className="flex items-center space-x-2 mb-3">
                    <div className="flex items-center">
                      {[...Array(5)].map((_, i) => (
                        <Star 
                          key={i} 
                          className={`w-4 h-4 ${i < Math.floor(product.rating) ? 'text-yellow-400 fill-current' : 'text-gray-300'}`} 
                        />
                      ))}
                    </div>
                    <span className="text-sm text-gray-600 dark:text-gray-400">
                      {product.rating} ({product.reviews} reviews)
                    </span>
                  </div>
                  
                  <div className="flex items-center space-x-2 mb-4">
                    <span className="text-xl font-bold text-red-600">{product.price}</span>
                    <span className="text-sm text-gray-500 line-through">{product.originalPrice}</span>
                  </div>
                  
                  <Button 
                    className="w-full bg-red-600 hover:bg-red-700 text-white"
                  >
                    <ShoppingBag className="w-4 h-4 mr-2" />
                    Add to Cart
                  </Button>
                </div>
              </div>
            ))}
          </div>

          {/* Call to Action */}
          <div className="text-center mt-12 bg-gray-50 dark:bg-gray-800 rounded-xl p-8">
            <h3 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">
              Can't Find What You're Looking For?
            </h3>
            <p className="text-gray-600 dark:text-gray-300 mb-6">
              Browse our complete collection of Canadian literature and international bestsellers
            </p>
            <Button size="lg" className="bg-red-600 hover:bg-red-700 text-white">
              View Full Catalog
            </Button>
          </div>
        </div>
      </main>
      <Footer />
    </div>
  );
}