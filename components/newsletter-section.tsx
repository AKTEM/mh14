"use client";

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Mail, CheckCircle, Users, Globe, Clock } from 'lucide-react';

export function NewsletterSection() {
  const [email, setEmail] = useState('');
  const [isSubscribed, setIsSubscribed] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Handle newsletter subscription
    setIsSubscribed(true);
    setEmail('');
    setTimeout(() => setIsSubscribed(false), 3000);
  };

  return (
    <section className="space-y-8">
      <div className="flex items-center space-x-3">
        <Mail className="w-8 h-8 text-red-600" />
        <h2 className="text-3xl font-bold text-gray-900 dark:text-white">
          Stay Connected
        </h2>
        <div className="flex-1 h-1 bg-red-600 rounded-full ml-4"></div>
      </div>

      <div className="bg-gradient-to-br from-red-600 to-red-700 rounded-2xl shadow-xl overflow-hidden">
        <div className="relative p-8 md:p-12">
          {/* Background Pattern */}
          <div className="absolute inset-0 opacity-10">
            <div className="absolute inset-0 bg-gradient-to-r from-white/20 to-transparent"></div>
          </div>
          
          <div className="relative z-10">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-center">
              {/* Left Content */}
              <div className="text-white">
                <h3 className="text-3xl md:text-4xl font-bold mb-4">
                  Never Miss Breaking News
                </h3>
                <p className="text-xl mb-6 opacity-90">
                  Get the latest headlines, exclusive stories, and in-depth analysis delivered straight to your inbox.
                </p>
                
                {/* Stats */}
                <div className="grid grid-cols-3 gap-4 mb-8">
                  <div className="text-center">
                    <Users className="w-8 h-8 mx-auto mb-2 opacity-80" />
                    <div className="text-2xl font-bold">250K+</div>
                    <div className="text-sm opacity-80">Subscribers</div>
                  </div>
                  <div className="text-center">
                    <Globe className="w-8 h-8 mx-auto mb-2 opacity-80" />
                    <div className="text-2xl font-bold">50+</div>
                    <div className="text-sm opacity-80">Countries</div>
                  </div>
                  <div className="text-center">
                    <Clock className="w-8 h-8 mx-auto mb-2 opacity-80" />
                    <div className="text-2xl font-bold">24/7</div>
                    <div className="text-sm opacity-80">Updates</div>
                  </div>
                </div>
              </div>

              {/* Right Form */}
              <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-2xl">
                <h4 className="text-xl font-bold text-gray-900 dark:text-white mb-4">
                  Subscribe to Our Newsletter
                </h4>
                
                {isSubscribed ? (
                  <div className="text-center py-8">
                    <CheckCircle className="w-16 h-16 text-green-500 mx-auto mb-4" />
                    <h5 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                      Successfully Subscribed!
                    </h5>
                    <p className="text-gray-600 dark:text-gray-300">
                      Welcome to our community. You'll receive your first newsletter soon.
                    </p>
                  </div>
                ) : (
                  <form onSubmit={handleSubmit} className="space-y-4">
                    <div>
                      <Input
                        type="email"
                        placeholder="Enter your email address"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        className="border-gray-300 focus:border-red-500 focus:ring-red-500"
                        required
                      />
                    </div>
                    
                    <Button 
                      type="submit"
                      className="w-full bg-red-600 hover:bg-red-700 text-white py-3 text-lg font-semibold"
                    >
                      Subscribe Now
                    </Button>
                    
                    <div className="flex items-start space-x-2 text-xs text-gray-500 dark:text-gray-400">
                      <CheckCircle className="w-4 h-4 text-green-500 mt-0.5 flex-shrink-0" />
                      <span>
                        By subscribing, you agree to receive our newsletter and promotional emails. 
                        You can unsubscribe at any time.
                      </span>
                    </div>
                  </form>
                )}
                
                {/* Features */}
                <div className="mt-6 space-y-2">
                  <div className="flex items-center space-x-2 text-sm text-gray-600 dark:text-gray-300">
                    <CheckCircle className="w-4 h-4 text-green-500" />
                    <span>Daily news digest</span>
                  </div>
                  <div className="flex items-center space-x-2 text-sm text-gray-600 dark:text-gray-300">
                    <CheckCircle className="w-4 h-4 text-green-500" />
                    <span>Breaking news alerts</span>
                  </div>
                  <div className="flex items-center space-x-2 text-sm text-gray-600 dark:text-gray-300">
                    <CheckCircle className="w-4 h-4 text-green-500" />
                    <span>Exclusive content access</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}