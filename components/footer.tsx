"use client";

import Link from 'next/link';
import { Facebook, Twitter, Instagram, Youtube, Linkedin, Mail, Phone, MapPin } from 'lucide-react';

export function Footer() {
  return (
    <footer className="bg-gray-900 text-white">
      <div className="container mx-auto px-4 py-12">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
          {/* Company Info */}
          <div className="space-y-4">
            <h3 className="text-2xl font-bold text-red-500">The Maple Epoch</h3>
            <p className="text-gray-400 text-sm">
              Your trusted source for breaking news, in-depth analysis, and stories that matter. 
              Stay informed with real-time coverage from around the world.
            </p>
            <div className="flex space-x-4">
              <Link href="https://facebook.com/mapleepoch" className="text-gray-400 hover:text-red-500 transition-colors">
                <Facebook className="w-5 h-5" />
              </Link>
              <Link href="https://x.com/mapleepoch" className="text-gray-400 hover:text-red-500 transition-colors">
                <Twitter className="w-5 h-5" />
              </Link>
              <Link href="#" className="text-gray-400 hover:text-red-500 transition-colors">
                <Instagram className="w-5 h-5" />
              </Link>
              <Link href="#" className="text-gray-400 hover:text-red-500 transition-colors">
                <Youtube className="w-5 h-5" />
              </Link>
              <Link href="https://linkedin.com/in/the-maple-epoch" className="text-gray-400 hover:text-red-500 transition-colors">
                <Linkedin className="w-5 h-5" />
              </Link>
            </div>
          </div>

          {/* Quick Links */}
          <div>
            <h4 className="text-lg font-semibold mb-4 text-red-500">Quick Links</h4>
            <ul className="space-y-2">
              <li><Link href="/" className="text-gray-400 hover:text-white transition-colors">Home</Link></li>
              <li><Link href="/politics" className="text-gray-400 hover:text-white transition-colors">Politics</Link></li>
              <li><Link href="/business" className="text-gray-400 hover:text-white transition-colors">Business</Link></li>
              <li><Link href="/health" className="text-gray-400 hover:text-white transition-colors">Health</Link></li>
              <li><Link href="/entertainment" className="text-gray-400 hover:text-white transition-colors">Entertainment</Link></li>
              <li><Link href="/sports" className="text-gray-400 hover:text-white transition-colors">Sports</Link></li>
              <li><Link href="/lifestyle" className="text-gray-400 hover:text-white transition-colors">Lifestyle</Link></li>
              <li><Link href="/the-friday-post" className="text-gray-400 hover:text-white transition-colors">The Friday Post</Link></li>
              <li><Link href="/about" className="text-gray-400 hover:text-white transition-colors">About Us</Link></li>
            </ul>
          </div>

          {/* Special Sections */}
          <div>
            <h4 className="text-lg font-semibold mb-4 text-red-500">Special Sections</h4>
            <ul className="space-y-2">
              <li><Link href="/events" className="text-gray-400 hover:text-white transition-colors">Events</Link></li>
              <li><Link href="/explore-canada" className="text-gray-400 hover:text-white transition-colors">Explore Canada</Link></li>
              <li><Link href="/you-may-have-missed" className="text-gray-400 hover:text-white transition-colors">You May Have Missed</Link></li>
              <li><Link href="/editors-picks" className="text-gray-400 hover:text-white transition-colors">Editor's Picks</Link></li>
              <li><Link href="/featured-articles" className="text-gray-400 hover:text-white transition-colors">Featured Articles</Link></li>
              <li><Link href="/resources" className="text-gray-400 hover:text-white transition-colors">Resources</Link></li>
            </ul>
          </div>

          {/* Contact Info */}
          <div>
            <h4 className="text-lg font-semibold mb-4 text-red-500">Contact Us</h4>
            <ul className="space-y-2">
              <li className="flex items-center space-x-2 text-gray-400">
                <Mail className="w-4 h-4" />
                <span>info@themapleepoch.com</span>
              </li>
              <li className="flex items-center space-x-2 text-gray-400">
                <Phone className="w-4 h-4" />
                <span>+233 20 293 5529</span>
              </li>
              <li className="flex items-center space-x-2 text-gray-400">
                <MapPin className="w-4 h-4" />
                <span>123 News Street, Media City</span>
              </li>
            </ul>
            <div className="mt-6">
              <Link 
                href="/write-for-us" 
                className="inline-block bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg text-sm transition-colors"
              >
                Write for Us
              </Link>
              <Link 
                href="/shop-a-tale" 
                className="inline-block bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg text-sm transition-colors ml-3"
              >
                Shop a Tale
              </Link>
            </div>
          </div>
        </div>

        <div className="border-t border-gray-800 mt-8 pt-8 flex flex-col md:flex-row justify-between items-center">
          <p className="text-gray-400 text-sm mb-4 md:mb-0">
            © 2025 The Maple Epoch. All rights reserved.
          </p>
          <div className="flex space-x-6 text-sm">
            <Link href="/privacy" className="text-gray-400 hover:text-white transition-colors">
              Privacy Policy
            </Link>
            <Link href="/terms" className="text-gray-400 hover:text-white transition-colors">
              Terms of Service
            </Link>
            <Link href="/about" className="text-gray-400 hover:text-white transition-colors">
              About Us
            </Link>
          </div>
        </div>
      </div>
    </footer>
  );
}