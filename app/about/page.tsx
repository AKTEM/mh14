import { Header } from '@/components/header';
import { Footer } from '@/components/footer';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Users, Award, Globe, Heart, ChevronRight } from 'lucide-react';
import Link from 'next/link';

const teamMembers = [
  {
    name: "Sarah Mitchell",
    role: "Editor-in-Chief",
    image: "https://images.pexels.com/photos/3763188/pexels-photo-3763188.jpeg?auto=compress&cs=tinysrgb&w=300",
    bio: "Award-winning journalist with 15+ years covering Canadian politics and international affairs."
  },
  {
    name: "Michael Chen",
    role: "Senior Technology Reporter",
    image: "https://images.pexels.com/photos/3763188/pexels-photo-3763188.jpeg?auto=compress&cs=tinysrgb&w=300",
    bio: "Tech industry expert specializing in AI, cybersecurity, and digital transformation."
  },
  {
    name: "Dr. Amanda Rodriguez",
    role: "Health & Science Correspondent",
    image: "https://images.pexels.com/photos/3763188/pexels-photo-3763188.jpeg?auto=compress&cs=tinysrgb&w=300",
    bio: "Medical doctor turned journalist, covering healthcare policy and medical breakthroughs."
  },
  {
    name: "David Park",
    role: "Sports Editor",
    image: "https://images.pexels.com/photos/3763188/pexels-photo-3763188.jpeg?auto=compress&cs=tinysrgb&w=300",
    bio: "Former Olympic athlete covering sports from grassroots to professional levels."
  }
];

const values = [
  {
    icon: Heart,
    title: "Integrity",
    description: "We uphold the highest standards of journalistic integrity and ethical reporting."
  },
  {
    icon: Globe,
    title: "Global Perspective",
    description: "We provide comprehensive coverage with both local insight and global context."
  },
  {
    icon: Users,
    title: "Community",
    description: "We serve our readers and communities with dedication and respect."
  },
  {
    icon: Award,
    title: "Excellence",
    description: "We strive for excellence in every story, every day."
  }
];

export default function AboutPage() {
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
              <span className="text-gray-900 dark:text-white">About</span>
            </nav>
          </div>
        </div>

        {/* Hero Section */}
        <div className="bg-gradient-to-r from-red-600 to-red-700 text-white py-16">
          <div className="container mx-auto px-4">
            <div className="text-center">
              <h1 className="text-4xl md:text-6xl font-bold mb-4">About The Maple Epoch</h1>
              <p className="text-xl opacity-90 max-w-3xl mx-auto">
                Your trusted source for breaking news, in-depth analysis, and stories that matter. 
                We're committed to delivering accurate, timely, and comprehensive news coverage.
              </p>
            </div>
          </div>
        </div>

        {/* Mission Section */}
        <div className="container mx-auto px-4 py-16">
          <div className="max-w-4xl mx-auto text-center">
            <h2 className="text-3xl font-bold text-gray-900 dark:text-white mb-6">Our Mission</h2>
            <p className="text-lg text-gray-600 dark:text-gray-300 mb-8">
              At The Maple Epoch, we believe in the power of informed citizens and the importance of quality journalism. 
              Our mission is to provide accurate, unbiased, and comprehensive news coverage that helps our readers 
              understand the world around them and make informed decisions.
            </p>
            <p className="text-lg text-gray-600 dark:text-gray-300">
              We cover everything from breaking news and politics to business, technology, health, sports, and entertainment, 
              ensuring our readers stay informed about the issues that matter most to them and their communities.
            </p>
          </div>
        </div>

        {/* Values Section */}
        <div className="bg-gray-50 dark:bg-gray-800 py-16">
          <div className="container mx-auto px-4">
            <div className="text-center mb-12">
              <h2 className="text-3xl font-bold text-gray-900 dark:text-white mb-4">Our Values</h2>
              <p className="text-lg text-gray-600 dark:text-gray-300 max-w-2xl mx-auto">
                These core values guide everything we do and shape how we serve our readers and communities.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
              {values.map((value, index) => {
                const IconComponent = value.icon;
                return (
                  <div key={index} className="text-center">
                    <div className="bg-red-600 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                      <IconComponent className="w-8 h-8 text-white" />
                    </div>
                    <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-2">
                      {value.title}
                    </h3>
                    <p className="text-gray-600 dark:text-gray-300">
                      {value.description}
                    </p>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Team Section */}

        {/* Contact CTA */}
        <div className="bg-red-600 text-white py-16">
          <div className="container mx-auto px-4 text-center">
            <h2 className="text-3xl font-bold mb-4">Get in Touch</h2>
            <p className="text-xl opacity-90 mb-8 max-w-2xl mx-auto">
              Have a story tip, feedback, or want to join our team? We'd love to hear from you.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              {/* <Button asChild size="lg" variant="secondary">
                <Link href="/contact">Contact Us</Link>
              </Button>
              <Button asChild size="lg" variant="outline" className="border-white text-white hover:bg-white hover:text-red-600">
                <Link href="/write-for-us">Write for Us</Link>
              </Button> */}
            </div>
          </div>
        </div>
      </main>
      <Footer />
    </div>
  );
}