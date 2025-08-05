import { Header } from '@/components/header';
import { Footer } from '@/components/footer';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { PenTool, Users, Award, Globe, ChevronRight } from 'lucide-react';
import Link from 'next/link';

const requirements = [
  "Strong writing skills and journalism experience",
  "Knowledge of AP Style and editorial standards",
  "Ability to meet deadlines and work independently",
  "Expertise in specific subject areas (politics, tech, health, etc.)",
  "Portfolio of published work or writing samples"
];

const benefits = [
  "Competitive compensation for published articles",
  "Byline credit and author bio",
  "Opportunity to build your journalism portfolio",
  "Access to press events and exclusive interviews",
  "Professional development and mentorship"
];

export default function WriteForUsPage() {
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
              <span className="text-gray-900 dark:text-white">Write for Us</span>
            </nav>
          </div>
        </div>

        {/* Hero Section */}
        <div className="bg-gradient-to-r from-red-600 to-red-700 text-white py-16">
          <div className="container mx-auto px-4">
            <div className="text-center">
              <PenTool className="w-16 h-16 mx-auto mb-4" />
              <h1 className="text-4xl md:text-6xl font-bold mb-4">Write for Us</h1>
              <p className="text-xl opacity-90 max-w-3xl mx-auto">
                Join our team of talented writers and contribute to one of the most trusted news sources. 
                Share your expertise and help inform our global audience.
              </p>
            </div>
          </div>
        </div>

        {/* Content Sections */}
        <div className="container mx-auto px-4 py-16">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12">
            {/* Left Column */}
            <div className="space-y-8">
              <div>
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">
                  Why Write for The Maple Epoch?
                </h2>
                <p className="text-gray-600 dark:text-gray-300 mb-6">
                  We're always looking for talented writers who can contribute fresh perspectives and 
                  expert insights to our publication. Whether you're an experienced journalist or an 
                  expert in your field, we want to hear from you.
                </p>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="text-center p-6 bg-gray-50 dark:bg-gray-800 rounded-lg">
                    <Users className="w-8 h-8 text-red-600 mx-auto mb-2" />
                    <h3 className="font-semibold text-gray-900 dark:text-white">250K+ Readers</h3>
                    <p className="text-sm text-gray-600 dark:text-gray-300">Monthly audience</p>
                  </div>
                  <div className="text-center p-6 bg-gray-50 dark:bg-gray-800 rounded-lg">
                    <Globe className="w-8 h-8 text-red-600 mx-auto mb-2" />
                    <h3 className="font-semibold text-gray-900 dark:text-white">50+ Countries</h3>
                    <p className="text-sm text-gray-600 dark:text-gray-300">Global reach</p>
                  </div>
                </div>
              </div>

              <div>
                <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-4">
                  What We're Looking For
                </h3>
                <ul className="space-y-2">
                  {requirements.map((requirement, index) => (
                    <li key={index} className="flex items-start space-x-2">
                      <div className="w-2 h-2 bg-red-600 rounded-full mt-2 flex-shrink-0"></div>
                      <span className="text-gray-600 dark:text-gray-300">{requirement}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div>
                <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-4">
                  What We Offer
                </h3>
                <ul className="space-y-2">
                  {benefits.map((benefit, index) => (
                    <li key={index} className="flex items-start space-x-2">
                      <Award className="w-4 h-4 text-red-600 mt-1 flex-shrink-0" />
                      <span className="text-gray-600 dark:text-gray-300">{benefit}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            {/* Right Column - Application Form */}
            <div className="bg-gray-50 dark:bg-gray-800 rounded-xl p-8">
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-6">
                Submit Your Application
              </h2>
              
              <form className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      First Name *
                    </label>
                    <Input placeholder="Your first name" required />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Last Name *
                    </label>
                    <Input placeholder="Your last name" required />
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Email Address *
                  </label>
                  <Input type="email" placeholder="your.email@example.com" required />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Areas of Expertise
                  </label>
                  <Input placeholder="e.g., Politics, Technology, Health, Sports" />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Professional Background
                  </label>
                  <Textarea 
                    placeholder="Tell us about your journalism experience, education, and relevant background..."
                    rows={4}
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Writing Samples / Portfolio
                  </label>
                  <Textarea 
                    placeholder="Please provide links to your published work or attach writing samples..."
                    rows={3}
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Story Ideas
                  </label>
                  <Textarea 
                    placeholder="Share some story ideas you'd like to write about..."
                    rows={3}
                  />
                </div>

                <Button type="submit" className="w-full bg-red-600 hover:bg-red-700 text-white">
                  Submit Application
                </Button>
              </form>

              <div className="mt-6 text-center">
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  We'll review your application and get back to you within 5-7 business days.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Guidelines Section */}
        <div className="bg-gray-50 dark:bg-gray-800 py-16">
          <div className="container mx-auto px-4">
            <div className="max-w-4xl mx-auto">
              <h2 className="text-3xl font-bold text-gray-900 dark:text-white mb-8 text-center">
                Editorial Guidelines
              </h2>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                <div>
                  <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">
                    Content Standards
                  </h3>
                  <ul className="space-y-2 text-gray-600 dark:text-gray-300">
                    <li>• Original, well-researched content only</li>
                    <li>• Fact-checked and properly sourced</li>
                    <li>• Unbiased and objective reporting</li>
                    <li>• Clear, engaging writing style</li>
                    <li>• Proper attribution and citations</li>
                  </ul>
                </div>
                
                <div>
                  <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">
                    Submission Process
                  </h3>
                  <ul className="space-y-2 text-gray-600 dark:text-gray-300">
                    <li>• Submit pitch before writing full article</li>
                    <li>• Follow our style guide and formatting</li>
                    <li>• Include relevant images and sources</li>
                    <li>• Allow time for editorial review</li>
                    <li>• Be responsive to feedback and edits</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>
      <Footer />
    </div>
  );
}