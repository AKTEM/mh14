import Link from 'next/link';
import { Header } from '@/components/header';
import { Footer } from '@/components/footer';
import { Button } from '@/components/ui/button';
import { Shield, Home, ArrowLeft } from 'lucide-react';

export default function UnauthorizedPage() {
  return (
    <div className="min-h-screen bg-white dark:bg-gray-900">
      <Header />
      <main className="pt-32">
        <div className="container mx-auto px-4 py-16">
          <div className="text-center max-w-2xl mx-auto">
            <div className="mb-8">
              <Shield className="w-16 h-16 text-red-600 mx-auto mb-4" />
              <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-4">
                Access Denied
              </h1>
              <p className="text-lg text-gray-600 dark:text-gray-300 mb-8">
                You don't have permission to access this page. This area is restricted to authors only.
              </p>
            </div>

            <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
              <Button asChild size="lg" className="bg-red-600 hover:bg-red-700">
                <Link href="/" className="flex items-center space-x-2">
                  <Home className="w-5 h-5" />
                  <span>Back to Home</span>
                </Link>
              </Button>
              
              <Button asChild variant="outline" size="lg">
                <Link href="/auth/signin" className="flex items-center space-x-2">
                  <ArrowLeft className="w-5 h-5" />
                  <span>Sign In</span>
                </Link>
              </Button>
            </div>

            <div className="mt-12 p-6 bg-gray-50 dark:bg-gray-800 rounded-xl">
              <h3 className="font-semibold text-gray-900 dark:text-white mb-2">
                Need Author Access?
              </h3>
              <p className="text-sm text-gray-600 dark:text-gray-300">
                If you believe you should have access to this area, please contact the site administrator 
                or sign up for an author account.
              </p>
            </div>
          </div>
        </div>
      </main>
      <Footer />
    </div>
  );
}