"use client";

import { useEffect, useState } from 'react';
import { useSession } from 'next-auth/react';
import Link from 'next/link';
import { Header } from '@/components/header';
import { Footer } from '@/components/footer';
import { ProtectedRoute } from '@/components/auth/protected-route';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { 
  PlusCircle, 
  Edit, 
  Trash2, 
  Eye, 
  Calendar,
  FileText,
  User
} from 'lucide-react';
import { fetchUserPosts, deletePost, WordPressPost } from '@/lib/wordpress-api';

export default function DashboardPage() {
  const { data: session } = useSession();
  const [posts, setPosts] = useState<WordPressPost[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    if (session?.user?.id) {
      loadPosts();
    }
  }, [session]);

  const loadPosts = async () => {
    try {
      setIsLoading(true);
      const userPosts = await fetchUserPosts(session?.user?.id);
      setPosts(userPosts);
    } catch (error) {
      setError('Failed to load posts');
      console.error('Error loading posts:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleDeletePost = async (postId: number) => {
    if (!confirm('Are you sure you want to delete this post? This action cannot be undone.')) {
      return;
    }

    try {
      // Use force=true to permanently delete the post
      const response = await fetch(`${process.env.NEXT_PUBLIC_WORDPRESS_SITE_URL}/wp-json/wp/v2/posts/${postId}?force=true`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${session?.user?.accessToken}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error('Failed to delete post');
      }

      setPosts(posts.filter(post => post.id !== postId));
      setError('');
    } catch (error) {
      setError('Failed to delete post');
      console.error('Error deleting post:', error);
    }
  };

  const getStatusBadge = (status: string) => {
    const statusConfig = {
      publish: { color: 'bg-green-100 text-green-800', label: 'Published' },
      draft: { color: 'bg-yellow-100 text-yellow-800', label: 'Draft' },
      pending: { color: 'bg-blue-100 text-blue-800', label: 'Pending' },
      private: { color: 'bg-gray-100 text-gray-800', label: 'Private' },
    };

    const config = statusConfig[status as keyof typeof statusConfig] || statusConfig.draft;
    
    return (
      <Badge className={config.color}>
        {config.label}
      </Badge>
    );
  };

  return (
    <ProtectedRoute requiredRole="author">
      <div className="min-h-screen bg-white dark:bg-gray-900">
        <Header />
        <main className="pt-32">
          <div className="container mx-auto px-4 py-8">
            {/* Dashboard Header */}
            <div className="flex items-center justify-between mb-8">
              <div>
                <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
                  Author Dashboard
                </h1>
                <p className="text-gray-600 dark:text-gray-300 mt-2">
                  Welcome back, {session?.user?.displayName || session?.user?.username}
                </p>
              </div>
              <Button asChild className="bg-red-600 hover:bg-red-700">
                <Link href="/dashboard/posts/new" className="flex items-center space-x-2">
                  <PlusCircle className="w-5 h-5" />
                  <span>New Post</span>
                </Link>
              </Button>
            </div>

            {/* Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
              <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6">
                <div className="flex items-center space-x-3">
                  <FileText className="w-8 h-8 text-red-600" />
                  <div>
                    <p className="text-2xl font-bold text-gray-900 dark:text-white">
                      {posts.length}
                    </p>
                    <p className="text-gray-600 dark:text-gray-300">Total Posts</p>
                  </div>
                </div>
              </div>
              
              <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6">
                <div className="flex items-center space-x-3">
                  <Eye className="w-8 h-8 text-green-600" />
                  <div>
                    <p className="text-2xl font-bold text-gray-900 dark:text-white">
                      {posts.filter(post => post.status === 'publish').length}
                    </p>
                    <p className="text-gray-600 dark:text-gray-300">Published</p>
                  </div>
                </div>
              </div>
              
              <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6">
                <div className="flex items-center space-x-3">
                  <Edit className="w-8 h-8 text-yellow-600" />
                  <div>
                    <p className="text-2xl font-bold text-gray-900 dark:text-white">
                      {posts.filter(post => post.status === 'draft').length}
                    </p>
                    <p className="text-gray-600 dark:text-gray-300">Drafts</p>
                  </div>
                </div>
              </div>
            </div>

            {error && (
              <Alert className="mb-6 border-red-200 bg-red-50 dark:bg-red-950">
                <AlertDescription className="text-red-800 dark:text-red-200">
                  {error}
                </AlertDescription>
              </Alert>
            )}

            {/* Posts List */}
            <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg overflow-hidden">
              <div className="p-6 border-b border-gray-200 dark:border-gray-700">
                <h2 className="text-xl font-bold text-gray-900 dark:text-white">
                  Your Posts
                </h2>
              </div>

              {isLoading ? (
                <div className="p-8 text-center">
                  <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto"></div>
                  <p className="mt-4 text-gray-600 dark:text-gray-300">Loading posts...</p>
                </div>
              ) : posts.length === 0 ? (
                <div className="p-8 text-center">
                  <FileText className="w-16 h-16 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
                  <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                    No posts yet
                  </h3>
                  <p className="text-gray-600 dark:text-gray-300 mb-6">
                    Start creating content by writing your first post.
                  </p>
                  <Button asChild className="bg-red-600 hover:bg-red-700">
                    <Link href="/dashboard/posts/new">
                      Create Your First Post
                    </Link>
                  </Button>
                </div>
              ) : (
                <div className="divide-y divide-gray-200 dark:divide-gray-700">
                  {posts.map((post) => (
                    <div key={post.id} className="p-6 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center space-x-3 mb-2">
                            <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                              {post.title.rendered}
                            </h3>
                            {getStatusBadge(post.status)}
                          </div>
                          
                          <div 
                            className="text-gray-600 dark:text-gray-300 text-sm mb-3 line-clamp-2"
                            dangerouslySetInnerHTML={{ 
                              __html: post.excerpt.rendered.replace(/<[^>]*>/g, '').substring(0, 150) + '...' 
                            }}
                          />
                          
                          <div className="flex items-center space-x-4 text-xs text-gray-500 dark:text-gray-400">
                            <div className="flex items-center space-x-1">
                              <Calendar className="w-4 h-4" />
                              <span>
                                {new Date(post.date).toLocaleDateString()}
                              </span>
                            </div>
                            <div className="flex items-center space-x-1">
                              <Edit className="w-4 h-4" />
                              <span>
                                Modified {new Date(post.modified).toLocaleDateString()}
                              </span>
                            </div>
                          </div>
                        </div>
                        
                        <div className="flex items-center space-x-2 ml-4">
                          <Button
                            asChild
                            variant="outline"
                            size="sm"
                          >
                            <Link href={`/dashboard/posts/edit/${post.id}`}>
                              <Edit className="w-4 h-4" />
                            </Link>
                          </Button>
                          
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleDeletePost(post.id)}
                            className="text-red-600 hover:text-red-700 hover:bg-red-50"
                          >
                            <Trash2 className="w-4 h-4" />
                          </Button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </main>
        <Footer />
      </div>
    </ProtectedRoute>
  );
}