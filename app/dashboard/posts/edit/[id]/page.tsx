"use client";

import { useState, useEffect } from 'react';
import { useRouter, useParams } from 'next/navigation';
import { Header } from '@/components/header';
import { Footer } from '@/components/footer';
import { ProtectedRoute } from '@/components/auth/protected-route';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Checkbox } from '@/components/ui/checkbox';
import { ArrowLeft, Save, Eye } from 'lucide-react';
import Link from 'next/link';
import { updatePost, fetchPost, fetchCategories, WordPressCategory, WordPressPost, uploadMedia, fetchMedia } from '@/lib/wordpress-api';

export default function EditPostPage() {
  const params = useParams();
  const postId = parseInt(params.id as string);
  const [formData, setFormData] = useState({
    title: '',
    content: '',
    categories: [] as number[],
    status: 'draft',
    featured_media: undefined as number | undefined
  });
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [imagePreviewUrl, setImagePreviewUrl] = useState<string | null>(null);
  const [isUploadingImage, setIsUploadingImage] = useState(false);
  const [categories, setCategories] = useState<WordPressCategory[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isLoadingPost, setIsLoadingPost] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const router = useRouter();

  useEffect(() => {
    if (postId) {
      loadPost();
      loadCategories();
    }
  }, [postId]);

  const loadPost = async () => {
    try {
      setIsLoadingPost(true);
      const post = await fetchPost(postId);
      setFormData({
        title: post.title.rendered,
        content: post.content.rendered,
        categories: post.categories,
        status: post.status,
        featured_media: post.featured_media
      });
      
      // Load featured image if exists
      if (post.featured_media) {
        try {
          const media = await fetchMedia(post.featured_media);
          setImagePreviewUrl(media.source_url);
        } catch (mediaError) {
          console.error('Error loading featured media:', mediaError);
        }
      }
    } catch (error) {
      setError('Failed to load post');
      console.error('Error loading post:', error);
    } finally {
      setIsLoadingPost(false);
    }
  };

  const loadCategories = async () => {
    try {
      const categoriesData = await fetchCategories();
      setCategories(categoriesData);
    } catch (error) {
      console.error('Error loading categories:', error);
    }
  };

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      setSelectedFile(file);
      setImagePreviewUrl(URL.createObjectURL(file));
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setIsLoading(true);

    try {
      let featuredMediaId = formData.featured_media;
      
      // Upload new image if selected
      if (selectedFile) {
        setIsUploadingImage(true);
        try {
          const mediaResponse = await uploadMedia(selectedFile);
          featuredMediaId = mediaResponse.id;
        } catch (uploadError) {
          setError('Failed to upload image. Please try again.');
          setIsLoading(false);
          setIsUploadingImage(false);
          return;
        }
        setIsUploadingImage(false);
      }

      await updatePost(postId, {
        ...formData,
        featured_media: featuredMediaId
      });
      setSuccess('Post updated successfully!');
      
      setTimeout(() => {
        router.push('/dashboard');
      }, 2000);
    } catch (error: any) {
      setError(error.message || 'Failed to update post');
    } finally {
      setIsLoading(false);
      setIsUploadingImage(false);
    }
  };

  const handleCategoryChange = (categoryId: number, checked: boolean) => {
    setFormData(prev => ({
      ...prev,
      categories: checked 
        ? [...prev.categories, categoryId]
        : prev.categories.filter(id => id !== categoryId)
    }));
  };

  if (isLoadingPost) {
    return (
      <ProtectedRoute requiredRole="author">
        <div className="min-h-screen bg-white dark:bg-gray-900">
          <Header />
          <main className="pt-32">
            <div className="container mx-auto px-4 py-8">
              <div className="text-center">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto"></div>
                <p className="mt-4 text-gray-600 dark:text-gray-300">Loading post...</p>
              </div>
            </div>
          </main>
          <Footer />
        </div>
      </ProtectedRoute>
    );
  }

  return (
    <ProtectedRoute requiredRole="author">
      <div className="min-h-screen bg-white dark:bg-gray-900">
        <Header />
        <main className="pt-32">
          <div className="container mx-auto px-4 py-8">
            {/* Header */}
            <div className="flex items-center space-x-4 mb-8">
              <Button asChild variant="outline">
                <Link href="/dashboard" className="flex items-center space-x-2">
                  <ArrowLeft className="w-4 h-4" />
                  <span>Back to Dashboard</span>
                </Link>
              </Button>
              <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
                Edit Post
              </h1>
            </div>

            {error && (
              <Alert className="mb-6 border-red-200 bg-red-50 dark:bg-red-950">
                <AlertDescription className="text-red-800 dark:text-red-200">
                  {error}
                </AlertDescription>
              </Alert>
            )}

            {success && (
              <Alert className="mb-6 border-green-200 bg-green-50 dark:bg-green-950">
                <AlertDescription className="text-green-800 dark:text-green-200">
                  {success}
                </AlertDescription>
              </Alert>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
              {/* Main Content */}
              <div className="lg:col-span-3">
                <form onSubmit={handleSubmit} className="space-y-6">
                  <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6">
                    <div className="space-y-6">
                      <div>
                        <Label htmlFor="title" className="text-gray-700 dark:text-gray-300">
                          Post Title
                        </Label>
                        <Input
                          id="title"
                          type="text"
                          value={formData.title}
                          onChange={(e) => setFormData(prev => ({ ...prev, title: e.target.value }))}
                          placeholder="Enter your post title"
                          className="mt-1"
                          required
                        />
                      </div>

                      <div>
                        <Label htmlFor="featuredImage" className="text-gray-700 dark:text-gray-300">
                          Featured Image
                        </Label>
                        <Input
                          id="featuredImage"
                          type="file"
                          accept="image/*"
                          onChange={handleFileChange}
                          className="mt-1"
                        />
                        {imagePreviewUrl && (
                          <div className="mt-4">
                            <img 
                              src={imagePreviewUrl} 
                              alt="Preview" 
                              className="w-full max-w-md h-48 object-cover rounded-lg border border-gray-300 dark:border-gray-600"
                            />
                          </div>
                        )}
                      </div>
                      <div>
                        <Label htmlFor="content" className="text-gray-700 dark:text-gray-300">
                          Content
                        </Label>
                        <Textarea
                          id="content"
                          value={formData.content}
                          onChange={(e) => setFormData(prev => ({ ...prev, content: e.target.value }))}
                          placeholder="Write your post content here..."
                          className="mt-1 min-h-[400px]"
                          required
                        />
                      </div>
                    </div>
                  </div>

                  {/* Action Buttons */}
                  <div className="flex items-center space-x-4">
                    <Button
                      type="submit"
                      className="bg-red-600 hover:bg-red-700"
                      disabled={isLoading || isUploadingImage}
                    >
                      <Save className="w-4 h-4 mr-2" />
                      {isUploadingImage ? 'Uploading Image...' : isLoading ? 'Updating...' : 'Update Post'}
                    </Button>
                    
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => setFormData(prev => ({ ...prev, status: 'publish' }))}
                      disabled={isLoading || isUploadingImage}
                    >
                      <Eye className="w-4 h-4 mr-2" />
                      Publish
                    </Button>
                  </div>
                </form>
              </div>

              {/* Sidebar */}
              <div className="lg:col-span-1">
                <div className="space-y-6">
                  {/* Post Status */}
                  <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
                      Post Status
                    </h3>
                    <Select 
                      value={formData.status} 
                      onValueChange={(value) => setFormData(prev => ({ ...prev, status: value }))}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Select status" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="draft">Draft</SelectItem>
                        <SelectItem value="publish">Publish</SelectItem>
                        <SelectItem value="pending">Pending Review</SelectItem>
                        <SelectItem value="private">Private</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  {/* Categories */}
                  <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
                      Categories
                    </h3>
                    <div className="space-y-3 max-h-64 overflow-y-auto">
                      {categories.map((category) => (
                        <div key={category.id} className="flex items-center space-x-2">
                          <Checkbox
                            id={`category-${category.id}`}
                            checked={formData.categories.includes(category.id)}
                            onCheckedChange={(checked) => 
                              handleCategoryChange(category.id, checked as boolean)
                            }
                          />
                          <Label 
                            htmlFor={`category-${category.id}`}
                            className="text-sm text-gray-700 dark:text-gray-300 cursor-pointer"
                          >
                            {category.name}
                          </Label>
                        </div>
                      ))}
                    </div>
                    {categories.length === 0 && (
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        No categories available
                      </p>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </main>
        <Footer />
      </div>
    </ProtectedRoute>
  );
}