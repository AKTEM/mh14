import { getSession } from 'next-auth/react';

const API_URL = (process.env.NEXT_PUBLIC_WORDPRESS_SITE_URL || 'https://mapleepoch.com') + '/wp-json/wp/v2';

export interface WordPressPost {
  id: number;
  title: {
    rendered: string;
  };
  content: {
    rendered: string;
  };
  excerpt: {
    rendered: string;
  };
  status: string;
  categories: number[];
  author: number;
  date: string;
  modified: string;
  slug: string;
  featured_media: number;
}

export interface WordPressCategory {
  id: number;
  name: string;
  slug: string;
  description: string;
}

async function getAuthHeaders() {
  if (typeof window !== 'undefined') {
    // Client-side: use getSession from next-auth/react
    const { getSession } = await import('next-auth/react');
    const session = await getSession();
    if (!session?.user?.accessToken) {
      throw new Error('No authentication token available');
    }
    return {
      'Authorization': `Bearer ${session.user.accessToken}`,
      'Content-Type': 'application/json',
    };
  } else {
    // Server-side: cannot access session, throw error
    throw new Error('Authentication not available on server-side');
  }
}

export async function fetchUserPosts(authorId?: string): Promise<WordPressPost[]> {
  try {
    const headers = await getAuthHeaders();
    const url = authorId 
      ? `${API_URL}/posts?author=${authorId}&_embed=true`
      : `${API_URL}/posts?_embed=true`;

    const response = await fetch(url, { headers });
    
    if (!response.ok) {
      throw new Error(`Failed to fetch posts: ${response.statusText}`);
    }

    return await response.json();
  } catch (error) {
    console.error('Error fetching user posts:', error);
    throw error;
  }
}

export async function createPost(postData: {
  title: string;
  content: string;
  categories: number[];
  status?: string;
  featured_media?: number;
}): Promise<WordPressPost> {
  try {
    const headers = await getAuthHeaders();
    
    const response = await fetch(`${API_URL}/posts`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        title: postData.title,
        content: postData.content,
        categories: postData.categories,
        status: postData.status || 'draft',
        featured_media: postData.featured_media,
      }),
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.message || 'Failed to create post');
    }

    return await response.json();
  } catch (error) {
    console.error('Error creating post:', error);
    throw error;
  }
}

export async function updatePost(
  postId: number,
  postData: {
    title?: string;
    content?: string;
    categories?: number[];
    status?: string;
    featured_media?: number;
  }
): Promise<WordPressPost> {
  try {
    const headers = await getAuthHeaders();
    
    const response = await fetch(`${API_URL}/posts/${postId}`, {
      method: 'PUT',
      headers,
      body: JSON.stringify(postData),
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.message || 'Failed to update post');
    }

    return await response.json();
  } catch (error) {
    console.error('Error updating post:', error);
    throw error;
  }
}

export async function deletePost(postId: number): Promise<void> {
  try {
    const headers = await getAuthHeaders();
    
    const response = await fetch(`${API_URL}/posts/${postId}`, {
      method: 'DELETE',
      headers,
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.message || 'Failed to delete post');
    }
  } catch (error) {
    console.error('Error deleting post:', error);
    throw error;
  }
}

export async function fetchCategories(): Promise<WordPressCategory[]> {
  try {
    const response = await fetch(`${API_URL}/categories?per_page=100`);
    
    if (!response.ok) {
      throw new Error('Failed to fetch categories');
    }

    return await response.json();
  } catch (error) {
    console.error('Error fetching categories:', error);
    throw error;
  }
}

export async function fetchPost(postId: number): Promise<WordPressPost> {
  try {
    const headers = await getAuthHeaders();
    
    const response = await fetch(`${API_URL}/posts/${postId}`, { headers });
    
    if (!response.ok) {
      throw new Error('Failed to fetch post');
    }

    return await response.json();
  } catch (error) {
    console.error('Error fetching post:', error);
    throw error;
  }
}

export async function uploadMedia(file: File): Promise<{ id: number; source_url: string }> {
  try {
    const headers = await getAuthHeaders();
    
    const formData = new FormData();
    formData.append('file', file);
    
    const response = await fetch(`${API_URL}/media`, {
      method: 'POST',
      headers: {
        'Authorization': headers.Authorization,
        'Content-Disposition': `attachment; filename="${file.name}"`,
      },
      body: formData,
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.message || 'Failed to upload media');
    }

    const mediaData = await response.json();
    return {
      id: mediaData.id,
      source_url: mediaData.source_url
    };
  } catch (error) {
    console.error('Error uploading media:', error);
    throw error;
  }
}

export async function fetchMedia(id: number): Promise<{ id: number; source_url: string }> {
  try {
    const headers = await getAuthHeaders();
    
    const response = await fetch(`${API_URL}/media/${id}`, { headers });
    
    if (!response.ok) {
      throw new Error('Failed to fetch media');
    }

    const mediaData = await response.json();
    return {
      id: mediaData.id,
      source_url: mediaData.source_url
    };
  } catch (error) {
    console.error('Error fetching media:', error);
    throw error;
  }
}