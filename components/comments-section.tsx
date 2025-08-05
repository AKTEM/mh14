"use client";

import { useState } from 'react';
import { useSession } from 'next-auth/react';
import Link from 'next/link';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { 
  MessageCircle, 
  User, 
  Clock, 
  Heart, 
  Reply, 
  Flag,
  Send,
  LogIn
} from 'lucide-react';

interface Comment {
  id: number;
  author: string;
  content: string;
  timestamp: Date;
  likes: number;
  isLiked: boolean;
  replies: Comment[];
}

interface CommentsSectionProps {
  articleId: number;
}

export function CommentsSection({ articleId }: CommentsSectionProps) {
  const { data: session } = useSession();
  const [comments, setComments] = useState<Comment[]>([
    {
      id: 1,
      author: "Sarah Johnson",
      content: "This is a really insightful article. The analysis provided here gives a fresh perspective on the current situation.",
      timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2 hours ago
      likes: 12,
      isLiked: false,
      replies: [
        {
          id: 2,
          author: "Mike Chen",
          content: "I completely agree! The data presented really supports the main arguments.",
          timestamp: new Date(Date.now() - 1 * 60 * 60 * 1000), // 1 hour ago
          likes: 5,
          isLiked: false,
          replies: []
        }
      ]
    },
    {
      id: 3,
      author: "Emma Rodriguez",
      content: "Thank you for covering this important topic. More people need to be aware of these developments.",
      timestamp: new Date(Date.now() - 3 * 60 * 60 * 1000), // 3 hours ago
      likes: 8,
      isLiked: false,
      replies: []
    }
  ]);
  
  const [newComment, setNewComment] = useState('');
  const [replyingTo, setReplyingTo] = useState<number | null>(null);
  const [replyContent, setReplyContent] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmitComment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newComment.trim() || !session) return;

    setIsSubmitting(true);
    
    // Simulate API call delay
    await new Promise(resolve => setTimeout(resolve, 1000));

    const comment: Comment = {
      id: Date.now(),
      author: session.user.displayName || session.user.username,
      content: newComment.trim(),
      timestamp: new Date(),
      likes: 0,
      isLiked: false,
      replies: []
    };

    setComments(prev => [comment, ...prev]);
    setNewComment('');
    setIsSubmitting(false);
  };

  const handleSubmitReply = async (parentId: number) => {
    if (!replyContent.trim() || !session) return;

    setIsSubmitting(true);
    
    // Simulate API call delay
    await new Promise(resolve => setTimeout(resolve, 1000));

    const reply: Comment = {
      id: Date.now(),
      author: session.user.displayName || session.user.username,
      content: replyContent.trim(),
      timestamp: new Date(),
      likes: 0,
      isLiked: false,
      replies: []
    };

    setComments(prev => prev.map(comment => 
      comment.id === parentId 
        ? { ...comment, replies: [...comment.replies, reply] }
        : comment
    ));
    
    setReplyContent('');
    setReplyingTo(null);
    setIsSubmitting(false);
  };

  const handleLikeComment = (commentId: number, isReply: boolean = false, parentId?: number) => {
    if (!session) return;

    if (isReply && parentId) {
      setComments(prev => prev.map(comment => 
        comment.id === parentId 
          ? {
              ...comment,
              replies: comment.replies.map(reply =>
                reply.id === commentId
                  ? {
                      ...reply,
                      likes: reply.isLiked ? reply.likes - 1 : reply.likes + 1,
                      isLiked: !reply.isLiked
                    }
                  : reply
              )
            }
          : comment
      ));
    } else {
      setComments(prev => prev.map(comment => 
        comment.id === commentId 
          ? {
              ...comment,
              likes: comment.isLiked ? comment.likes - 1 : comment.likes + 1,
              isLiked: !comment.isLiked
            }
          : comment
      ));
    }
  };

  const formatTimeAgo = (timestamp: Date) => {
    const now = new Date();
    const diffInMinutes = Math.floor((now.getTime() - timestamp.getTime()) / (1000 * 60));
    
    if (diffInMinutes < 1) return 'Just now';
    if (diffInMinutes < 60) return `${diffInMinutes}m ago`;
    
    const diffInHours = Math.floor(diffInMinutes / 60);
    if (diffInHours < 24) return `${diffInHours}h ago`;
    
    const diffInDays = Math.floor(diffInHours / 24);
    return `${diffInDays}d ago`;
  };

  const CommentComponent = ({ comment, isReply = false, parentId }: { 
    comment: Comment; 
    isReply?: boolean; 
    parentId?: number;
  }) => (
    <div className={`${isReply ? 'ml-8 border-l-2 border-gray-200 dark:border-gray-700 pl-4' : ''}`}>
      <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
        <div className="flex items-start justify-between mb-3">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 bg-red-600 rounded-full flex items-center justify-center">
              <User className="w-4 h-4 text-white" />
            </div>
            <div>
              <div className="font-medium text-gray-900 dark:text-white text-sm">
                {comment.author}
              </div>
              <div className="flex items-center space-x-2 text-xs text-gray-500 dark:text-gray-400">
                <Clock className="w-3 h-3" />
                <span>{formatTimeAgo(comment.timestamp)}</span>
              </div>
            </div>
          </div>
          
          <Button variant="ghost" size="sm" className="text-gray-400 hover:text-red-600">
            <Flag className="w-4 h-4" />
          </Button>
        </div>
        
        <p className="text-gray-700 dark:text-gray-300 text-sm mb-3 leading-relaxed">
          {comment.content}
        </p>
        
        <div className="flex items-center space-x-4">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => handleLikeComment(comment.id, isReply, parentId)}
            className={`text-xs ${comment.isLiked ? 'text-red-600' : 'text-gray-500 dark:text-gray-400'} hover:text-red-600`}
            disabled={!session}
          >
            <Heart className={`w-4 h-4 mr-1 ${comment.isLiked ? 'fill-current' : ''}`} />
            {comment.likes}
          </Button>
          
          {!isReply && session && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setReplyingTo(replyingTo === comment.id ? null : comment.id)}
              className="text-xs text-gray-500 dark:text-gray-400 hover:text-red-600"
            >
              <Reply className="w-4 h-4 mr-1" />
              Reply
            </Button>
          )}
        </div>
        
        {/* Reply Form */}
        {replyingTo === comment.id && session && (
          <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-600">
            <form onSubmit={(e) => { e.preventDefault(); handleSubmitReply(comment.id); }}>
              <Textarea
                value={replyContent}
                onChange={(e) => setReplyContent(e.target.value)}
                placeholder="Write a reply..."
                className="mb-3 text-sm"
                rows={3}
              />
              <div className="flex items-center space-x-2">
                <Button 
                  type="submit" 
                  size="sm"
                  className="bg-red-600 hover:bg-red-700"
                  disabled={!replyContent.trim() || isSubmitting}
                >
                  <Send className="w-4 h-4 mr-1" />
                  {isSubmitting ? 'Posting...' : 'Reply'}
                </Button>
                <Button 
                  type="button" 
                  variant="outline" 
                  size="sm"
                  onClick={() => {
                    setReplyingTo(null);
                    setReplyContent('');
                  }}
                >
                  Cancel
                </Button>
              </div>
            </form>
          </div>
        )}
      </div>
      
      {/* Replies */}
      {comment.replies.length > 0 && (
        <div className="mt-4 space-y-4">
          {comment.replies.map((reply) => (
            <CommentComponent 
              key={reply.id} 
              comment={reply} 
              isReply={true} 
              parentId={comment.id}
            />
          ))}
        </div>
      )}
    </div>
  );

  return (
    <section className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6 mt-8">
      <div className="flex items-center space-x-3 mb-6">
        <MessageCircle className="w-6 h-6 text-red-600" />
        <h3 className="text-xl font-bold text-gray-900 dark:text-white">
          Comments ({comments.length})
        </h3>
      </div>

      {/* Comment Form */}
      {session ? (
        <div className="mb-8">
          <div className="flex items-center space-x-3 mb-4">
            <div className="w-10 h-10 bg-red-600 rounded-full flex items-center justify-center">
              <User className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="font-medium text-gray-900 dark:text-white">
                {session.user.displayName || session.user.username}
              </div>
              <div className="text-sm text-gray-500 dark:text-gray-400">
                Share your thoughts
              </div>
            </div>
          </div>
          
          <form onSubmit={handleSubmitComment} className="space-y-4">
            <Textarea
              value={newComment}
              onChange={(e) => setNewComment(e.target.value)}
              placeholder="What are your thoughts on this article?"
              className="min-h-[100px] resize-none"
              maxLength={1000}
            />
            
            <div className="flex items-center justify-between">
              <div className="text-sm text-gray-500 dark:text-gray-400">
                {newComment.length}/1000 characters
              </div>
              <Button 
                type="submit"
                className="bg-red-600 hover:bg-red-700"
                disabled={!newComment.trim() || isSubmitting}
              >
                <Send className="w-4 h-4 mr-2" />
                {isSubmitting ? 'Posting...' : 'Post Comment'}
              </Button>
            </div>
          </form>
        </div>
      ) : (
        <Alert className="mb-8 border-red-200 bg-red-50 dark:bg-red-950">
          <LogIn className="w-4 h-4" />
          <AlertDescription className="text-red-800 dark:text-red-200">
            <div className="flex items-center justify-between">
              <span>Please sign in to join the conversation and share your thoughts.</span>
              <div className="flex items-center space-x-2 ml-4">
                <Button asChild size="sm" className="bg-red-600 hover:bg-red-700">
                  <Link href="/auth/signin">Sign In</Link>
                </Button>
                <Button asChild variant="outline" size="sm">
                  <Link href="/auth/signup">Sign Up</Link>
                </Button>
              </div>
            </div>
          </AlertDescription>
        </Alert>
      )}

      {/* Comments List */}
      <div className="space-y-6">
        {comments.length > 0 ? (
          comments.map((comment) => (
            <CommentComponent key={comment.id} comment={comment} />
          ))
        ) : (
          <div className="text-center py-12">
            <MessageCircle className="w-12 h-12 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
            <h4 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
              No comments yet
            </h4>
            <p className="text-gray-600 dark:text-gray-300">
              Be the first to share your thoughts on this article.
            </p>
          </div>
        )}
      </div>

      {/* Comment Guidelines */}
      <div className="mt-8 pt-6 border-t border-gray-200 dark:border-gray-700">
        <h4 className="font-medium text-gray-900 dark:text-white mb-3">
          Community Guidelines
        </h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-gray-600 dark:text-gray-400">
          <div className="flex items-start space-x-2">
            <div className="w-2 h-2 bg-red-600 rounded-full mt-2 flex-shrink-0"></div>
            <span>Be respectful and constructive in your comments</span>
          </div>
          <div className="flex items-start space-x-2">
            <div className="w-2 h-2 bg-red-600 rounded-full mt-2 flex-shrink-0"></div>
            <span>Stay on topic and relevant to the article</span>
          </div>
          <div className="flex items-start space-x-2">
            <div className="w-2 h-2 bg-red-600 rounded-full mt-2 flex-shrink-0"></div>
            <span>No spam, harassment, or offensive language</span>
          </div>
          <div className="flex items-start space-x-2">
            <div className="w-2 h-2 bg-red-600 rounded-full mt-2 flex-shrink-0"></div>
            <span>Report inappropriate content using the flag button</span>
          </div>
        </div>
      </div>
    </section>
  );
}