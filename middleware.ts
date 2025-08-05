import { NextRequest, NextResponse } from 'next/server';
import { getToken } from 'next-auth/jwt';

export default async function middleware(request: NextRequest) {
  const token = await getToken({ 
    req: request,
    secret: process.env.NEXTAUTH_SECRET || 'fallback-secret-for-development'
  });
  
  const { pathname } = request.nextUrl;
  
  // Protect dashboard routes - require author role
  if (pathname.startsWith('/dashboard')) {
    if (!token || !token.roles?.includes('author')) {
      return NextResponse.redirect(new URL('/unauthorized', request.url));
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    '/dashboard/:path*',
    '/api/posts/:path*'
  ]
};