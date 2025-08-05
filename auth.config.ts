import type { NextAuthConfig } from 'next-auth';

export const authConfig = {
  trustHost: true,
  useSecureCookies: process.env.NODE_ENV === 'production',
  pages: {
    signIn: '/auth/signin',
  },
  callbacks: {
    authorized({ auth, request: { nextUrl } }) {
      const isLoggedIn = !!auth?.user;
      const isOnDashboard = nextUrl.pathname.startsWith('/dashboard');
      
      if (isOnDashboard) {
        if (isLoggedIn && auth?.user?.roles?.includes('author')) return true;
        return false;
      }
      
      return true;
    },
    jwt({ token, user }) {
      if (user) {
        token.id = user.id || '';
        token.username = (user as any).username || '';
        token.roles = (user as any).roles || ['subscriber'];
        token.accessToken = (user as any).token || '';
        token.displayName = (user as any).displayName || user.name || '';
      }
      return token;
    },
    session({ session, token }) {
      if (token) {
        session.user.id = (token.id as string) || '';
        session.user.username = (token.username as string) || '';
        session.user.roles = (token.roles as string[]) || ['subscriber'];
        session.user.accessToken = (token.accessToken as string) || '';
        session.user.displayName =
          (token.displayName as string) || session.user.name || '';
      }
      return session;
    },
  },
  providers: [],
} satisfies NextAuthConfig;