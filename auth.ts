import NextAuth from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';

export interface WordPressUser {
  id: string;
  username: string;
  email: string;
  displayName: string;
  roles: string[];
  token: string;
}

export const authOptions = {
  providers: [
    CredentialsProvider({
      name: 'WordPress',
      credentials: {
        username: { label: 'Username', type: 'text' },
        password: { label: 'Password', type: 'password' },
      },
      async authorize(credentials) {
        if (!credentials?.username || !credentials?.password) {
          return null;
        }

        try {
          const tokenResponse = await fetch(
            `${process.env.NEXT_PUBLIC_WORDPRESS_SITE_URL}/wp-json/jwt-auth/v1/token`,
            {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({
                username: credentials.username,
                password: credentials.password,
              }),
            }
          );

          if (!tokenResponse.ok) return null;

          const tokenData = await tokenResponse.json();

          const userResponse = await fetch(
            `${process.env.NEXT_PUBLIC_WORDPRESS_SITE_URL}/wp-json/wp/v2/users/me`,
            {
              headers: {
                Authorization: `Bearer ${tokenData.token}`,
              },
            }
          );

          if (!userResponse.ok) return null;

          const userData = await userResponse.json();

          return {
            id: userData.id.toString(),
            name: userData.name,
            email: userData.email,
            username: userData.slug,
            displayName: userData.name,
            roles: userData.roles || ['subscriber'],
            token: tokenData.token,
          };
        } catch (error) {
          console.error('Authentication error:', error);
          return null;
        }
      },
    }),
  ],
  session: {
    strategy: 'jwt' as const,
  },
  pages: {
    signIn: '/auth/signin',
  },
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.id = user.id;
        token.username = (user as any).username;
        token.roles = (user as any).roles;
        token.accessToken = (user as any).token;
        token.displayName = (user as any).displayName || user.name;
      }
      return token;
    },
    async session({ session, token }) {
      session.user.id = token.id;
      session.user.username = token.username;
      session.user.roles = token.roles;
      session.user.accessToken = token.accessToken;
      session.user.displayName = token.displayName;
      return session;
    },
  },
  secret: process.env.NEXTAUTH_SECRET || 'fallback-secret-for-development',
};

export default NextAuth(authOptions);
