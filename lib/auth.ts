import { getServerSession } from 'next-auth/next';
import { authOptions } from '@/auth';

export { authOptions };

// Server-side auth utilities
export async function getServerSession() {
  return await getServerSession(authOptions);
}

export async function requireAuth() {
  const session = await getServerSession(authOptions);
  if (!session) {
    throw new Error('Authentication required');
  }
  return session;
}

export async function requireRole(role: string) {
  const session = await requireAuth();
  if (!session.user?.roles?.includes(role)) {
    throw new Error(`Role '${role}' required`);
  }
  return session;
}