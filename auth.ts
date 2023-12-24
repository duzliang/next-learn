import NextAuth from 'next-auth';
import { authConfig } from './auth.config';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import { sql } from '@vercel/postgres';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';

async function getUserByEmail(email: string) {
  try {
    const { rows } = await sql<User>`SELECT * FROM users WHERE email = ${email}`;
    return rows[0];
  } catch (err) {
    console.error('Failed to fetch user:', err);
    throw new Error('Failed to fetch user');
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [Credentials({
    async authorize(credentials) {
      const parsedCredentials = z.object({
        email: z.string().email(),
        password: z.string().min(6),
      }).safeParse(credentials);

      if (parsedCredentials.success) {
        const { email, password } = parsedCredentials.data;

        if (email) {
          const user = await getUserByEmail(email);
          if (!user) {
            return null;
          }

          const passwordMatch = await bcrypt.compare(password, user.password);
          if (passwordMatch) {
            return user;
          }
        }
      }

      console.log('log=>Invalid credentials');
      return null;
    }
  })],
});
