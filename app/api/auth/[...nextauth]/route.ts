// Next.js App Router API Route: [...nextauth]는 catch-all route로, /api/auth/로 시작하는 모든 경로를 처리합니다

import bycrypt from "bcrypt";
import NextAuth, { AuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import GithubProvider from "next-auth/providers/github";
import GoogleProvider from "next-auth/providers/google";
import { PrismaAdapter } from "@next-auth/prisma-adapter";

import prisma from "@/app/libs/prismadb";

export const authOptions: AuthOptions = {
  adapter: PrismaAdapter(prisma),
  providers: [
    GithubProvider({
      clientId: process.env.GITHUB_ID as string,
      clientSecret: process.env.GITHUB_SECRET as string,
    }),
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID as string,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET as string,
    }),
    CredentialsProvider({ // using email and password
      name: "credentials",
      credentials: {
        email: { label: "email", type: "text" },
        password: { label: "password", type: "password" },
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) {
          throw new Error("Missing email or password");
        }

        const user = await prisma.user.findUnique({
          where: {
            email: credentials.email,
          },
        });

        if (!user || !user?.hashedPassword) { // users sigend in with google or github will not have a hashed password
          throw new Error("Invalid credentials");
        }

        const isCorrectPassword = await bycrypt.compare(
          credentials.password, // password from the form
          user.hashedPassword // password from the database
        );

        if (!isCorrectPassword) {
          throw new Error("Invalid credentials");
        }

        return user;
      },
    })
  ],
  debug: process.env.NODE_ENV === "development", // only show debug messages in development
  session: {
    strategy: "jwt",
  },
  secret: process.env.NEXTAUTH_SECRET,
};

const handler = NextAuth(authOptions);

// HTTP 메서드 내보내기: NextAuth가 GET과 POST 요청을 모두 처리할 수 있도록 handler를 두 메서드로 내보냅니다
export { handler as GET, handler as POST };