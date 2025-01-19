import { db } from "@/adapter";
import { userTable } from "../schemas/auth";
import { eq } from "drizzle-orm";
import type { User } from "lucia";

export async function createUser(
  userId: string,
  username: string,
  passwordHash: string,
) {
  await db.insert(userTable).values({
    id: userId,
    username,
    password_hash: passwordHash,
  });
}

export async function getUserFromUsername(username: string) {
  const [existingUser] = await db
    .select()
    .from(userTable)
    .where(eq(userTable.username, username))
    .limit(1);

  return existingUser;
}

export async function getUsernameFromUserId(user: User) {
  const [existingUser] = await db
    .select()
    .from(userTable)
    .where(eq(userTable.id, user.id))
    .limit(1);

  return existingUser.username;
}
