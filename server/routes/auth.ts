import type { Context } from "@/context";
import {
  createUser,
  getUserFromUsername,
  getUsernameFromUserId,
} from "@/db/queries/auth";
import { lucia } from "@/lucia";
import { loggedIn } from "@/middleware/logged-in";
import { loginSchema, type SuccessResponse } from "@/shared/types";
import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import { generateId } from "lucia";
import postgres from "postgres";

export const authRouter = new Hono<Context>()
  .post("/signup", zValidator("form", loginSchema), async (c) => {
    const { username, password } = c.req.valid("form");
    const passwordHash = await Bun.password.hash(password);
    const userId = generateId(15);

    try {
      await createUser(userId, username, passwordHash);

      const session = await lucia.createSession(userId, { username });
      const sessionCookie = lucia.createSessionCookie(session.id).serialize();

      c.header("Set-Cookie", sessionCookie, { append: true });
      return c.json<SuccessResponse>(
        {
          success: true,
          message: "User Created",
        },
        201,
      );
    } catch (error) {
      if (error instanceof postgres.PostgresError && error.code === "23505") {
        throw new HTTPException(409, { message: "Username already used" });
      }
      throw new HTTPException(500, { message: "Failed to create user" });
    }
  })
  .post("/login", zValidator("form", loginSchema), async (c) => {
    const { username, password } = c.req.valid("form");

    const existingUser = await getUserFromUsername(username);

    if (!existingUser) {
      throw new HTTPException(401, { message: "Incorrect username" });
    }

    const validPassword = Bun.password.verify(
      password,
      existingUser.password_hash,
    );

    if (!validPassword) {
      throw new HTTPException(401, { message: "Incorrect password" });
    }

    const session = await lucia.createSession(existingUser.id, { username });
    const sessionCookie = lucia.createSessionCookie(session.id).serialize();

    c.header("Set-Cookie", sessionCookie, { append: true });
    return c.json<SuccessResponse>(
      {
        success: true,
        message: "Logged In",
      },
      200,
    );
  })
  .get("/logout", async (c) => {
    const session = c.get("session");

    if (!session) {
      return c.redirect("/");
    }

    await lucia.invalidateSession(session.id);
    c.header("Set-Cookie", lucia.createBlankSessionCookie().serialize());

    return c.redirect("/");
  })
  .get("/user", loggedIn, async (c) => {
    const user = c.get("user")!;
    const username = await getUsernameFromUserId(user);

    return c.json<SuccessResponse<{ username: string }>>({
      success: true,
      message: "User fetched",
      data: { username },
    });
  });
