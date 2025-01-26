import test from "node:test";
import assert from "node:assert";
import { comparePassword, hashPassword } from "../../utils/auth.utils";

test("hashPassword should hash a password", async () => {
  const password = "password123";
  const hashedPassword = await hashPassword(password);
  assert.notStrictEqual(hashedPassword, password);
  assert.strictEqual(typeof hashedPassword, "string");
});

test("comparePassword should return true for a matching password", async () => {
  const password = "password123";
  const hashedPassword = await hashPassword(password);
  const result = await comparePassword(password, hashedPassword);
  assert.strictEqual(result, true);
});

test("comparePassword should return false for a non-matching password", async () => {
  const password = "password123";
  const hashedPassword = await hashPassword(password);
  const result = await comparePassword("wrongpassword", hashedPassword);
  assert.strictEqual(result, false);
});
