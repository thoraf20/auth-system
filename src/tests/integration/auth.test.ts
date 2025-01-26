import test from "node:test";
import assert from "node:assert";
import request from "supertest";
import { createUserTable } from "../../models/user.models";
import pool from "../../config/db";
import app from "../../app";

// Setup: Run before all tests
test.before(async () => {
  await createUserTable(); // Ensure the users table exists
  // await pool.query(
  //   "INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4)",
  //   ["Admin User", "admin@example.com", "hashedpassword", "admin"]
  // );
});

// Teardown: Run after all tests
test.after(async () => {
  await pool.query("DROP TABLE IF EXISTS users"); // Clean up the users table
  await pool.end(); // Close the database connection pool
});

// Test: User Registration
test("User Registration - should register a new user", async () => {
  const res = await request(app).post("/api/auth/register").send({
    name: "Test User",
    email: "test@example.com",
    password: "password123",
  });

  assert.strictEqual(res.status, 201);
  assert.strictEqual(res.body.message, "User registered successfully");

  // Check if the user was saved in the database
  const { rows } = await pool.query("SELECT * FROM users WHERE email = $1", [
    "test@example.com",
  ]);
  assert.strictEqual(rows.length, 1);
  assert.strictEqual(rows[0].name, "Test User");
  assert.strictEqual(rows[0].email, "test@example.com");
  assert.strictEqual(rows[0].role, "user");
});

test("User Login - should log in a user and return a token", async () => {
  // Insert a test user
  await pool.query(
    "INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4)",
    ["Test User", "test@example.com", "hashedpassword", "user"]
  );

  // Log in the user
  const res = await request(app).post("/api/login").send({
    email: "test@example.com",
    password: "password123", // Assuming the password is hashed correctly
  });

  assert.strictEqual(res.status, 200);
  assert.strictEqual(typeof res.body.token, "string");
});

test("Admin Access - should allow admin to access admin-only route", async () => {
  // Insert an admin user
  await pool.query(
    "INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4)",
    ["Admin User", "admin@example.com", "hashedpassword", "admin"]
  );

  // Log in the admin user
  const loginRes = await request(app).post("/api/login").send({
    email: "admin@example.com",
    password: "password123",
  });

  const token = loginRes.body.token;

  // Access an admin-only route
  const res = await request(app)
    .get("/api/admin")
    .set("Authorization", `Bearer ${token}`);

  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.body.message, "Welcome, Admin");
});

test.afterEach(async () => {
  await pool.query("DELETE FROM users");
});