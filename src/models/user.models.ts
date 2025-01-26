import pool from "../config/db";

export type Role = "admin" | "user";

export interface User {
  id: number;
  name: string;
  email: string;
  password: string;
  role: Role;
}

export const createUserTable = async () => {
  const query = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      email VARCHAR(100) UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role VARCHAR(10) DEFAULT 'user'
    );
  `;

  await pool.query(query);
  console.log("User table created");
};
