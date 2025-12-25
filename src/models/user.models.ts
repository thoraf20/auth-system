import pool from "../config/db";
import logger from "../utils/logger";

export type Role = "admin" | "user";

export interface User {
  id: number;
  name: string;
  email: string;
  password: string;
  role: Role;
  refresh_token?: string;
  is_verified: boolean;
  verification_token?: string;
  reset_token?: string;
  reset_token_expiry?: number;
  two_factor_secret?: string;
  is_two_factor_enabled: boolean;
}

export const createUserTable = async () => {
  const query = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      email VARCHAR(100) UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role VARCHAR(10) DEFAULT 'user',
      refresh_token TEXT,
      is_verified BOOLEAN DEFAULT FALSE,
      verification_token VARCHAR(255),
      reset_token VARCHAR(255),
      reset_token_expiry BIGINT,
      two_factor_secret VARCHAR(255),
      is_two_factor_enabled BOOLEAN DEFAULT FALSE
    );
  `;

  await pool.query(query);
  logger.info("User table created/updated");
};


