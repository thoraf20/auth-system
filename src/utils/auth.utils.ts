import bcrypt from "bcryptjs";
import nodemailer from "nodemailer"
import crypto from "crypto"

export async function hashPassword(password: string): Promise<string> {
  const saltRounds = 10;
  return bcrypt.hash(password, saltRounds);
}

export async function comparePassword(
  password: string,
  hashedPassword: string
): Promise<boolean> {
  return bcrypt.compare(password, hashedPassword);
}

// Generate a random token
export const generateToken = () => crypto.randomBytes(20).toString('hex');

// Nodemailer transporter (configure with your email service)
export const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER, // Your email
    pass: process.env.EMAIL_PASS, // Your email password
  },
});