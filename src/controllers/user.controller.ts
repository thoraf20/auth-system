import pool from "../config/db";

export const getUserProfile = async (req, res) => {
  const { id } = req.user;

  try {
    const user = await pool.query("SELECT * FROM users WHERE id = $1", [
    id,
  ]);
  if (user.rows.length === 0) {
    return res.status(404).json({ message: "User not found" });
  }

  return res.status(200).json({
    message: "Successfully retrieved",
    user: { id: user.rows[0].id, name: user.rows[0].name, email: user.rows[0].email },
  });
  } catch (error) {
    console.error("Registration Error:", error);
    return res.status(500).json({ message: "Server error" });
  }
};