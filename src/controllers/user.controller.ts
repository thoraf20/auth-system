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

// Update Profile Controller
export const updateProfile = async (req, res) => {
  const { name, email } = req.body;
  const userId = (req as any).user.id;

  try {
    // Check if the new email is already taken by another user
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1 AND id != $2', [
      email,
      userId,
    ]);
    if (rows.length > 0) {
      return res.status(400).json({ message: 'Email already in use' });
    }

    // Update the user's profile
    await pool.query('UPDATE users SET name = $1, email = $2 WHERE id = $3', [
      name,
      email,
      userId,
    ]);

    res.status(200).json({ message: 'Profile updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
};