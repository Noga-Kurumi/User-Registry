const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { pool } = require("../db/pool.js");

const authRouter = express.Router();

authRouter.post("/login", async (req, res) => {
  let { email, password } = req.body;

  if (typeof email !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "Datos del body invalidos" });
  }

  email = email.trim().toLowerCase();
  password = password.trim();

  if (email === "" || password === "") {
    return res.status(400).json({ error: "Datos del body vacíos" });
  }

  try {
    const result = await pool.query(
      "SELECT id, email, display_name, password_hash, is_active, role FROM users WHERE email = $1",
      [email]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({ error: "Email o contraseña incorrectos." });
    }

    if (!process.env.JWT_SECRET) {
      console.error("Falta JWT_SECRET");
      return res
        .status(500)
        .json({ error: "Configuración del servidor inválida" });
    }

    if (!result.rows[0].is_active) {
      return res.status(403).json({ error: "Cuenta desactivada." });
    }

    const matchPassword = await bcrypt.compare(
      password,
      result.rows[0].password_hash
    );

    const user = result.rows[0];

    if (matchPassword) {
      const token = jwt.sign(
        { sub: user.id, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES || "12h" }
      );

      return res.json({
        token,
        user: {
          id: user.id,
          email: user.email,
          display_name: user.display_name,
          role: user.role,
        },
      });
    } else {
      return res.status(401).json({ error: "Email o contraseña incorrectos." });
    }
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Error en la base de datos." });
  }
});

module.exports = authRouter;
