const express = require("express");
const bcrypt = require("bcrypt");
const { auth, ownerOrAdmin } = require("../middleware/auth.js");
const { pool } = require("../db/pool.js");

const usersRouter = express.Router();

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const cryptSaltRounds = 12;

usersRouter.get("/", auth(["admin"]), async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, display_name, email, created_at FROM users ORDER BY id ASC"
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Error en la base de datos" });
  }
});

usersRouter.get("/:id", auth(), ownerOrAdmin, async (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "ID Invalido" });
  }

  try {
    const result = await pool.query(
      "SELECT id, display_name, email, created_at FROM users WHERE id = $1",
      [id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Usuario no encontrado." });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Error en la base de datos" });
  }
});

usersRouter.post("/", async (req, res) => {
  let { username, email, password } = req.body;

  if (
    typeof username !== "string" ||
    typeof email !== "string" ||
    typeof password !== "string"
  ) {
    return res.status(400).json({ error: "Datos del body invalidos" });
  }

  username = username.trim();
  email = email.trim().toLowerCase();
  password = password.trim();

  if (username === "" || email === "" || password === "") {
    return res.status(400).json({ error: "Datos del body vacios" });
  }

  if (username.length < 2 || username.length > 50) {
    return res.status(400).json({ error: "Usuario muy corto o largo" });
  }

  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: "Formato de email invalido." });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: "Contraseña muy corta." });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, cryptSaltRounds);

    const result = await pool.query(
      "INSERT INTO users (email, password_hash, display_name) VALUES ($1, $2, $3) RETURNING id, display_name, email, created_at",
      [email, hashedPassword, username]
    );
    res
      .status(201)
      .location(`/api/users/${result.rows[0].id}`)
      .json(result.rows[0]);
  } catch (err) {
    if (err.code === "23505") {
      console.error(err);
      return res.status(400).json({ error: "Usuario o mail ya registrados." });
    } else {
      return res.status(500).json({ error: "Error en la base de datos" });
    }
  }
});

usersRouter.put("/:id", auth(), ownerOrAdmin, async (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "ID Invalido" });
  }

  let { username, email, password } = req.body;

  if (
    typeof username !== "string" ||
    typeof email !== "string" ||
    typeof password !== "string"
  ) {
    return res.status(400).json({ error: "Datos del body invalidos" });
  }

  username = username.trim();
  email = email.trim().toLowerCase();
  password = password.trim();

  if (username === "" || email === "" || password === "") {
    return res.status(400).json({ error: "Datos del body vacios" });
  }

  if (username.length < 2 || username.length > 50) {
    return res.status(400).json({ error: "Usuario muy corto o largo" });
  }

  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: "Formato de email invalido." });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: "Contraseña muy corta." });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, cryptSaltRounds);
    const result = await pool.query(
      "UPDATE users SET email = $1, password_hash = $2, display_name = $3 WHERE id = $4 RETURNING id, email, display_name, created_at",
      [email, hashedPassword, username, id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Usuario no encontrado." });
    }

    res.json(result.rows[0]);
  } catch (err) {
    if (err.code === "23505") {
      console.error(err);
      return res.status(400).json({ error: "Usuario o mail ya registrados." });
    } else {
      return res.status(500).json({ error: "Error en la base de datos" });
    }
  }
});

usersRouter.delete("/:id", auth("admin"), async (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "ID Invalido" });
  }

  try {
    const result = await pool.query("DELETE FROM users WHERE id = $1", [id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Usuario no encontrado." });
    }

    return res.status(204).end();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error en la base de datos" });
  }
});

module.exports = usersRouter;
