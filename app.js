const express = require("express");
require("dotenv").config();

const app = express();
app.use(express.json());

const usersRouter = require("./routes/users.js");
app.use("/api/users", usersRouter);

const authRouter = require("./routes/auth.js");
app.use("/api/auth", authRouter);

app.listen(process.env.PORT || 3000, () =>
  console.log(
    `Servidor escuchando en http://localhost:${process.env.PORT || 3000}`
  )
);
