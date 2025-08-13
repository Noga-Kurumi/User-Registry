const jwt = require("jsonwebtoken");

function auth(requiredRole) {
  return (req, res, next) => {
    const authHeaders = req.get("authorization");

    if (!authHeaders || !authHeaders.startsWith("Bearer ")) {
      return res
        .status(401)
        .json({ error: "Autenticacion con formato invalido." });
    }

    const token = authHeaders.split(" ")[1];

    if (!token) {
      return res.status(401).json({ error: "Token no proporcionado" });
    }

    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET);

      req.user = { sub: payload.sub, role: payload.role };

      if (requiredRole) {
        const needed = Array.isArray(requiredRole)
          ? requiredRole
          : [requiredRole];

        if (!needed.includes(req.user.role)) {
          return res.status(403).json({ error: "Rol no autorizado." });
        } else {
          console.log("Acceso concedido");
        }
      }

      return next();
    } catch (err) {
      console.error(err);
      return res.status(401).json({ error: "Token expirado o invalido" });
    }
  };
}

function ownerOrAdmin(req, res, next) {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "ID inválido" });
  }

  if (req.user?.role === "admin" || req.user?.sub === id) {
    return next();
  }
  return res.status(403).json({ error: "No autorizado" });
}

module.exports = { auth, ownerOrAdmin };
