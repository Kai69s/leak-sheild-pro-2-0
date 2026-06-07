const { setApiSecurityHeaders } = require("../_security");

module.exports = function handler(req, res) {
  setApiSecurityHeaders(req, res, { methods: "GET,OPTIONS" });

  if (req.method === "OPTIONS") return res.status(204).end();
  return res.status(404).json({ detail: "Scan history is stored in the browser for the free Vercel demo." });
};

