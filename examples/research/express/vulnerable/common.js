// Owned CommonJS fixture; never executed.
const express = require("express");
const child = require("node:child_process");
const files = require("node:fs");
const app = express();
app.get("/owned-command", (request, response) => {
  child.exec(request.query.command, () => response.end());
});
app.post("/owned-expression", (request, response) => {
  response.send(eval(request.body.expression));
});
app.get("/owned-file/:name", (request, response) => {
  files.readFile(request.params.name, () => response.end());
});
