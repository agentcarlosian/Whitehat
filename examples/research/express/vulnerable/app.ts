// Owned static-analysis fixture. This file is never executed or installed.
import express, { Request, Response } from "express";
import { exec as runShell } from "node:child_process";
import { readFile } from "node:fs";

const app = express();
app.get("/owned-command", (req: Request, res: Response) => {
  const command = req.query.command;
  runShell(command, () => res.end());
});
app.post("/owned-expression", (req: Request, res: Response) => {
  const expression = req.body.expression;
  res.send(eval(expression));
});
app.get("/owned-file/:name", (req: Request, res: Response) => {
  const filename = req.params.name;
  readFile(filename, () => res.end());
});
