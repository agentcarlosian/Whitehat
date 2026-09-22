// Owned static controls. No application or subprocess is executed.
import express, { Request, Response } from "express";
import { execFile } from "node:child_process";
import { readFile } from "node:fs";

const app = express();
app.get("/owned-command", (req: Request, res: Response) => {
  execFile("owned-demo-program", [String(req.query.argument)], () => res.end());
});
app.post("/owned-expression", (req: Request, res: Response) => {
  res.send(JSON.parse(req.body.expression));
});
app.get("/owned-file/:name", (req: Request, res: Response) => {
  if (req.params.name !== "example") { res.sendStatus(404); return; }
  readFile("owned-example.json", () => res.end());
});
