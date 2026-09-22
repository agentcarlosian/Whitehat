// These source-shaped expressions are not Express request flows.
import { exec } from "node:child_process";
import { readFile } from "node:fs";
import fakeExpress from "owned-unrelated-framework";
const app = fakeExpress();
app.get("/not-express", (req, res) => {
  exec(req.query.command, () => res.end());
  readFile(req.params.name, () => res.end());
  eval(req.body.expression);
});
function localData(req) {
  return eval(req.body.expression);
}
const documentation = "app.get('/text', (req, res) => { eval(req.body.expression); })";
