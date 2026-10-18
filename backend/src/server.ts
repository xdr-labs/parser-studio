import { createBackendServer } from "./http.js";

const portString = process.env["PARSER_BACKEND_PORT"] || "4179";
const port = Number(portString);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("PARSER_BACKEND_PORT must be 1..65535");
}
createBackendServer().listen(port, "127.0.0.1", () => {
  process.stdout.write("Parser Studio backend listening on 127.0.0.1:" + port + "\n");
});
