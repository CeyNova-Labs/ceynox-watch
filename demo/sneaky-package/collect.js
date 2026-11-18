// A harmless imitation of what credential-stealing install scripts do, for
// demonstrating ceynox-watch. It opens the places such scripts go for, and
// opens one connection to example.com. It keeps nothing and sends nothing:
// file contents are read and dropped, and the connection is closed unused.
const fs = require("fs");
const os = require("os");
const net = require("net");
const path = require("path");

const wanted = [".aws/credentials", ".ssh/id_ed25519", ".config/gh/hosts.yml"];
for (const rel of wanted) {
  try {
    fs.readFileSync(path.join(os.homedir(), rel));
  } catch {
    // Not there: nothing to imitate.
  }
}

const socket = net.connect(443, "example.com", () => socket.end());
socket.on("error", () => {});
