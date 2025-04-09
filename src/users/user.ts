import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT, BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import http from "http";
import {
  rsaEncrypt
} from "../crypto";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export async function user(userId: number) {
  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;

  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  _user.get("/status", (req, res) => {
    res.send("live");
  });

  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });

  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });

  _user.post("/message", (req, res) => {
    const { message } = req.body;
    lastReceivedMessage = message;
    res.send("success");
  });

  _user.post("/sendMessage", async (req, res) => {
    const { message, destinationUserId } = req.body as SendMessageBody;
    lastSentMessage = message;

    const nodes: { nodeId: number; pubKey: string }[] = await new Promise((resolve, reject) => {
      http.get(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`, (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          const parsed = JSON.parse(data);
          resolve(parsed.nodes);
        });
      }).on("error", reject);
    });

    const shuffled = [...nodes].sort(() => Math.random() - 0.5);
    const selected = shuffled.slice(0, 3);
    const pathPorts = selected.map((n) => BASE_ONION_ROUTER_PORT + n.nodeId);

    let payload = JSON.stringify({
      destinationPort: BASE_USER_PORT + destinationUserId,
      message
    });

    for (let i = 2; i >= 0; i--) {
      const layer = JSON.stringify({
        nextHopPort: i === 2 ? BASE_USER_PORT + destinationUserId : pathPorts[i + 1],
        payload: Buffer.from(payload).toString("base64")
      });
      payload = await rsaEncrypt(layer, selected[i].pubKey);
    }

    const postData = JSON.stringify({ payload });

    const options = {
      hostname: "localhost",
      port: pathPorts[0],
      path: "/forward",
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(postData),
      },
    };

    const request = http.request(options, (r) => {
      r.on("data", () => {});
      r.on("end", () => res.send("success"));
    });

    request.on("error", () => res.status(500).send("fail"));
    request.write(postData);
    request.end();
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(`User ${userId} is listening on port ${BASE_USER_PORT + userId}`);
  });

  return server;
}
