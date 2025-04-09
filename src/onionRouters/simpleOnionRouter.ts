import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import { generateKeyPairSync, privateDecrypt } from "crypto";
import http from "http";

let circuit: number[] = [];

export async function simpleOnionRouter(nodeId: number) {
  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;

  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
  });

  const pubKeyBase64 = publicKey
    .replace("-----BEGIN PUBLIC KEY-----", "")
    .replace("-----END PUBLIC KEY-----", "")
    .replace(/\r?\n/g, "")
    .trim();

  const privKeyBase64 = privateKey
    .replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "")
    .replace(/\r?\n/g, "")
    .trim();

  const postData = JSON.stringify({ nodeId, pubKey: pubKeyBase64 });
  const options = {
    hostname: "localhost",
    port: REGISTRY_PORT,
    path: "/registerNode",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(postData),
    },
  };
  const req = http.request(options, (res) => {
    res.on("data", () => {});
  });
  req.on("error", () => {});
  req.write(postData);
  req.end();

  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  onionRouter.post("/forward", (req, res) => {
    try {
      const encryptedPayload = Buffer.from(req.body.payload, "base64");
      lastReceivedEncryptedMessage = req.body.payload;

      const decrypted = privateDecrypt(privateKey, encryptedPayload).toString("utf8");
      lastReceivedDecryptedMessage = decrypted;

      const layer = JSON.parse(decrypted);
      const { nextHopPort, payload } = layer;
      lastMessageDestination = nextHopPort;
      circuit.push(BASE_ONION_ROUTER_PORT + nodeId);

      const nextPayload = JSON.stringify({ payload });
      const options = {
        hostname: "localhost",
        port: nextHopPort,
        path: "/forward",
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(nextPayload),
        },
      };

      const forwardReq = http.request(options, (forwardRes) => {
        forwardRes.on("data", () => {});
        forwardRes.on("end", () => {
          res.send("forwarded");
        });
      });

      forwardReq.on("error", (e) => {
        console.error(e);
        res.status(500).send("Forward failed");
      });

      forwardReq.write(nextPayload);
      forwardReq.end();
    } catch (err) {
      console.error(err);
      res.status(500).send("Error processing onion layer");
    }
  });

  onionRouter.post("/deliver", (req, res) => {
    try {
      const decrypted = privateDecrypt(privateKey, Buffer.from(req.body.payload, "base64")).toString("utf8");
      const { destinationPort, message } = JSON.parse(decrypted);

      const postData = JSON.stringify({ message });
      const options = {
        hostname: "localhost",
        port: destinationPort,
        path: "/message",
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(postData),
        },
      };

      const clientReq = http.request(options, (clientRes) => {
        clientRes.on("data", () => {});
        clientRes.on("end", () => {
          res.send("delivered to user");
        });
      });

      clientReq.on("error", (e) => {
        console.error(e);
        res.status(500).send("Delivery to user failed");
      });

      clientReq.write(postData);
      clientReq.end();
    } catch (err) {
      console.error(err);
      res.status(500).send("Delivery error");
    }
  });

  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: lastReceivedEncryptedMessage });
  });

  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: lastReceivedDecryptedMessage });
  });

  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: lastMessageDestination });
  });

  onionRouter.get("/getPrivateKey", (req, res) => {
    res.json({ result: privKeyBase64 });
  });

  onionRouter.get("/getLastCircuit", (req, res) => {
    res.json({ result: circuit });
  });

  onionRouter.get("/status", (req, res) => {
    res.send("live");
  });

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(`Onion router ${nodeId} listening on port ${BASE_ONION_ROUTER_PORT + nodeId}`);
  });

  return server;
}
