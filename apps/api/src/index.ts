import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { signHandler } from "./routes/sign.js";
import { cors } from "hono/cors";

const app = new Hono().basePath("/api");

app.use(cors({ origin: ["http://localhost:3000"] }));

const routes = [signHandler] as const;

routes.forEach((route) => app.route("/", route));

serve(
  {
    fetch: app.fetch,
    port: 3852,
  },
  (info) => {
    console.log(`Server is running on http://localhost:${info.port}`);
  }
);
