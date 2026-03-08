import { APP_NAME } from "../../shared/appConfig";
import { getAgentHealth } from "../services/python-bridge";

const health = await getAgentHealth();

if (health.status !== "ok") {
  console.error(`${APP_NAME} agent smoke check failed.`);
  console.error(JSON.stringify(health, null, 2));
  process.exit(1);
}

console.log(JSON.stringify(health, null, 2));
