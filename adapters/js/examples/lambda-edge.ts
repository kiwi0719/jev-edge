// Lambda@Edge, viewer-request trigger with "Include Body" enabled. Deploy in
// us-east-1 as a numbered version. There are no environment variables on
// Lambda@Edge: fetch the key from Secrets Manager once per execution
// environment and build the handler with it.
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import { lambdaEdgeHandler, type CfEvent } from "@jev-edge/js/aws";

let handlerPromise: Promise<ReturnType<typeof lambdaEdgeHandler>> | undefined;

async function build() {
  const sm = new SecretsManagerClient({ region: "us-east-1" });
  const secret = await sm.send(new GetSecretValueCommand({ SecretId: "jev-edge/typesafe-api-key" }));
  return lambdaEdgeHandler({
    config: {
      jev: { provider: "jev", api_key: secret.SecretString, deployment_context: "…", timeout_ms: 400, timeout_max_ms: 1000 },
      policy: { mode: "monitor" },
    },
  });
}

export const handler = async (event: CfEvent) => {
  handlerPromise ??= build();
  return (await handlerPromise)(event);
};
