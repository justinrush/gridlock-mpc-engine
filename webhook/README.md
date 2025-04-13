# MVP Webhook

This is a small side-car project to the main mvp project. It is responsible for listening for redeployment requests from the CD workflow. Read more about this workflow at `/.github/workflows/README_CD.md`.

The webhook is exposed at `$scheme://$DOMAIN/hooks/redeploy-$WEBHOOK_SECRET`.

The hook calls the `redeploy.sh` script in this folder.

The reason this webhook is in a different compose project than the production configuration is when `redeploy.sh` runs `up -d` it does not result in potentially restarting the webhook itself. If the webhook service gets inadvertently restarted during deployment, the deploy will be canceled from container shutdown and the system left in an inconsistent sate. This means that it is not possible to update the webhook code via CD, but these updates should be rare. You must manually SSH into the deployment environment to make this change.

To update the webhook container on a deployment environment, you can run the same commands you used to deploy the stack in `/README.md`:

```bash
docker-compose -f docker-compose.webhook.yml -p mvp-webhook build --pull
docker-compose -f docker-compose.webhook.yml -p mvp-webhook up -d --remove-orphans
```
