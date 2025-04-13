# CD (Continuous Delivery) docs

`cd.yml` is the workflow file that manages deployments for this project. The workflow is triggered on pushes to either the `master` or `staging` branches.

The workflow has one job that will build both the frontend and backend, build the frontend and backend Docker images and push them to GitHub Container Registry, and finally trigger a webhook on the deployment environment to trigger a deployment.

The Docker images are tagged using the branch name the job ran on. The multiple tags enables the deployment environment to select the correct release channel to pull from.

The webhook works by extracting the URL of the webhook server on the deployment environment from a [GitHub secret](https://github.com/GridlockNetwork/mvp/settings/secrets/actions). This secret is appropriately named `HOOK_<branch>`, e.g. the `master` branch is `HOOK_MASTER`. The branch name is not case sensitive and cannot contain slashes or other special characters (because GitHub secrets cannot contain these).

See `/webhook/README.md` for further details on the webhook server and how it performs a deployment.

## Adding a new deployment environment

If you want to add a third deployment environment from `master` and `staging`, all you have to do is:

- make a new branch
- follow the docs in `/README.md` to setup and start the new environment
- add a `HOOK_<branch>` secret
- adjust the push triggers on `cd.yml` to include your new branch
