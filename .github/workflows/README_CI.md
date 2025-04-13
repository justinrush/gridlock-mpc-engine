# CI (Continuous Integration) docs

`ci-*.yml` are workflow files that build, test, etc. the projects. This is useful for continuous integration to ensuring code is both valid and correct before integration with an upstream branch such as `master` or `staging`.

## `ci-backend.yml`

The backend workflow will check that the code is both valid (`cargo check`) and correct (`cargo test`),
as well as being formatted correctly (`cargo fmt --check`). The build is done using the `--lock` flag, to ensure
that `Cargo.lock` is up-to-date, ensuring that dependencies only change when an updated `Cargo.lock` file is committed.

## `ci-docker.yml`

The docker workflow ensures that docker-compose configuration files pass validation.
