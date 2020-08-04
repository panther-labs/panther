# Panther Github Actions

This folder holds the publicly defined github actions for Panther OSS. Currently, it's home to:

- [pr_sync](./pr_sync/index.js)

Defines an action that allows to sync PRs accross different repos. Specifically, when the source
repo has a PR merged, an automatic PR for the same changes is created in the dest repo. This action
is useful for repos that extend one another, allowing you to quickly send any changes from upstream
to all downstream repos.

## Updating an Action

To update an action's source code, simply modify the related JS files found
(except for the ones found in the `dist` directory of the related action).

To update the action itself (in case additional inputs or outputs are needed, the runtime needs to be upgraded, etc.),
modify the `action.yml` file located within each action folder.

## Building an action

To build **any** action, go to its designated folder and write

`npm run build`

This assumes that you have Node 12+ locally installed. By running it, an artifact is generated in
the `<ACTION-FOLDER>/dist/index.js`. This is a single file that includes all dependencies and
source code, bundled in a single file.

## Using an action

Any action that has been built can be directly used in a `.github/workflow.yml`. Simply
reference the **folder** it's located under (i.e. `/build/actions/pr_sync`) and everything will work.
