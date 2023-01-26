# Developing Engine Documentation

Anchore Engine documentation is managed in the `docs` branch only. All changes and updates should be
branched from and merged into the `docs` branch.

Publication of the documentation is triggered via a GitHub Action on pushes to the `publish-docs` branch.
The regular process for publishing changes is to merge (via PR) drain changes into `docs` branch, then
merge (via PR) the `docs` branch into the `publish-docs` branch to make the change live.

Engine documentation is not multi-version, it only applies to the most recent release of the project.

## Setup

The documentation uses the Hugo system, specifically [hugo-extended](https://github.com/gohugoio/hugo/releases/). So you'll need to install hugo locally to dev/test.

## Workflow

1. Create new branch for your changes, starting from "docs" branch.

```
git checkout docs
git pull
git checkout -b my_docs_updates
```

2. Make your docs changes
3. Test using Hugo
```
hugo server --watch
```
Point your browser at http://localhost:1313 to see them rendered and updated as you make changes.

4. Commit your changes into your branch.
5. Open a PR for your branch to merge to the `docs` branch
6. Get approval and once approval is granted, merge the PR.
7. A docs owner will PR the `docs` branch into `publish-docs` when the team is ready to publish changes. This may be per-update or batched as needed.




