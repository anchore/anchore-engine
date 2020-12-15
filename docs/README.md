# Anchore Engine Documentation

This is the source for the engine.anchore.io site and the site is updated in conjunction with Engine releases.

## Filing Bugs/Issues:

See [Issues](https://github.com/anchore/anchore-engine/issues) and mark the issue as a docs issue by
putting [docs] as a prefix on the issue title


### Making Changes/Contribution Workflow

1. Fork the repository

1. Install [hugo-extended](https://github.com/gohugoio/hugo/releases/), this is necessary because the docsy theme uses some scss functionality only in the extended version.

1. Install 'postcss-cli' and 'autoprefixer' using npm:
`npm install`

1. Clone the forked repo locally, with submodules to ensure the theme is available:
 `git clone --recurse-submodules https://github.com/<your_repo>`

  If you cloned already, then update the submodules with:
  `git submodule update --init --recursive`

1. Run hugo for local debugging/dev:
`cd anchore-engine/docs ; hugo server`

1. Make changes

1. Commit and push

1. Open PR to github.com/anchore/anchore-engine for merge to master

1. Project maintainers will publish docs updates on engine releases




