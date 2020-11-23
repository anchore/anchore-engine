# Enterprise Documentation

This is the repository for the Anchore Enterprise Documentation site.

## Filing Bugs/Issues:

See [Issues](https://github.com/anchore/enterprise-docs/issues)

## Contributing

See [Contributing](CONTRIBUTING.rst) for the DCO and sign-off information. In short, sign all
commits with 'Signed-of-by X' with `git commit -s`.

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
`cd enterprise-docs ; hugo server`

1. Make changes

1. Commit and push

1. Open PR to github.com/anchore/enterprise-docs for merge to master




