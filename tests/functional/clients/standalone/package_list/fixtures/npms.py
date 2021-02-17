# though there are other node modules in the image, they are all owned by the npm APK package, which means engine will ignore them

pkgs = {
    "/node_modules/lodash/package.json": {
        "name": "lodash",
        "lics": ["MIT"],
        "versions": ["4.17.4"],
        "latest": "4.17.4",
        "origins": [
            "John-David Dalton <john.david.dalton@gmail.com> (http://allyoucanleet.com/)"
        ],
        "sourcepkg": "git+https://github.com/lodash/lodash.git",
    },
}
