---
title: "Upgrading the Anchore CLI"
weight: 1
---

The Anchore CLI is published as a Python Package that can be installed from source from the Python PyPI package repository on any platform supporting PyPi. Upgrades to the Anchore CLI are performed using the identical method used for installation.

`$ pip install --user --upgrade anchorecli`

To check if an update is available from the PyPI package repository run the following command:

```
$ pip search anchorecli
anchorecli (0.2.0)  - Anchore Service CLI
  INSTALLED: 0.1.10
  LATEST:    0.2.0
```

In this example the pip search command shows that we have anchorecli version 0.1.10 installed however the latest available version is 0.2.0.

**Note:** Python package names cannot include a dash so while the command name is anchore-cli the PyPi packages is anchorecli.
