# Development Setup for Anchore Engine

*Note: These directions are for PyCharm only (tested in Pycharm 2021.1.3)*

## Dev Dependencies:

In the same environment as your project interpereter, run `pip3 install -r requirements-dev.txt`

## File Watchers
Please import the file watchers in watchers.xml to use with the [File Watchers Pycharm Plugin](https://plugins.jetbrains.com/plugin/7177-file-watchers).

Steps to import:
* PyCharm > Preferences... > Tools > File Watchers > Import

## Dev Tools Overview:
Formatter Setup:
* [Black](https://github.com/psf/black) is used for formatting
* [isort](https://github.com/PyCQA/isort) is used for import sorting
* [pylint](https://pylint.org/) is used for linting
  * To learn more about an error message: `pylint --list-msgs | grep <ERROR CODE> -A 5` 
