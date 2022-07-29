# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
# import os
# import sys
# sys.path.insert(0, os.path.abspath('.'))
import re
from pprint import pprint

from pip._vendor import pkg_resources

from kedro_kubeflow import __name__ as _package_name
from kedro_kubeflow import version as release

# -- Project information -----------------------------------------------------

project = "Kedro Kubeflow Plugin"
copyright = "2020, GetInData"
author = "GetInData"

myst_substitutions = {
    "tested_kedro": "0.17.7",
    "release": release,
}

# The full version, including alpha/beta/rc tags
version = re.match(r"^([0-9]+\.[0-9]+).*", release).group(1)
_package_name = _package_name.replace("_", "-")
_package = pkg_resources.working_set.by_key[_package_name]

# Extending keys for subsitutions with versions of package
myst_substitutions.update(
    {"req_" + p.name: str(p) for p in _package.requires()}
)
myst_substitutions.update(
    {
        "req_build_" + p.name: pkg_resources.get_distribution(p).version
        for p in _package.requires()
    }
)

conditions = {
    "upper": ["<", "<=", "~=", "==", "==="],
    "lower": [">", ">=", "~=", "==", "==="],
}
for k, cond in conditions.items():
    myst_substitutions.update(
        {
            f"req_{k}_"
            + p.name: "".join(
                ["".join(i) for i in filter(lambda x: x[0] in cond, p.specs)]
            )
            for p in _package.requires()
        }
    )

print("Available patterns for substituion:")
pprint(myst_substitutions)

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    # "sphinx.ext.autodoc",
    # "sphinx.ext.napoleon",
    # "sphinx_autodoc_typehints",
    # "sphinx.ext.doctest",
    # "sphinx.ext.todo",
    # "sphinx.ext.coverage",
    # "sphinx.ext.mathjax",
    # "sphinx.ext.ifconfig",
    # "sphinx.ext.viewcode",
    # "sphinx.ext.mathjax",
    "myst_parser",
    "sphinx_rtd_theme",
]
myst_enable_extensions = [
    "replacements",
    "strikethrough",
    "substitution",
]

# Add any paths that contain templates here, relative to this directory.

autosummary_generate = True
templates_path = ["_templates"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "sphinx_rtd_theme"

html_theme_options = {
    "collapse_navigation": False,
    "style_external_links": True,
}


# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
# html_static_path = ["_static"]

language = "en"

pygments_style = "sphinx"
