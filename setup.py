"""Build script for the hashcheck C extension."""

from setuptools import Extension, setup

setup(
    name="phantom",
    version="1.0.0",
    description="Phantom — personal threat intelligence toolkit",
    ext_modules=[
        Extension(
            "hashcheck",
            sources=["hashcheck.c"],
        ),
    ],
    py_modules=[],
)
