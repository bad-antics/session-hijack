from setuptools import setup, find_packages
setup(name="session-hijack", version="2.0.0", author="bad-antics", description="Session hijacking attack and defense toolkit", packages=find_packages(where="src"), package_dir={"":"src"}, python_requires=">=3.8")
