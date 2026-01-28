# Update the libsecp256k1 submodule

Standing in K1 project root, call it `K1_ROOT`.

Find path to submodule (libsecp256k1) 

```sh
cat .gitmodules
```

Which will print something like:
```
[submodule "Sources/secp256k1/libsecp256k1"]
	path = Sources/secp256k1/libsecp256k1
	url = https://github.com/bitcoin-core/secp256k1.git
```

Read the value of `path` and save it into `DEPENDENCY_PATH` (`Sources/secp256k1/libsecp256k1`).

## Get current (old) tag and commit
Read out the current tag and commit:
```sh
git submodule status | grep $DEPENDENCY_PATH
```

which will output something like
```
1a53f4961f337b4d166c25fce72ef0dc88806618 Sources/secp256k1/libsecp256k1 (v0.7.1)
```

save it into `OLD_VERSION`.

Extract the current (old) commit and tag
```sh
OLD_COMMIT=$(printf '%s\n' "$CURRENT_VERSION" | awk '{print $1}')
OLD_TAG=$(printf '%s\n' "$CURRENT_VERSION" | awk -F'[()]' '{print $2}')
```

```sh
cd $DEPENDENCY_PATH
```

Git fetch

```sh
git fetch
```

Extract latest tag:
```sh
git describe --tags --abbrev=0
```
Call it `LATEST_TAG`

Checkout latest tag

```sh
git checkout $LATEST_TAG
```

Extract commit from tag
```sh
git rev-list -n 1 $LATEST_TAG
```
call it `NEW_COMMIT`

Go back to project root

```sh
cd $K1_ROOT
```

Stage changes
```sh
git add $DEPENDENCY_PATH
```

Run tests
```sh
swift test
```

If and only if all tests passes, proceed

## Update documented version in README.md

in README.md replace old values of

```text
> Current `libsecp256k1` version is [$OLD_TAG ($OLD_COMMIT)](https://github.com/bitcoin-core/secp256k1/releases/tag/$OLD_TAG)
```

with new version:
```text
> Current `libsecp256k1` version is [$LATEST_TAG ($NEW_COMMIT)](https://github.com/bitcoin-core/secp256k1/releases/tag/$LATEST_TAG)
```

Stage README.md changes:
```sh
git add README.md
```

Checkout new branch
```sh
git checkout -b bump/libsecp256k1_to_$LATEST_TAG
```

Commit changes
```sh
git commit -m "Update libsecp256k1 dependency to $LATEST_TAG ($NEW_COMMIT) [all unit tests passed]"
```

Push changes
```sh
git push --set-upstream origin $(git_current_branch)
```