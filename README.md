# Arch packages for Minecraft

This repository contains build scripts (PKGBUILDs and their generation scripts) to use Pacman as a Minecraft version manager.

Packages are separated into `minecraft-xxx` and `minecraft-assets-xxx`, because the later is huge and takes a long to package, and is also optional for some users.

I made a generator in C to fetch version JSONs and convert them into partial PKGBUILDs and launcher.gen files.

This repository does not contain any launchers. Instead, it exposes some variables from the manifest to launchers through launcher.gen files. Launchers should source them to run the game (see `launcher` as an example).

## makepkg

1. Compile the generator and generate `PKGBUILD.gen` and `launcher.gen`: `./switch 1.18.1`

2. Bulid and install the Minecraft package: `cd mc; makepkg`

3. (Optional) Build and install the assets package: `cd assets; makepkg`

4. (Optional) Build and install the fabric package: `cd fabric; makepkg`

Whenever you need to build a different Minecraft version, do the steps again (changing the arguments of `./switch` will cause it to generate new build files).

## Tested versions

| MC        | Assets | Fabric | Working |
|-----------|--------|--------|---------|
| 1.18      | Y      | N      | Y       |
| 1.17.1    | Y      | Y      | Y       |
| 1.17      | Y      | N      | Y       |
| 1.16      | N      | N      | Y       |
| 1.15      | N      | Y      | Y       |
| 1.14      | N      | N      | Y       |
| 1.13      | Y      | N      | Y       |
| 1.12      | Y      | N      | Y       |
| 1.8       | Y      | N      | Y       |
| rd-132211 | Y      | N      | Y       |

Note that for versions <= 1.12, you need Java 8 instead.

## Fabric

After install the `minecraft-fabric-xxx` package, you will have Fabric jars in the same directory as Minecraft jars, and they will be added to the classpath (but not used). If you want to use Fabric, source the `launcher.fabric.gen` after sourcing `launcher.gen`. It will set necessary environment variables (e.g. `MAIN_CLASS`) for you.

## TODO

Forge support

Rewrite argument processing

Provide a JSON as well

## Known issues

Assets folders cannot be shared across versions (i.e. you must have a dedicated assets folder for each asset version).

Compatibility with legacy versions that do not include `-cp` in their manifest.

Some arguments are not supported.

## License

Thanks to my friends' help.

Minecraft itself is a proprietary software. Its files subject to its EULA and are not included in this repository.

The build scripts are licensed under GPL v2.
