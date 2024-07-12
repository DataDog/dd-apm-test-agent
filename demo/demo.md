# Using nix to handle dependencies and make *some* workflow definitions work exactly the same on dev system

## the curious case of the dd-apm-test-agent

PR adding nix to the repository:
https://github.com/DataDog/dd-apm-test-agent/pull/182/files


### Benefits:
#### 1. universal formatting via treefmt

Nix flake.lock locks the dependencies to specific version

In result - the exact same formatting tools will be used for both local and CI. Additionally no explicit setup needs to happen in CI (other than installing nix itself). 

simply run:

`nix fmt`

soon: on system-tests https://github.com/DataDog/system-tests/pull/2600
already in RelEnv too (where treefmt automatically formats 6+ languages)

#### 2. repeatable builds

Every build fetches exactly the same dependencies, and builds happen in isolation from local env

#### 3. portability within an OS

Tools built with nix will reference their runtime nix dependencies automatically inferred during the build process.

And this relationship can be used to create special docker images - that can be used to quickly install needed tools.

```
# this command is enough to install a moderately complex Python app with exact needed python version
# onot any docker container!

COPY --from=ghcr.io/pawelchcki/ddapm-test-agent:latest / /
```

#### 3. easy local installation and usage

Nix takes care of dependencies, and because of build isolation and good dependency tracking its very fast 

Run this to get the exact same ddapm-test-agent as used in this demo:

```
nix run github:datadog/dd-apm-test-agent/pawel/demo_jul_12

# or e.g.
# nix profile install ...  
```

#### 4. it can replace brew, and simplify cross OS setup (only WSL on Windows sorry :( ))

You don't need to know brew to successfully use it - same with Nix. 
Just install nix and enjoy using it to install deps you need locally.


### Demo example:

Add test agent onto docker image and run simple test.


