{
  description = "ddapm-test-agent";
  nixConfig.bash-prompt-prefix = "\[ddapm-test-agent\] ";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/25.05";

    flake-utils.url = "github:numtide/flake-utils";

    treefmt-nix.url = "github:numtide/treefmt-nix";

    nix-github-actions.url = "github:nix-community/nix-github-actions/";
    nix-github-actions.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      treefmt-nix,
      nix-github-actions,
    }:
    (flake-utils.lib.eachDefaultSystem (
      system:
      let
        # setup dependencies
        pkgs = nixpkgs.legacyPackages.${system};
        python = pkgs.python312;

        treefmt = treefmt-nix.lib.evalModule pkgs ./treefmt.nix;

        # include dependencies not publish to nixpkgs
        ddsketch = pkgs.callPackage ./ddsketch.nix { inherit python pkgs; };
        ddtrace = pkgs.callPackage ./ddtrace.nix { inherit python pkgs ddsketch; };
        pretendVersion = "0.0.0";
        # build test agent
        ddapm-test-agent_base = (
          attrs:
          python.pkgs.buildPythonApplication {
            inherit (attrs) doCheck;

            name = "ddapm-test-agent";
            version = pretendVersion;
            src = ./.;

            postPatch = ''
              # remove riot since its not available from nixpkgs
              substituteInPlace test_deps.txt --replace "riot==0.13.0" ""
            '';

            dontUseCmakeConfigure = true;

            propagatedBuildInputs = with python.pkgs; [
              aiohttp
              msgpack
              ddsketch
              requests
              yarl
              vcrpy
              requests-aws4auth
              protobuf
              opentelemetry-proto
              grpcio
            ];
            nativeBuildInputs = with python.pkgs; [
              setuptools
              setuptools_scm
            ];
            checkInputs = [
              python.pkgs.pytest
              ddtrace
              pkgs.cmake
            ];

            installCheckPhase = ''
              runHook preCheck
              export TEST_AGENT="$out/bin/ddapm-test-agent"
              $TEST_AGENT --version

              # use nix provided agent for testing
              substituteInPlace \
                  tests/test_snapshot_integration.py \
                  tests/test_agent.py \
                  tests/conftest.py \
                   --replace "ddapm-test-agent" "$TEST_AGENT"

              ${python.pkgs.pytest}/bin/pytest -vv

              runHook postCheck
            '';

            env.SETUPTOOLS_SCM_PRETEND_VERSION = pretendVersion;
          }
        );

        ddapm-test-agent = ddapm-test-agent_base { doCheck = false; };
        skopeo = pkgs.skopeo;

        image = pkgs.dockerTools.buildImage {
          name = "ghcr.io/pawelchcki/ddapm-test-agent";
          tag = "latest";
          copyToRoot = pkgs.buildEnv {
            name = "root";
            paths = [ ddapm-test-agent ];
            pathsToLink = [ "/bin" ];
          };
          config = {
            entrypoint = [ "/bin/ddapm-test-agent" ];
          };
        };
      in
      {
        packages = {
          inherit
            python
            ddapm-test-agent
            ddtrace
            ddsketch
            image
            skopeo
            ;
          default = ddapm-test-agent;
          reno = pkgs.reno;
        };

        formatter = treefmt.config.build.wrapper;

        checks = {
          ddapm-test-agent = ddapm-test-agent_base { doCheck = true; };
          formatting = treefmt.config.build.check self;
        };

        devShells.default = pkgs.mkShell {
          venvDir = "./.venv";
          nativeBuildInputs = ddapm-test-agent.nativeBuildInputs ++ [ ddapm-test-agent ];
        };
      }
    ))
    // {
      githubActions = nix-github-actions.lib.mkGithubMatrix {
        attrPrefix = "";
        checks = {
          inherit (self.checks) x86_64-linux;

          aarch64-darwin = builtins.removeAttrs (self.checks.aarch64-darwin) [ "formatting" ];
        };
      };
    };
}
