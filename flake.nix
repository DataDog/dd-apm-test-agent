{
  description = "ddapm-test-agent";
  nixConfig.bash-prompt-prefix = "\[ddapm-test-agent\] ";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/24.05";

    flake-utils.url = "github:numtide/flake-utils";
    nix-filter.url = "github:numtide/nix-filter";

    nix2containerPkg.url = "github:nlewo/nix2container";
    treefmt-nix.url = "github:numtide/treefmt-nix";

    nix-github-actions.url = "github:nix-community/nix-github-actions/";
    nix-github-actions.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      nix-filter,
      treefmt-nix,
      nix2containerPkg,
      nix-github-actions,
    }:
    (flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        python = pkgs.python312;

        treefmt = treefmt-nix.lib.evalModule pkgs ./treefmt.nix;

        nix2container = nix2containerPkg.packages.${system}.nix2container;
        getExe = pkgs.lib.getExe;

        ddsketch = pkgs.callPackage ./ddsketch.nix { inherit python pkgs; };
        ddtrace = pkgs.callPackage ./ddtrace.nix { inherit python pkgs ddsketch; };

        ddapm-test-agent = python.pkgs.buildPythonApplication rec {
          name = "ddapm-test-agent";
          version = "0.0.0";
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

          doCheck = false;

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

          env.SETUPTOOLS_SCM_PRETEND_VERSION = version;
        };

        run_with_agent = pkgs.writeShellScriptBin "run_with_agent" ''
          #!${pkgs.bash}/bin/bash
          set -euxo pipefail
          export storagePath=$(${pkgs.mktemp}/bin/mktemp -d)

          ${pkgs.coreutils}/bin/nohup ${pkgs.bash}/bin/bash -c "${ddapm-test-agent}/bin/ddapm-test-agent" &

          exec $@
        '';

        toolContainer = nix2container.buildImage {
          name = "ghcr.io/pawelchcki/ddapm-test-agent";
          tag = "latest";
          config = {
            entrypoint = [ "/bin/ddapm-test-agent" ];
          };

          copyToRoot = pkgs.buildEnv {
            name = "root";
            paths = [ ddapm-test-agent run_with_agent];
            pathsToLink = [ "/bin" ];
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
            toolContainer
            run_with_agent
            ;
          default = ddapm-test-agent;
          reno = pkgs.reno;
        };

        formatter = treefmt.config.build.wrapper;

        checks = {
          ddapm-test-agent = ddapm-test-agent.override { doCheck = true; };
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
