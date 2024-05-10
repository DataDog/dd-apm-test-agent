{
  description = "ddapm_test_agent";
  nixConfig.bash-prompt-prefix = "\[ddapm_test_agent\] ";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    nixpkgs.url = "github:NixOS/nixpkgs/23.11";

    pyproject-nix.url = "github:nix-community/pyproject.nix";

    nix2containerPkg.url = "github:nlewo/nix2container";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    treefmt-nix,
    pyproject-nix,
    nix2containerPkg,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      project = pyproject-nix.lib.project.loadPyproject {
        projectRoot = ./.;
      };
      pkgs = nixpkgs.legacyPackages.${system};
      nix2container = nix2containerPkg.packages.${system}.nix2container;

      python = pkgs.python312;
      pythonPkgs = pkgs.python312Packages;

      packageAttrs = project.renderers.buildPythonPackage {inherit python;};
      packageDeps = project.renderers.withPackages {inherit python;};

      pythonDevEnv = python.withPackages packageDeps;

      treefmt = treefmt-nix.lib.evalModule pkgs ./treefmt.nix;

      finalPackage = python.pkgs.buildPythonPackage packageAttrs;
      finalApp = python.pkgs.buildPythonApplication packageAttrs;
      devEnv = pkgs.buildEnv {
        name = "root";
        paths = [pkgs.bashInteractive pkgs.coreutils treefmt.config.build.wrapper pythonDevEnv];
        pathsToLink = ["/bin"];
      };
    in {
      packages = {
        python = python;
        ciContainer = nix2container.buildImage {
          name = "registry.ddbuild.io/apm-reliability-environment/handmade/nixci";

          copyToRoot = pkgs.buildEnv {
            name = "root";
            paths = [devEnv pythonPkgs.pytest];
            pathsToLink = ["/bin"];
          };
        };
        toolContainer = nix2container.buildImage {
          name = "registry.ddbuild.io/apm-reliability-environment/handmade/docker-builder";
          tag = "latest";
          config = {
            entrypoint = ["/bin/docker-builder"];
          };

          copyToRoot = pkgs.buildEnv {
            name = "root";
            paths = [finalApp];
            pathsToLink = ["/bin"];
          };
        };
      };

      packages.default = finalPackage;
      formatter = treefmt.config.build.wrapper;

      devShells.default =
        pkgs.mkShell
        {
          venvDir = "./.venv";
          nativeBuildInputs = [pythonDevEnv pythonPkgs.venvShellHook];
          packages = [
            devEnv
            pythonPkgs.pytest
          ];
          postShellHook = ''
            export PYTHONPATH="$PYTHONPATH:$(pwd)" # ensuring pytest invocation works
          '';
        };
    });
}
