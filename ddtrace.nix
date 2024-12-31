{
  python,
  pkgs,
  ddsketch,
  ...
}:

let
  envier = python.pkgs.buildPythonPackage rec {
    pname = "envier";
    version = "0.5.2";

    pyproject = true;
    propagatedBuildInputs = with python.pkgs; [
      hatchling
      hatch-vcs
    ];

    src = pkgs.fetchPypi {
      inherit pname version;
      sha256 = "sha256-Tn45jLCajdNgUI734SURoVI1VCbSVEuEh6NNrSfMIK0=";
    };
  };

  ddtrace = python.pkgs.buildPythonPackage rec {
    pname = "ddtrace";
    version = "2.9.2";
    pyproject = true;

    nativeBuildInputs =
      [ pkgs.cmake ]
      ++ (with python.pkgs; [
        cmake
        setuptools
        setuptools_scm
        cython
      ]);

    propagatedBuildInputs = with python.pkgs; [
      attrs
      cattrs
      ddsketch
      envier
      opentelemetry-api
      protobuf
      six
      xmltodict
      bytecode
    ];

    buildInputs = pkgs.lib.optionals pkgs.stdenv.isDarwin [ pkgs.darwin.apple_sdk.frameworks.IOKit ];

    postPatch = ''
      substituteInPlace setup.py --replace "cmake>=3.24.2,<3.28" "cmake"

      # downloading artifacts is impossible in sandboxed build
      substituteInPlace setup.py --replace "cls.download_artifacts()" "pass"

      substituteInPlace pyproject.toml --replace "cmake>=3.24.2,<3.28" "cmake"
    '';

    dontUseCmakeConfigure = true;

    src = pkgs.fetchFromGitHub {
      owner = "datadog";
      repo = "dd-trace-py";
      rev = "refs/tags/v${version}";
      hash = "sha256-Ax220/uBNwSZNBFYxbxAe0rmLrqYYf3a8K/PIuSE150=";
    };
  };
in
(ddtrace)
