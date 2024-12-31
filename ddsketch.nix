{ python, pkgs, ... }:
python.pkgs.buildPythonPackage rec {
  name = "ddsketch";
  version = "3.0.1";

  src = pkgs.fetchFromGitHub {
    owner = "datadog";
    repo = "sketches-py";
    rev = "refs/tags/v${version}";
    hash = "sha256-SmdKq5aXi5B3FNBxPQDNKNBujGGEPXF132YGadGFPpo=";
  };

  propagatedBuildInputs = with python.pkgs; [
    six
    protobuf
    setuptools
  ];
  nativeBuildInputs = with python.pkgs; [ setuptools_scm ];
  checkInputs = with python.pkgs; [
    pytest
    numpy
  ];
  env.SETUPTOOLS_SCM_PRETEND_VERSION = version;

  pythonImportsCheck = [ "ddsketch" ];

  postPatch = ''
    patchShebangs setup.py
    ls -lah
    echo version=\"${version}\" > ddsketch/__version.py
  '';
}
