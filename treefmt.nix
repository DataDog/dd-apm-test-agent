# treefmt.nix
{ pkgs, ... }:
{
  # Used to find the project root
  projectRootFile = "flake.nix";
  # Enable the Nix formatter 
  programs.nixfmt.enable = true;
  # Enable the Python formatter
  programs.black.enable = true;
  programs.isort.enable = true;

  settings.formatter.black.excludes = [ "ddsketch/pb/*" ];
}
