# treefmt.nix
{pkgs, ...}: {
  # Used to find the project root
  projectRootFile = "flake.nix";
  # Enable the Nix formatter "alejandra"
  programs.alejandra.enable = true;

  # Format py sources
  programs.black.enable = true;
  # Format .sh scripts
  programs.shfmt.enable = true;
}
