{
  description = "Caddy with the Coraza WAF and OWASP CRS, a memory-safe stand-in for nginx + ModSecurity, built with Nix";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  };

  outputs = {self, ...} @ inputs:
    inputs.flake-utils.lib.eachSystem ["x86_64-linux" "aarch64-linux"] (system: let
      pkgs = import inputs.nixpkgs {inherit system;};

      # Plugin versions are pinned here; bump them together with the hash.
      caddy = pkgs.caddy.withPlugins {
        plugins = [
          "github.com/corazawaf/coraza-caddy/v2@v2.6.2"
          "github.com/mholt/caddy-ratelimit@v0.1.0"
        ];
        hash = "sha256-o2wN/aNxiE8xLE1oZnoLIQpX8HPFFvLXmh0jPxYP73c=";
      };

      crs = pkgs.fetchFromGitHub {
        owner = "coreruleset";
        repo = "coreruleset";
        tag = "v4.30.0";
        hash = "sha256-fwy6LwwccZ7wrcmXZdWkkwmprfd7PhikQToO4mdEfFE=";
      };

      # /etc/caddy-waf: Caddyfile, engine settings, CRS rules and the empty
      # drop-in directories the Deployment mounts over.
      config = pkgs.runCommand "caddy-waf-config" {} ''
        d=$out/etc/caddy-waf
        mkdir -p $d/crs $d/rules $d/site.d $d/proxy.d
        cp ${./caddy/Caddyfile} $d/Caddyfile
        cp ${./coraza/coraza.conf} $d/coraza.conf
        cp -r --no-preserve=mode ${crs}/rules $d/crs/rules
        # The example files are not rules; an Include glob would load them.
        rm $d/crs/rules/*.example
        echo '# Mount app exclusions here.' > $d/rules/000-none.conf
        echo '# Mount pre-WAF handlers here.' > $d/site.d/000-none.caddy
        echo '# Mount reverse_proxy subdirectives here.' > $d/proxy.d/000-none.caddy
      '';

      container = pkgs.dockerTools.buildLayeredImage {
        name = "caddy-waf";
        tag = "latest";
        contents = [
          caddy
          config
          pkgs.dockerTools.caCertificates
          pkgs.dockerTools.fakeNss
        ];
        extraCommands = ''
          mkdir -p tmp
          chmod 1777 tmp
        '';
        config = {
          Entrypoint = ["/bin/caddy" "run" "--config" "/etc/caddy-waf/Caddyfile" "--adapter" "caddyfile"];
          User = "101:101";
          ExposedPorts."8080/tcp" = {};
          Env = [
            "PATH=/bin"
            # Caddy wants writable config and data dirs; /tmp is an emptyDir
            # in the cluster so the root filesystem can be read-only.
            "HOME=/tmp"
            "XDG_CONFIG_HOME=/tmp/caddy/config"
            "XDG_DATA_HOME=/tmp/caddy/data"
          ];
        };
      };

    in {
      packages = {
        inherit caddy config container;
        default = container;
      };

      checks = {inherit config;};

      devShells.default = pkgs.mkShell {
        packages = with pkgs; [just podman skopeo shellcheck];
      };
    });
}
