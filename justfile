# Build the image and load it into podman
build:
    nix build -o container '.#packages.x86_64-linux.container'
    podman load < container

# Smoke-test the loaded image (needs ports 8080 and 18081 free)
test: build
    nix run '.#smoke-test'

# Inspect the image
dive:
    dive podman://localhost/caddy-waf:latest

alias b := build
alias t := test
alias d := dive
