# Clean-room policy

RyProx is written from scratch. This policy keeps it legally independent of other projects, especially those with commercial or source-available licences.

## The rules

1. **Do not read the source code of any proprietary, source-available or commercially licensed software** in this space (reverse proxies, tunnels, access gateways). Not to learn from, not to compare, not "just to check".
2. **Do not copy code from other open-source projects in this space either**, whatever their licence. RyProx is written from scratch so its authors hold the copyright in every line.
3. **Features are designed from public information only:** product documentation, marketing pages, blog posts, public talks, and our own black-box testing of software we are allowed to run.
4. **Every feature gets a short spec in [`docs/specs/`](docs/specs/)** before it is built, saying what it does and where the idea came from. These specs are our record that the design is independent.
5. **Libraries are fine.** Using openly licensed libraries (Caddy, Go's standard library, WireGuard, etc.) under their own licences is normal and expected. Record them in `go.mod` and keep their licence notices.
6. **No branding overlap.** Don't use other projects' names, logos, screenshots or wording.

## If you have already read restricted code

You can still help: write specs, test, review docs, design the UI. Please don't write code for the area of RyProx that corresponds to what you read, and say so in your pull request.

## AI-assisted code

RyProx is built with help from AI coding assistants. Contributors must not prompt an assistant to reproduce, translate or port code from restricted projects. All AI-assisted code is reviewed and tested like any other code.
