# Wiki source

These pages are the source for the GitHub wiki at
<https://github.com/MrTimonM/fairproof-bcolbd/wiki>. They are kept in the
repository so they are versioned with the code and reviewable in a pull
request, rather than editable only through a web form.

`[[Double bracket]]` links are wiki syntax: GitHub resolves `[[Local Setup]]`
to `Local-Setup.md`. They will not render as links when browsing this folder.

## Publishing them

GitHub creates a wiki's git repository only after the first page is saved
through the web UI, and there is no API for it. So, once:

1. Open the repository's **Wiki** tab and create any page (the content does not
   matter — it will be overwritten).
2. Then push these files:

```bash
git clone https://github.com/MrTimonM/fairproof-bcolbd.wiki.git
cp wiki/*.md fairproof-bcolbd.wiki/
cd fairproof-bcolbd.wiki && rm -f README.md
git add -A && git commit -m "Publish wiki" && git push
```

`_Sidebar.md` becomes the navigation on every page. Delete `README.md` from the
wiki checkout — it is a note to maintainers, not a wiki page.

## Pages

| Page | Covers |
|---|---|
| `Home.md` | What FairProof is, and where to go next |
| `Protocol-Flow.md` | All nine phases: who acts, what is enforced, what the chain records |
| `Local-Setup.md` | Clean clone to a working procurement |
| `Architecture.md` | Repository layout, contracts, circuits, the dashboard |
| `Benchmarks.md` | Every measured constraint count, gas figure and test total |
| `Limitations.md` | What none of it guarantees |
| `FAQ.md` | The questions reviewers actually ask |
