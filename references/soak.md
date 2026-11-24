# Mass testing on vibe-coded repositories (the soak)

jankhunt42 was tested on public repositories built with AI coding tools, in batches, with frontier and local AI models
checking a sample of each batch's findings; no person repeated the labels. This page states what was done and what it
showed, as aggregate numbers. Repository names are never published.

Three numbers are kept apart on purpose: how many repositories were **collected**, how many were **scanned**, and how
many findings were **sampled and checked**. All three are useful; mixing them up is not.

## How it was done

- **Finding repositories.** Public GitHub repositories whose README says they were built with AI app builders or
  coding agents (Lovable, Bolt, v0, Cursor, Claude Code, Replit and similar), or that pair common vibe-coding stacks
  (Supabase with Stripe, Streamlit with OpenAI, n8n workflows, Power Apps), found through GitHub's repository search.
- **Cloning.** Shallow clones only: no hooks, no submodules, no LFS, no credential prompts; nothing built or run.
- **Scanning.** Each repository was scanned in a container with no network, a read-only root and read-only mounts,
  no capabilities and resource limits. The scanner was the jankhunt42 build current at the time (from a pre-2.7.0 build to 3.6.0).
- **Checking.** For every batch an AI model sampled findings and labelled each one, and a second model checked the
  labels against the code: at first TP (the code does what the rule claims and a person should look), FP (it does
  not), NOISE (true but not worth a person's time) or UNSURE; from batch 19 on, simply whether the finding's claim is
  true, false or unsure. The labels are defined in [precision.md](precision.md). False positives were fixed between
  batches, which is why the rate falls.

## What it showed

| Batches | Unique repositories scanned | Findings | Sampled | Result |
|---|---|---|---|---|
| b01-b16 | 591 | 191,779 | 1,676 findings | 468 TP, 142 FP (8.5%), 982 noise, 22 unsure |
| b17-b18 | 111 | 31,302 | 189 findings | 86 TP, 2 FP, 101 noise |
| b19-b32 | 552 | 140,258 | 1,041 claims | 1,020 true, 16 false, 5 unsure |
| **b01-b32** | **1,254** | | **2,906** | |

The last six batches (b27 to b32, 240 repositories) had **461 of 461** sampled claims true. After that the mass
test was stopped: the scanner's claims were holding.

Eleven later batch runs (b33 to b43) scanned **365** further repositories with release builds, without a sampled
review, so they add to what was scanned, not to what was checked. Unique repositories scanned in all: **1,619**.

**Correction.** Earlier changelog entries add the first batches as 80 + 160 + 40 = 280 repositories. Batches b01 to
b04 rescanned the repositories cloned before them, so unique repositories through b05 were **200**. The changelog is
left as written; this page is the corrected count.

## The evaluation corpus

A larger corpus of **17,529 public repositories** was collected on 2026-11-17:

| Group | Repositories |
|---|---|
| Vibe-coded or AI-built (README discovery, including the soak's own) | 3,510 |
| Found by code search for specific file types (low-code exports, Supabase and Firebase, agent configs, CI, WinGet) | 6,070 |
| Ordinary repositories across 16 languages, for false-alarm rates | 7,949 |

**How each snapshot is pinned.** Each snapshot is identified by its git tree hash, which names its exact content.
When it was pinned, the tip of the repository's default branch was also recorded; for a repository that kept
changing, that tip can be later than the snapshot. On 2026-11-24 the first two groups (9,580 repositories) were
fetched again with their history: for **9,043** of them the commit holding the snapshot's content is now recorded
(8,866 with the identical tree, 177 with the same files and different file permissions). For 193 no commit in the
history fetched matches, 169 were not checked and 175 are no longer available. The ordinary-repositories group is
identified by tree hash only.

**Release measurement.** Since 4.22.0 each release is compared, before it ships, with the previous one on a full scan
of the same **1,840** repositories from this corpus (1,239 found by code search, 396 ordinary, 205 vibe-coded), in the
same locked-down containers; the release's changelog entry states what changed. For 4.22.2, 200 of them were also
scanned with and without their git folders: the two scans read the same files and reported the same findings, except
that a committed secrets file is rated critical only when git can show it is committed.

No precision figure on this page comes from the corpus: the release measurement counts what changed, not whether each
finding is right.
