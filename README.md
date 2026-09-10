# NAME

Perl::Critic::Policy::PreferredBinaries - Recommend a perl sub over shelling out to a binary that does the same job

# VERSION

version 0.001

# SYNOPSIS

In `.perlcriticrc`:

```
[PreferredBinaries]
config = ~/.preferred_binaries.ini
```

In `.preferred_binaries.ini`:

```
[ssh-keygen]
prefer = Provisioner::Utils::write_ssh_keypair
reason = "In-process: no quoting to get wrong, no temp file, and errors you can catch"

[ssh-keygen -y]
prefer = Provisioner::Utils::ssh_pubkey_from_private
reason = "Derives the public half with CryptX"

[wget]
reason = "Nothing here should be fetching anything with this"

[curl]
prefer = HTTP::Tiny
reason = "One HTTP client, and one place redirects and timeouts are decided"

[dig]
prefer = Net::DNS
reason = "Parsing dig output is parsing a UI"
```

Then this is reported:

```perl
system( 'ssh-keygen', '-t', 'rsa', '-f', $path );
my $out = `dig +short $name`;
open( my $fh, '-|', 'curl', '-s', $url );
```

# DESCRIPTION

[Perl::Critic::Policy::logicLAB::ProhibitShellDispatch](https://metacpan.org/pod/Perl%3A%3ACritic%3A%3APolicy%3A%3AlogicLAB%3A%3AProhibitShellDispatch) says not to shell out.
This says what to do instead, for the binaries somebody has already worked out
an answer for -- which is what makes the difference between a rule people
suppress and a rule people follow.

It is the shelling-out counterpart of
[Perl::Critic::Policy::PreferredModules](https://metacpan.org/pod/Perl%3A%3ACritic%3A%3APolicy%3A%3APreferredModules), and deliberately the same shape: an
INI file of sections and `prefer`/`reason` pairs, so one convention covers
both halves of "we already decided this".

Nothing is configured by default.  A distribution with no
`.preferred_binaries.ini` gets no violations, because the policy has no
opinion of its own about which binaries are worth replacing -- only about
recording the ones you have decided.

## What it looks at

Anywhere a command reaches a shell or an `exec`:

- `system` and `exec`, in list or string form
- backticks and `qx//`
- a piped `open`, either `'-|'` or `'|-'`, in two- or
three-argument form
- the argument-list form of the usual runners: `IPC::Run3::run3`,
`IPC::Run::run`, `IPC::Cmd::run`, and `Capture::Tiny`'s `capture`,
`capture_merged`, `tee` and friends

In each case it takes the first word of the command, drops any directory in
front of it, and looks that up.  So `/usr/bin/ssh-keygen` and
`ssh-keygen` are the same binary, and `$ENV{SSH_KEYGEN}` is not one
it can see -- a name computed at runtime is a name this cannot know, and it
says nothing rather than guessing.

## Matching a flag as well as a binary

A section name may carry arguments: `[ssh-keygen -y]` matches only an
invocation whose first two words are `ssh-keygen` and `-y`.  The longest
matching section wins, so a bare `[ssh-keygen]` can name the general
answer while `[ssh-keygen -y]` names the one for reading a public key
back.

Only leading words count, and only literal ones.  `[ssh-keygen -y]` does
not match `ssh-keygen -q -y`, because working out whether two argument
lists mean the same thing is a job for something that understands the binary.

# CONFIGURATION

## config

Path to the INI file.  `~` is expanded.  Defaults to
`.preferred_binaries.ini` in the current directory.

Sections are binary names, optionally with leading arguments.  Each takes:

- `prefer` -- what to use instead.  A module name, or a fully qualified
sub, or a method call written however your readers will recognise it.  Printed
verbatim.
- `reason` -- why, in a few words.  Printed after it.
- `severity` -- 1 to 5 for this entry alone.

**A section with no `prefer` is a ban rather than a recommendation**, and is
reported as one: "Shelling out to 'wget' is not recommended".  That is how
[Perl::Critic::Policy::PreferredModules](https://metacpan.org/pod/Perl%3A%3ACritic%3A%3APolicy%3A%3APreferredModules) reads a section with no `prefer`,
and it is worth knowing because consecutive sections look like they share the
entry below them and do not:

```
[wget]
[curl]
prefer = HTTP::Tiny
```

names one ban and one recommendation, not two recommendations.  Config::INI
carries nothing forward, so each section needs its own `prefer` if that is
what it means.

# BUGS

Please report any bugs or feature requests on the bugtracker website
[https://github.com/Troglodyne-Internet-Widgets/perl-critic-policy-preferredbinaries/issues](https://github.com/Troglodyne-Internet-Widgets/perl-critic-policy-preferredbinaries/issues)

When submitting a bug or request, please include a test-file or a
patch to an existing test-file that illustrates the bug or desired
feature.

# AUTHORS

Current Maintainers:

- George S. Baugh <george@troglodyne.net>

# COPYRIGHT AND LICENSE

Copyright (c) 2026 Troglodyne LLC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
