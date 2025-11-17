
#!/usr/bin/env python3


d
def main(argv: List[str]) -> int:
    import argparse

    def error_exit():
        print("Expected command", file=sys.stderr)
        print("Usage: <gerrit> <command> [args...]")
        sys.exit(1)

    default_gerrit = os.environ.get("GERRIT_CLI_DEFAULT_GERRIT_HOST")
    root = git_root()
    _project = None
    gerrit_server = None
    if root:
        _project, gerrit_server = review_info(root)

    if gerrit_server is None:
        gerrit_server = default_gerrit

    # It is okay if filter is None.
    git_project_filter = _project

    parser = argparse.ArgumentParser(allow_abbrev=False)
    # TODO: Make it 'global' and add into each subparser.
    parser.add_argument("--dry-run", action="store_true")
    subs = parser.add_subparsers(dest="command")
    subs.required = True

    _resolve = subs.add_parser(
        "resolve",
        help="Resolve Revision to its ShaId. [ShaId, ChangeId, Git Symbolic Reference] -> ShaId"
    )
    _resolve.add_argument("change")

    _topic = subs.add_parser(
        "topic",
        help="""Set topic for changes.

        The API expects change-ids for the changes, but commit sha1 ids can also be specified,
        in which case a lookup is performed

        [ShaId, ChangeId]...
        """,
    )

    topic_actions = _topic.add_mutually_exclusive_group(required=True)
    topic_actions.add_argument("--topic")
    # TODO: Change this to a subparser?
    # https://jmmv.dev/2013/08/cli-design-putting-flags-to-good-use.html
    topic_actions.add_argument("--delete", action='store_true')
    _topic.add_argument("changes", metavar="change", nargs='+', help="Commits to set topic for.")

    _fetch = subs.add_parser(
        "fetch",
        help="""Fetch a revision to your local git database.

        The change must be for the same repository and the remote must be configured.
        [ShaId, ChangeId, Git Symbolic Reference]""",
    )
    _fetch.add_argument("change")

    _incoming = subs.add_parser("incoming", help="Incoming changes to review.")
    _outgoing = subs.add_parser("outgoing", help="Outgoing changes to review.")

    _reviewers = subs.add_parser("reviewers", help="Add reviewers for changes.")
    # TODO: default commit to HEAD?
    _reviewer_sub_parsers = _reviewers.add_subparsers(dest="review_subcommand")
    _reviewer_subs = []
    _clear_reviewers = _reviewer_sub_parsers.add_parser(
        "clear",
        help="Clear all reviewers from a change.",
    )
    _clear_reviewers.add_argument(
        "changes",
        nargs="+",
        metavar="change",
    )
    _reviewer_subs.append(_clear_reviewers)
    _list_reviewers = _reviewer_sub_parsers.add_parser(
        "list",
        help="List reviewers for changes.",
    )
    _list_reviewers.add_argument(
        "changes",
        nargs="+",
        metavar="change",
    )
    _reviewer_subs.append(_list_reviewers)
    _add_reviewers = _reviewer_sub_parsers.add_parser(
        "add",
        help="Add reviewers to changes.",
    )
    _reviewer_subs.append(_add_reviewers)
    _add_reviewers.add_argument(
        "--changes",
        nargs="+",
        metavar="change",
        required=True,
    )
    _add_reviewers.add_argument(
        "--reviewers",
        nargs="+",
        metavar="reviewer or group",
        required=True,
    )
    for review_parser in _reviewer_subs:
        review_parser.add_argument(
            "--entire-topic",
            action='store_true',
            help="If a commit (is part of) a topic, update all constituent commits in Gerrit.",
        )

    _comments = subs.add_parser(
        "comments",
        help="View review comments for a change. [Revision, ChangeId, Git Symbolic Reference]"
    )
    _comments.add_argument(
        "--entire-topic",
        action='store_true',
        help="If a commit (is part of) a topic, download comments for all commits.",
    )
    _comments.add_argument(
        "change",
    )

    # # Specific votes
    # TODO: Parameterize this to a schema file,
    # and possibly query Gerrit for this file
    # so the user does not have to write it herself.
    MAINTAINER_REVIEW_CHOICES = [str(v) for v in [-1, 0, 1]]
    MAINTAINER_REVIEW = "Maintainer-Review"

    _vote = subs.add_parser(
        "vote",
        # TODO: or view votes: votes are available with query --dump
        help="Vote on a change. [XXX]",
    )
    _vote.add_argument(
        "--change",
        required=True,
    )
    _vote.add_argument(
        "--mr",
        choices=MAINTAINER_REVIEW_CHOICES,
    )
    _vote.add_argument(
        "--vote",
        help="Vote: general Gerrit votes for any label (<label>=<value>, Code-Review=2 (plus is not supported yet)."
    )

    _message = subs.add_parser(
        "message",
        help="Write a top-level message to a commit. [XXX]",
    )
    _message.add_argument(
        "--change",
        required=True,
    )
    _message.add_argument(
        "message",
    )

    MESSAGE_FILTER_CHOICES_NO_FILTER = "no-filter"
    MESSAGE_FILTER_CHOICES_HUMAN = "human"
    MESSAGE_FILTER_CHOICES_JOB_FAILURES = "job-failures"
    MESSAGE_FILTER_CHOICES = [
        MESSAGE_FILTER_CHOICES_NO_FILTER,
        MESSAGE_FILTER_CHOICES_HUMAN,
        MESSAGE_FILTER_CHOICES_JOB_FAILURES,
    ]
    _messages = subs.add_parser(
        "messages",
        help="View top level messages for a change. [Revision, ChangeId, Git Symbolic Reference]"
    )
    # TODO: Phrasing and semantics, is `filters` sufficient?
    # Make sure it is clear to the user whether this filters things away,
    # or whether this is what should remain after filtering.
    _messages.add_argument(
        "--filter",
        choices=MESSAGE_FILTER_CHOICES,
        default=MESSAGE_FILTER_CHOICES_NO_FILTER,
        help="Filter message kinds to display."
    )
    _messages.add_argument(
        "change",
    )

    _timing = subs.add_parser(
        "timing",
        help="Parse for CI response times in a change.",
    )
    _timing.add_argument(
        "change",
    )

    _abandon = subs.add_parser(
        "abandon",
        help="Abandon changes. [ChangeId]",
    )
    _abandon.add_argument(
        "changes", nargs="+", metavar="change",
    )

    _group = subs.add_parser("group", help="Query the group database.")
    _group.add_argument(
        "group",
        help="Group substring to lookup.",
    )
    _user = subs.add_parser("user", help="Query the user database.")
    _user.add_argument(
        "user",
        help="User substring to lookup.",
    )

    _query = subs.add_parser("query", help="Query Gerrit changes. [Gerrit Query Language]")

    _patchsets = subs.add_parser("patchsets", help="List patchsets for a change.")
    _patchsets.add_argument("change")
    # TODO: Should this have `--dump` and `--project` flags?

    _rebase = subs.add_parser("rebase", help="Rebase Gerrit change.")
    _rebase.add_argument("change")
    _rebase.add_argument(
        "--onto",
        help=(
            "Rebase onto a specific branch or commit."
            " By default the commit is rebased on its parent and target branch."
        ),
    )

    _move = subs.add_parser("move", help="Move a Gerrit change to a branch.")
    _move.add_argument("change")
    _move.add_argument("--branch", required=True)

    _query_commands = [
        _incoming,
        _outgoing,
        _query,
    ]

    for sub in _query_commands:
        if sub == _query:
            sub.add_argument("query", nargs='+')
        else:
            sub.add_argument("query", nargs='*')

    QUERY_OUTPUT_DUMP = Literal["dump"]
    QUERY_OUTPUT_FETCH_REF = Literal["fetch"]
    QUERY_OUTPUT_SHAID = Literal["shaid"]
    QUERY_OUTPUT_CHANGEID = Literal["changeid"]
    QUERY_OUTPUT_SUMMARY = Literal["summary"]
    QUERY_OUTPUT_URL = Literal["url"]
    QUERY_OUTPUT_WEB = Literal["web"]  # Url and title

    QUERY_CHOICES = Literal[
        QUERY_OUTPUT_CHANGEID,
        QUERY_OUTPUT_DUMP,
        QUERY_OUTPUT_FETCH_REF,
        QUERY_OUTPUT_SHAID,
        QUERY_OUTPUT_SUMMARY,
        QUERY_OUTPUT_URL,
        QUERY_OUTPUT_WEB,
    ]

    for sub in _query_commands:
        sub.add_argument(
            "--output",
            choices=typing.get_args(QUERY_CHOICES),
            help="Query result output format.",
            default=typing.get_args(QUERY_OUTPUT_SUMMARY)[0],
        )
        sub.add_argument(
            "--all-patch-sets",
            action="store_true",
            help="Query for all patch sets. These are available with `--dump`. Use the patchset command instead."
        )
        sub.add_argument(
            "--this-project",
            help=(
                "Limit the query to a this Gerrit project."
                " To query for another repo use the Gerrit query language `project:`."
            ),
            action='store_true',
        )
        sub.add_argument(
            "--dry-run",
            help="Print the query and HTTP endpoint request.",
            action='store_true',
        )

    args = parser.parse_args()
    command: str = args.command

    assert gerrit_server, "Cannot find which Gerrit server to use, `$GERRIT_CLI_DEFAULT_GERRIT_HOST` is not set."

    try:
        auth = HTTPBasicAuthFromNetrc(url=gerrit_server)
    except ValueError as e:
        print(f"Could not find credentials for Gerrit server {gerrit_server} in netrc.")
        print(e)
        return 1

    rest_api = GerritRestAPI(url=gerrit_server, auth=auth)
    ctx = Context(
        rest_api,
        gerrit_server.replace("https://", ""),
        args.dry_run,
    )

    # TODO(nils): Is there a better way to operate on the names again?
    def sub_command_name(sub: argparse.ArgumentParser) -> str:
        """ Find the deepest subcommand

        'gerrit.py incoming' -> 'incoming'
        'gerrit.py reviewers list' -> 'list'
         """
        return sub.prog.split(' ')[-1]

    if command in [sub_command_name(c) for c in _query_commands]:
        user_query: Optional[str] = None
        output_format: QUERY_CHOICES = args.output

        this_project: bool = args.this_project
        all_patch_sets: bool = args.all_patch_sets

        def format_topic(topic: Optional[str]) -> str:
            return topic if topic is not None else "no-topic"

        display: Callable[[Change], None] = lambda c: print(c)  # noqa

        if output_format == typing.get_args(QUERY_OUTPUT_SUMMARY)[0]:
            display = lambda c: print(  # noqa
                c.revision[:10], c.project, format_topic(c.topic), c.subject, sep="\t"
            )

        if output_format == typing.get_args(QUERY_OUTPUT_SHAID)[0]:
            display = lambda c: print(c.revision)  # noqa

        if output_format == typing.get_args(QUERY_OUTPUT_CHANGEID)[0]:
            display = lambda c: print(c.qualifiedchangeid())  # noqa

        if output_format == typing.get_args(QUERY_OUTPUT_DUMP)[0]:
            display = lambda c: print(c.json())  # noqa

        if output_format == typing.get_args(QUERY_OUTPUT_FETCH_REF)[0]:
            display = lambda c: print(c.print_fetch())  # noqa

        if output_format == typing.get_args(QUERY_OUTPUT_URL)[0]:
            display = lambda c: print(c.url)

        if output_format == typing.get_args(QUERY_OUTPUT_WEB)[0]:
            display = lambda c: print(c.url + " " + c.subject)

        query = "status:open"
        if command == "query":
            user_query = args.query
            assert user_query
            query = " ".join(user_query)
        if command == "incoming":
            user_query = args.query
            query = "status:open (cc:self or reviewer:self) and not owner:self"
            if user_query:
                query += " " + " ".join(user_query)
        if command == "outgoing":
            user_query = args.query
            query = "status:open owner:self"
            if user_query:
                query += " " + " ".join(user_query)

        if this_project:
            query += f" project:{git_project_filter}"

        response = query_changes(ctx, query, all_patch_sets=all_patch_sets)
        for c in response:
            display(c)

        return 0

    def topic_command() -> int:
        # NB: Only two cases of these two arguments may exist:
        # either delete (True) or set a topic (topic).
        # But the type of both is `Optional` in the argument namespace.
        topic: Optional[str] = args.topic

        changes: List[Revision] = args.changes
        rchanges: List[ResolvedRevision] = resolve_changes(ctx, changes)

        description, verb = {
            True: (
                "set",
                lambda change: set_topic(
                    ctx,
                    change=change.Qualifiedchangeid(),
                    topic=topic  # type: ignore
                ),
            ),
            False: (
                "delete",
                lambda change: delete_topic(ctx, change=change.Qualifiedchangeid()),
            ),
        }[topic is not None]

        oks = True
        for r in rchanges:
            ok = verb(r)
            if not ok:
                print(f"Warning: could not {description} topic '{topic}' for '{r}'.", file=sys.stderr)
            oks |= ok

        return 0 if oks else 1

    if command == sub_command_name(_topic):
        return topic_command()

    def resolve_command() -> int:
        from_user: Union[Revision, SymbolicRef] = args.change
        maybe_qualified = canonicalize_revision(ctx, from_user)
        assert maybe_qualified is None or len(maybe_qualified) == 1, "Topics are not handled here."

        if maybe_qualified:
            print(maybe_qualified[0].shaid)
        return 0 if maybe_qualified else 1

    if command == sub_command_name(_resolve):
        return resolve_command()

    def fetch_command() -> int:
        assert root, "Unable to find the git repo root, cannot fetch commits."
        modality = repo_modality(root)
        if modality == "plain-git":
            def fetch(ctx, changes: List[ResolvedRevision]) -> int:
                _ = ctx

                # TODO: Support multiples
                assert len(changes) == 1
                change = changes[0]
                res, shaid = regular_fetch(change.shaid)
                if res == 0:
                    print(change.shaid)
                return res
        if modality == "git-toprepo":
            def fetch(ctx, changes: List[ResolvedRevision]) -> int:
                # TODO: Support multiples
                assert len(changes) == 1
                change = changes[0]
                res, shaid = toprepo_fetch(ctx, change, toprepo="git-toprepo")
                if res == 0:
                    print(shaid)
                return res

        from_user = args.change
        maybe_qualified = canonicalize_revision(ctx, from_user, entire_topic=True)
        assert maybe_qualified

        return fetch(ctx, maybe_qualified)

    if command == sub_command_name(_fetch):
        return fetch_command()

    def user_command() -> int:
        user: str = args.user
        for u in lookup_users(ctx, user):
            print(u)
        return 0

    if command == sub_command_name(_user):
        return user_command()

    def group_command() -> int:
        group: str = args.group
        maybe = lookup_group(ctx, group)
        if not maybe:
            return 1

        print(maybe.name)
        return 0

    if command == sub_command_name(_group):
        return group_command()

    def reviewers_command() -> int:
        subcommand: str = args.review_subcommand

        def list_and_clear() -> int:
            changes: List[str] = args.changes
            entire_topic: bool = args.entire_topic

            # assume the user gave a valid revision
            assert len(changes) == 1, "Only reviewers for a single change can be listed or cleared"
            change, other = revision(changes[0])
            assert change

            # TODO: Can we verify that in code, or is it enough to just give it
            # to Gerrit and find out?
            # The biggest problem is symbolic references like HEAD.
            # That matches way to much on the Gerrit side...
            #
            # Should we maybe have an (optional) safety limit of a hundred or
            # so? I have created topics with 10-20 myself so it should be higher
            # than that.
            # Especially with `clear reviewers` it can be dangerous to
            # accidentally match too much...
            #
            # An owner:self is probably a good default safeguard.
            maybe_resolved = canonicalize_revision(ctx, change, entire_topic=entire_topic)
            if ctx.dry_run:
                maybe_resolved = [
                    ResolvedRevision(
                        project="<project>",
                        branch="<branch>",
                        changeid=ChangeId("<changeid>"),
                        shaid=ShaId("<shaid>"),
                    )
                ]
            if not maybe_resolved:
                return 1
            resolved = maybe_resolved
            reviewers: Set[Person] = set()
            for r in resolved:
                res = query_reviewers(ctx, change=r.Qualifiedchangeid(), body={})
                if not ctx.dry_run:
                    assert res
                    for p in res:
                        reviewers.add(p)
                else:
                    reviewers.add(
                        Person(
                            name="<name>",
                            email=Email("<email>"),
                            tags=None,
                        )
                    )

            if subcommand == sub_command_name(_list_reviewers):
                for p in reviewers:
                    print(p)
            if subcommand == sub_command_name(_clear_reviewers):
                for r in resolved:
                    for p in reviewers:
                        if email := p.email:
                            delete_reviewer(ctx, change=r.Qualifiedchangeid(), reviewer=email)

            return 0

        if subcommand in [
            sub_command_name(_list_reviewers),
            sub_command_name(_clear_reviewers),
        ]:
            return list_and_clear()

        if subcommand == sub_command_name(_add_reviewers):
            arg_reviewers: List[str] = args.reviewers
            entire_topic: bool = args.entire_topic
            changes: List[str] = args.changes

            commits: List[ResolvedRevision] = []

            reviewers: List[Reviewer] = []
            # TODO: The typing of these is a little lax.
            # As we have a try-and-see approach to finding the types.
            # Some type coercion is required.
            for arg in arg_reviewers:
                if "@" in arg:
                    must_be_email = Email(arg)
                    reviewers.append(must_be_email)
                    continue

                maybe_account = try_account(ctx, arg)
                if maybe_account:
                    reviewers.append(maybe_account)
                    continue

                maybe_group = lookup_group(ctx, arg)
                if maybe_group:
                    members = group_members(ctx, maybe_group)
                    reviewers.extend(members)
                    continue

                assert False, f"Could not understand reviewer: '{arg}'"

            for arg in changes:
                must_be_revision = ShaId(arg)
                maybe_resolved = canonicalize_revision(ctx, must_be_revision, entire_topic=entire_topic)

                if maybe_resolved:
                    commits.extend(maybe_resolved)
                    continue

                assert False, f"Could not understand change: '{arg}'"

            oks = True

            if len(commits) == 0:
                print("Error: No commits provided, exiting.", file=sys.stderr)
                return 3

            for rchange in commits:
                for reviewer in reviewers:
                    ok = add_reviewer(
                        ctx,
                        change=rchange.Qualifiedchangeid(),
                        reviewer=reviewer
                    )
                    if not ok:
                        print(f"Warning: could not add reviewer '{reviewer}' for change '{rchange}'.", file=sys.stderr)
                        oks |= ok

            return 0 if oks else 1

        assert False, f"Unrecognized review subcommand '{subcommand}'"

    if command == sub_command_name(_reviewers):
        return reviewers_command()

    def comments_command() -> int:
        from_user = args.change
        entire_topic = args.entire_topic

        maybe_qualified = canonicalize_revision(ctx, from_user, entire_topic=entire_topic)
        if not maybe_qualified:
            return 1
        # This is just a single repo, that is, not a topic.
        # No consideration for submodules is required.
        single_repo = len(maybe_qualified) == 1

        per_repo: Dict[str, List[ReviewComment]] = {}
        for change in maybe_qualified:
            per_repo[change.project], _ = comments(ctx, change.Qualifiedchangeid())

        if single_repo:
            assert len(per_repo.keys()) == 1
            for comment in list(per_repo.values())[0]:
                print(comment.gcc_error_format())

        if not single_repo:
            for project, rcomments in per_repo.items():
                for comment in rcomments:
                    # TODO: Find the path on disk for the project
                    # to print on the gcc error format.
                    print(f"{project}::{comment.gcc_error_format()}")

        return 0

    if command == sub_command_name(_comments):
        return comments_command()

    def messages_command() -> int:
        from_user = args.change
        filter = args.filter
        assert filter in MESSAGE_FILTER_CHOICES

        maybe_qualified = canonicalize_revision(ctx, from_user, entire_topic=False)
        assert maybe_qualified is None or len(maybe_qualified) == 1, "Topics are not handled here."
        if not maybe_qualified:
            return 1
        change = maybe_qualified[0]

        top_level = top_level_messages(ctx, change.Qualifiedchangeid())

        predicate = {
            MESSAGE_FILTER_CHOICES_NO_FILTER: lambda m: True,
            MESSAGE_FILTER_CHOICES_HUMAN: lambda m: not is_bot_message(m),
            MESSAGE_FILTER_CHOICES_JOB_FAILURES: lambda m: is_bot_message(m) and "Build failed." in m.message,
        }[filter]
        formatter = {
            MESSAGE_FILTER_CHOICES_JOB_FAILURES: lambda m:
                format_job_failures(zuul_failures((m.message.splitlines()))),
        }.get(filter, lambda m: m)

        filtered = []
        for m in top_level:
            if predicate(m):
                filtered.append(m)

        for m in filtered:
            print(formatter(m))

        return 0

    if command == sub_command_name(_messages):
        return messages_command()

    if command == sub_command_name(_timing):
        return timing_command()

    def abandon_command() -> int:
        changeids: List[ChangeId] = args.changes
        code = 0
        for rev in changeids:
            # TODO: Share code with `comments`.
            change = must_resolve_unique_change(ctx, rev)
            code += 0 if abandon(ctx, change) else 1

        return code

    if command == sub_command_name(_abandon):
        return abandon_command()

    def patchsets_command() -> int:
        rev = args.change
        change = must_resolve_unique_change(ctx, rev)
        response = query_changes(ctx, change.qualifiedchangeid(), all_patch_sets=True)
        for c in response:
            for n, s in c.patchsets:
                # TODO: also print commit message subject.
                print(n, s)
        return 0

    if command == sub_command_name(_patchsets):
        return patchsets_command()

    def vote_command() -> int:
        # https://gerrit-review.googlesource.com/Documentation/rest-api-changes.html#list-votes
        # https://gerrit-review.googlesource.com/Documentation/rest-api-changes.html#delete-vote
        #
        # https://gerrit-review.googlesource.com/Documentation/rest-api-changes.html#set-review
        # TODO: include message with the vote?
        vote_s: Optional[str] = args.vote
        mr: Optional[int] = args.mr
        rev = args.change

        vote: Dict[str, int] = {}

        assert (
            sum([vote_s is not None, mr is not None]) == 1
        ), "Either a general vote or Maintainer Review must be given. But not both."

        if mr:
            vote = {MAINTAINER_REVIEW: mr}
        if vote_s:
            label, value = vote_s.split('=')
            # TODO: handle plus
            vote = {label: int(value)}

        assert vote != {}, "Could not parse vote"

        change = must_resolve_unique_change(ctx, rev)
        code = 0 if review(ctx, change, votes=vote) else 1
        return code

    if command == sub_command_name(_vote):
        return vote_command()

    def message_command() -> int:
        # https://gerrit-review.googlesource.com/Documentation/rest-api-changes.html#set-review
        message: str = args.message
        rev = args.change
        change = must_resolve_unique_change(ctx, rev)
        code = 0 if review(ctx, change, message=message) else 1
        return code

    if command == sub_command_name(_message):
        return message_command()

    def rebase_command() -> int:
        onto = args.onto
        rev = args.change
        change = must_resolve_unique_change(ctx, rev)

        code = 0 if rebase(ctx, change.Qualifiedchangeid(), onto) else 1
        return code

    if command == sub_command_name(_rebase):
        return rebase_command()

    def move_command() -> int:
        target = args.branch
        rev = args.change
        change = must_resolve_unique_change(ctx, rev)

        code = 0 if move(ctx, change.Qualifiedchangeid(), target) else 1
        return code

    print("Error: unimplemented code path", file=sys.stderr)
    return 3


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
