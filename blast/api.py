"""Public analysis pipeline.

``analyze`` is the single entry point. It is a pure function over the command
string, the directory root, the catalog, the policy and the caller's declared
environment. It never executes the analyzed string.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from .capabilities import evaluate
from .catalog import Catalog, load_catalog, validate_catalog
from .evidence import resolve
from .expand import expand_word
from .model import (
    EXIT_ERROR,
    SCHEMA_VERSION,
    STATUS_ERROR,
    TOOL_VERSION,
    VERDICT_DENY,
    AnalysisResult,
    Budget,
    EvidenceReport,
    Invocation,
    ParseIssue,
    Pipeline,
    Redirect,
    SimpleCommand,
    Span,
    SyntaxModel,
    sha256_text,
)
from .parser import parse
from .policy import Policy, decide, load_policy, validate_policy


def _expand_model(model: SyntaxModel, trusted_env: Optional[Dict[str, str]],
                  trusted_home: Optional[str]) -> SyntaxModel:
    def expand_pipeline(pipeline: Pipeline) -> Pipeline:
        commands = []
        for cmd in pipeline.commands:
            words = tuple(expand_word(w, trusted_env, trusted_home) for w in cmd.words)
            redirects = tuple(
                Redirect(
                    r.op,
                    expand_word(r.target, trusted_env, trusted_home) if r.target else None,
                    r.fd, r.span,
                )
                for r in cmd.redirects
            )
            commands.append(SimpleCommand(
                words, redirects, cmd.assignments, cmd.span, cmd.background
            ))
        return Pipeline(tuple(commands), pipeline.span)

    pipelines = tuple(expand_pipeline(p) for p in model.pipelines)
    invocations = []
    for inv in model.invocations:
        invocations.append(Invocation(
            name=expand_word(inv.name, trusted_env, trusted_home),
            args=tuple(expand_word(w, trusted_env, trusted_home) for w in inv.args),
            redirects=tuple(
                Redirect(
                    r.op,
                    expand_word(r.target, trusted_env, trusted_home) if r.target else None,
                    r.fd, r.span,
                )
                for r in inv.redirects
            ),
            assignments=inv.assignments,
            pipeline_index=inv.pipeline_index,
            position=inv.position,
            pipe_in=inv.pipe_in,
            pipe_out=inv.pipe_out,
            background=inv.background,
            span=inv.span,
        ))
    return SyntaxModel(pipelines, tuple(invocations), model.issues, model.span)


def _internal_error(
    command: str, dialect: str, catalog: Optional[Catalog],
    policy: Optional[Policy], message: str, exc: BaseException,
) -> AnalysisResult:
    issue = ParseIssue(
        "INTERNAL_ERROR",
        "%s: %s: %s" % (message, type(exc).__name__, str(exc)[:200]),
        "error",
        Span(0, len(command), 1, 1),
        command[:120],
    )
    return AnalysisResult(
        schema_version=SCHEMA_VERSION,
        tool_version=TOOL_VERSION,
        input_sha256=sha256_text(command),
        dialect=dialect,
        catalog_version=catalog.version if catalog else "unavailable",
        catalog_digest=catalog.digest if catalog else "",
        policy_version=policy.version if policy else "unavailable",
        policy_digest=policy.digest if policy else "",
        status=STATUS_ERROR,
        assertions=(),
        unknowns=(),
        parse_issues=(issue,),
        evidence=EvidenceReport.empty(),
        verdict=VERDICT_DENY,
        reasons=("internal analyzer failure: fail closed",),
        exit_code=EXIT_ERROR,
    )


def analyze(
    command: str,
    root: str = ".",
    catalog_path: Optional[str] = None,
    policy_path: Optional[str] = None,
    dialect: str = "bash",
    strict: bool = False,
    trusted_env: Optional[Dict[str, str]] = None,
    trusted_home: Optional[str] = None,
    budget: Optional[Budget] = None,
    catalog_data: Optional[Dict[str, Any]] = None,
    policy_data: Optional[Dict[str, Any]] = None,
) -> AnalysisResult:
    """Analyze a shell command and return a deterministic, fail-closed result."""
    if not isinstance(command, str):
        raise TypeError("command must be a string")
    budget = budget or Budget()
    catalog: Optional[Catalog] = None
    policy: Optional[Policy] = None
    try:
        if catalog_data is not None:
            validate_catalog(catalog_data)
            catalog = Catalog(catalog_data, "<memory>")
        else:
            catalog = load_catalog(catalog_path)
        if policy_data is not None:
            validate_policy(policy_data)
            policy = Policy(policy_data, "<memory>")
        else:
            policy = load_policy(policy_path)
        assert catalog is not None and policy is not None

        model = parse(command, dialect, budget)
        expanded = _expand_model(model, trusted_env, trusted_home)
        eval_result = evaluate(expanded, catalog, dialect=dialect)
        evidence = resolve(eval_result.assertions, root, budget)
        decision = decide(eval_result, evidence, policy, strict=strict)

        status = eval_result.status
        if evidence.truncated and status != STATUS_ERROR:
            status = "opaque"

        return AnalysisResult(
            schema_version=SCHEMA_VERSION,
            tool_version=TOOL_VERSION,
            input_sha256=sha256_text(command),
            dialect=dialect,
            catalog_version=catalog.version,
            catalog_digest=catalog.digest,
            policy_version=policy.version,
            policy_digest=policy.digest,
            status=status,
            assertions=eval_result.assertions,
            unknowns=eval_result.unknowns,
            parse_issues=expanded.issues,
            evidence=evidence,
            verdict=decision.verdict,
            reasons=decision.reasons,
            exit_code=decision.exit_code,
        )
    except Exception as exc:  # noqa: BLE001 - fail closed on analysis failure
        return _internal_error(command, dialect, catalog, policy,
                               "analysis pipeline", exc)


def analyze_with_defaults(command: str, **kwargs: Any) -> AnalysisResult:
    """Convenience alias used by examples and tests."""
    return analyze(command, **kwargs)
