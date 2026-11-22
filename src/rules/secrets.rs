use super::{FileInfo, Rule};
use crate::{Family, Severity};

fn any_text(_: &FileInfo) -> bool {
    true
}

fn env_file(f: &FileInfo) -> bool {
    (f.name == ".env" || f.name.starts_with(".env."))
        && !["example", "sample", "template", "dist", "defaults"]
            .iter()
            .any(|s| f.name.ends_with(s))
}

const ROTATE: &str = "Revoke this credential at the provider, then load it from the environment or a secrets manager and keep it out of the repository.";

macro_rules! secret {
    ($id:literal, $sev:ident, $pat:literal, $msg:literal) => {
        Rule {
            id: $id,
            family: Family::Secret,
            severity: Severity::$sev,
            files: any_text,
            pattern: $pat,
            unless: None,
            message: $msg,
            fix: ROTATE,
        }
    };
}

pub static RULES: &[Rule] = &[
    secret!(
        "secret.aws-access-key",
        Critical,
        r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
        "An AWS access key id is written in the file."
    ),
    secret!(
        "secret.github-token",
        Critical,
        r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})",
        "A GitHub token is written in the file."
    ),
    secret!(
        "secret.slack-token",
        High,
        r"\bxox[baprs]-[A-Za-z0-9-]{10,}",
        "A Slack token is written in the file."
    ),
    secret!(
        "secret.stripe-live-key",
        Critical,
        r"\b[sr]k_live_[A-Za-z0-9]{24,}",
        "A live Stripe secret key is written in the file."
    ),
    secret!(
        "secret.anthropic-key",
        Critical,
        r"\bsk-ant-[A-Za-z0-9_\-]{32,}",
        "An Anthropic API key is written in the file."
    ),
    secret!(
        "secret.openai-key",
        Critical,
        r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{32,}|\bsk-[A-Za-z0-9]{48}\b",
        "An OpenAI API key is written in the file."
    ),
    secret!(
        "secret.google-api-key",
        High,
        r"\bAIza[0-9A-Za-z_\-]{35}",
        "A Google API key is written in the file."
    ),
    secret!(
        "secret.private-key",
        Critical,
        r"-----BEGIN ((RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED) )?PRIVATE KEY( BLOCK)?-----\r?\n[A-Za-z0-9+/=]{20,}",
        "A private key is stored in the repository."
    ),
    Rule {
        id: "secret.hardcoded-password",
        family: Family::Secret,
        severity: Severity::High,
        files: any_text,
        pattern: r#"(?i)\b(password|passwd|pwd|secret|api_?key|access_?token|auth_?token|client_?secret)\b["']?\s*[:=]\s*["']([^"'\s]{8,})["']"#,
        unless: Some(
            r#"(?i)[:=]\s*["'][^"']*(?:\.\.\.|…)|[:=]\s*["'](\$|changeme|password|secret|example|x{3,}|your[-_]|<|\$\{|\{\{|%\(|dummy|test|placeholder|redacted|\*{3,}|none|null)"#,
        ),
        message: "A password or secret is written in the code.",
        fix: ROTATE,
    },
    Rule {
        id: "secret.url-credentials",
        family: Family::Secret,
        severity: Severity::High,
        files: any_text,
        pattern: r#"\b[a-z][a-z0-9+.\-]*://[^\s:/@"'`]+:[^\s@/"'`$]{4,}@[^\s"'`]+"#,
        unless: Some(
            r"(?i)localhost|127\.0\.0\.1|0\.0\.0\.0|example\.(com|org)|:password@|:pass@|\$\{|\buser(?:name)?:(?:token|pass(?:word)?|secret|pat)@|:\*+@",
        ),
        message: "A connection string carries a username and password.",
        fix: ROTATE,
    },
    Rule {
        id: "secret.env-file",
        family: Family::Secret,
        severity: Severity::Medium,
        files: env_file,
        pattern: r"\A(?:.*\n)*?[A-Za-z_][A-Za-z0-9_]*=\S",
        unless: None,
        message: "A .env file with values is in the repository; these usually hold real secrets.",
        fix: "Remove the file from git (keep a .env.example without values) and add .env to .gitignore.",
    },
];
