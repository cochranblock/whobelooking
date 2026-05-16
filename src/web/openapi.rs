// All Rights Reserved — The Cochran Block, LLC
//! OpenAPI 3.0.3 spec at `/openapi.json` + Swagger UI at `/docs` +
//! self-hosted Claude Code skill at `/skill` and one-liner installer at
//! `/install-skill.sh`. External clients can discover, exercise, and
//! install against the public surface-scan API.

use axum::{
    http::header,
    response::{Html, IntoResponse},
};

const OPENAPI: &str = include_str!("openapi.json");
const SKILL_MD: &str = include_str!("../../.claude/skills/whobelooking-scan/SKILL.md");

pub async fn json() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
        ],
        OPENAPI,
    )
}

pub async fn skill_md() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/markdown; charset=utf-8"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
        ],
        SKILL_MD,
    )
}

pub async fn install_skill_sh() -> impl IntoResponse {
    let script = format!(
        "#!/usr/bin/env bash\n\
         # whobelooking-scan — Claude Code skill installer.\n\
         # Drops SKILL.md into ~/.claude/skills/whobelooking-scan/ so any\n\
         # Claude Code session can call the public surface-scan API.\n\
         #\n\
         # Usage: curl -sSL https://whobelooking.cochranblock.org/install-skill.sh | bash\n\
         set -eu\n\
         DEST=\"${{HOME}}/.claude/skills/whobelooking-scan\"\n\
         mkdir -p \"$DEST\"\n\
         cat > \"$DEST/SKILL.md\" <<'WBLSKILLEOF'\n\
         {body}\n\
         WBLSKILLEOF\n\
         echo \"whobelooking-scan installed at $DEST/SKILL.md\"\n\
         echo \"In any Claude Code session, ask: 'scan example.com' to invoke it.\"\n",
        body = SKILL_MD
    );
    (
        [
            (header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
        ],
        script,
    )
}

pub async fn ui() -> Html<&'static str> {
    Html(SWAGGER_UI_HTML)
}

const SWAGGER_UI_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>whobelooking API — Swagger UI</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
<style>
  body { margin: 0; background: #050508; }
  .swagger-ui .topbar { display: none; }
</style>
</head>
<body>
<div id="ui"></div>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js" crossorigin></script>
<script>
window.ui = SwaggerUIBundle({
  url: '/openapi.json',
  dom_id: '#ui',
  deepLinking: true,
  layout: 'BaseLayout',
  defaultModelsExpandDepth: 1,
  tryItOutEnabled: true
});
</script>
</body>
</html>
"##;
