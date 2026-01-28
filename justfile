default: test

test: 
  swift test
  
bump-dep dryRun="false":
  swift run \
    --package-path scripts/update-libsecp \
    update-libsecp \
    {{ if dryRun == "true" { "--dry-run" } else { "" } }}