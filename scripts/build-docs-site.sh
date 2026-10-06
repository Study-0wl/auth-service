#!/usr/bin/env bash
# Builds the GitHub Pages site into _site/ from docs/specs/<version>/openapi.yaml.
# Layout: / (Swagger UI with version picker), /specs/<v>/openapi.yaml.
set -euo pipefail

SPECS_DIR="docs/specs"
OUT="_site"

mapfile -t VERSIONS < <(ls -1 "$SPECS_DIR" | sort -V)
[ "${#VERSIONS[@]}" -gt 0 ] || { echo "No specs found in $SPECS_DIR" >&2; exit 1; }
LATEST="${VERSIONS[-1]}"

rm -rf "$OUT"
mkdir -p "$OUT/specs"

for v in "${VERSIONS[@]}"; do
  spec="$SPECS_DIR/$v/openapi.yaml"
  declared=$(awk '/^info:/{i=1;next} i && /^[^ ]/{i=0} i && /^  version:/{gsub(/["\047 ]/,"",$2); print $2; exit}' "$spec")
  if [ "$declared" != "$v" ]; then
    echo "info.version ($declared) in $spec does not match folder name ($v)" >&2
    exit 1
  fi
  npx --yes -p @seriousme/openapi-schema-validator validate-api "$spec"
  mkdir -p "$OUT/specs/$v"
  cp "$spec" "$OUT/specs/$v/openapi.yaml"
done

# versions.json drives the Swagger UI dropdown
{
  printf '{"latest":"%s","versions":[' "$LATEST"
  sep=""
  for ((i=${#VERSIONS[@]}-1; i>=0; i--)); do
    printf '%s"%s"' "$sep" "${VERSIONS[i]}"
    sep=","
  done
  printf ']}\n'
} > "$OUT/versions.json"

# Swagger UI
npm install --no-save swagger-ui-dist
cp docs/swagger/index.html "$OUT/index.html"
cp node_modules/swagger-ui-dist/swagger-ui.css \
   node_modules/swagger-ui-dist/swagger-ui-bundle.js \
   node_modules/swagger-ui-dist/swagger-ui-standalone-preset.js "$OUT/"

echo "Built ${#VERSIONS[@]} version(s); latest = $LATEST"
