#!/bin/bash

set -e

run_shellcheck() {
  set -o pipefail
  shopt -s nullglob
  files=()
  while IFS='' read -r -d '' line; do
    files+=("$line")
  done < <(find ./stages -name '*.sh' -print0)
  if [ -n "${files[0]}" ]; then
    echo " Scanning shell scripts..."
    (
      IFS=$'\n'
      echo "${files[*]}"
    )
    shellcheck --exclude=SC2153 --format=gcc -- "${files[@]}"
    ret=$?
  fi

  echo "# Scanning embedded scripts..."
  while IFS= read -r -d '' file; do
    echo "# $file"
    yq -r '.[] | objects | .before_script, .script, .after_script | select(. != null) | join("\n")' "$file" | shellcheck --exclude=SC2153 --format=gcc -s bash -
    yq_ret=$?
    if [ $yq_ret -ne 0 ]; then
      ret=$yq_ret
    fi
  done < <(find . \( -name '*.yaml' -o -name '*.yml' ! -path './scripts/analysis/*' \) -print0)
}

run_black() {
  echo "Running black..."
  if [ "$1" == "format_in_place" ]; then
    black -t py311 -- .
  else
    black --check --diff --color -t py311 .
  fi
}

run_docformatter() {
  python3 -m pip install docformatter
  echo "Running docformatter..."
  if [ "$1" == "format_in_place" ]; then
    docformatter --in-place -r stages ironbank
  else
    docformatter --check --diff -r stages ironbank
  fi
}

run_autoflake() {
  echo "Running autoflake..."
  if [ "$1" == "format_in_place" ]; then
    autoflake --in-place --remove-unused-variables --remove-all-unused-imports --remove-duplicate-keys --recursive .
  else
    autoflake --check-diff --quiet --recursive .
  fi
}

run_radon() {
  python3 -m pip install radon radon[toml]
  python3 -m radon cc ironbank/ stages/
}

# Function to run pylama
run_pylama() {
  echo "Running pylama..."
  pip install pylama --upgrade
  pylama
}

# Function to run prettier
run_prettier() {
  echo "Running prettier..."
  if [ "$1" == "format_in_place" ]; then
    npx prettier --write .
  else
    npx prettier -c .
  fi
}

# Function to run pylint
run_pylint() {
  echo "Running pylint..."
  mkdir ./pylint
  pylint stages/ ironbank/ | tee ./pylint/pylint.log || pylint-exit $?
  PYLINT_SCORE=$(sed -n 's/^Your code has been rated at \([-0-9.]*\)\/.*/\1/p' ./pylint/pylint.log)
  anybadge --label=Pylint --file=pylint/pylint.svg --value="${PYLINT_SCORE}" 3=red 6=orange 9=yellow 10=green
  echo "Pylint score is '${PYLINT_SCORE}'"
}

run_shfmt() {
  echo "Running shfmt..."
  if [ "$1" == "format_in_place" ]; then
    shfmt -w .
  else
    shfmt -d .
  fi
}

run_unit_tests() {
  echo "Running unit testing..."
  python3 -m pip install .
  python3 -m pytest -m "not slow"
}

run_check_secrets() {
  echo "running check secrets"
  docker run -it --entrypoint /proj/code_checker.sh --rm -v $(pwd):/proj registry1.dso.mil/ironbank/opensource/trufflehog/trufflehog3:3.0.6 run_trufflehog
}

run_trufflehog() {
  git config --global --add safe.directory /proj
  current_branch=$(git rev-parse --abbrev-ref HEAD)
  first_commit=$(git rev-list --reverse master.. | head -n 1)
  # Installing prettier locally install the node_module folders some public github token we don't care about
  # We're removing this from the result
  rm -rf /proj/node_modules/prettier
  trufflehog3 --no-entropy --ignore-nosecret --branch "${current_branch}" --since "${first_commit}" /proj
}

run_isort() {
  echo "Running isort..."
  if [ "$1" == "format_in_place" ]; then
    isort **/*.py -v --overwrite-in-place
  else
    isort **/*.py --check-only --diff
  fi
}

lint_all() {
  rm -rf pylint
  python3 -m pip install .
  run_pylint
  run_shellcheck
  run_pylama
  run_radon
}

format_check_all() {
  python3 -m pip install .
  run_isort
  run_black
  run_autoflake
  run_prettier
  run_shfmt
  run_docformatter
}

format_in_place() {
  python3 -m pip install .
  run_isort format_in_place
  run_black format_in_place
  run_autoflake format_in_place
  run_prettier format_in_place
  run_shfmt format_in_place
  run_docformatter format_in_place
}

if declare -f "$1" >/dev/null; then
  # call arguments verbatim
  "$@"
else
  # Show a helpful error
  echo "'$1' is not a known function name" >&2
  exit 1
fi
