#!/bin/bash

set -e
set -o pipefail

run_shellcheck() {
  echo "*******************"
  echo "Running shellcheck"
  echo "*******************"
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
    shellcheck --exclude=SC2153,SC2164 --format=gcc -- "${files[@]}"
  fi

  echo "# Scanning embedded scripts..."
  while IFS= read -r -d '' file; do
    echo "# $file"
    yq -r '.[] | objects | .before_script, .script, .after_script | select(. != null) | join("\n")' "$file" | shellcheck --exclude=SC2153,SC2164 --format=gcc -s bash -
  done < <(find . \( -name '*.yaml' -o -name '*.yml' ! -path './scripts/analysis/*' \) -print0)
  echo -e "\n"
}

run_black() {
  echo "*********************"
  echo "Running black..."
  echo "*********************"
  if [ "$1" == "format_in_place" ]; then
    black -t py311 -- .
  else
    black --check --diff --color -t py311 .
  fi
  echo -e "\n"
}

run_docformatter() {
  echo "*********************"
  echo "Running docformatter..."
  echo "*********************"
  if [ "$1" == "format_in_place" ]; then
    docformatter --in-place -r stages ironbank
  else
    docformatter --check --diff -r stages ironbank
  fi
  echo -e "\n"
}

run_autoflake() {
  echo "*********************"
  echo "Running autoflake..."
  echo "*********************"
  if [ "$1" == "format_in_place" ]; then
    autoflake --in-place --remove-unused-variables --remove-all-unused-imports --remove-duplicate-keys --recursive .
  else
    autoflake --check-diff --quiet --recursive .
  fi
  echo -e "\n"
}

run_radon() {
  echo "*****************"
  echo "Running radon"
  echo "*****************"
  output=$(python3 -m radon cc -e "*test_*.py" -n "D" ironbank/ stages/)
  if [[ -z "$output" ]]; then
    echo "radon found no problems"
  else
    echo "$output"
    echo -e "\n"
    exit 1
  fi
  echo -e "\n"
}

# Function to run prettier
run_prettier() {
  echo "*********************"
  echo "Running prettier..."
  echo "*********************"
  if [ "$1" == "format_in_place" ]; then
    npx prettier --write .
  else
    npx prettier -c .
  fi
  echo -e "\n"
}

# Function to run pylint
run_pylint() {
  echo "*****************"
  echo "Running pylint..."
  echo "*****************"
  mkdir ./pylint
  pylint stages/ ironbank/ | tee ./pylint/pylint.log
  PYLINT_SCORE=$(sed -n 's/^Your code has been rated at \([-0-9.]*\)\/.*/\1/p' ./pylint/pylint.log)
  anybadge --label=Pylint --file=pylint/pylint.svg --value="${PYLINT_SCORE}" 3=red 6=orange 9=yellow 10=green
  echo "Pylint score is '${PYLINT_SCORE}'"
  echo -e "\n"
  echo "Running pylint with tests and mocks"
  pylint stages/ ironbank/ --rcfile=.pylinttestrc | tee ./pylint/pylinttests.log || pylint-exit $?
  echo -e "\n"
}

run_shfmt() {
  echo "*****************"
  echo "Running shfmt..."
  echo "*****************"
  if [ "$1" == "format_in_place" ]; then
    shfmt -w .
  else
    shfmt -d .
  fi
  echo -e "\n"
}

run_unit_tests() {
  echo "********************"
  echo "Running unit tests"
  echo "********************"
  python3 -m pytest -m "not slow"
  echo -e "\n"
}

run_check_secrets() {
  echo "*********************"
  echo "running check secrets"
  echo "*********************"
  docker run -it --entrypoint /proj/code_checker.sh --rm -v $(pwd):/proj registry1.dso.mil/ironbank/opensource/trufflehog/trufflehog3:3.0.6 run_trufflehog
  echo -e "\n"
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
  echo "*********************"
  echo "Running isort..."
  echo "*********************"
  if [ "$1" == "format_in_place" ]; then
    isort **/*.py -v --overwrite-in-place
  else
    isort **/*.py --check-only --diff
  fi
  echo -e "\n"
}

lint_all() {
  rm -rf pylint
  run_pylint
  run_shellcheck
  run_radon
}

format_check_all() {
  run_isort
  run_black
  run_autoflake
  run_prettier
  run_shfmt
  run_docformatter
}

format_in_place() {
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
