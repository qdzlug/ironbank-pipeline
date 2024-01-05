.PHONY: install_dependencies lint_all format_check_all format_in_place run_unit_tests check_secrets

install_dependencies:
	brew install poetry
	brew install shfmt
	brew install npm
	brew install shellcheck
	brew install jq
	npm install --save-dev --save-exact prettier
	poetry install

lint_all:
	./code_checker.sh lint_all
format_check_all:
	./code_checker.sh format_check_all
format_in_place:
	./code_checker.sh format_in_place
run_radon:
	./code_checker.sh run_radon
run_shellcheck:
	./code_checker.sh run_shellcheck
run_unit_tests:
	./code_checker.sh run_unit_tests
run_bandit:
	./code_checker.sh run_bandit
check_secrets:
	./code_checker.sh run_check_secrets
