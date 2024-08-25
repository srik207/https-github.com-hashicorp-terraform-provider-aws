DATAFY_PROJECT_NAME := terraform-provider-datafyaws
DATAFY_MODIFIED_PACKAGES=./internal/service/ec2 ./internal/provider

default: datafy-build

.PHONY: datafy-build
datafy-build: build datafy-rename-bin

.PHONY: datafy-install
datafy-install: install datafy-rename-bin

.PHONY: datafy-rename-bin
datafy-rename-bin:
	@mv ~/go/bin/terraform-provider-aws ~/go/bin/$(DATAFY_PROJECT_NAME)


.PHONY: datafy-rebase
datafy-rebase:
	@echo "make: Update CODEOWNERS..."
	@echo "* @datafy-io/back-end" > CODEOWNERS

	@echo "make: Cleaning github workflow files..."
	@EXCLUDE=("provider.yml" "datafy-release.yml") ; \
	PATTERN=$$(printf "! -name %s " "$${EXCLUDE[@]}") ; \
	find ./.github/workflows $$PATTERN -mindepth 1 -maxdepth 1 -exec rm -rf {} + > /dev/null 2>&1;

	@echo "make: Refactoring remaining github workflow files..."
	@find ./.github/workflows -type f -exec sed -i '' 's|runs-on:.*|runs-on: datafy-16-cores|' {} +
	@find ./.github/workflows -type f -exec sed -i '' 's|run: go test.*|run: go test $(DATAFY_MODIFIED_PACKAGES)|' {} + > /dev/null 2>&1;

	@echo "make: Refactoring goreleaser.yml file..."
	@docker run --rm -v `pwd`:/workdir mikefarah/yq eval -i '.project_name = "$(DATAFY_PROJECT_NAME)"' .goreleaser.yml
	@docker run --rm -v `pwd`:/workdir mikefarah/yq -i 'del(.publishers)' .goreleaser.yml
	@docker run --rm -v `pwd`:/workdir mikefarah/yq -i '.signs = [{"artifacts":"checksum","args":["--batch","--local-user","{{ .Env.GPG_FINGERPRINT }}","--output","$${signature}","--detach-sign","$${artifact}"]}]' .goreleaser.yml
	@docker run --rm -v `pwd`:/workdir mikefarah/yq -i '.changelog = {"filters":{"include": ["^Datafy:", "^DT-[0-9]+:"]}}' .goreleaser.yml