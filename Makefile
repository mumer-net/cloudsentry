PLAN = terraform plan -input=false -var offline=true -var ami_id=ami-0123456789abcdef0
OFFLINE = AWS_PROFILE= AWS_ACCESS_KEY_ID=offline AWS_SECRET_ACCESS_KEY=offline

.PHONY: test fixtures clean-lab faulty-lab destroy

test:
	uv run ruff check .
	uv run ruff format --check .
	uv run pytest -q

# Plan both lab modes without touching AWS and keep the JSON as test fixtures.
fixtures:
	mkdir -p tests/fixtures
	cd lab && $(OFFLINE) $(PLAN) -var faults=false -out clean.tfplan && terraform show -json clean.tfplan > ../tests/fixtures/plan-clean.json
	cd lab && $(OFFLINE) $(PLAN) -var faults=true -out faults.tfplan && terraform show -json faults.tfplan > ../tests/fixtures/plan-faults.json

clean-lab:
	cd lab && terraform apply -var faults=false

faulty-lab:
	cd lab && terraform apply -var faults=true

destroy:
	cd lab && terraform destroy
