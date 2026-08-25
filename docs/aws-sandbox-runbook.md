# AWS sandbox acceptance runbook

Use this only in a dedicated personal training account. Never use a production, employer, client, shared, or third-party AWS account.

## 1. Prepare the account

1. Enable MFA on the account owner and create a separate administrative lab identity.
2. Configure an AWS Budget with email alerts before creating resources.
3. Install AWS CLI v2 and Terraform, then authenticate with a named sandbox profile.
4. Verify the active identity:

   ```powershell
   aws sts get-caller-identity --profile cloudstrike-sandbox
   ```

5. Set the profile only for the current terminal:

   ```powershell
   $env:AWS_PROFILE = "cloudstrike-sandbox"
   ```

## 2. Review before creating anything

From `infrastructure/terraform`:

```powershell
Copy-Item vulnerable.tfvars.example vulnerable.tfvars
terraform init
terraform validate
terraform plan -var-file vulnerable.tfvars -out lab.tfplan
terraform show lab.tfplan
```

Edit `vulnerable.tfvars` with your owner label and explicitly acknowledge the sandbox guard. Confirm every planned resource is named or tagged `cloudstrike-lab` and that the account shown by AWS CLI is the intended sandbox.

## 3. Deploy and capture the safety manifest

```powershell
terraform apply lab.tfplan
terraform output -json | Set-Content -Encoding utf8 ..\..\work\terraform-output.json
```

Do not hand-edit this output. It binds discovery to the created account, region, roles, and fake secret.

## 4. Run read-only discovery

From the repository root:

```powershell
$env:PYTHONPATH = "$PWD\engine"
python -m cloudstrike aws-plan --manifest work\terraform-output.json --output outputs\aws-plan.json
```

Expected result: the graph contains the lab chain and the plan reports zero executed actions. A caller-account mismatch, missing lab tag, unexpected ARN, or resource-name mismatch must stop the run.

## 5. Ingest telemetry

Download only the lab CloudTrail records into `work/cloudtrail.json`, then run:

```powershell
python -m cloudstrike ingest-cloudtrail --manifest work\terraform-output.json --input work\cloudtrail.json --output outputs\cloudtrail-events.json
```

Check that unrelated accounts, regions, and resources were excluded and sensitive request fields were redacted.

## 6. Apply the fixed policy and inspect again

```powershell
Set-Location infrastructure\terraform
Copy-Item fixed.tfvars.example fixed.tfvars
terraform plan -var-file fixed.tfvars -out fixed.tfplan
terraform apply fixed.tfplan
Set-Location ..\..
python -m cloudstrike aws-plan --manifest work\terraform-output.json --output outputs\aws-plan-fixed.json
```

The risky `iam:PassRole` edge should no longer produce a complete exploitable path.

## 7. Tear down and verify

```powershell
Set-Location infrastructure\terraform
terraform destroy -var-file fixed.tfvars
```

Confirm the destroy completes, then check the AWS console and Cost Explorer for unexpected resources or spend. Retain only sanitized reports; do not commit credentials, Terraform state, raw CloudTrail exports, or account-specific manifests.
