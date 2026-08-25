output "lab_id" {
  value = "cloudstrike-lab-iam-passrole"
}

output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "aws_region" {
  value = var.aws_region
}

output "cloudtrail_bucket" {
  value = aws_s3_bucket.trail.id
}

output "app_role_arn" {
  value = aws_iam_role.app.arn
}

output "privileged_role_arn" {
  value = aws_iam_role.lambda_privileged.arn
}

output "secret_arn" {
  value = aws_secretsmanager_secret.crown_jewel.arn
}

output "vulnerable_policy_enabled" {
  value = var.enable_vulnerable_policy
}
