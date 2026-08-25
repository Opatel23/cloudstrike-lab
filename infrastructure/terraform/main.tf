provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "cloudstrike-lab"
      LabID     = "cloudstrike-lab-iam-passrole"
      Owner     = var.lab_owner
      ManagedBy = "terraform"
      Purpose   = "authorized-security-training"
    }
  }
}

data "aws_caller_identity" "current" {}

resource "random_id" "suffix" {
  byte_length = 3
}

resource "aws_secretsmanager_secret" "crown_jewel" {
  name                    = "cloudstrike-lab/demo-database-${random_id.suffix.hex}"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "crown_jewel" {
  secret_id     = aws_secretsmanager_secret.crown_jewel.id
  secret_string = jsonencode({ username = "demo-user", password = "NOT-A-REAL-CREDENTIAL" })
}

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_privileged" {
  name               = "cloudstrike-lab-lambda-privileged-${random_id.suffix.hex}"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

data "aws_iam_policy_document" "secret_read" {
  statement {
    sid       = "ReadOnlyTheDemoSecret"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.crown_jewel.arn]
  }
}

resource "aws_iam_role_policy" "secret_read" {
  name   = "cloudstrike-lab-secret-read"
  role   = aws_iam_role.lambda_privileged.id
  policy = data.aws_iam_policy_document.secret_read.json
}

data "aws_iam_policy_document" "app_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = ["cloudstrike-lab-only"]
    }
  }
}

resource "aws_iam_role" "app" {
  name               = "cloudstrike-lab-app-${random_id.suffix.hex}"
  assume_role_policy = data.aws_iam_policy_document.app_trust.json
}

data "aws_iam_policy_document" "vulnerable_app" {
  count = var.enable_vulnerable_policy ? 1 : 0
  statement {
    sid       = "IntentionallyVulnerablePassRole"
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.lambda_privileged.arn]
  }
  statement {
    sid = "CreateOnlyTaggedLabFunctions"
    actions = [
      "lambda:CreateFunction",
      "lambda:InvokeFunction",
      "lambda:DeleteFunction",
      "lambda:GetFunction"
    ]
    resources = ["arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:cloudstrike-lab-*"]
  }
}

resource "aws_iam_role_policy" "vulnerable_app" {
  count  = var.enable_vulnerable_policy ? 1 : 0
  name   = "INTENTIONALLY-VULNERABLE-cloudstrike-passrole"
  role   = aws_iam_role.app.id
  policy = data.aws_iam_policy_document.vulnerable_app[0].json
}

resource "aws_cloudtrail" "lab" {
  name                          = "cloudstrike-lab-${random_id.suffix.hex}"
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_logging                = true
  depends_on                    = [aws_s3_bucket_policy.trail]
}

resource "aws_s3_bucket" "trail" {
  bucket        = "cloudstrike-lab-trail-${data.aws_caller_identity.current.account_id}-${random_id.suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
  statement {
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail_bucket.json
}

