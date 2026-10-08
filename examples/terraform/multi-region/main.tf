# The same cloud seen from three regions (examples/multiregion-local):
# palaven-1 (home), tuchanka-1 and thessia-1, one provider alias each.
#
#   - IAM is global: the replication role is created once.
#   - S3: a versioned bucket in palaven-1 replicates every new version, delete
#     markers included, to a versioned bucket in thessia-1.
#   - DynamoDB: a global table (version 2019.11.21) created in palaven-1 with
#     replicas in tuchanka-1 and thessia-1; every replica accepts writes.
#   - SQS is regional, as in AWS: one queue per region through the aliases.
#
# examples/terraform/multi-region/smoke.sh starts the three regions and runs
# init, apply, plan -detailed-exitcode, a replication check and destroy.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

variable "endpoints" {
  description = "Citadel endpoint of each region."
  type        = map(string)
  default = {
    "palaven-1"  = "http://127.0.0.1:8441"
    "tuchanka-1" = "http://127.0.0.1:8440"
    "thessia-1"  = "http://127.0.0.1:8442"
  }
}

variable "name" {
  description = "Prefix for every resource name."
  type        = string
  default     = "tf-multi"
}

# One provider per region. The provider reaches a global table's replicas
# through the endpoint of the provider that owns the table, signing for the
# replica's region; Citadel routes such requests to the region they are
# signed for.

provider "aws" {
  alias  = "palaven"
  region = "palaven-1"

  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  s3_use_path_style           = true

  endpoints {
    dynamodb = var.endpoints["palaven-1"]
    iam      = var.endpoints["palaven-1"]
    s3       = var.endpoints["palaven-1"]
    sqs      = var.endpoints["palaven-1"]
    sts      = var.endpoints["palaven-1"]
  }
}

provider "aws" {
  alias  = "tuchanka"
  region = "tuchanka-1"

  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  s3_use_path_style           = true

  endpoints {
    dynamodb = var.endpoints["tuchanka-1"]
    iam      = var.endpoints["tuchanka-1"]
    s3       = var.endpoints["tuchanka-1"]
    sqs      = var.endpoints["tuchanka-1"]
    sts      = var.endpoints["tuchanka-1"]
  }
}

provider "aws" {
  alias  = "thessia"
  region = "thessia-1"

  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  s3_use_path_style           = true

  endpoints {
    dynamodb = var.endpoints["thessia-1"]
    iam      = var.endpoints["thessia-1"]
    s3       = var.endpoints["thessia-1"]
    sqs      = var.endpoints["thessia-1"]
    sts      = var.endpoints["thessia-1"]
  }
}

# ---- IAM (global) --------------------------------------------------------------

data "aws_iam_policy_document" "assume_s3" {
  provider = aws.palaven

  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "replication" {
  provider           = aws.palaven
  name               = "${var.name}-replication"
  assume_role_policy = data.aws_iam_policy_document.assume_s3.json
}

data "aws_iam_policy_document" "replication" {
  provider = aws.palaven

  statement {
    actions   = ["s3:GetReplicationConfiguration", "s3:ListBucket"]
    resources = [aws_s3_bucket.source.arn]
  }
  statement {
    actions   = ["s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging"]
    resources = ["${aws_s3_bucket.source.arn}/*"]
  }
  statement {
    actions   = ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"]
    resources = ["${aws_s3_bucket.replica.arn}/*"]
  }
}

resource "aws_iam_role_policy" "replication" {
  provider = aws.palaven
  name     = "replicate"
  role     = aws_iam_role.replication.id
  policy   = data.aws_iam_policy_document.replication.json
}

# ---- S3 cross-region replication ------------------------------------------------

resource "aws_s3_bucket" "source" {
  provider      = aws.palaven
  bucket        = "${var.name}-source"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "source" {
  provider = aws.palaven
  bucket   = aws_s3_bucket.source.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket" "replica" {
  provider      = aws.thessia
  bucket        = "${var.name}-replica"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "replica" {
  provider = aws.thessia
  bucket   = aws_s3_bucket.replica.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_replication_configuration" "source" {
  provider = aws.palaven
  # Versioning must be on at both ends before replication can be configured.
  depends_on = [aws_s3_bucket_versioning.source, aws_s3_bucket_versioning.replica]

  role   = aws_iam_role.replication.arn
  bucket = aws_s3_bucket.source.id

  rule {
    id       = "everything"
    priority = 1
    status   = "Enabled"

    filter {}

    delete_marker_replication {
      status = "Enabled"
    }

    destination {
      bucket        = aws_s3_bucket.replica.arn
      storage_class = "STANDARD"
    }
  }
}

# ---- DynamoDB global table ------------------------------------------------------

resource "aws_dynamodb_table" "sessions" {
  provider     = aws.palaven
  name         = "${var.name}-sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  # Global tables replicate through the table's stream.
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  attribute {
    name = "id"
    type = "S"
  }

  replica {
    region_name = "tuchanka-1"
  }

  replica {
    region_name = "thessia-1"
  }
}

# ---- SQS (regional) --------------------------------------------------------------

resource "aws_sqs_queue" "palaven" {
  provider = aws.palaven
  name     = "${var.name}-events"
}

resource "aws_sqs_queue" "tuchanka" {
  provider = aws.tuchanka
  name     = "${var.name}-events"
}

resource "aws_sqs_queue" "thessia" {
  provider = aws.thessia
  name     = "${var.name}-events"
}

# ---- outputs ----------------------------------------------------------------------

output "source_bucket" {
  value = aws_s3_bucket.source.id
}

output "replica_bucket" {
  value = aws_s3_bucket.replica.id
}

output "table_name" {
  value = aws_dynamodb_table.sessions.name
}

output "queue_urls" {
  value = {
    "palaven-1"  = aws_sqs_queue.palaven.url
    "tuchanka-1" = aws_sqs_queue.tuchanka.url
    "thessia-1"  = aws_sqs_queue.thessia.url
  }
}
