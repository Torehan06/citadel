# A small but realistic stack against one Citadel region: a versioned bucket
# with a policy and lifecycle rules, a DynamoDB table with a GSI, an SQS queue
# with a dead-letter queue, an IAM role for a Lambda function, and the function
# itself fed by the queue. examples/terraform/smoke.sh builds the function zip,
# then runs init, apply, plan -detailed-exitcode and destroy.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

variable "endpoint" {
  description = "Citadel region endpoint."
  type        = string
  default     = "http://127.0.0.1:8420"
}

variable "region" {
  type    = string
  default = "tuchanka-1"
}

variable "name" {
  description = "Prefix for every resource name."
  type        = string
  default     = "tf-single"
}

variable "lambda_zip" {
  description = "Deployment package containing bootstrap.wasm (built by smoke.sh)."
  type        = string
  default     = "build/function.zip"
}

provider "aws" {
  region = var.region

  # Citadel is not AWS: no account lookup through STS, no EC2 metadata, and a
  # region name the provider does not know.
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  s3_use_path_style           = true

  endpoints {
    dynamodb = var.endpoint
    iam      = var.endpoint
    lambda   = var.endpoint
    logs     = var.endpoint
    s3       = var.endpoint
    sqs      = var.endpoint
    sts      = var.endpoint
  }

  default_tags {
    tags = {
      Stack = "single-region"
    }
  }
}

locals {
  function_name = "${var.name}-worker"
}

# ---- IAM ---------------------------------------------------------------------

data "aws_iam_policy_document" "assume_lambda" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "worker" {
  name                 = "${var.name}-worker"
  path                 = "/service/"
  description          = "Execution role for the worker function"
  assume_role_policy   = data.aws_iam_policy_document.assume_lambda.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "worker" {
  statement {
    sid       = "Queue"
    actions   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
    resources = [aws_sqs_queue.jobs.arn]
  }
  statement {
    sid       = "Table"
    actions   = ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:Query"]
    resources = [aws_dynamodb_table.orders.arn, "${aws_dynamodb_table.orders.arn}/index/*"]
  }
  statement {
    sid       = "Bucket"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.data.arn}/*"]
  }
}

resource "aws_iam_policy" "worker" {
  name        = "${var.name}-worker"
  description = "Lets the worker read its queue and write orders"
  policy      = data.aws_iam_policy_document.worker.json
}

resource "aws_iam_role_policy_attachment" "worker" {
  role       = aws_iam_role.worker.name
  policy_arn = aws_iam_policy.worker.arn
}

data "aws_iam_policy_document" "worker_logs" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "worker_logs" {
  name   = "logs"
  role   = aws_iam_role.worker.id
  policy = data.aws_iam_policy_document.worker_logs.json
}

# ---- S3 ------------------------------------------------------------------------

resource "aws_s3_bucket" "data" {
  bucket        = "${var.name}-data"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

data "aws_iam_policy_document" "data_bucket" {
  statement {
    sid       = "WorkerReads"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.data.arn}/*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.worker.arn]
    }
  }
  statement {
    sid       = "WorkerLists"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.data.arn]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.worker.arn]
    }
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["in/*", "out/*"]
    }
  }
}

resource "aws_s3_bucket_policy" "data" {
  bucket = aws_s3_bucket.data.id
  policy = data.aws_iam_policy_document.data_bucket.json
}

resource "aws_s3_bucket_lifecycle_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    id     = "expire-tmp"
    status = "Enabled"
    filter {
      prefix = "tmp/"
    }
    expiration {
      days = 7
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }

  rule {
    id     = "abort-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 3
    }
  }

  depends_on = [aws_s3_bucket_versioning.data]
}

# ---- DynamoDB --------------------------------------------------------------------

resource "aws_dynamodb_table" "orders" {
  name         = "${var.name}-orders"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }
  attribute {
    name = "sk"
    type = "S"
  }
  attribute {
    name = "customer"
    type = "S"
  }

  global_secondary_index {
    name            = "by-customer"
    projection_type = "ALL"
    key_schema {
      attribute_name = "customer"
      key_type       = "HASH"
    }
    key_schema {
      attribute_name = "sk"
      key_type       = "RANGE"
    }
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
}

# ---- SQS -------------------------------------------------------------------------

resource "aws_sqs_queue" "jobs_dlq" {
  name                      = "${var.name}-jobs-dlq"
  message_retention_seconds = 1209600
}

resource "aws_sqs_queue" "jobs" {
  name                       = "${var.name}-jobs"
  visibility_timeout_seconds = 60
  receive_wait_time_seconds  = 10
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.jobs_dlq.arn
    maxReceiveCount     = 3
  })
}

# ---- Lambda ------------------------------------------------------------------------

resource "aws_lambda_function" "worker" {
  function_name    = local.function_name
  description      = "Consumes the jobs queue"
  role             = aws_iam_role.worker.arn
  runtime          = "provided.al2023"
  handler          = "bootstrap"
  filename         = var.lambda_zip
  source_code_hash = filebase64sha256(var.lambda_zip)
  memory_size      = 128
  timeout          = 10

  environment {
    variables = {
      TABLE  = aws_dynamodb_table.orders.name
      BUCKET = aws_s3_bucket.data.id
    }
  }

  depends_on = [aws_iam_role_policy_attachment.worker, aws_iam_role_policy.worker_logs]
}

resource "aws_lambda_event_source_mapping" "jobs" {
  event_source_arn                   = aws_sqs_queue.jobs.arn
  function_name                      = aws_lambda_function.worker.arn
  batch_size                         = 5
  maximum_batching_window_in_seconds = 1
  function_response_types            = ["ReportBatchItemFailures"]
}

output "bucket" {
  value = aws_s3_bucket.data.id
}

output "queue_url" {
  value = aws_sqs_queue.jobs.url
}

output "function_arn" {
  value = aws_lambda_function.worker.arn
}
