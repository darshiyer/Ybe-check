provider "aws" {
  region = "us-east-1"
}

# S3 bucket with proper security controls
resource "aws_s3_bucket" "public_bucket" {
  bucket = "fake-vibe-public-bucket"

  tags = {
    Name        = "Vibe Public Bucket"
    Environment = "production"
    ManagedBy   = "Terraform"
  }
}

# Enable versioning (protects against accidental deletion)
resource "aws_s3_bucket_versioning" "public_bucket" {
  bucket = aws_s3_bucket.public_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Enable server-side encryption (AES256)
resource "aws_s3_bucket_server_side_encryption_configuration" "public_bucket" {
  bucket = aws_s3_bucket.public_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# Block all public access (unless explicitly needed)
resource "aws_s3_bucket_public_access_block" "public_bucket" {
  bucket = aws_s3_bucket.public_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable access logging for audit trail
resource "aws_s3_bucket_logging" "public_bucket" {
  bucket = aws_s3_bucket.public_bucket.id

  target_bucket = aws_s3_bucket.public_bucket.id
  target_prefix = "access-logs/"
}

# Apply secure bucket ACL (private by default)
resource "aws_s3_bucket_acl" "public_bucket" {
  bucket = aws_s3_bucket.public_bucket.id
  acl    = "private"

  depends_on = [aws_s3_bucket_ownership_controls.public_bucket]
}

# Set bucket ownership controls
resource "aws_s3_bucket_ownership_controls" "public_bucket" {
  bucket = aws_s3_bucket.public_bucket.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}
