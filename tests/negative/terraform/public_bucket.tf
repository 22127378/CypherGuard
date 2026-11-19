# DELIBERATELY INSECURE fixture for scripts/scan.sh negative. Never applied.
# Must be blocked by Checkov: public ACL, public policy, no public access block.

resource "aws_s3_bucket" "leaky" {
  bucket = "cipherguard-negative-test-leaky"
}

resource "aws_s3_bucket_acl" "leaky" {
  bucket = aws_s3_bucket.leaky.id
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "leaky" {
  bucket                  = aws_s3_bucket.leaky.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "leaky" {
  bucket = aws_s3_bucket.leaky.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.leaky.arn}/*"
    }]
  })
}
