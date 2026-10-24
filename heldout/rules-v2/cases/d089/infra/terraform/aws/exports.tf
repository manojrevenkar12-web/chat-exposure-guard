resource "aws_s3_bucket" "exports" {
  bucket = "kindred-chat-exports"
}

resource "aws_s3_bucket_ownership_controls" "exports" {
  bucket = aws_s3_bucket.exports.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "exports" {
  depends_on = [aws_s3_bucket_ownership_controls.exports]
  bucket     = aws_s3_bucket.exports.id
  acl        = "public-read"
}

resource "aws_s3_bucket_lifecycle_configuration" "exports" {
  bucket = aws_s3_bucket.exports.id
  rule {
    id     = "expire"
    status = "Enabled"
    expiration {
      days = 7
    }
  }
}
