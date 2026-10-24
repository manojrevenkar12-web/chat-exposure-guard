resource "aws_s3_bucket" "media" {
  bucket = "companion-media"
}

resource "aws_s3_bucket_public_access_block" "media" {
  bucket                  = aws_s3_bucket.media.id
  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "media_previews" {
  bucket = aws_s3_bucket.media.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::companion-media/previews/*"
  }]
}
POLICY
}

resource "aws_security_group" "search" {
  name = "search"
  ingress {
    from_port   = 9200
    to_port     = 9200
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_msk_cluster" "events" {
  cluster_name           = "events"
  kafka_version          = "3.6.0"
  number_of_broker_nodes = 3
  broker_node_group_info {
    instance_type   = "kafka.m5.large"
    client_subnets  = ["subnet-a", "subnet-b", "subnet-c"]
    security_groups = ["sg-kafka"]
  }
  client_authentication {
    unauthenticated = true
  }
}

resource "aws_db_instance" "billing" {
  identifier          = "billing"
  engine              = "postgres"
  instance_class      = "db.t4g.medium"
  publicly_accessible = false
}
