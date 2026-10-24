resource "random_password" "db" {
  length  = 32
  special = false
}

resource "aws_security_group" "edge" {
  name   = "edge"
  vpc_id = var.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "db" {
  name   = "memory-db"
  vpc_id = var.vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    cidr_blocks     = [var.vpc_cidr]
    security_groups = [aws_security_group.edge.id]
  }
}

resource "aws_db_instance" "memory" {
  identifier             = "kindred-memory-prod"
  engine                 = "postgres"
  instance_class         = "db.t4g.large"
  allocated_storage      = 100
  username               = "memory_admin"
  password               = random_password.db.result
  publicly_accessible    = false
  vpc_security_group_ids = [aws_security_group.db.id]
}
