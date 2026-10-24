resource "aws_security_group" "chat_db" {
  name   = "chat-db"
  vpc_id = var.vpc_id

  ingress {
    description = "postgres"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "chat" {
  identifier             = "kindred-chat-prod"
  engine                 = "postgres"
  engine_version         = "16.4"
  instance_class         = "db.r6g.large"
  allocated_storage      = 200
  db_name                = "chat"
  username               = "kindred_admin"
  password               = "Tn6wLq9zRk3vXp2mHc8bYs4f"
  publicly_accessible    = true
  storage_encrypted      = true
  vpc_security_group_ids = [aws_security_group.chat_db.id]
  db_subnet_group_name   = aws_db_subnet_group.chat.name
  skip_final_snapshot    = false
}
