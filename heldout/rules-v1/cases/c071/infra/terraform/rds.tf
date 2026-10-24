resource "aws_db_instance" "chat" {
  identifier                = "lumachat-chat-prod"
  engine                    = "postgres"
  engine_version            = "16.3"
  instance_class            = "db.r6g.large"
  allocated_storage         = 200
  db_name                   = "chat"
  username                  = "chat_admin"
  password                  = "Hn4wZ8qP2xL7vB9kT3mR6yC1"
  db_subnet_group_name      = aws_db_subnet_group.chat.name
  vpc_security_group_ids    = [aws_security_group.chat_db.id]
  publicly_accessible       = true
  storage_encrypted         = true
  backup_retention_period   = 14
  deletion_protection       = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "lumachat-chat-prod-final"
}
