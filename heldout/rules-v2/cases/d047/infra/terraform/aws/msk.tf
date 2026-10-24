resource "aws_msk_cluster" "chat_events" {
  cluster_name           = "kindred-chat-events"
  kafka_version          = "3.6.0"
  number_of_broker_nodes = 3

  broker_node_group_info {
    instance_type   = "kafka.m5.large"
    client_subnets  = var.private_subnet_ids
    security_groups = [aws_security_group.msk.id]

    storage_info {
      ebs_storage_info {
        volume_size = 500
      }
    }
  }

  client_authentication {
    unauthenticated = true

    sasl {
      iam = false
    }
  }

  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
  }

  tags = {
    service = "chat"
    env     = var.env
  }
}
