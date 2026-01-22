resource "aws_security_group" "alb_sg" {
  name   = "alb-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
    description = "Public HTTPS"
  }

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["10.20.0.0/16"]
    description = "Only to VPC"
  }
}

resource "aws_security_group" "app_sg" {
  name   = "app-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    protocol        = "tcp"
    from_port       = 8080
    to_port         = 8080
    security_groups = [aws_security_group.alb_sg.id]
    description     = "Only ALB to app"
  }

  egress {
    protocol    = "tcp"
    from_port   = 5432
    to_port     = 5432
    cidr_blocks = ["10.20.21.0/24"]
    description = "App to DB subnet only"
  }
}
