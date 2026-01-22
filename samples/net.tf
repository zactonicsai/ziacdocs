resource "aws_vpc" "main" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "demo-vpc" }
}

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.20.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true
  tags = { Name = "public-a" }
}

resource "aws_subnet" "private_app_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.20.11.0/24"
  availability_zone = "us-east-1a"
  tags = { Name = "private-app-a" }
}

resource "aws_subnet" "private_data_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.20.21.0/24"
  availability_zone = "us-east-1a"
  tags = { Name = "private-data-a" }
}
