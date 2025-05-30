# Example Terraform configuration for testing

# Overprovisioned EC2 instance
resource "aws_instance" "example" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.xlarge"  # This might be overprovisioned for testing
  
  tags = {
    Name = "test-instance"
  }
}

# Security group with overly permissive rules
resource "aws_security_group" "example" {
  name        = "allow_all"
  description = "Allow all traffic"
  
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "allow_all"
  }
}
