resource "aws_security_group_rule" "ssh" {
  from_port   = 22
  cidr_blocks = ["0.0.0.0/0"]
}
resource "aws_s3_bucket_acl" "b" {
  acl = "public-read"
}
