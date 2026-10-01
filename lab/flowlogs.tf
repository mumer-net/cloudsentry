resource "aws_s3_bucket" "flow_logs" {
  bucket_prefix = "cloudsentry-flow-logs-"
  force_destroy = true
}

resource "aws_flow_log" "a" {
  vpc_id               = aws_vpc.a.id
  traffic_type         = "REJECT"
  log_destination      = aws_s3_bucket.flow_logs.arn
  log_destination_type = "s3"
}

# Seeded fault: VPC B has no flow log.
resource "aws_flow_log" "b" {
  count                = var.faults ? 0 : 1
  vpc_id               = aws_vpc.b.id
  traffic_type         = "REJECT"
  log_destination      = aws_s3_bucket.flow_logs.arn
  log_destination_type = "s3"
}
