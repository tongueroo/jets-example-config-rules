class CheckRule < ApplicationRule
  desc "CIS 2.2, 2.7 - Ensure CloudTrail log file validation is enabled (Scored), ensure CloudTrail logs are encrypted at rest using KMS CMKs (Scored)"
  scope "AWS::CloudTrail::Trail"
  python :cloud_trail_log_integrity

  desc "CIS 4.1: Ensure no security groups allow ingress from 0.0.0.0/0 to port 22"
  scope "AWS::EC2::SecurityGroup"
  managed_rule :incoming_ssh_disabled
end