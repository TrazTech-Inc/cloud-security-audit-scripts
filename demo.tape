Output demo.gif

Set FontSize 14
Set Width 1200
Set Height 600
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 40ms

Type "# TrazTech Cloud Security Audit Scripts"
Enter
Sleep 500ms
Type "# Pre-audit evidence collection for AWS, GCP, and Azure"
Enter
Sleep 1s

Type "python3 aws/aws_audit.py --help"
Enter
Sleep 2s

Type "python3 aws/aws_audit.py --output-format markdown --output-dir reports/"
Enter
Sleep 1s

Type ""
Sleep 500ms
# Simulate output
Type "  TrazTech Cloud Security Audit - AWS"
Enter
Type "  ======================================"
Enter
Sleep 500ms
Type ""
Enter
Type "  [*] Checking IAM configuration..."
Enter
Sleep 400ms
Type "    [PASS] Root account MFA is enabled"
Enter
Sleep 200ms
Type "    [PASS] Password policy meets minimum requirements"
Enter
Sleep 200ms
Type "    [WARN] 2 IAM users without MFA enabled"
Enter
Sleep 200ms
Type "    [FAIL] 3 access keys older than 90 days (CC6.1)"
Enter
Sleep 400ms
Type ""
Enter
Type "  [*] Checking S3 bucket security..."
Enter
Sleep 400ms
Type "    [PASS] Account-level public access block is enabled"
Enter
Sleep 200ms
Type "    [PASS] All buckets have encryption at rest"
Enter
Sleep 200ms
Type "    [WARN] 1 bucket missing access logging"
Enter
Sleep 400ms
Type ""
Enter
Type "  [*] Checking CloudTrail configuration..."
Enter
Sleep 400ms
Type "    [PASS] CloudTrail enabled in all regions"
Enter
Sleep 200ms
Type "    [PASS] Log file validation is enabled"
Enter
Sleep 200ms
Type "    [PASS] CloudTrail logs delivered to S3"
Enter
Sleep 400ms
Type ""
Enter
Type "  [*] Checking EC2/VPC security..."
Enter
Sleep 400ms
Type "    [FAIL] 2 security groups allow 0.0.0.0/0 on port 22 (CC6.6)"
Enter
Sleep 200ms
Type "    [PASS] Default VPC not in use"
Enter
Sleep 200ms
Type "    [PASS] EBS encryption enabled by default"
Enter
Sleep 400ms
Type ""
Enter
Type "  [*] Checking RDS configuration..."
Enter
Sleep 400ms
Type "    [PASS] No publicly accessible RDS instances"
Enter
Sleep 200ms
Type "    [PASS] All RDS instances encrypted"
Enter
Sleep 200ms
Type "    [PASS] Automated backups enabled"
Enter
Sleep 600ms
Type ""
Enter
Type "  ======================================"
Enter
Type "  Summary: 12 PASS | 3 WARN | 2 FAIL"
Enter
Type "  SOC 2 Controls Tested: CC6.1, CC6.6, CC7.1, CC7.2, CC8.1, A1.2"
Enter
Type "  Report saved to: reports/aws-audit-2026-09-10.md"
Enter
Sleep 3s
