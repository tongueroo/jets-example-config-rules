import json
import boto3
import datetime
import time
client_ct = boto3.client('cloudtrail')
config = boto3.client('config')
def lambda_handler(event, context):
  for trail in client_ct.describe_trails()['trailList']:
    is_compliant = True
    if trail['HomeRegion'] == context.invoked_function_arn.split(':')[3]:
      current_region_trail = trail
      annotation = ''
      # evaluate log file validation
      if not current_region_trail['LogFileValidationEnabled']:
        is_compliant = False
        annotation = annotation + ' CloudTrail log file validation is not enabled.'
      # evaluate log file encryption
      if not 'KmsKeyId' in current_region_trail:
        is_compliant = False
        annotation = annotation + ' CloudTrail log files are not encrypted in S3.'
      result_token = 'No token found.'
      if 'resultToken' in event: result_token = event['resultToken']
      evaluations = [
        {
          'ComplianceResourceType': 'AWS::CloudTrail::Trail',
          'ComplianceResourceId': current_region_trail['Name'],
          'ComplianceType': 'COMPLIANT' if is_compliant else 'NON_COMPLIANT',
          'OrderingTimestamp': datetime.datetime.now()
        }
      ]
      if is_compliant: annotation = 'CloudTrail log files are encrypted and validated in S3.'

      if annotation: evaluations[0]['Annotation'] = annotation

      print(evaluations)
      config.put_evaluations(
        Evaluations = evaluations,
        ResultToken = result_token
      )

if __name__ == "__main__":
  # Thanks: https://gist.github.com/thiago-vieira/4164936/227acbc80acb74bf07c6b46eeda4687ba586843f
  class Context:
    pass

  context = Context()
  context.invoked_function_arn = 'arn:aws:lambda:us-west-2:667805533836:function:config-dev-check_rule-cloud_trail_log_integrity'

  event = {'hi': 'world'}
  lambda_handler(event, context)
