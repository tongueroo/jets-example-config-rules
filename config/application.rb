Jets.application.configure do
  config.project_name = "rules"
  config._mode = 'job'
  config.cors = true # for '*''
  config.function.timeout = 20

  config.managed_iam_policy = %w[
    AWSCloudTrailReadOnlyAccess
    service-role/AWSConfigRulesExecutionRole
    service-role/AWSLambdaBasicExecutionRole
  ]
end
