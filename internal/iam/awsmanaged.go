package iam

import (
	"strings"
	"time"
)

// A few AWS managed policies, built in so they can be attached and
// evaluated. They are global, read-only and identical in every account.
var awsManagedDocs = []struct{ path, name, doc string }{
	{"/", "AdministratorAccess", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`},
	{"/", "PowerUserAccess", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:*","organizations:*","account:*"],"Resource":"*"},{"Effect":"Allow","Action":["iam:CreateServiceLinkedRole","iam:DeleteServiceLinkedRole","iam:ListRoles","organizations:DescribeOrganization","account:ListRegions"],"Resource":"*"}]}`},
	{"/", "ReadOnlyAccess", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:Get*","s3:List*","dynamodb:Describe*","dynamodb:List*","dynamodb:Get*","dynamodb:BatchGet*","dynamodb:Query","dynamodb:Scan","sqs:Get*","sqs:List*","iam:Get*","iam:List*","lambda:Get*","lambda:List*"],"Resource":"*"}]}`},
	{"/", "IAMFullAccess", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:*","organizations:DescribeAccount","organizations:DescribeOrganization","organizations:DescribeOrganizationalUnit","organizations:DescribePolicy","organizations:ListChildren","organizations:ListParents","organizations:ListPoliciesForTarget","organizations:ListRoots","organizations:ListPolicies","organizations:ListTargetsForPolicy"],"Resource":"*"}]}`},
	{"/", "IAMReadOnlyAccess", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:GenerateCredentialReport","iam:GenerateServiceLastAccessedDetails","iam:Get*","iam:List*","iam:SimulateCustomPolicy","iam:SimulatePrincipalPolicy"],"Resource":"*"}]}`},
	{"/", "AmazonS3FullAccess", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*","s3-object-lambda:*"],"Resource":"*"}]}`},
	{"/", "AmazonS3ReadOnlyAccess", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:Get*","s3:List*","s3:Describe*","s3-object-lambda:Get*","s3-object-lambda:List*"],"Resource":"*"}]}`},
	{"/", "AmazonDynamoDBFullAccess", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["dynamodb:*"],"Resource":"*"}]}`},
	{"/", "AmazonDynamoDBReadOnlyAccess", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["dynamodb:BatchGetItem","dynamodb:Describe*","dynamodb:List*","dynamodb:GetItem","dynamodb:Query","dynamodb:Scan","dynamodb:PartiQLSelect"],"Resource":"*"}]}`},
	{"/", "AmazonSQSFullAccess", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["sqs:*"],"Resource":"*"}]}`},
	{"/", "AmazonSQSReadOnlyAccess", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["sqs:GetQueueAttributes","sqs:GetQueueUrl","sqs:ListDeadLetterSourceQueues","sqs:ListQueues","sqs:ListMessageMoveTasks","sqs:ListQueueTags"],"Resource":"*"}]}`},
	{"/", "AWSLambda_FullAccess", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["lambda:*","iam:PassRole","iam:ListRoles","logs:*"],"Resource":"*"}]}`},
	{"/", "IAMUserChangePassword", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:ChangePassword"],"Resource":["arn:aws:iam::*:user/${aws:username}"]},{"Effect":"Allow","Action":["iam:GetAccountPasswordPolicy"],"Resource":"*"}]}`},
	{"/service-role/", "AWSLambdaBasicExecutionRole", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],"Resource":"*"}]}`},
	{"/service-role/", "AWSLambdaSQSQueueExecutionRole", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["sqs:ReceiveMessage","sqs:DeleteMessage","sqs:GetQueueAttributes","logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],"Resource":"*"}]}`},
	{"/service-role/", "AWSLambdaDynamoDBExecutionRole", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["dynamodb:DescribeStream","dynamodb:GetRecords","dynamodb:GetShardIterator","dynamodb:ListStreams","logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],"Resource":"*"}]}`},
}

var awsManagedByARN = func() map[string]*Policy {
	created := time.Date(2015, 2, 6, 18, 39, 46, 0, time.UTC)
	m := map[string]*Policy{}
	for i, d := range awsManagedDocs {
		arn := "arn:aws:iam::aws:policy" + d.path + d.name
		m[arn] = &Policy{Path: d.path, Name: d.name, ID: "ANPAAWSMANAGED" + strings.Repeat("0", 5) + string(rune('A'+i%26)) + string(rune('A'+i/26)),
			ARN: arn, Created: created, Updated: created, Default: "v1",
			Versions: []PolicyVersion{{ID: "v1", Document: d.doc, Created: created}}}
	}
	return m
}()

// awsManaged returns the built-in AWS managed policy with this ARN (any
// partition), or nil.
func awsManaged(arn string) *Policy {
	if i := strings.Index(arn, ":iam::aws:policy/"); i >= 0 && strings.HasPrefix(arn, "arn:") {
		return awsManagedByARN["arn:aws"+arn[i:]]
	}
	return nil
}

func awsManagedList() []*Policy {
	out := make([]*Policy, 0, len(awsManagedDocs))
	for _, d := range awsManagedDocs {
		out = append(out, awsManagedByARN["arn:aws:iam::aws:policy"+d.path+d.name])
	}
	return out
}
