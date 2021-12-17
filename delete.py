import logging
import boto3
import traceback
import json
import os
from boto3.session import Session

logger = logging.getLogger()
logger.setLevel(logging.INFO)

role_name = os.getenv('role_name', 'OrganizationAccountAccessRole')
region = os.getenv('region', 'us-east-2')
region_sample = os.getenv('region_sample', 'us-west-2')
user_name = os.getenv('user_name', 'cdk-student')
table_name = os.getenv('table_name', 'account_list')

def sts_assume_role(account_id):
    try:
        role_arn = "arn:aws:iam::{account_id}:role/{role_name}".format(
            account_id=account_id,
            role_name=role_name
        )
        session_name = "cdk-initial"
 
        client = boto3.client('sts')
 
        response = client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name
        )
 
        session = Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken'],
            region_name=region
        )
 
        return session
        
    except:
        logger.error(traceback.format_exc())
        raise Exception(traceback.format_exc())
        
def s3_bucket_delete(session):
    try:
        s3 = session.client('s3')
        buckets = s3.list_buckets()['Buckets']
        s3_waiter = s3.get_waiter('object_not_exists')

        for bucket in buckets:
            try:
                logger.info(bucket['Name'])
                list_objects = s3.list_objects_v2(
                    Bucket=bucket['Name']
                )
                if list_objects['KeyCount'] > 0:
                    objects = list_objects['Contents']
            
                    for object in objects:
                        s3.delete_object(
                            Bucket=bucket['Name'],
                            Key=object['Key']
                        )
                        s3_waiter.wait(
                            Bucket=bucket['Name'],
                            Key=object['Key']
                        )
    
                response = s3.delete_bucket(
                    Bucket=bucket['Name']  
                )
                logger.info(response)
            except:
                logger.error(traceback.format_exc())
                continue
        
    except:
        logger.error(traceback.format_exc())
        raise Exception(traceback.format_exc())
        
def apigateway_api_delete(session):
    try:
        api = session.client('apigateway')
        rest_apis = api.get_rest_apis()
        if rest_apis['items']:
            for item in rest_apis['items']:
                response = api.delete_rest_api(
                    restApiId=item['id']
                )
                logger.info(response)
    
    except:
        logger.error(traceback.format_exc())
        raise Exception(traceback.format_exc())
        
def lambda_function_delete(session):
    try:
        lambda_client = session.client('lambda')
        functions_list = lambda_client.list_functions()
        if functions_list['Functions']:
            for function in functions_list['Functions']:
                response = lambda_client.delete_function(
                    FunctionName=function['FunctionName']
                )
                logger.info(response)
        
    except:
        logger.error(traceback.format_exc())
        raise Exception(traceback.format_exc())
        
def iam_iamrole_delete(session):
    try:
        iam = session.resource('iam')
        role_iterator = iam.roles.all()
        for role in role_iterator:
            if 'lambda_' in role.role_name:
                logger.info(role.role_name)
                attached_policy_iterator = role.attached_policies.all()
                for attached_policy in attached_policy_iterator:
                    role.detach_policy(
                        PolicyArn=attached_policy.arn
                    )
                role_policy_iterator = role.policies.all()
                for role_policy in role_policy_iterator:
                    role_policy.delete()
                
                response = role.delete()
                logger.info(response)
        
    except:
        logger.error(traceback.format_exc())
        raise Exception(traceback.format_exc())
        
def dyanamodb_table_delete(session):
    try:
        dynamodb = session.resource('dynamodb')
        table_iterator = dynamodb.tables.all()
        for table in table_iterator:
            response = table.delete()
            logger.info(response)
        
    except:
        logger.error(traceback.format_exc())
        raise Exception(traceback.format_exc())
 
def cloudwatch_alarm_delete(session):
    try:
        cloudwatch = session.resource('cloudwatch')
        alarm_iterator = cloudwatch.alarms.all()
        for alarm in alarm_iterator:
            response = alarm.delete()
            logger.info(response)
        
    except:
        logger.error(traceback.format_exc())
        raise Exception(traceback.format_exc())
        
def sqs_queue_delete(session):
    try:
        sqs = session.resource('sqs')
        queue_iterator = sqs.queues.all()
        for queue in queue_iterator:
            response = queue.delete()
            logger.info(response)
        
    except:
        logger.error(traceback.format_exc())
        raise Exception(traceback.format_exc())
        
def sns_topic_delete(session):
    try:
        sns = session.resource('sns')
        subscription_iterator = sns.subscriptions.all()
        for subscription in subscription_iterator:
            response = subscription.delete()
            logger.info(response)
        
        topic_iterator = sns.topics.all()
        for topic in topic_iterator:
            response = topic.delete()
            logger.info(response)
        
    except:
        logger.error(traceback.format_exc())
        raise Exception(traceback.format_exc())
        
def cloud9_environment_delete(session):
    try:
        cloud9 = session.client('cloud9')
        environments = cloud9.list_environments()
        if environments['environmentIds']:
            for environment_id in environments['environmentIds']:
                response = cloud9.delete_environment(
                    environmentId=environment_id
                )
                logger.info(response)
        
    except:
        logger.error(traceback.format_exc())
        raise Exception(traceback.format_exc())
        
def cfn_stack_delete(session, region_name=region):
    try:
        cloudformation = session.resource(
            'cloudformation',
            region_name=region_name
        )
        stack_iterator = cloudformation.stacks.all()
        for stack in stack_iterator:
            response = stack.delete()
            logger.info(response)
        
    except:
        logger.error(traceback.format_exc())
        raise Exception(traceback.format_exc())
    
def iam_user_password(session):
    try:
        sm = session.client('secretsmanager')
        password = sm.get_random_password(
            PasswordLength=10,
            ExcludeCharacters='lI0O1oi',
            ExcludeNumbers=False,
            ExcludePunctuation=True,
            ExcludeUppercase=False,
            ExcludeLowercase=False,
            IncludeSpace=False,
            RequireEachIncludedType=True
        )
        
        iam = session.resource('iam')
        login_profile = iam.LoginProfile(user_name)
        response = login_profile.update(
            Password=password['RandomPassword'],
            PasswordResetRequired=False
        )
        logger.info(response)
        return password['RandomPassword']
        
    except:
        logger.error(traceback.format_exc())
        raise Exception(traceback.format_exc())
        
def password_putitem(account_id, password):
    try:
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(table_name)
        table.put_item(
            Item={
                'account_id': account_id,
                'iam_user': user_name,
                'password': password
            }
        )
    except:
        logger.error(traceback.format_exc())
        raise Exception(traceback.format_exc())

def lambda_handler(event, context):
    try:
        logger.info(event)
        session = sts_assume_role(event)
        
        s3_bucket_delete(session)
        apigateway_api_delete(session)
        lambda_function_delete(session)
        iam_iamrole_delete(session)
        dyanamodb_table_delete(session)
        cloudwatch_alarm_delete(session)
        sqs_queue_delete(session)
        sns_topic_delete(session)
        cloud9_environment_delete(session)
        cfn_stack_delete(session)
        password = iam_user_password(session)
        password_putitem(event, password)
        
        cfn_stack_delete(session, region_sample)

        return {
            'statusCode': 200,
            'body': event + 'success'
        }
        
    except:
        logger.error(traceback.format_exc())
        raise Exception(traceback.format_exc())
