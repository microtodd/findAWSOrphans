#
# Compare running resources to the CF stacks, determine if anything is "orphaned".
#
import boto3
import sys
import getopt

###
def printHelp():
    print '''
    findOrphans.py

    Required:
    -e <arn>        ARN of role to run as
    -p <name>       Profile name to run as
    -r <region>     Region

    Optional:
    -h              print help and exit
    -v              verbose mode
    -l              check ELBs
    -s              check SGs
    -i              check EIPs
    -a              check All
    '''

###
def checkELBs(stsCreds,stackELBs,verbose=False,region='us-east-1'):

    # Local
    unmatchedELBs = []

    # Get list of running ELBs
    elbClient = boto3.client('elb',
        aws_access_key_id=stsCreds['AccessKeyId'],
        aws_secret_access_key=stsCreds['SecretAccessKey'],
        aws_session_token=stsCreds['SessionToken'],
        region_name=region)
    runningELBs = elbClient.describe_load_balancers()
    
    # Find unmatched
    for runningELB in runningELBs['LoadBalancerDescriptions']:
        if verbose:
            print 'runningELB => ' + runningELB['LoadBalancerName']
        if runningELB['LoadBalancerName'] not in stackELBs:
            unmatchedELBs.append(runningELB['LoadBalancerName'])
    for unmatchedELB in unmatchedELBs:
        print 'unmatchedELB => ' + unmatchedELB

    return unmatchedELBs

###
def checkSGs(stsCreds,stackSGs,verbose=False,region='us-east-1'):

    # Local
    unmatchedSGs = []

    # Get list of SGs in the environment
    sgClient = boto3.client('ec2',
        aws_access_key_id=stsCreds['AccessKeyId'],
        aws_secret_access_key=stsCreds['SecretAccessKey'],
        aws_session_token=stsCreds['SessionToken'],
        region_name=region)
    runningSGs = sgClient.describe_security_groups()

    # Find unmatched
    for runningSG in runningSGs['SecurityGroups']:
        if verbose:
            print 'runningSG => ' + runningSG['GroupId']
        if runningSG['GroupId'] not in stackSGs:
            unmatchedSGs.append(runningSG['GroupId'] + ' (' + runningSG['GroupName'] + ')')
    for sg in unmatchedSGs:
        print 'unmatchedSG => ' + sg

    return unmatchedSGs

###
def checkEIPs(stsCreds,stackEIPs,verbose=False,region='us-east-1'):

    # Local
    unmatchedEIPs = []

    # Get list of EIPs in the environment
    sgClient = boto3.client('ec2',
        aws_access_key_id=stsCreds['AccessKeyId'],
        aws_secret_access_key=stsCreds['SecretAccessKey'],
        aws_session_token=stsCreds['SessionToken'],
        region_name=region)
    runningEIPs = sgClient.describe_addresses()

    # Find unmatched
    for running in runningEIPs['Addresses']:
        if verbose:
            print 'runningEIP => ' + running['PublicIp']
        if running['PublicIp'] not in stackEIPs:
            unmatchedEIPs.append(running['PublicIp'])
    for addr in unmatchedEIPs:
        print 'unmatchedEIPs => ' + addr

    return unmatchedEIPs

###
def main(argv):

    # Session
    ARN = None
    Profile = None
    Verbose = False
    CheckELBs = False
    CheckSGs = False
    CheckEIPs = False

    # Parse CL opts
    opts, args = getopt.getopt(argv,'hvlsae:p:r:')
    for opt, arg in opts:
        if opt == '-h':
            printHelp()
            sys.exit(0)
        if opt == '-e':
            ARN = str(arg)
        if opt == '-p':
            Profile = str(arg)
        if opt == '-r':
            Region = str(arg)
        if opt == '-v':
            Verbose = True
        if opt == '-l':
            CheckELBs = True
        if opt == '-s':
            CheckSGs = True
        if opt == '-i':
            CheckEIPs = True
        if opt == '-a':
            CheckELBs = True
            CheckSGs = True
            CheckEIPs = True

    # Validate
    if ARN == None or Profile == None:
        print 'Error: Must specify environment with -e and profile with -p'
        sys.exit(-1)

    # Get applicable creds
    mySession = boto3.Session(profile_name=Profile)
    stsClient = mySession.client('sts')
    stsCreds = stsClient.assume_role(RoleArn=ARN,RoleSessionName='thisSession')
    stsCreds = stsCreds['Credentials']

    # Get all running stacks/resources
    stackELBs = {} # AWS::ElasticLoadBalancing::LoadBalancer
    # TODO stackInstances = {}
    stackSGs = {} # AWS::EC2::SecurityGroup
    stackEIPs = {} # AWS::EC2::EIP
    # TODO stackENIs = {} # AWS::EC2::NetworkInterface
    stackResourceTypes = {}
    cfClient = boto3.client('cloudformation',
        aws_access_key_id=stsCreds['AccessKeyId'],
        aws_secret_access_key=stsCreds['SecretAccessKey'],
        aws_session_token=stsCreds['SessionToken'],
        region_name=Region)
    allRunningStacks = cfClient.list_stacks(StackStatusFilter=['CREATE_COMPLETE','UPDATE_COMPLETE'])

    # Pull all info for all running stacks
    for stack in allRunningStacks['StackSummaries']:
    
        # Some of the API calls only give you a paginated return list
        nextToken = 1
        while nextToken is not None:
            thisStackResources = None
            if nextToken == 1:
                thisStackResources = cfClient.list_stack_resources(StackName=stack['StackName'])
            else:
                thisStackResources = cfClient.list_stack_resources(StackName=stack['StackName'],NextToken=nextToken)
            if 'NextToken' in thisStackResources:
                nextToken = thisStackResources['NextToken']
            else:
                nextToken = None
    
            for resource in thisStackResources['StackResourceSummaries']:
                stackResourceTypes[resource['ResourceType']] = 1
    
                # Only check running resources
                if resource['ResourceStatus'] != 'CREATE_COMPLETE' and resource['ResourceStatus'] != 'UPDATE_COMPLETE':
                    continue
    
                # ELBs
                if resource['ResourceType'] == 'AWS::ElasticLoadBalancing::LoadBalancer' and CheckELBs:
    
                    if Verbose:
                        print 'stackelb => ' + resource['PhysicalResourceId'] + ' => ' + stack['StackName']
                    stackELBs[resource['PhysicalResourceId']] = stack['StackName']
    
                # Security Groups
                elif resource['ResourceType'] == 'AWS::EC2::SecurityGroup' and CheckSGs:
                    if Verbose:
                        print 'stacksg => ' + resource['PhysicalResourceId'] + ' => ' + stack['StackName']
                    stackSGs[resource['PhysicalResourceId']] = stack['StackName']

                # Elastic IPs
                elif resource['ResourceType'] == 'AWS::EC2::EIP' and CheckEIPs:
                    if Verbose:
                        print 'stackeip => ' + resource['PhysicalResourceId'] + ' => ' + stack['StackName']
                    stackEIPs[resource['PhysicalResourceId']] = stack['StackName']
    
    # Do ELBs
    unmatchedELBs = None
    if CheckELBs:
        unmatchedELBs = checkELBs(stsCreds,stackELBs,verbose=Verbose,region=Region)
    
    # DO SGs
    unmatchedSGs = None
    if CheckSGs:
        unmatchedSGs = checkSGs(stsCreds,stackSGs,verbose=Verbose,region=Region)

    # Do EIPs
    unmatchedEIPs = None
    if CheckEIPs:
        unmatchedEIPs = checkEIPs(stsCreds,stackEIPs,verbose=Verbose,region=Region)

###
if __name__ == '__main__':
    main(sys.argv[1:])

